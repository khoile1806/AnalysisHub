package egress

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"
)

// sourceCtxKey tags a request context with the originating module so the flow
// log can attribute traffic. Callers set it with WithSource.
type sourceCtxKey struct{}

// WithSource returns a context that stamps every egress request made under it
// with src (e.g. "osint:<scanID>", "threat-intel"). The flow logger reads it.
func WithSource(ctx context.Context, src string) context.Context {
	return context.WithValue(ctx, sourceCtxKey{}, src)
}

func sourceFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(sourceCtxKey{}).(string); ok {
		return v
	}
	return ""
}

// Probe health-checks an arbitrary proxy URL WITHOUT touching the live config,
// so the UI can test a pool profile before switching to it. It GETs the same
// probe URL the background checker uses, through the given proxy.
func Probe(proxyURL string) Health {
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL == "" {
		return Health{Healthy: false, LastCheck: time.Now(), Err: "empty proxy URL"}
	}
	pu, err := url.Parse(proxyURL)
	if err != nil {
		return Health{Healthy: false, LastCheck: time.Now(), Err: "invalid proxy URL"}
	}
	mu.RLock()
	probe := probeURL
	mu.RUnlock()

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(pu)},
	}
	start := time.Now()
	resp, err := client.Get(probe)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return Health{Healthy: false, LastCheck: time.Now(), LatencyMs: lat, Err: err.Error()}
	}
	_ = resp.Body.Close()
	return Health{Healthy: resp.StatusCode < 500, LastCheck: time.Now(), LatencyMs: lat}
}

// Flow is one recorded outbound request/response through the egress layer. It is
// intentionally dependency-free (no models import) so the egress package stays a
// leaf; the API layer converts it to a persisted record.
type Flow struct {
	Time       time.Time
	Method     string
	Scheme     string
	Host       string
	URL        string
	Status     int
	ViaProxy   bool
	ProxyLabel string
	Source     string // originating module (osint, threat-intel, …) or "app"
	// Leaked is true when a proxy was active but this request went DIRECT to a
	// non-loopback host — an anonymity leak the UI flags in red.
	Leaked      bool
	ContentType string
	TLSVersion  string
	BytesOut    int64
	BytesIn     int64
	DurationMs  int64
	// Timing breakdown (ms). Zero when a phase did not occur (e.g. reused conn).
	DNSMs     int64
	ConnectMs int64
	TLSMs     int64
	TTFBMs    int64
	Error     string
}

var (
	flowMu      sync.RWMutex
	flowSink    func(Flow)
	activeLabel = "direct"
)

// SetFlowSink registers the callback that receives each completed flow. Passing
// nil disables recording. The sink is invoked once per request (on response-body
// close, or immediately on transport error), so BytesIn reflects bytes actually
// read over the wire.
func SetFlowSink(fn func(Flow)) {
	flowMu.Lock()
	flowSink = fn
	flowMu.Unlock()
}

// SetActiveLabel records a human label (the active proxy profile name, or
// "direct") stamped onto every subsequent flow so the UI can attribute traffic.
func SetActiveLabel(label string) {
	if label == "" {
		label = "direct"
	}
	flowMu.Lock()
	activeLabel = label
	flowMu.Unlock()
}

func emitFlow(f Flow) {
	flowMu.RLock()
	fn := flowSink
	flowMu.RUnlock()
	if fn != nil {
		fn(f)
	}
}

func currentLabel() string {
	flowMu.RLock()
	defer flowMu.RUnlock()
	return activeLabel
}

// NewLoggingTransport wraps base so every request/response is recorded as a Flow.
// When no sink is registered the overhead is a single nil check, so it is safe to
// install unconditionally. base is typically an *http.Transport whose Proxy is
// egress.Proxy.
func NewLoggingTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &loggingTransport{base: base}
}

type loggingTransport struct{ base http.RoundTripper }

// Unwrap exposes the wrapped transport so callers that need the underlying
// *http.Transport (e.g. to inspect its Proxy/Dial settings) can reach it.
func (l *loggingTransport) Unwrap() http.RoundTripper { return l.base }

func (l *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()

	// Capture connection-phase timings. Any phase that doesn't run (e.g. a reused
	// keep-alive connection, or DNS skipped for a proxied request) stays zero.
	var tDNSStart, tDNSDone, tConnStart, tConnDone, tTLSDone, tFirstByte time.Time
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { tDNSStart = time.Now() },
		DNSDone:  func(httptrace.DNSDoneInfo) { tDNSDone = time.Now() },
		ConnectStart: func(_, _ string) {
			if tConnStart.IsZero() {
				tConnStart = time.Now()
			}
		},
		ConnectDone:          func(_, _ string, _ error) { tConnDone = time.Now() },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { tTLSDone = time.Now() },
		GotFirstResponseByte: func() { tFirstByte = time.Now() },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	viaProxy := false
	if req.URL != nil {
		if u, err := Proxy(req); err == nil && u != nil {
			viaProxy = true
		}
	}

	f := Flow{
		Time:       start,
		Method:     req.Method,
		ViaProxy:   viaProxy,
		ProxyLabel: labelFor(viaProxy),
		Source:     sourceFor(req),
		BytesOut:   nonNeg(req.ContentLength),
	}
	if req.URL != nil {
		f.Host = req.URL.Hostname()
		f.Scheme = req.URL.Scheme
		f.URL = redactURL(req.URL)
		// Anonymity leak: a proxy is active but this request went straight out to
		// a non-loopback host. Loopback bypasses (localhost SIEM, etc.) are fine.
		f.Leaked = !viaProxy && !Direct() && !isLoopbackHost(f.Host)
	}

	resp, err := l.base.RoundTrip(req)
	f.DurationMs = time.Since(start).Milliseconds()
	f.DNSMs = msBetween(tDNSStart, tDNSDone)
	f.ConnectMs = msBetween(tConnStart, tConnDone)
	f.TLSMs = msBetween(tConnDone, tTLSDone)
	f.TTFBMs = msBetween(start, tFirstByte)
	if err != nil {
		f.Error = capString(err.Error(), 256)
		emitFlow(f)
		return resp, err
	}

	f.Status = resp.StatusCode
	f.ContentType = firstToken(resp.Header.Get("Content-Type"))
	if resp.TLS != nil {
		f.TLSVersion = tlsVersionName(resp.TLS.Version)
	}
	// Count response bytes as the caller reads them; emit the finished flow once
	// the body is closed (Go requires every response body to be closed).
	resp.Body = &countingBody{rc: resp.Body, flow: f}
	return resp, nil
}

func sourceFor(req *http.Request) string {
	if s := sourceFromContext(req.Context()); s != "" {
		return s
	}
	ua := req.Header.Get("User-Agent")
	if strings.Contains(ua, "OSINT") {
		return "osint"
	}
	return "app"
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func msBetween(a, b time.Time) int64 {
	if a.IsZero() || b.IsZero() || b.Before(a) {
		return 0
	}
	return b.Sub(a).Milliseconds()
}

func firstToken(s string) string {
	if i := strings.IndexAny(s, ";, "); i >= 0 {
		return s[:i]
	}
	return s
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	default:
		return ""
	}
}

// countingBody tallies bytes read from a response body and emits the flow exactly
// once, when the body is closed.
type countingBody struct {
	rc   io.ReadCloser
	flow Flow
	n    int64
	once sync.Once
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countingBody) Close() error {
	err := c.rc.Close()
	c.once.Do(func() {
		c.flow.BytesIn = c.n
		emitFlow(c.flow)
	})
	return err
}

func labelFor(viaProxy bool) string {
	if !viaProxy {
		return "direct"
	}
	return currentLabel()
}

func nonNeg(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}

func capString(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}

// secretParam lists query-string parameter names that carry credentials and must
// never be persisted into the flow log. Many collectors pass API keys in the URL
// (Shodan/Pulsedive ?key=, NumVerify ?access_key=), so their values are redacted.
var secretParam = map[string]bool{
	"key": true, "api_key": true, "apikey": true, "apitoken": true,
	"token": true, "access_key": true, "access_token": true,
	"password": true, "passwd": true, "secret": true, "auth": true, "sig": true,
}

// redactURL renders a request URL for logging with any credential-bearing query
// parameter value replaced by "REDACTED", then length-capped. Non-secret params
// (e.g. the OSINT target ?q=) are preserved because they are useful context.
func redactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	if u.RawQuery == "" {
		return capString(u.String(), 512)
	}
	q := u.Query()
	for k := range q {
		if secretParam[strings.ToLower(k)] {
			for i := range q[k] {
				q[k][i] = "REDACTED"
			}
		}
	}
	c := *u
	c.RawQuery = q.Encode()
	return capString(c.String(), 512)
}

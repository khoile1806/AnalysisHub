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

	// Reuse the shared probe cycle so a per-profile check matches the background
	// checker: multi-URL fallback + 407 (bad-credentials) treated as unhealthy.
	ok, lat, errStr := probeProxyOnce(pu, append([]string{probe}, fallbackProbes...))
	return Health{Healthy: ok, LastCheck: time.Now(), LatencyMs: lat, Err: errStr}
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

// NewLoggingTransport wraps base for the DEFAULT egress lane: it attributes
// each flow to the active Proxy Manager profile (via egress.Proxy) and flags a
// leak when a proxy is configured but a request went direct. Safe to install
// unconditionally — with no sink registered the overhead is a nil check.
func NewLoggingTransport(base http.RoundTripper) http.RoundTripper {
	return NewLoggingTransportLane(base, "", nil, nil)
}

// NewLoggingTransportLane wraps base for a NAMED egress lane (e.g. "osint") whose
// upstream proxy differs from the default egress proxy. Without this, a request
// routed through OSINT_PROXY would be mislabelled "direct" because the default
// egress.Proxy doesn't know about it.
//
//   - lane:        label stamped on proxied flows from this transport ("" = use
//     the active profile name, for the default egress lane).
//   - proxyFn:     resolves the ACTUAL upstream proxy for this lane (nil = the
//     default egress.Proxy). A non-nil result means the request is proxied.
//   - expectProxy: reports whether this lane is meant to be anonymized right now,
//     used for leak detection (nil = !egress.Direct(), the default lane's state).
func NewLoggingTransportLane(base http.RoundTripper, lane string, proxyFn func(*http.Request) (*url.URL, error), expectProxy func() bool) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &loggingTransport{base: base, lane: lane, proxyFn: proxyFn, expectProxy: expectProxy}
}

type loggingTransport struct {
	base        http.RoundTripper
	lane        string
	proxyFn     func(*http.Request) (*url.URL, error)
	expectProxy func() bool
}

// Unwrap exposes the wrapped transport so callers that need the underlying
// *http.Transport (e.g. to inspect its Proxy/Dial settings) can reach it.
func (l *loggingTransport) Unwrap() http.RoundTripper { return l.base }

// resolveProxy returns this lane's proxy resolver (its own, or the default).
func (l *loggingTransport) resolveProxy() func(*http.Request) (*url.URL, error) {
	if l.proxyFn != nil {
		return l.proxyFn
	}
	return Proxy
}

// labelFor names a flow: the lane (or active profile) when proxied, else direct.
func (l *loggingTransport) labelFor(viaProxy bool) string {
	if !viaProxy {
		return "direct"
	}
	if l.lane != "" {
		return l.lane
	}
	return currentLabel()
}

// expectsProxy reports whether this lane should currently be anonymized, so a
// direct request can be flagged as a leak only when a proxy was expected.
func (l *loggingTransport) expectsProxy() bool {
	if l.expectProxy != nil {
		return l.expectProxy()
	}
	return !Direct()
}

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
		if u, err := l.resolveProxy()(req); err == nil && u != nil {
			viaProxy = true
		}
	}

	f := Flow{
		Time:       start,
		Method:     req.Method,
		ViaProxy:   viaProxy,
		ProxyLabel: l.labelFor(viaProxy),
		Source:     sourceFor(req),
		BytesOut:   nonNeg(req.ContentLength),
	}
	if req.URL != nil {
		f.Host = req.URL.Hostname()
		f.Scheme = req.URL.Scheme
		f.URL = redactURL(req.URL)
		// Anonymity leak: this lane expects a proxy but the request went straight
		// out to a non-loopback host. Loopback bypasses (localhost SIEM, etc.) fine.
		f.Leaked = !viaProxy && l.expectsProxy() && !isLoopbackHost(f.Host)
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

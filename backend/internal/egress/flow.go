package egress

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

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
	Host       string
	URL        string
	Status     int
	ViaProxy   bool
	ProxyLabel string
	BytesOut   int64
	BytesIn    int64
	DurationMs int64
	Error      string
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
		BytesOut:   nonNeg(req.ContentLength),
	}
	if req.URL != nil {
		f.Host = req.URL.Hostname()
		f.URL = capString(req.URL.String(), 512)
	}

	resp, err := l.base.RoundTrip(req)
	f.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		f.Error = capString(err.Error(), 256)
		emitFlow(f)
		return resp, err
	}

	f.Status = resp.StatusCode
	// Count response bytes as the caller reads them; emit the finished flow once
	// the body is closed (Go requires every response body to be closed).
	resp.Body = &countingBody{rc: resp.Body, flow: f}
	return resp, nil
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

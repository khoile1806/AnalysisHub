// Package egress centralises the project-wide outbound HTTP proxy. Unlike the
// old env-var approach (http.ProxyFromEnvironment, whose value is cached for the
// process lifetime), this holds the proxy in a live config that can be changed
// at runtime with no restart, and adds periodic health checking with an optional
// automatic fall-back to a direct connection when the proxy is down.
//
// Every egress HTTP client uses Proxy as its Transport.Proxy func, so a single
// Set() call re-points all of them at once.
package egress

import (
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/http/httpproxy"
)

// Health is the latest result of the background proxy probe.
type Health struct {
	Healthy   bool      `json:"healthy"`
	LastCheck time.Time `json:"last_check"`
	LatencyMs int64     `json:"latency_ms"`
	Err       string    `json:"error,omitempty"`
}

var (
	mu             sync.RWMutex
	proxyURL       string
	noProxy        string
	fallbackDirect bool
	probeURL       = "https://www.google.com/generate_204"
	proxyFn        func(*url.URL) (*url.URL, error)
	health         Health
)

func rebuildLocked() {
	cfg := &httpproxy.Config{HTTPProxy: proxyURL, HTTPSProxy: proxyURL, NoProxy: noProxy}
	proxyFn = cfg.ProxyFunc()
}

// Init sets the initial proxy configuration (typically from app config).
func Init(proxy, np string, fallback bool, probe string) {
	mu.Lock()
	defer mu.Unlock()
	proxyURL = proxy
	noProxy = np
	fallbackDirect = fallback
	if probe != "" {
		probeURL = probe
	}
	rebuildLocked()
}

// Set updates the proxy configuration at runtime; every egress client picks up
// the change on its next request (no restart). A fresh health check is kicked
// off in the background.
func Set(proxy, np string, fallback bool) {
	mu.Lock()
	proxyURL = proxy
	noProxy = np
	fallbackDirect = fallback
	rebuildLocked()
	mu.Unlock()
	go CheckNow()
}

// Proxy is the Transport.Proxy function shared by all egress clients. It reads
// the live config on every call. When a proxy is configured but unhealthy and
// fall-back is enabled, it returns nil (direct) so traffic keeps flowing.
func Proxy(req *http.Request) (*url.URL, error) {
	mu.RLock()
	defer mu.RUnlock()
	if proxyURL == "" {
		return nil, nil // no proxy → direct
	}
	if fallbackDirect && !health.Healthy && !health.LastCheck.IsZero() {
		return nil, nil // proxy down → fall back to direct
	}
	return proxyFn(req.URL)
}

// Direct reports whether outbound traffic currently bypasses any proxy — either
// because none is configured, or because the configured proxy is unhealthy and
// fall-back-to-direct is enabled. Callers use it to decide when it is safe to
// apply an SSRF dial guard: when a proxy IS in use the dialed address is the
// proxy itself (often a loopback Tor port), so the guard must be skipped to avoid
// breaking anonymity routing and leaking a local DNS lookup.
func Direct() bool {
	mu.RLock()
	defer mu.RUnlock()
	if proxyURL == "" {
		return true
	}
	if fallbackDirect && !health.Healthy && !health.LastCheck.IsZero() {
		return true
	}
	return false
}

// Status returns the live configuration plus the latest health snapshot.
func Status() (proxy, np string, fallback bool, h Health) {
	mu.RLock()
	defer mu.RUnlock()
	return proxyURL, noProxy, fallbackDirect, health
}

// StartHealthCheck runs the probe immediately and then every interval.
func StartHealthCheck(interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			CheckNow()
			<-t.C
		}
	}()
}

// CheckNow probes the proxy once and records the result. When no proxy is
// configured the egress path is direct and reported healthy.
func CheckNow() {
	mu.RLock()
	p, probe := proxyURL, probeURL
	mu.RUnlock()

	if p == "" {
		setHealth(Health{Healthy: true, LastCheck: time.Now()})
		return
	}
	pu, err := url.Parse(p)
	if err != nil {
		setHealth(Health{Healthy: false, LastCheck: time.Now(), Err: "invalid proxy URL"})
		return
	}
	// Force the proxy (ignore fall-back) so we actually test it.
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(pu)},
	}
	start := time.Now()
	resp, err := client.Get(probe)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		setHealth(Health{Healthy: false, LastCheck: time.Now(), LatencyMs: lat, Err: err.Error()})
		return
	}
	_ = resp.Body.Close()
	setHealth(Health{Healthy: resp.StatusCode < 500, LastCheck: time.Now(), LatencyMs: lat})
}

func setHealth(h Health) {
	mu.Lock()
	health = h
	mu.Unlock()
}

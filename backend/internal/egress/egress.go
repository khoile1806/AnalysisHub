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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpproxy"
)

// ErrKillSwitch is returned by Proxy when the kill-switch is armed and no healthy
// anonymising proxy is available, so the request fails closed instead of leaking
// the real IP via a direct connection.
var ErrKillSwitch = errors.New("egress kill-switch active: no healthy anonymising proxy")

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
	// proxyDown is the COMMITTED unhealthy state — only set true after
	// unhealthyThreshold consecutive failed probe cycles. Fall-back-to-direct keys
	// off this (not a single blip) so a transient probe failure can't silently
	// deanonymise traffic by flipping the whole egress to direct.
	proxyDown  bool
	failStreak int
	killSwitch bool
)

// SetKillSwitch arms/disarms the fail-closed kill-switch.
func SetKillSwitch(on bool) {
	mu.Lock()
	killSwitch = on
	mu.Unlock()
}

// laneProxies maps a named egress lane ("osint", "vulnscan") to its upstream
// proxy, so a Proxy Manager profile can drive a specific traffic class without an
// env var. The default lane uses the global proxyURL, not this map.
var laneProxies = map[string]*url.URL{}

// SetLaneProxy binds (or clears, when rawURL is empty) the proxy for a lane.
func SetLaneProxy(lane, rawURL string) {
	mu.Lock()
	defer mu.Unlock()
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		delete(laneProxies, lane)
		return
	}
	if u, err := url.Parse(rawURL); err == nil {
		laneProxies[lane] = u
	} else {
		delete(laneProxies, lane)
	}
}

// LaneProxy returns the proxy bound to a lane, or nil when none is set.
func LaneProxy(lane string) *url.URL {
	mu.RLock()
	defer mu.RUnlock()
	return laneProxies[lane]
}

// fallbackProbes are tried when the primary probe fails, so a single blocked
// endpoint (Google is frequently 403'd on Tor exits and some corporate egress)
// doesn't produce a false "proxy down".
var fallbackProbes = []string{
	"https://cloudflare.com/cdn-cgi/trace",
	"https://www.wikipedia.org/",
}

// unhealthyThreshold is how many CONSECUTIVE failed probe cycles are required
// before the proxy is declared down. Debounces transient blips.
const unhealthyThreshold = 2

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
	failStreak, proxyDown = 0, false
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
	// A switch to a different proxy starts from an unknown-but-not-down state, so
	// the previous proxy's failure streak doesn't leak onto the new one.
	failStreak, proxyDown = 0, false
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
	// Kill-switch: when armed and no healthy proxy is available, fail closed —
	// block the request rather than let it leak out directly. Takes precedence
	// over fall-back-to-direct.
	if killSwitch && (proxyURL == "" || proxyDown) {
		return nil, ErrKillSwitch
	}
	if proxyURL == "" {
		return nil, nil // no proxy → direct
	}
	if fallbackDirect && proxyDown {
		return nil, nil // proxy confirmed down → fall back to direct
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
	if fallbackDirect && proxyDown {
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

// CheckNow probes the proxy and records the result. A proxy is only declared
// DOWN after unhealthyThreshold consecutive failed cycles (debounce), and a
// cycle succeeds if ANY probe URL returns a non-error, non-auth-failure response
// — so one blocked endpoint doesn't force a deanonymising fall-back to direct.
// When no proxy is configured the egress path is direct and reported healthy.
func CheckNow() {
	mu.RLock()
	p, primary := proxyURL, probeURL
	mu.RUnlock()

	now := time.Now()
	if p == "" {
		mu.Lock()
		failStreak, proxyDown = 0, false
		health = Health{Healthy: true, LastCheck: now}
		mu.Unlock()
		return
	}
	pu, err := url.Parse(p)
	if err != nil {
		mu.Lock()
		proxyDown = true
		health = Health{Healthy: false, LastCheck: now, Err: "invalid proxy URL"}
		mu.Unlock()
		return
	}

	ok, lat, errStr := probeProxyOnce(pu, append([]string{primary}, fallbackProbes...))

	mu.Lock()
	defer mu.Unlock()
	if ok {
		failStreak, proxyDown = 0, false
		health = Health{Healthy: true, LastCheck: now, LatencyMs: lat}
		return
	}
	failStreak++
	if failStreak >= unhealthyThreshold {
		proxyDown = true
		health = Health{Healthy: false, LastCheck: now, LatencyMs: lat, Err: errStr}
		return
	}
	// Transient failure below the threshold: keep the last committed health so the
	// proxy isn't flapped down on a single blip, but surface the latest attempt.
	health.LastCheck = now
	health.Err = errStr
}

// probeProxyOnce runs one probe cycle THROUGH pu, trying each URL until one
// answers. Returns (ok, latencyMs, err). A 407 (proxy auth required) is an
// immediate, unambiguous failure — the proxy is reachable but the credentials
// are wrong, which must not be treated as "healthy".
func probeProxyOnce(pu *url.URL, probes []string) (bool, int64, string) {
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(pu)},
	}
	var lastErr string
	for _, probe := range probes {
		start := time.Now()
		resp, err := client.Get(probe)
		lat := time.Since(start).Milliseconds()
		if err != nil {
			lastErr = err.Error()
			continue
		}
		code := resp.StatusCode
		_ = resp.Body.Close()
		if code == http.StatusProxyAuthRequired {
			return false, lat, "proxy authentication failed (HTTP 407)"
		}
		if code < 400 {
			return true, lat, ""
		}
		lastErr = fmt.Sprintf("probe %s returned HTTP %d", probe, code)
	}
	return false, 0, lastErr
}

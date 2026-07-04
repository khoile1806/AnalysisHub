package osint

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/analysishub/backend/internal/egress"
)

// osintDedicatedProxy returns the parsed OSINT_PROXY, or nil when unset/invalid.
// This is a dedicated, operator-chosen proxy for OSINT recon — a CLEAN proxy
// (residential/datacenter) that hides the real IP WITHOUT the reliability cost of
// Tor (Tor exit nodes are widely 403-blocked by Cloudflare/WAFs). Read from the
// environment each call so it tracks config without a restart.
func osintDedicatedProxy() *url.URL {
	raw := strings.TrimSpace(os.Getenv("OSINT_PROXY"))
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	return u
}

// osintProxy resolves the egress proxy for OSINT recon. Precedence:
//  1. OSINT_PROXY — a dedicated clean proxy for OSINT only (does not affect
//     news/AI/CVE, which follow the default transport).
//  2. the project-wide egress proxy (OUTBOUND_PROXY / a Proxy Manager active
//     profile) when set.
//  3. direct.
//
// OSINT is intentionally NOT forced through Tor: hiding the real IP behind a clean
// proxy is enough, and Tor breaks too many intel sources (403 / timeouts).
func osintProxy(req *http.Request) (*url.URL, error) {
	// A Proxy Manager profile assigned to the "osint" lane wins over the env var,
	// so the exit can be switched from the UI at runtime.
	if p := egress.LaneProxy("osint"); p != nil {
		return p, nil
	}
	if p := osintDedicatedProxy(); p != nil {
		return p, nil
	}
	return egress.Proxy(req)
}

// osintDirect reports whether OSINT egress has NO proxy at all — i.e. requests go
// straight to the target. The SSRF dialer uses it to decide whether to enforce the
// non-public-IP guard on the target.
func osintDirect() bool {
	if egress.LaneProxy("osint") != nil {
		return false
	}
	if osintDedicatedProxy() != nil {
		return false
	}
	return egress.Direct()
}

// osintAnonymized is the inverse of osintDirect: OSINT egress is routed through a
// proxy, so the operator's real IP is hidden from targets.
func osintAnonymized() bool { return !osintDirect() }

// osintProxyURLString returns the effective OSINT egress proxy URL for subprocess
// tools (e.g. maigret's --proxy), or "" when OSINT egress is direct.
func osintProxyURLString() string {
	if p := egress.LaneProxy("osint"); p != nil {
		return p.String()
	}
	if p := osintDedicatedProxy(); p != nil {
		return p.String()
	}
	if p, _, _, _ := egress.Status(); strings.TrimSpace(p) != "" {
		return strings.TrimSpace(p)
	}
	return ""
}

// ssrfSafeDialContext is the shared dialer for collector HTTP clients. It blocks
// connections to non-public addresses (loopback / RFC1918 / link-local / cloud
// metadata) to stop an attacker-controlled target (or a redirect) from pointing
// a collector at internal services — re-checked on every hop because each hop is
// a fresh dial.
//
// It only enforces this in DIRECT egress mode. When a proxy (e.g. Tor) is in use
// the address being dialed is the PROXY, not the target, so guarding here would
// (a) reject a loopback proxy like 127.0.0.1:9050 and (b) require a local DNS
// lookup that would defeat the anonymity the proxy exists to provide. In proxy
// mode the target is resolved and reached by the proxy, and internal addresses
// are unreachable through an external proxy anyway.
func ssrfSafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	// When OSINT egress goes through ANY proxy (OSINT_PROXY / OUTBOUND_PROXY /
	// Proxy Manager), the address dialed here is the PROXY — possibly a private or
	// loopback host — so the non-public guard must NOT run or it would block the
	// proxy hop and force a deanonymizing local DNS lookup.
	if !osintDirect() {
		return d.DialContext(ctx, network, addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("osint: cannot resolve %q", host)
	}
	for _, ip := range ips {
		if !isPublicIP(ip) {
			return nil, fmt.Errorf("osint: refusing to dial non-public address %s", ip)
		}
	}
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
}

const (
	userAgent    = "AnalysisHub-OSINT/1.0 (+https://github.com/analysishub)"
	maxBodyBytes = 8 * 1024 * 1024 // cap response bodies so one runaway reply can't exhaust memory
)

// osintHTTPClient is shared by every collector so TLS connections are reused.
// The 30s timeout is a hard ceiling per request; collectors additionally run
// under a per-collector context deadline set by the engine.
var osintHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	// Wrapped on the "osint" lane so traffic through OSINT_PROXY is attributed to
	// that lane in the Proxy Manager flow log (not mislabelled "direct" by the
	// default egress proxy) and leaks are judged against OSINT's own egress state.
	Transport: egress.NewLoggingTransportLane(&http.Transport{
		Proxy:           osintProxy, // OSINT_PROXY, else OUTBOUND_PROXY / Proxy Manager
		DialContext:     ssrfSafeDialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConns:    32,
		IdleConnTimeout: 60 * time.Second,
	}, "osint", osintProxy, osintAnonymized),
}

// rateLimiter enforces a minimum interval between calls to one external API.
// It is a plain spacing limiter (no burst) - dependency-free and good enough
// for the low call volume of an OSINT scan.
type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newRateLimiter(interval time.Duration) *rateLimiter {
	return &rateLimiter{interval: interval}
}

// wait blocks until the caller is allowed to proceed, or ctx is cancelled.
func (r *rateLimiter) wait(ctx context.Context) error {
	r.mu.Lock()
	now := time.Now()
	var delay time.Duration
	if r.next.After(now) {
		delay = r.next.Sub(now)
		r.next = r.next.Add(r.interval)
	} else {
		r.next = now.Add(r.interval)
	}
	r.mu.Unlock()

	if delay <= 0 {
		return nil
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Per-API limiters - sized to each provider's free-tier budget.
var (
	rlCrtSh = newRateLimiter(3 * time.Second)         // crt.sh is slow & rate-limited
	rlRDAP  = newRateLimiter(1 * time.Second)         // rdap.org is a redirector to many registries
	rlIPAPI = newRateLimiter(1500 * time.Millisecond) // ip-api.com free ~ 45 req/min
	rlVT    = newRateLimiter(16 * time.Second)        // VirusTotal free ~ 4 req/min
)

// httpGetBody performs a rate-limited GET and returns the (capped) body and
// HTTP status. A non-2xx status is NOT an error here - collectors decide what
// each status means (e.g. 404 from Shodan InternetDB just means "no data").
func httpGetBody(ctx context.Context, rl *rateLimiter, url string, headers map[string]string) ([]byte, int, error) {
	var lastStatus int
	var lastErr error
	var respBody []byte

	delays := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}
	maxAttempts := len(delays) + 1

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if rl != nil {
			if err := rl.wait(ctx); err != nil {
				return nil, 0, err
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := osintHTTPClient.Do(req)
		if err != nil {
			lastErr = err
			lastStatus = 0
		} else {
			lastStatus = resp.StatusCode
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
			resp.Body.Close()
			if readErr != nil {
				lastErr = fmt.Errorf("read body: %w", readErr)
			} else {
				respBody = body
				lastErr = nil
			}

			// Don't retry on success or non-retriable client errors
			if lastStatus != 429 && lastStatus < 500 {
				return respBody, lastStatus, lastErr
			}
		}

		if attempt < maxAttempts-1 {
			select {
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			case <-time.After(delays[attempt]):
			}
		}
	}
	return respBody, lastStatus, lastErr
}

// httpGetJSON does a rate-limited GET and decodes a 2xx JSON body into out.
// Returns the status so callers can branch on 404/401/429 themselves.
func httpGetJSON(ctx context.Context, rl *rateLimiter, url string, headers map[string]string, out interface{}) (int, error) {
	body, status, err := httpGetBody(ctx, rl, url, headers)
	if err != nil {
		return status, err
	}
	if status >= 200 && status < 300 && out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return status, fmt.Errorf("decode response: %w", err)
		}
	}
	return status, nil
}

// httpPostBody performs a rate-limited POST with the given content type and
// body, returning the (capped) response body and HTTP status. Non-2xx is not an
// error - the caller decides what each status means.
func httpPostBody(ctx context.Context, rl *rateLimiter, url, contentType string, body []byte, headers map[string]string) ([]byte, int, error) {
	var lastStatus int
	var lastErr error
	var respBody []byte

	delays := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}
	maxAttempts := len(delays) + 1

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if rl != nil {
			if err := rl.wait(ctx); err != nil {
				return nil, 0, err
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "application/json")
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := osintHTTPClient.Do(req)
		if err != nil {
			lastErr = err
			lastStatus = 0
		} else {
			lastStatus = resp.StatusCode
			b, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
			resp.Body.Close()
			if readErr != nil {
				lastErr = fmt.Errorf("read body: %w", readErr)
			} else {
				respBody = b
				lastErr = nil
			}

			// Don't retry on success or non-retriable client errors
			if lastStatus != 429 && lastStatus < 500 {
				return respBody, lastStatus, lastErr
			}
		}

		if attempt < maxAttempts-1 {
			select {
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			case <-time.After(delays[attempt]):
			}
		}
	}
	return respBody, lastStatus, lastErr
}

// toJSON marshals v to a compact JSON string, or "" on error. Used to fill
// OsintFinding.Data without forcing every caller to handle the error.
func toJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

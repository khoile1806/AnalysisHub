package osint

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/analysishub/backend/internal/egress"
)

const (
	userAgent    = "AnalysisHub-OSINT/1.0 (+https://github.com/analysishub)"
	maxBodyBytes = 8 * 1024 * 1024 // cap response bodies so one runaway reply can't exhaust memory
)

// osintHTTPClient is shared by every collector so TLS connections are reused.
// The 30s timeout is a hard ceiling per request; collectors additionally run
// under a per-collector context deadline set by the engine.
var osintHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		Proxy:           egress.Proxy, // project-wide egress proxy (live, health-checked)
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConns:    32,
		IdleConnTimeout: 60 * time.Second,
	},
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

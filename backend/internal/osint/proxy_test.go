package osint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/forensichub/backend/internal/egress"
)

// proxyURLFor calls a transport's Proxy func for a sample request and returns
// the proxy URL string it selects (or "" when none / on error).
func proxyURLFor(t *testing.T, tr *http.Transport, target string) string {
	t.Helper()
	if tr.Proxy == nil {
		return ""
	}
	req, _ := http.NewRequest(http.MethodGet, target, nil)
	u, err := tr.Proxy(req)
	if err != nil || u == nil {
		return ""
	}
	return u.String()
}

func transportOf(c *http.Client) *http.Transport {
	if tr, ok := c.Transport.(*http.Transport); ok {
		return tr
	}
	return nil
}

func samePtr(a, b interface{}) bool {
	return reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer()
}

// The shared external clients must route through the project-wide egress proxy,
// i.e. their transport's Proxy is wired to http.ProxyFromEnvironment.
func TestExternalClientsHonorEnvProxy(t *testing.T) {
	for name, c := range map[string]*http.Client{
		"osintHTTPClient":  osintHTTPClient,
		"socialHTTPClient": socialHTTPClient,
	} {
		tr := transportOf(c)
		if tr == nil {
			t.Fatalf("%s: expected a *http.Transport", name)
		}
		if tr.Proxy == nil {
			t.Errorf("%s: Proxy is nil — will NOT honour OUTBOUND_PROXY", name)
			continue
		}
		if !samePtr(tr.Proxy, egress.Proxy) {
			t.Errorf("%s: Proxy is not egress.Proxy", name)
		}
	}
}

// A dark-web crawler given an explicit (Tor) proxy must dial through exactly
// that proxy; given none it must fall back to the env proxy.
func TestCrawlerProxySelection(t *testing.T) {
	const tor = "socks5://127.0.0.1:9050"
	c := newCrawlerProvider([]string{"http://x.invalid/"}, tor)
	if !c.viaTor {
		t.Error("expected viaTor=true when a proxy is configured")
	}
	if got := proxyURLFor(t, transportOf(c.client), "http://x.invalid/"); got != tor {
		t.Errorf("crawler proxy = %q, want %q", got, tor)
	}

	c2 := newCrawlerProvider([]string{"http://x.invalid/"}, "")
	if c2.viaTor {
		t.Error("expected viaTor=false when no proxy is configured")
	}
	tr := transportOf(c2.client)
	if tr.Proxy == nil || !samePtr(tr.Proxy, egress.Proxy) {
		t.Error("crawler with no Tor proxy should fall back to egress.Proxy")
	}
}

// Integration: stand up a fake HTTP proxy and prove the crawler's outbound fetch
// actually goes THROUGH it (the target host is never contacted directly) and the
// selector match still works end-to-end.
func TestCrawlerRoutesThroughProxy(t *testing.T) {
	var proxied int32
	var sawHost string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A proxied http request arrives with an absolute request-URI; the proxy
		// (not the origin) answers here, so the origin is never really reached.
		atomic.StoreInt32(&proxied, 1)
		sawHost = r.Host
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("leak dump for victim banka.com : creds inside"))
	}))
	defer proxy.Close()

	crawler := newCrawlerProvider([]string{"http://monitored-source.invalid/feed"}, proxy.URL)
	hits, err := crawler.Search(context.Background(), []string{"banka.com"})
	if err != nil {
		t.Fatalf("Search error: %v", err)
	}
	if atomic.LoadInt32(&proxied) != 1 {
		t.Fatal("request did NOT go through the proxy")
	}
	if sawHost != "monitored-source.invalid" {
		t.Errorf("proxy saw host %q, want monitored-source.invalid", sawHost)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 selector hit, got %d", len(hits))
	}
	if hits[0].URL != "http://monitored-source.invalid/feed" {
		t.Errorf("hit URL = %q", hits[0].URL)
	}
}

// A direct (no-proxy) crawler must NOT route through the proxy server: prove the
// negative so the proxy test above is meaningful.
func TestCrawlerNoProxyDoesNotHitProxy(t *testing.T) {
	var proxied int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.StoreInt32(&proxied, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()

	// A real origin to hit directly (so the fetch can succeed without a proxy).
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("contains banka.com selector"))
	}))
	defer origin.Close()

	crawler := newCrawlerProvider([]string{origin.URL}, "") // no Tor, env proxy unset in test
	hits, err := crawler.Search(context.Background(), []string{"banka.com"})
	if err != nil {
		t.Fatalf("Search error: %v", err)
	}
	if atomic.LoadInt32(&proxied) == 1 {
		t.Error("direct crawler unexpectedly routed through the proxy server")
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit from direct fetch, got %d", len(hits))
	}
}

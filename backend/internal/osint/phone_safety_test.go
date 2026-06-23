package osint

import (
	"net"
	"strings"
	"testing"
)

// TestCollectPhoneMeta verifies the offline libphonenumber path returns rich,
// accurate metadata (line type, region, timezone) without any network call.
func TestCollectPhoneMeta(t *testing.T) {
	fs, err := collectPhoneMeta(nil, &collectorEnv{target: "+84912345678"})
	if err != nil {
		t.Fatalf("collectPhoneMeta: %v", err)
	}
	got := map[string]string{}
	for _, f := range fs {
		got[f.Title] = f.Value
	}
	if !strings.Contains(got["Region / country"], "VN") {
		t.Errorf("expected VN region, got %q", got["Region / country"])
	}
	if got["Line type"] != "mobile" {
		t.Errorf("expected mobile line type, got %q", got["Line type"])
	}
	if _, ok := got["Timezone(s)"]; !ok {
		t.Error("expected a timezone finding")
	}
}

// TestCollectPhoneMetaFallback ensures an unparseable number still yields the
// static-table fallback rather than an error.
func TestCollectPhoneMetaFallback(t *testing.T) {
	fs, err := collectPhoneMeta(nil, &collectorEnv{target: "12"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fs) == 0 {
		t.Fatal("expected fallback findings, got none")
	}
}

// TestIsPublicIP guards the SSRF/internal-address filter used to keep resolved
// private addresses out of findings and pivots.
func TestIsPublicIP(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8": true, "1.1.1.1": true, "2606:4700:4700::1111": true,
		"10.0.0.1": false, "192.168.1.1": false, "172.16.0.1": false,
		"127.0.0.1": false, "100.64.0.1": false, "169.254.1.1": false,
		"0.0.0.0": false, "::1": false, "fc00::1": false, "224.0.0.1": false,
	}
	for s, want := range cases {
		if got := isPublicIP(net.ParseIP(s)); got != want {
			t.Errorf("isPublicIP(%s)=%v want %v", s, got, want)
		}
	}
}

// TestNilCacheSafe verifies the cache degrades to a no-op when Redis is absent,
// so a Redis outage can never break a scan.
func TestNilCacheSafe(t *testing.T) {
	var c *osintCache // nil — simulates "Redis not configured / unavailable"
	if _, _, ok := c.get(nil, "k"); ok {
		t.Error("nil cache reported a hit")
	}
	c.set(nil, "k", 200, []byte(`{}`), 0) // must not panic
	if !cacheableStatus(200) || !cacheableStatus(404) {
		t.Error("200/404 should be cacheable")
	}
	if cacheableStatus(429) || cacheableStatus(500) || cacheableStatus(403) {
		t.Error("transient statuses must not be cached")
	}
}

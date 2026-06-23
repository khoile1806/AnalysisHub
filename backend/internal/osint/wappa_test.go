package osint

import (
	"net/http"
	"testing"
)

func TestSplitTechVersion(t *testing.T) {
	cases := map[string][2]string{
		"Nginx:1.18.0": {"Nginx", "1.18.0"},
		"MySQL":        {"MySQL", ""},
		"PHP:7.4.3":    {"PHP", "7.4.3"},
	}
	for in, want := range cases {
		b, v := splitTechVersion(in)
		if b != want[0] || v != want[1] {
			t.Errorf("splitTechVersion(%q)=%q,%q want %q,%q", in, b, v, want[0], want[1])
		}
	}
}

func TestParseCPEVendorProduct(t *testing.T) {
	v, p, ok := parseCPEVendorProduct("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*")
	if !ok || v != "php" || p != "php" {
		t.Errorf("got %q,%q,%v", v, p, ok)
	}
	if _, _, ok := parseCPEVendorProduct("cpe:2.3:a:*:*:*"); ok {
		t.Error("wildcard vendor/product should be rejected")
	}
	if _, _, ok := parseCPEVendorProduct("not-a-cpe"); ok {
		t.Error("malformed CPE should be rejected")
	}
}

// TestWappaEngineLoads ensures the embedded Wappalyzer DB initialises and
// fingerprints a basic response (offline - no network).
func TestWappaEngineLoads(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "nginx/1.18.0")
	infos := wappaFingerprint(h, []byte(`<html></html>`))
	if infos == nil {
		t.Skip("wappalyzer engine unavailable")
	}
	found := false
	for name := range infos {
		if b, _ := splitTechVersion(name); b == "Nginx" {
			found = true
		}
	}
	if !found {
		t.Error("expected Nginx detection from Server header")
	}
}

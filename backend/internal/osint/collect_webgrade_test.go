package osint

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestGradeSecurityHeaders(t *testing.T) {
	// All headers present → A, nothing missing.
	full := http.Header{}
	for _, sh := range gradedHeaders {
		full.Set(sh.name, "x")
	}
	if g, missing := gradeSecurityHeaders(full); g != "A" || len(missing) != 0 {
		t.Errorf("full headers: grade=%s missing=%v, want A / none", g, missing)
	}

	// No headers → F, everything missing.
	if g, missing := gradeSecurityHeaders(http.Header{}); g != "F" || len(missing) != len(gradedHeaders) {
		t.Errorf("no headers: grade=%s missing=%d, want F / %d", g, len(missing), len(gradedHeaders))
	}

	// CSP frame-ancestors satisfies X-Frame-Options.
	h := http.Header{}
	h.Set("Content-Security-Policy", "frame-ancestors 'self'")
	_, missing := gradeSecurityHeaders(h)
	for _, m := range missing {
		if m == "X-Frame-Options" {
			t.Error("X-Frame-Options should be satisfied by CSP frame-ancestors")
		}
	}
}

func TestGradeTLS(t *testing.T) {
	cases := []struct {
		ver  uint16
		want string
	}{
		{tls.VersionTLS13, "A"},
		{tls.VersionTLS12, "B"},
		{tls.VersionTLS10, "D"},
	}
	for _, c := range cases {
		cs := &tls.ConnectionState{Version: c.ver, CipherSuite: tls.TLS_AES_128_GCM_SHA256}
		if g, _ := gradeTLS(cs); g != c.want {
			t.Errorf("gradeTLS(0x%04x) = %s, want %s", c.ver, g, c.want)
		}
	}
}

func TestIsWeakCipher(t *testing.T) {
	if !isWeakCipher(tls.TLS_RSA_WITH_RC4_128_SHA) {
		t.Error("RC4 should be flagged weak")
	}
	if isWeakCipher(tls.TLS_AES_256_GCM_SHA384) {
		t.Error("AES-GCM should not be flagged weak")
	}
}

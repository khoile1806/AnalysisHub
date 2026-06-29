package osint

import (
	"net/http"
	"testing"
)

func TestExtractVersion(t *testing.T) {
	cases := map[string]string{
		"nginx/1.18.0":         "1.18.0",
		"OpenSSH_8.2p1 Ubuntu": "8.2",
		"Apache/2.4.49 (Unix)": "2.4.49",
		"no version here":      "",
		"PHP/7.4.3":            "7.4.3",
	}
	for in, want := range cases {
		if got := extractVersion(in); got != want {
			t.Errorf("extractVersion(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSplitServerToken(t *testing.T) {
	n, v := splitServerToken("nginx/1.18.0")
	if n != "nginx" || v != "1.18.0" {
		t.Errorf("got %q,%q", n, v)
	}
	n, v = splitServerToken("Apache/2.4.49 (Unix)")
	if n != "Apache" || v != "2.4.49" {
		t.Errorf("got %q,%q", n, v)
	}
	n, _ = splitServerToken("cloudflare")
	if n != "cloudflare" {
		t.Errorf("got %q", n)
	}
}

func TestCpeKeyFor(t *testing.T) {
	if cpeKeyFor("nginx") != "nginx" {
		t.Error("nginx key")
	}
	if cpeKeyFor("Apache") != "apache" {
		t.Error("apache key")
	}
	if cpeKeyFor("cloudflare") != "cloudflare" {
		t.Error("unknown product should map to its lowercase name")
	}
}

func TestCvssToSeverity(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{{9.8, "critical"}, {7.5, "high"}, {5.0, "medium"}, {2.1, "low"}}
	for _, c := range cases {
		if got := cvssToSeverity(c.score, ""); got != c.want {
			t.Errorf("cvssToSeverity(%.1f)=%q want %q", c.score, got, c.want)
		}
	}
}

func TestParseServiceBanner(t *testing.T) {
	p, v := parseServiceBanner(22, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
	if p != "OpenSSH" || v != "8.2" {
		t.Errorf("ssh banner parse got %q,%q", p, v)
	}
	p, _ = parseServiceBanner(21, "220 ProFTPD 1.3.5 Server ready")
	if p != "ProFTPD" {
		t.Errorf("ftp banner parse got %q", p)
	}
}

func TestFingerprint(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "nginx/1.18.0")
	h.Set("X-Powered-By", "PHP/7.4.3")
	body := `<html><meta name="generator" content="WordPress 6.2"><link href="/wp-content/themes/x.css"></html>`
	techs := fingerprint(h, body)
	var hasNginx, hasWP, hasPHP bool
	for _, tt := range techs {
		switch tt.name {
		case "nginx":
			hasNginx = tt.version == "1.18.0" && tt.cpeKey == "nginx"
		case "WordPress":
			hasWP = true
		case "PHP":
			hasPHP = true
		}
	}
	if !hasNginx || !hasWP || !hasPHP {
		t.Errorf("fingerprint missing tech: nginx=%v wp=%v php=%v", hasNginx, hasWP, hasPHP)
	}
}

func TestSecurityHeaderPosture(t *testing.T) {
	bare := securityHeaderPosture(http.Header{})
	if bare.Severity != "medium" {
		t.Errorf("missing all headers should be medium, got %q", bare.Severity)
	}
	full := http.Header{}
	for _, hdr := range []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"} {
		full.Set(hdr, "x")
	}
	if securityHeaderPosture(full).Severity != "info" {
		t.Error("all headers present should be info")
	}
}

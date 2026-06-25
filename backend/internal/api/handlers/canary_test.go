package handlers

import "testing"

func TestValidRedirectTarget(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"https://example.com", true},
		{"http://example.com/path?q=1", true},
		{"https://sub.example.com:8443/a", true},
		{"ftp://example.com", false},
		{"javascript:alert(1)", false},
		{"example.com", false}, // no scheme
		{"", false},
		{"https://", false}, // no host
	}
	for _, c := range cases {
		if got := validRedirectTarget(c.in); got != c.want {
			t.Errorf("validRedirectTarget(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestNormalizeURL(t *testing.T) {
	cases := map[string]string{
		"":                              "",
		"  ":                            "",
		"vnexpress.net/a-b-5089809.html": "https://vnexpress.net/a-b-5089809.html",
		"example.com":                   "https://example.com",
		"http://example.com":            "http://example.com",
		"https://example.com/x":         "https://example.com/x",
		"HTTPS://Example.com":           "HTTPS://Example.com", // scheme already present (any case)
		"  example.com/p  ":             "https://example.com/p",
	}
	for in, want := range cases {
		if got := normalizeURL(in); got != want {
			t.Errorf("normalizeURL(%q) = %q, want %q", in, got, want)
		}
	}
	// A normalised bare host must pass redirect validation.
	if !validRedirectTarget(normalizeURL("vnexpress.net/a.html")) {
		t.Error("normalizeURL+validRedirectTarget rejected a bare host that should pass")
	}
}

func TestCanarySlugify(t *testing.T) {
	cases := map[string]string{
		"":                "",
		"  ":              "",
		"My Bait Link":    "My-Bait-Link",
		"safe_slug-123":   "safe_slug-123",
		"weird!@#$chars":  "weirdchars",
		"keep.Case-AZ09":  "keepCase-AZ09", // '.' dropped, case preserved
	}
	for in, want := range cases {
		if got := canarySlugify(in); got != want {
			t.Errorf("canarySlugify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRandomSlugUnguessable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		s := randomSlug()
		if len(s) != 10 {
			t.Fatalf("randomSlug len = %d, want 10 (%q)", len(s), s)
		}
		if seen[s] {
			t.Fatalf("randomSlug collision after %d draws: %q", i, s)
		}
		seen[s] = true
	}
}

func TestIsPrivateOrLoopback(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1":     true,
		"10.1.2.3":      true,
		"192.168.0.5":   true,
		"172.16.0.1":    true,
		"::1":           true,
		"169.254.1.1":   true,
		"not-an-ip":     true, // unparseable → treated as non-routable
		"8.8.8.8":       false,
		"1.1.1.1":       false,
		"203.0.113.10":  false,
	}
	for ip, want := range cases {
		if got := isPrivateOrLoopback(ip); got != want {
			t.Errorf("isPrivateOrLoopback(%q) = %v, want %v", ip, got, want)
		}
	}
}

func TestIsBotUserAgent(t *testing.T) {
	bots := []string{
		"",
		"curl/8.4.0",
		"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
		"Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
		"TelegramBot (like TwitterBot)",
		"WhatsApp/2.23",
		"Mozilla/5.0 (compatible; Discordbot/2.0)",
		"Mozilla/5.0 (compatible; Googlebot/2.1)",
		"Microsoft-CryptoAPI/10.0",
		"Mozilla/5.0 ... SafeLinks",
	}
	for _, ua := range bots {
		if !isBotUserAgent(ua) {
			t.Errorf("isBotUserAgent(%q) = false, want true", ua)
		}
	}
	// Real human browsers must NOT be flagged.
	humans := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Windows NT 10.0) Edg/120.0",
	}
	for _, ua := range humans {
		if isBotUserAgent(ua) {
			t.Errorf("isBotUserAgent(%q) = true, want false (false positive on real browser)", ua)
		}
	}
}

func TestParseUserAgent(t *testing.T) {
	cases := []struct {
		ua                          string
		wantBrowser, wantOS, wantDev string
	}{
		{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
			"Chrome", "Windows", "desktop",
		},
		{
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
			"Safari", "iOS", "mobile",
		},
		{
			"curl/8.4.0",
			"", "", "bot",
		},
		{
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Gecko/20100101 Firefox/121.0",
			"Firefox", "macOS", "desktop",
		},
		{
			"Mozilla/5.0 (Windows NT 10.0) Edg/120.0",
			"Edge", "Windows", "desktop",
		},
	}
	for _, c := range cases {
		b, o, d := parseUserAgent(c.ua)
		if b != c.wantBrowser || o != c.wantOS || d != c.wantDev {
			t.Errorf("parseUserAgent(%q) = (%q,%q,%q), want (%q,%q,%q)",
				c.ua, b, o, d, c.wantBrowser, c.wantOS, c.wantDev)
		}
	}
}

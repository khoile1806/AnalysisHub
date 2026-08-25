package handlers

import (
	"net/http"
	"testing"
)

// req builds the minimal request the upgrade check reads: the Host the browser
// addressed (nginx forwards it verbatim) and the Origin the browser sent.
func req(host, origin string) *http.Request {
	r := &http.Request{Host: host, Header: http.Header{}}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	return r
}

func TestWSAcceptsSameOriginOnAnyAddress(t *testing.T) {
	// The point of the fix: a deployment reached by IP must work without the
	// operator first enumerating that IP in ALLOWED_ORIGINS. Before, HTTP worked
	// and every WebSocket failed — a silent half-broken state.
	SetAllowedOrigins(nil)
	for _, c := range []struct{ host, origin string }{
		{"localhost:3000", "http://localhost:3000"},
		{"10.228.122.249:3000", "http://10.228.122.249:3000"},
		{"hub.example.com", "https://hub.example.com"},
		{"HUB.EXAMPLE.COM", "https://hub.example.com"}, // Host casing is not significant
	} {
		if !upgrader.CheckOrigin(req(c.host, c.origin)) {
			t.Errorf("same-origin rejected: Host=%s Origin=%s", c.host, c.origin)
		}
	}
}

func TestWSRejectsCrossOrigin(t *testing.T) {
	// What the check exists for: a page on another site opening a socket here.
	SetAllowedOrigins(nil)
	for _, c := range []struct{ host, origin string }{
		{"hub.example.com", "https://evil.test"},
		{"hub.example.com", "https://hub.example.com.evil.test"}, // suffix trick
		{"10.228.122.249:3000", "http://10.228.122.249:9999"},    // different port
	} {
		if upgrader.CheckOrigin(req(c.host, c.origin)) {
			t.Errorf("cross-origin accepted: Host=%s Origin=%s", c.host, c.origin)
		}
	}
}

func TestWSAcceptsConfiguredExtraOrigin(t *testing.T) {
	// A separately hosted frontend still works through ALLOWED_ORIGINS.
	SetAllowedOrigins([]string{"https://admin.example.com"})
	if !upgrader.CheckOrigin(req("hub.example.com", "https://admin.example.com")) {
		t.Error("a configured cross-origin must still be accepted")
	}
	if upgrader.CheckOrigin(req("hub.example.com", "https://other.example.com")) {
		t.Error("an unconfigured cross-origin must still be rejected")
	}
	SetAllowedOrigins(nil)
}

func TestWSAcceptsMissingOrigin(t *testing.T) {
	// The Go agent is not a browser and sends no Origin; there is no cross-site
	// hijacking risk to protect it from.
	SetAllowedOrigins(nil)
	if !upgrader.CheckOrigin(req("hub.example.com", "")) {
		t.Error("a client with no Origin header must be accepted")
	}
}

func TestWSRejectsMalformedOrigin(t *testing.T) {
	SetAllowedOrigins(nil)
	for _, o := range []string{"not a url", "://", "http://"} {
		if upgrader.CheckOrigin(req("hub.example.com", o)) {
			t.Errorf("malformed Origin accepted: %q", o)
		}
	}
}

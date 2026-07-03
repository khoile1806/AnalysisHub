package egress

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestRedactURL(t *testing.T) {
	cases := []struct {
		in       string
		mustHave []string
		mustNot  []string
	}{
		{"https://api.shodan.io/host/search?key=SECRET123&q=evil.com",
			[]string{"key=REDACTED", "q=evil.com"}, []string{"SECRET123"}},
		{"https://numverify.com/api?access_key=ABCDEF&number=123",
			[]string{"access_key=REDACTED", "number=123"}, []string{"ABCDEF"}},
		{"https://example.com/path", []string{"https://example.com/path"}, []string{"REDACTED"}},
	}
	for _, c := range cases {
		u, _ := url.Parse(c.in)
		got := redactURL(u)
		for _, m := range c.mustHave {
			if !strings.Contains(got, m) {
				t.Errorf("redactURL(%q)=%q missing %q", c.in, got, m)
			}
		}
		for _, m := range c.mustNot {
			if strings.Contains(got, m) {
				t.Errorf("redactURL(%q)=%q leaked %q", c.in, got, m)
			}
		}
	}
}

type fakeRT struct {
	body   string
	status int
}

func (f fakeRT) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: f.status,
		Body:       io.NopCloser(strings.NewReader(f.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func TestLoggingTransportRecordsFlowOnBodyClose(t *testing.T) {
	var mu sync.Mutex
	var got []Flow
	SetFlowSink(func(f Flow) { mu.Lock(); got = append(got, f); mu.Unlock() })
	defer SetFlowSink(nil)

	rt := NewLoggingTransport(fakeRT{body: "hello world", status: 200})
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/path", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}

	// The flow must not be emitted until the body is closed.
	mu.Lock()
	pre := len(got)
	mu.Unlock()
	if pre != 0 {
		t.Fatalf("flow emitted before body close: %d", pre)
	}

	b, _ := io.ReadAll(resp.Body)
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if string(b) != "hello world" {
		t.Fatalf("body corrupted: %q", b)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("want exactly 1 flow, got %d", len(got))
	}
	f := got[0]
	if f.Method != "GET" || f.Host != "example.com" || f.Status != 200 {
		t.Errorf("unexpected flow: %+v", f)
	}
	if f.BytesIn != int64(len("hello world")) {
		t.Errorf("BytesIn = %d, want %d", f.BytesIn, len("hello world"))
	}
	if f.ViaProxy {
		t.Errorf("ViaProxy = true, want false (no proxy configured)")
	}
}

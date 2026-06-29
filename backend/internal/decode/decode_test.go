package decode

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func TestSingleLayer(t *testing.T) {
	cases := []struct {
		name, in, wantFinal, wantCodec string
	}{
		// '+' is intentionally NOT turned into space (it would corrupt a base64
		// layer underneath), so we test %XX escapes only.
		{"url", "a%2Fb%3Fc%3D1", "a/b?c=1", "url"},
		{"base64", base64.StdEncoding.EncodeToString([]byte("admin:secret")), "admin:secret", "base64"},
		{"base64url", base64.RawURLEncoding.EncodeToString([]byte("token=abc/def")), "token=abc/def", "base64"},
		{"hex", "48656c6c6f21", "Hello!", "hex"},
		{"html", "a &lt;b&gt; &amp; c", "a <b> & c", "html"},
		{"unicode", "\\u0048\\u0069\\u0021", "Hi!", "unicode"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Analyze(c.in)
			if r.Final != c.wantFinal {
				t.Fatalf("final = %q, want %q (steps=%+v)", r.Final, c.wantFinal, r.Steps)
			}
			if len(r.Steps) == 0 || r.Steps[0].Codec != c.wantCodec {
				t.Fatalf("first codec = %v, want %s", r.Steps, c.wantCodec)
			}
		})
	}
}

func TestMultiLayer(t *testing.T) {
	// url( base64( "id=42&role=admin" ) )
	inner := base64.StdEncoding.EncodeToString([]byte("id=42&role=admin"))
	outer := url.QueryEscape(inner)
	r := Analyze(outer)
	if r.Final != "id=42&role=admin" {
		t.Fatalf("multi-layer final = %q (steps=%+v)", r.Final, r.Steps)
	}
	if r.Layers < 2 {
		t.Fatalf("expected >=2 layers, got %d: %+v", r.Layers, r.Steps)
	}
}

func TestBase64Gzip(t *testing.T) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write([]byte("the quick brown fox jumps over the lazy dog"))
	_ = w.Close()
	in := base64.StdEncoding.EncodeToString(buf.Bytes())
	r := Analyze(in)
	if !strings.Contains(r.Final, "quick brown fox") {
		t.Fatalf("base64+gzip final = %q (steps=%+v)", r.Final, r.Steps)
	}
}

func TestJWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.sig"
	r := Analyze(jwt)
	if len(r.Steps) == 0 || r.Steps[0].Codec != "jwt" {
		t.Fatalf("expected jwt step, got %+v", r.Steps)
	}
	if !strings.Contains(r.Final, "John Doe") || !strings.Contains(r.Final, "HS256") {
		t.Fatalf("jwt decode missing claims: %q", r.Final)
	}
}

func TestPlainTextUnchanged(t *testing.T) {
	for _, s := range []string{"hello", "GET /index.html", "1234", "user@example.com"} {
		r := Analyze(s)
		if r.Final != s || r.Layers != 0 {
			t.Fatalf("plain %q got decoded to %q (steps=%+v)", s, r.Final, r.Steps)
		}
	}
}

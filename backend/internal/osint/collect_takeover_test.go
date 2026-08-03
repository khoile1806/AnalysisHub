package osint

import "testing"

func TestMatchTakeoverSig(t *testing.T) {
	cases := []struct {
		cname   string
		service string
		match   bool
	}{
		{"myrepo.github.io", "GitHub Pages", true},
		{"app-123.herokudns.com", "Heroku", true},
		{"bucket.s3-website-us-east-1.amazonaws.com", "AWS S3", true},
		{"foo.azurewebsites.net", "Azure", true},
		{"legit.google.com", "", false},
		{"cdn.cloudflare.net", "", false},
	}
	for _, c := range cases {
		sig, ok := matchTakeoverSig(c.cname)
		if ok != c.match {
			t.Errorf("matchTakeoverSig(%q) matched=%v, want %v", c.cname, ok, c.match)
			continue
		}
		if ok && sig.service != c.service {
			t.Errorf("matchTakeoverSig(%q) service=%q, want %q", c.cname, sig.service, c.service)
		}
	}
}

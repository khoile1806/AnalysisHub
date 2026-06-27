package osint

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
)

func TestParseSocialProfile(t *testing.T) {
	cases := []struct {
		raw          string
		wantPlatform string
		wantHandle   string
		wantOK       bool
	}{
		{"https://twitter.com/johndoe", "twitter", "johndoe", true},
		{"https://x.com/johndoe", "twitter", "johndoe", true},
		{"twitter.com/johndoe", "twitter", "johndoe", true}, // no scheme
		{"https://github.com/torvalds", "github", "torvalds", true},
		{"https://www.reddit.com/user/spez", "reddit", "spez", true},
		{"https://reddit.com/u/spez", "reddit", "spez", true},
		{"https://t.me/durov", "telegram", "durov", true},
		{"https://www.linkedin.com/in/jdoe", "linkedin", "jdoe", true},
		{"https://www.tiktok.com/@charlidamelio", "tiktok", "charlidamelio", true},
		{"https://www.youtube.com/@mkbhd", "youtube", "mkbhd", true},
		{"https://infosec.exchange/@SwiftOnSecurity", "mastodon", "SwiftOnSecurity@infosec.exchange", true},
		{"https://keybase.io/maxtaco", "keybase", "maxtaco", true},

		// Negatives: bare platform domain / site sections must NOT be a profile.
		{"twitter.com", "", "", false},
		{"https://twitter.com/home", "", "", false},
		{"https://github.com/search", "", "", false},
		{"https://example.com", "", "", false},
		{"not a url", "", "", false},
	}
	for _, c := range cases {
		p, ok := ParseSocialProfile(c.raw)
		if ok != c.wantOK {
			t.Errorf("ParseSocialProfile(%q) ok=%v want %v", c.raw, ok, c.wantOK)
			continue
		}
		if ok && (p.Platform != c.wantPlatform || p.Handle != c.wantHandle) {
			t.Errorf("ParseSocialProfile(%q) = {%s,%s} want {%s,%s}",
				c.raw, p.Platform, p.Handle, c.wantPlatform, c.wantHandle)
		}
	}
}

func TestDetectTargetType_SocialProfile(t *testing.T) {
	if tt, err := DetectTargetType("https://twitter.com/johndoe"); err != nil || tt != TargetSocial {
		t.Errorf("profile URL should detect as social_profile, got %q (err=%v)", tt, err)
	}
	// A bare platform domain stays a domain.
	if tt, _ := DetectTargetType("twitter.com"); tt != TargetDomain {
		t.Errorf("bare twitter.com should be domain, got %q", tt)
	}
}

func TestHandleForUsernamePivot(t *testing.T) {
	if got := handleForUsernamePivot(SocialProfile{Handle: "user@host.social"}); got != "user" {
		t.Errorf("mastodon handle should reduce to bare user, got %q", got)
	}
	if got := handleForUsernamePivot(SocialProfile{Handle: "johndoe"}); got != "johndoe" {
		t.Errorf("plain handle unchanged, got %q", got)
	}
}

// pngBytes encodes a half-black/half-white image to PNG for hashing tests.
func pngBytes(t *testing.T, swap bool) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			dark := x < 8
			if swap {
				dark = !dark
			}
			if dark {
				img.Set(x, y, color.Black)
			} else {
				img.Set(x, y, color.White)
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestAverageHash(t *testing.T) {
	a, ok := AverageHash(pngBytes(t, false))
	if !ok || len(a) != 16 {
		t.Fatalf("expected a 16-char hash, got %q ok=%v", a, ok)
	}
	// Identical image → identical hash (cross-platform same-avatar linking).
	a2, _ := AverageHash(pngBytes(t, false))
	if a != a2 {
		t.Errorf("same image must hash identically: %s vs %s", a, a2)
	}
	// Mirrored image → different hash.
	b, _ := AverageHash(pngBytes(t, true))
	if a == b {
		t.Errorf("different images should hash differently")
	}
	// Garbage bytes → not ok.
	if _, ok := AverageHash([]byte("nope")); ok {
		t.Error("non-image must not hash")
	}
}

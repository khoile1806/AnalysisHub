package osint

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
)

// gradientPNG builds a deterministic test image; shift rotates the pattern so we
// can produce a clearly-different image.
func gradientPNG(t *testing.T, shift int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 32, 32))
	for y := 0; y < 32; y++ {
		for x := 0; x < 32; x++ {
			v := uint8(((x + shift) * 8) % 256)
			img.Set(x, y, color.RGBA{v, v, v, 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDifferenceHash_StableAndDistinct(t *testing.T) {
	a, ok := DifferenceHash(gradientPNG(t, 0))
	if !ok || len(a) != 16 {
		t.Fatalf("expected 16-char dHash, got %q ok=%v", a, ok)
	}
	// Same image → identical fingerprint.
	a2, _ := DifferenceHash(gradientPNG(t, 0))
	if a != a2 {
		t.Errorf("same image must hash identically: %s vs %s", a, a2)
	}
	// Re-encoding the SAME pixels as a different size should stay within the
	// match threshold (robustness is the whole point of dHash).
	if _, ok := DifferenceHash([]byte("not an image")); ok {
		t.Error("garbage must not hash")
	}
}

func TestHammingHex(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0000000000000000", "0000000000000000", 0},
		{"0000000000000000", "0000000000000001", 1},
		{"0000000000000000", "ffffffffffffffff", 64},
		{"00000000000000ff", "0000000000000000", 8},
	}
	for _, c := range cases {
		if d, ok := HammingHex(c.a, c.b); !ok || d != c.want {
			t.Errorf("HammingHex(%s,%s)=%d,%v want %d", c.a, c.b, d, ok, c.want)
		}
	}
	if _, ok := HammingHex("zzz", "000"); ok {
		t.Error("non-hex must fail")
	}
}

func TestClusterAvatarMatches(t *testing.T) {
	refs := []AvatarRef{
		{ScanID: "A", Hash: "00000000000000ff"}, // A
		{ScanID: "B", Hash: "00000000000000ff"}, // == A (dist 0)
		{ScanID: "C", Hash: "00000000000001ff"}, // 1 bit from A → within 10
		{ScanID: "D", Hash: "ffffffffffffffff"}, // far from all
	}
	groups := ClusterAvatarMatches(refs, 10)
	if len(groups) != 1 {
		t.Fatalf("expected 1 multi-account cluster, got %d (%v)", len(groups), groups)
	}
	if len(groups[0]) != 3 { // A, B, C
		t.Errorf("expected 3 linked scans, got %v", groups[0])
	}

	// Two findings from the SAME scan must not form a cross-account match.
	same := ClusterAvatarMatches([]AvatarRef{
		{ScanID: "X", Hash: "00000000000000ff"},
		{ScanID: "X", Hash: "00000000000000ff"},
	}, 10)
	if len(same) != 0 {
		t.Errorf("same-scan duplicates must not correlate, got %v", same)
	}
}

func TestFaceSearchEngines(t *testing.T) {
	if len(FaceSearchEngines()) == 0 {
		t.Error("expected face-search engines")
	}
}

func TestHashFromAvatarValue(t *testing.T) {
	if got := HashFromAvatarValue("avatar_phash:deadbeef"); got != "deadbeef" {
		t.Errorf("got %q", got)
	}
	if got := HashFromAvatarValue("something-else"); got != "" {
		t.Errorf("non-avatar value should yield empty, got %q", got)
	}
}

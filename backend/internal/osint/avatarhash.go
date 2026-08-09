package osint

import (
	"bytes"
	"context"
	"fmt"
	"image"
	_ "image/gif"  // register GIF decoder
	_ "image/jpeg" // register JPEG decoder
	_ "image/png"  // register PNG decoder
	"io"
	"math/bits"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/analysishub/backend/internal/models"
	_ "golang.org/x/image/webp" // register WebP decoder (modern avatars)
)

// avatarhash.go — perceptual avatar hashing for cross-platform identity linking.
// Two accounts on different platforms using the SAME profile picture are very
// likely the same person, even under different handles. We fingerprint each
// avatar and link accounts whose fingerprints are within a small Hamming
// distance — so resized/recompressed copies of the same image still match (an
// exact-equality check would miss them). The emitted fingerprint is a dHash
// (difference hash): robust to brightness/gamma shifts, cheap, stdlib + WebP.

const avatarMaxBytes = 4 << 20 // 4 MB cap on a fetched avatar

var avatarHTTPClient = &http.Client{Timeout: 10 * time.Second}

// squareBounds returns the centred square sub-rectangle of b, so circular/cropped
// avatars of different aspect ratios normalise to a comparable frame.
func squareBounds(b image.Rectangle) image.Rectangle {
	w, h := b.Dx(), b.Dy()
	if w == h {
		return b
	}
	side := min(w, h)
	offX := b.Min.X + (w-side)/2
	offY := b.Min.Y + (h-side)/2
	return image.Rect(offX, offY, offX+side, offY+side)
}

// grayGrid downsamples an image to gw×gh grayscale cells using block AVERAGING
// (not a single nearest-neighbour pixel), which suppresses compression noise.
func grayGrid(img image.Image, gw, gh int) []float64 {
	sq := squareBounds(img.Bounds())
	W, H := sq.Dx(), sq.Dy()
	out := make([]float64, gw*gh)
	if W == 0 || H == 0 {
		return out
	}
	for cy := 0; cy < gh; cy++ {
		for cx := 0; cx < gw; cx++ {
			x0 := sq.Min.X + cx*W/gw
			x1 := sq.Min.X + (cx+1)*W/gw
			y0 := sq.Min.Y + cy*H/gh
			y1 := sq.Min.Y + (cy+1)*H/gh
			if x1 <= x0 {
				x1 = x0 + 1
			}
			if y1 <= y0 {
				y1 = y0 + 1
			}
			// Cap samples per block so a huge image stays cheap to hash.
			stepX := max(1, (x1-x0)/4)
			stepY := max(1, (y1-y0)/4)
			var sum float64
			var cnt int
			for y := y0; y < y1; y += stepY {
				for x := x0; x < x1; x += stepX {
					r, g, b, _ := img.At(x, y).RGBA()
					sum += 0.299*float64(r) + 0.587*float64(g) + 0.114*float64(b)
					cnt++
				}
			}
			if cnt == 0 {
				cnt = 1
			}
			out[cy*gw+cx] = sum / float64(cnt)
		}
	}
	return out
}

// AverageHash computes an 8×8 average hash (kept for reference/testing).
func AverageHash(data []byte) (string, bool) {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return "", false
	}
	g := grayGrid(img, 8, 8)
	var sum float64
	for _, v := range g {
		sum += v
	}
	mean := sum / float64(len(g))
	var b uint64
	for i, v := range g {
		if v >= mean {
			b |= 1 << uint(i)
		}
	}
	return fmt.Sprintf("%016x", b), true
}

// DifferenceHash computes a 9×8 dHash: each bit is whether a cell is brighter
// than its right neighbour. Robust to overall brightness/contrast changes, so it
// matches the same avatar across platforms that re-encode it.
func DifferenceHash(data []byte) (string, bool) {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return "", false
	}
	const w, h = 9, 8
	g := grayGrid(img, w, h)
	var bitsv uint64
	bit := 0
	for y := 0; y < h; y++ {
		for x := 0; x < w-1; x++ {
			if g[y*w+x] < g[y*w+x+1] {
				bitsv |= 1 << uint(bit)
			}
			bit++
		}
	}
	return fmt.Sprintf("%016x", bitsv), true
}

// HammingHex returns the bit distance between two 16-char hex fingerprints.
// ok is false if either is not parseable.
func HammingHex(a, b string) (int, bool) {
	x, err1 := strconv.ParseUint(a, 16, 64)
	y, err2 := strconv.ParseUint(b, 16, 64)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	return bits.OnesCount64(x ^ y), true
}

// AvatarRef pairs an avatar fingerprint with the scan that produced it.
type AvatarRef struct {
	ScanID string
	Hash   string // 16-char hex
}

// ClusterAvatarMatches groups scans whose avatars are within maxDist Hamming
// bits of each other (single-linkage). Only groups spanning ≥2 DISTINCT scans
// are returned — those are the cross-account avatar matches. Returns each group
// as a deduplicated list of scan IDs.
func ClusterAvatarMatches(refs []AvatarRef, maxDist int) [][]string {
	n := len(refs)
	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[ra] = rb
		}
	}
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if d, ok := HammingHex(refs[i].Hash, refs[j].Hash); ok && d <= maxDist {
				union(i, j)
			}
		}
	}
	groups := map[int]map[string]bool{}
	for i := 0; i < n; i++ {
		r := find(i)
		if groups[r] == nil {
			groups[r] = map[string]bool{}
		}
		groups[r][refs[i].ScanID] = true
	}
	var out [][]string
	for _, set := range groups {
		if len(set) < 2 {
			continue
		}
		ids := make([]string, 0, len(set))
		for id := range set {
			ids = append(ids, id)
		}
		out = append(out, ids)
	}
	return out
}

// fetchAvatarHash downloads an avatar and returns its dHash fingerprint.
func fetchAvatarHash(ctx context.Context, avatarURL string) (string, bool) {
	if avatarURL == "" {
		return "", false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, avatarURL, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("User-Agent", browserUA)
	resp, err := avatarHTTPClient.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, avatarMaxBytes))
	if err != nil || len(data) == 0 {
		return "", false
	}
	return DifferenceHash(data)
}

// HashFromAvatarValue extracts the hex fingerprint from an "avatar_phash:<hex>"
// finding value, or "" if it is not one.
func HashFromAvatarValue(v string) string {
	const p = "avatar_phash:"
	if strings.HasPrefix(v, p) {
		return strings.TrimPrefix(v, p)
	}
	return ""
}

// avatarFinding builds a correlatable finding for an avatar fingerprint.
func avatarFinding(source, avatarURL, hash string) models.OsintFinding {
	f := newFinding(source, "identity", "Avatar fingerprint (perceptual hash)", "avatar_phash:"+hash)
	f.VerifyNote = "accounts with a near-matching avatar fingerprint are likely the same person"
	f.SourceURL = avatarURL
	return f
}

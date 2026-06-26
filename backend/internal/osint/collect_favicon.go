package osint

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/forensichub/backend/internal/models"
)

// collectFavicon computes the target's favicon hash the way Shodan does
// (mmh3 over base64-with-newlines) and — when a Shodan key is present — pivots
// `http.favicon.hash:<hash>` to surface other hosts serving the SAME favicon.
// This is a high-signal infrastructure-clustering technique: phishing kits,
// C2 panels and an org's own fleet often share one favicon across many IPs.
func collectFavicon(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	// Build candidate favicon URLs (https first, then http).
	var bases []string
	if env.ttype == TargetIP {
		bases = []string{"http://" + env.target, "https://" + env.target}
	} else {
		bases = []string{"https://" + env.target, "http://" + env.target}
	}

	var icon []byte
	var usedURL string
	for _, b := range bases {
		if data, err := fetchFavicon(ctx, b+"/favicon.ico"); err == nil && len(data) > 0 {
			icon = data
			usedURL = b + "/favicon.ico"
			break
		}
	}
	if len(icon) == 0 {
		env.emit("[*] favicon: target serves no /favicon.ico — skipped")
		return nil, nil
	}

	hash := faviconHash(icon)
	searchURL := "https://www.shodan.io/search?query=" + url.QueryEscape("http.favicon.hash:"+strconv.Itoa(int(hash)))

	out := []models.OsintFinding{
		withSource(newFinding("favicon", "network",
			"Favicon hash (Shodan pivot)",
			fmt.Sprintf("%d  (%s)", hash, usedURL)), searchURL),
	}

	// Pivot to co-located hosts via Shodan host/search (needs a paid key).
	if env.keys.Shodan != "" {
		u := "https://api.shodan.io/shodan/host/search?key=" + url.QueryEscape(env.keys.Shodan) +
			"&query=" + url.QueryEscape("http.favicon.hash:"+strconv.Itoa(int(hash)))
		var r shodanSearchResp
		// Cache key excludes the API key so the secret is never persisted.
		status, err := cachedGetJSON(ctx, env.cache, fmt.Sprintf("shodan:favicon:%d", hash), nil, u, nil, &r, ttlShodan)
		switch {
		case err != nil:
			env.emit("[*] favicon: Shodan search error: " + err.Error())
		case status == 401:
			env.emit("[*] favicon: Shodan rejected the API key (HTTP 401)")
		case status == 403:
			env.emit("[*] favicon: Shodan host/search needs a paid membership — hash reported, pivot skipped")
		case status >= 200 && status < 300:
			seen := map[string]bool{env.target: true}
			added := 0
			for _, m := range r.Matches {
				ip := m.IPStr
				if ip == "" || seen[ip] {
					continue
				}
				seen[ip] = true
				f := newFinding("favicon", "network", "Host sharing this favicon (Shodan)", ip)
				f.Severity = "medium"
				if m.Org != "" {
					f.Data = `{"org":"` + jsonEscape(m.Org) + `"}`
				}
				out = append(out, withSource(withRelated(f, RelatedEntity{Type: TargetIP, Value: ip}), searchURL))
				if added++; added >= 25 { // cap to keep the graph sane
					break
				}
			}
			if r.Total > added {
				env.emit(fmt.Sprintf("[*] favicon: %d host(s) share this favicon (showing %d)", r.Total, added))
			}
		}
	}

	return out, nil
}

// shodanSearchResp is the subset of the Shodan host/search response we use.
type shodanSearchResp struct {
	Total   int `json:"total"`
	Matches []struct {
		IPStr string `json:"ip_str"`
		Org   string `json:"org"`
	} `json:"matches"`
}

// fetchFavicon GETs a favicon, returning its bytes (capped) on a 2xx response.
func fetchFavicon(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := osintHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB cap
}

// faviconHash reproduces Shodan's favicon hash: mmh3_x86_32(base64.encodebytes(icon)).
func faviconHash(icon []byte) int32 {
	return mmh3x86_32(b64EncodeBytes(icon), 0)
}

// b64EncodeBytes mirrors Python's base64.encodebytes: standard base64 with a
// newline every 76 output chars and a trailing newline.
func b64EncodeBytes(data []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(data)
	var b bytes.Buffer
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		b.WriteString(enc[i:end])
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// mmh3x86_32 is the 32-bit x86 MurmurHash3 (the variant Shodan/mmh3 use),
// returned as a signed int32.
func mmh3x86_32(data []byte, seed uint32) int32 {
	const c1 = 0xcc9e2d51
	const c2 = 0x1b873593
	h := seed
	length := len(data)
	nblocks := length / 4
	for i := 0; i < nblocks; i++ {
		k := binary.LittleEndian.Uint32(data[i*4:])
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
		h = (h << 13) | (h >> 19)
		h = h*5 + 0xe6546b64
	}
	var k uint32
	tail := data[nblocks*4:]
	switch length & 3 {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
	}
	h ^= uint32(length)
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return int32(h)
}

// jsonEscape escapes the few characters that would break a hand-built JSON string.
func jsonEscape(s string) string {
	r := make([]rune, 0, len(s))
	for _, c := range s {
		switch c {
		case '"', '\\':
			r = append(r, '\\', c)
		case '\n', '\r', '\t':
			r = append(r, ' ')
		default:
			r = append(r, c)
		}
	}
	return string(r)
}

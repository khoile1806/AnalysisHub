// Package decode implements a recursive, auto-detecting "magic" decoder for the
// common encodings seen in OOB callbacks and pentest payloads: URL-encoding,
// Base64 (standard + URL-safe), Base32, hex, HTML entities, Unicode/hex string
// escapes, gzip/zlib compression and JWTs. It peels layers one at a time until
// the value stops changing, so multiply-encoded strings (e.g. url(base64(gzip)))
// are fully unwrapped and the whole chain is reported.
package decode

import (
	"compress/gzip"
	"compress/zlib"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"html"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxDepth     = 12
	maxOutputLen = 64 * 1024
)

// Step is one decode layer applied to the running value.
type Step struct {
	Codec  string `json:"codec"`            // url | base64 | base32 | hex | html | unicode | gzip | zlib | jwt
	Label  string `json:"label"`            // human label, e.g. "Base64 decode"
	Output string `json:"output"`           // value after this step (display-safe)
	Binary bool   `json:"binary,omitempty"` // true when Output is a preview of non-text bytes
	Note   string `json:"note,omitempty"`
}

// Result is the full decode chain for an input.
type Result struct {
	Input  string `json:"input"`
	Steps  []Step `json:"steps"`
	Final  string `json:"final"`
	Binary bool   `json:"final_binary,omitempty"`
	Layers int    `json:"layers"`
}

// Analyze peels every encoding layer it confidently detects, returning the
// ordered chain. When nothing decodes, Steps is empty and Final == Input.
func Analyze(input string) Result {
	res := Result{Input: input}
	cur := input
	seen := map[string]bool{cur: true}

	for len(res.Steps) < maxDepth {
		codec, label, out, note, ok := decodeOne(cur)
		if !ok || out == cur || seen[out] {
			break
		}
		bin := !utf8.ValidString(out)
		res.Steps = append(res.Steps, Step{
			Codec:  codec,
			Label:  label,
			Output: display(out),
			Binary: bin,
			Note:   note,
		})
		seen[out] = true
		cur = out
	}

	res.Final = display(cur)
	res.Binary = !utf8.ValidString(cur)
	res.Layers = len(res.Steps)
	return res
}

// decodeOne tries each codec in priority order and returns the first that
// confidently applies. Order matters: structural/markered codecs (jwt, gzip,
// url, html, unicode) are tried before the ambiguous charset ones (hex, base64,
// base32) so a value isn't mis-attributed.
func decodeOne(s string) (codec, label, out, note string, ok bool) {
	if s == "" {
		return
	}
	if o, n, ok := tryJWT(s); ok {
		return "jwt", "JWT decode", o, n, true
	}
	if o, ok := tryGzip(s); ok {
		return "gzip", "Gzip decompress", o, "", true
	}
	if o, ok := tryZlib(s); ok {
		return "zlib", "Zlib/Deflate decompress", o, "", true
	}
	if o, ok := tryURL(s); ok {
		return "url", "URL decode", o, "", true
	}
	if o, ok := tryHTML(s); ok {
		return "html", "HTML entity decode", o, "", true
	}
	if o, ok := tryUnicodeEscape(s); ok {
		return "unicode", "Unicode/hex escape decode", o, "", true
	}
	if o, ok := tryHex(s); ok {
		return "hex", "Hex decode", o, "", true
	}
	if o, ok := tryBase64(s); ok {
		return "base64", "Base64 decode", o, "", true
	}
	if o, ok := tryBase32(s); ok {
		return "base32", "Base32 decode", o, "", true
	}
	return
}

// ── individual codecs ──────────────────────────────────────────────────────

func tryURL(s string) (string, bool) {
	if !strings.Contains(s, "%") {
		return "", false
	}
	// PathUnescape decodes %XX without turning '+' into space (safer default).
	out, err := url.PathUnescape(s)
	if err != nil || out == s {
		return "", false
	}
	return out, true
}

func tryHTML(s string) (string, bool) {
	if !strings.ContainsRune(s, '&') {
		return "", false
	}
	if !htmlEntity.MatchString(s) {
		return "", false
	}
	out := html.UnescapeString(s)
	if out == s {
		return "", false
	}
	return out, true
}

var htmlEntity = regexp.MustCompile(`&(#\d+|#x[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]+);`)

var escSeq = regexp.MustCompile(`\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|%u[0-9a-fA-F]{4}`)

func tryUnicodeEscape(s string) (string, bool) {
	if !escSeq.MatchString(s) {
		return "", false
	}
	out := escSeq.ReplaceAllStringFunc(s, func(m string) string {
		hexPart := m[2:]
		n, err := strconv.ParseInt(hexPart, 16, 32)
		if err != nil {
			return m
		}
		return string(rune(n))
	})
	if out == s {
		return "", false
	}
	return out, true
}

var hexOnly = regexp.MustCompile(`^[0-9a-fA-F]+$`)

func tryHex(s string) (string, bool) {
	t := strings.TrimSpace(s)
	if len(t) < 6 || len(t)%2 != 0 || !hexOnly.MatchString(t) {
		return "", false
	}
	b, err := hex.DecodeString(t)
	if err != nil || !looksDecodable(b) {
		return "", false
	}
	return string(b), true
}

var b64Charset = regexp.MustCompile(`^[A-Za-z0-9+/_-]+={0,2}$`)

func tryBase64(s string) (string, bool) {
	t := strings.TrimSpace(s)
	if len(t) < 8 || !b64Charset.MatchString(t) {
		return "", false
	}
	// Skip pure-lowercase-letter words (very likely plain text, not base64).
	if isLowerWord(t) {
		return "", false
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(t); err == nil && looksDecodable(b) {
			return string(b), true
		}
	}
	return "", false
}

var b32Charset = regexp.MustCompile(`^[A-Z2-7]+={0,6}$`)

func tryBase32(s string) (string, bool) {
	t := strings.ToUpper(strings.TrimSpace(s))
	if len(t) < 8 || !b32Charset.MatchString(t) {
		return "", false
	}
	for _, enc := range []*base32.Encoding{base32.StdEncoding, base32.StdEncoding.WithPadding(base32.NoPadding)} {
		if b, err := enc.DecodeString(t); err == nil && looksDecodable(b) {
			return string(b), true
		}
	}
	return "", false
}

func tryGzip(s string) (string, bool) {
	if len(s) < 3 || s[0] != 0x1f || s[1] != 0x8b {
		return "", false
	}
	r, err := gzip.NewReader(strings.NewReader(s))
	if err != nil {
		return "", false
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, maxOutputLen))
	if err != nil || len(b) == 0 {
		return "", false
	}
	return string(b), true
}

func tryZlib(s string) (string, bool) {
	// zlib stream: first byte 0x78 with valid FCHECK, or raw deflate fallback.
	if len(s) < 3 || s[0] != 0x78 {
		return "", false
	}
	r, err := zlib.NewReader(strings.NewReader(s))
	if err != nil {
		return "", false
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, maxOutputLen))
	if err != nil || len(b) == 0 {
		return "", false
	}
	return string(b), true
}

var jwtRe = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$`)

func tryJWT(s string) (string, string, bool) {
	t := strings.TrimSpace(s)
	if !jwtRe.MatchString(t) {
		return "", "", false
	}
	parts := strings.Split(t, ".")
	header, ok := decodeB64JSON(parts[0])
	if !ok {
		return "", "", false
	}
	payload, ok := decodeB64JSON(parts[1])
	if !ok {
		return "", "", false
	}
	out := "// header\n" + header + "\n// payload\n" + payload
	note := "signature not verified"
	return out, note, true
}

func decodeB64JSON(seg string) (string, bool) {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		if b, err = base64.URLEncoding.DecodeString(seg); err != nil {
			return "", false
		}
	}
	var v interface{}
	if json.Unmarshal(b, &v) != nil {
		return "", false
	}
	pretty, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", false
	}
	return string(pretty), true
}

// ── heuristics ─────────────────────────────────────────────────────────────

// looksDecodable reports whether a freshly-decoded byte slice is worth keeping:
// either it's mostly printable text, valid UTF-8, valid JSON, or it carries a
// compression magic so the next iteration can decompress it. This is what keeps
// the decoder from "decoding" arbitrary text into base64/hex garbage.
func looksDecodable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b { // gzip
		return true
	}
	if len(b) >= 2 && b[0] == 0x78 { // zlib
		return true
	}
	return isMostlyText(b)
}

func isMostlyText(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c <= 0x7e) {
			printable++
		}
	}
	ratio := float64(printable) / float64(len(b))
	// Accept clearly-printable ASCII, or valid multibyte UTF-8 text.
	return ratio >= 0.85 || (utf8.Valid(b) && ratio >= 0.6)
}

func isLowerWord(s string) bool {
	for _, c := range s {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

// display renders a possibly-binary value safely for JSON transport: valid text
// passes through (truncated), binary becomes a hex preview.
func display(s string) string {
	if utf8.ValidString(s) {
		if len(s) > maxOutputLen {
			return s[:maxOutputLen] + "…(truncated)"
		}
		return s
	}
	b := []byte(s)
	if len(b) > 512 {
		b = b[:512]
	}
	return "binary " + strconv.Itoa(len(s)) + " bytes, hex: " + hex.EncodeToString(b)
}

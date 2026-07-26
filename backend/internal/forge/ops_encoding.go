package forge

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"math/big"
	"net/url"
	"strconv"
	"strings"
)

func init() {
	// ── Base64 ────────────────────────────────────────────────────────────────
	register(&Operation{
		Name: "To Base64", Category: "Encoding",
		Description: "Encode bytes to Base64.",
		Args: []ArgSpec{{Key: "alphabet", Label: "Alphabet", Type: ArgSelect,
			Default: "standard", Options: []string{"standard", "url-safe", "standard-nopad", "url-safe-nopad"}}},
		run: func(in []byte, a Args) ([]byte, error) {
			return []byte(b64Encoding(a.str("alphabet", "standard")).EncodeToString(in)), nil
		},
	})
	register(&Operation{
		Name: "From Base64", Category: "Encoding",
		Description: "Decode Base64. Tries the selected alphabet, then the others, so pasted blobs 'just work'.",
		Args: []ArgSpec{{Key: "alphabet", Label: "Alphabet", Type: ArgSelect,
			Default: "auto", Options: []string{"auto", "standard", "url-safe", "standard-nopad", "url-safe-nopad"}}},
		run: func(in []byte, a Args) ([]byte, error) {
			s := strings.TrimSpace(string(in))
			alpha := a.str("alphabet", "auto")
			if alpha != "auto" {
				return b64Encoding(alpha).DecodeString(s)
			}
			for _, enc := range []*base64.Encoding{
				base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
			} {
				if out, err := enc.DecodeString(s); err == nil {
					return out, nil
				}
			}
			return nil, fmt.Errorf("not valid Base64 in any alphabet")
		},
	})

	// ── Base32 ────────────────────────────────────────────────────────────────
	register(&Operation{
		Name: "To Base32", Category: "Encoding", Description: "Encode bytes to Base32.",
		run: func(in []byte, a Args) ([]byte, error) {
			return []byte(base32.StdEncoding.EncodeToString(in)), nil
		},
	})
	register(&Operation{
		Name: "From Base32", Category: "Encoding", Description: "Decode Base32 (padded or unpadded).",
		run: func(in []byte, a Args) ([]byte, error) {
			s := strings.ToUpper(strings.TrimSpace(string(in)))
			if out, err := base32.StdEncoding.DecodeString(s); err == nil {
				return out, nil
			}
			return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(s, "="))
		},
	})

	// ── Base58 (Bitcoin alphabet) ─────────────────────────────────────────────
	register(&Operation{
		Name: "To Base58", Category: "Encoding",
		Description: "Encode bytes to Base58 (Bitcoin alphabet) — common in wallet addresses and some malware config.",
		run: func(in []byte, a Args) ([]byte, error) { return []byte(base58Encode(in)), nil },
	})
	register(&Operation{
		Name: "From Base58", Category: "Encoding", Description: "Decode Base58 (Bitcoin alphabet).",
		run: func(in []byte, a Args) ([]byte, error) { return base58Decode(strings.TrimSpace(string(in))) },
	})

	// ── Hex ───────────────────────────────────────────────────────────────────
	register(&Operation{
		Name: "To Hex", Category: "Encoding", Description: "Encode bytes to hexadecimal.",
		Args: []ArgSpec{{Key: "delimiter", Label: "Delimiter", Type: ArgSelect,
			Default: "none", Options: []string{"none", "space", "colon", "0x", "\\x", "comma"}}},
		run: func(in []byte, a Args) ([]byte, error) {
			return []byte(hexEncode(in, a.str("delimiter", "none"))), nil
		},
	})
	register(&Operation{
		Name: "From Hex", Category: "Encoding",
		Description: "Decode hexadecimal. Ignores common delimiters (spaces, colons, 0x, \\x, commas).",
		run: func(in []byte, a Args) ([]byte, error) {
			return hex.DecodeString(stripHexDelims(string(in)))
		},
	})

	// ── URL ───────────────────────────────────────────────────────────────────
	register(&Operation{
		Name: "URL Encode", Category: "Encoding", Description: "Percent-encode for use in a URL.",
		Args: []ArgSpec{{Key: "all", Label: "Encode all chars", Type: ArgBool, Default: "false",
			Help: "Encode every character, not just reserved ones."}},
		run: func(in []byte, a Args) ([]byte, error) {
			if a.boolv("all") {
				var b strings.Builder
				for _, by := range in {
					fmt.Fprintf(&b, "%%%02X", by)
				}
				return []byte(b.String()), nil
			}
			return []byte(url.QueryEscape(string(in))), nil
		},
	})
	register(&Operation{
		Name: "URL Decode", Category: "Encoding", Description: "Decode percent-encoding (%XX and + for space).",
		run: func(in []byte, a Args) ([]byte, error) {
			s, err := url.QueryUnescape(string(in))
			if err != nil {
				// QueryUnescape is strict; fall back to PathUnescape which tolerates '+'.
				if s2, e2 := url.PathUnescape(string(in)); e2 == nil {
					return []byte(s2), nil
				}
				return nil, err
			}
			return []byte(s), nil
		},
	})

	// ── HTML entities ─────────────────────────────────────────────────────────
	register(&Operation{
		Name: "HTML Entity Encode", Category: "Encoding", Description: "Escape &, <, >, \" and ' as HTML entities.",
		run: func(in []byte, a Args) ([]byte, error) { return []byte(html.EscapeString(string(in))), nil },
	})
	register(&Operation{
		Name: "HTML Entity Decode", Category: "Encoding", Description: "Decode HTML entities (&amp; &#x41; &#65; …).",
		run: func(in []byte, a Args) ([]byte, error) { return []byte(html.UnescapeString(string(in))), nil },
	})

	// ── Charcode / binary / decimal ───────────────────────────────────────────
	register(&Operation{
		Name: "To Decimal", Category: "Encoding", Description: "Byte values as space-separated decimal numbers.",
		run: func(in []byte, a Args) ([]byte, error) {
			parts := make([]string, len(in))
			for i, b := range in {
				parts[i] = strconv.Itoa(int(b))
			}
			return []byte(strings.Join(parts, " ")), nil
		},
	})
	register(&Operation{
		Name: "From Decimal", Category: "Encoding", Description: "Parse space/comma-separated decimal byte values.",
		run: func(in []byte, a Args) ([]byte, error) { return numbersToBytes(string(in), 10) },
	})
	register(&Operation{
		Name: "To Binary", Category: "Encoding", Description: "Each byte as 8 binary digits.",
		run: func(in []byte, a Args) ([]byte, error) {
			parts := make([]string, len(in))
			for i, b := range in {
				parts[i] = fmt.Sprintf("%08b", b)
			}
			return []byte(strings.Join(parts, " ")), nil
		},
	})
	register(&Operation{
		Name: "From Binary", Category: "Encoding", Description: "Parse groups of binary digits back into bytes.",
		run: func(in []byte, a Args) ([]byte, error) {
			fields := strings.Fields(string(in))
			if len(fields) == 1 {
				// One long run of bits — split into bytes of 8.
				bits := fields[0]
				for i := 0; i+8 <= len(bits); i += 8 {
					fields = append(fields, bits[i:i+8])
				}
				fields = fields[1:]
			}
			out := make([]byte, 0, len(fields))
			for _, f := range fields {
				v, err := strconv.ParseUint(f, 2, 8)
				if err != nil {
					return nil, fmt.Errorf("invalid binary %q", f)
				}
				out = append(out, byte(v))
			}
			return out, nil
		},
	})
	register(&Operation{
		Name: "To Charcode", Category: "Encoding", Description: "Unicode code points as space-separated decimals.",
		run: func(in []byte, a Args) ([]byte, error) {
			var parts []string
			for _, r := range string(in) {
				parts = append(parts, strconv.Itoa(int(r)))
			}
			return []byte(strings.Join(parts, " ")), nil
		},
	})
	register(&Operation{
		Name: "From Charcode", Category: "Encoding", Description: "Decimal code points back to text.",
		run: func(in []byte, a Args) ([]byte, error) {
			var b strings.Builder
			for _, f := range splitNums(string(in)) {
				n, err := strconv.Atoi(f)
				if err != nil {
					return nil, fmt.Errorf("invalid code point %q", f)
				}
				b.WriteRune(rune(n))
			}
			return []byte(b.String()), nil
		},
	})
}

func b64Encoding(alpha string) *base64.Encoding {
	switch alpha {
	case "url-safe":
		return base64.URLEncoding
	case "standard-nopad":
		return base64.RawStdEncoding
	case "url-safe-nopad":
		return base64.RawURLEncoding
	default:
		return base64.StdEncoding
	}
}

func hexEncode(in []byte, delim string) string {
	if delim == "none" || delim == "" {
		return hex.EncodeToString(in)
	}
	parts := make([]string, len(in))
	for i, b := range in {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	switch delim {
	case "space":
		return strings.Join(parts, " ")
	case "colon":
		return strings.Join(parts, ":")
	case "comma":
		return strings.Join(parts, ",")
	case "0x":
		return "0x" + strings.Join(parts, "0x")
	case "\\x":
		return "\\x" + strings.Join(parts, "\\x")
	}
	return strings.Join(parts, "")
}

func stripHexDelims(s string) string {
	r := strings.NewReplacer(" ", "", "\n", "", "\r", "", "\t", "", ":", "", ",", "", "0x", "", "0X", "", "\\x", "", "\\X", "", "%", "")
	return r.Replace(s)
}

func numbersToBytes(s string, base int) ([]byte, error) {
	fields := splitNums(s)
	out := make([]byte, 0, len(fields))
	for _, f := range fields {
		v, err := strconv.ParseUint(f, base, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid number %q", f)
		}
		if v > 0xff {
			return nil, fmt.Errorf("value %d out of byte range", v)
		}
		out = append(out, byte(v))
	}
	return out, nil
}

func splitNums(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ';'
	})
}

// ── Base58 (Bitcoin) ───────────────────────────────────────────────────────

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var base58Big = big.NewInt(58)

func base58Encode(in []byte) string {
	x := new(big.Int).SetBytes(in)
	var out []byte
	mod := new(big.Int)
	zero := big.NewInt(0)
	for x.Cmp(zero) > 0 {
		x.DivMod(x, base58Big, mod)
		out = append(out, base58Alphabet[mod.Int64()])
	}
	// Preserve leading zero bytes as '1'.
	for _, b := range in {
		if b != 0 {
			break
		}
		out = append(out, base58Alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func base58Decode(s string) ([]byte, error) {
	x := big.NewInt(0)
	for _, r := range s {
		idx := strings.IndexRune(base58Alphabet, r)
		if idx < 0 {
			return nil, fmt.Errorf("invalid Base58 character %q", string(r))
		}
		x.Mul(x, base58Big)
		x.Add(x, big.NewInt(int64(idx)))
	}
	out := x.Bytes()
	// Restore leading zeros.
	var zeros int
	for _, r := range s {
		if r != rune(base58Alphabet[0]) {
			break
		}
		zeros++
	}
	return append(make([]byte, zeros), out...), nil
}

// hexDump renders bytes as an offset/hex/ascii dump, used to show binary output.
func hexDump(b []byte) string {
	var sb strings.Builder
	const perLine = 16
	for i := 0; i < len(b); i += perLine {
		end := i + perLine
		if end > len(b) {
			end = len(b)
		}
		fmt.Fprintf(&sb, "%08x  ", i)
		for j := i; j < i+perLine; j++ {
			if j < end {
				fmt.Fprintf(&sb, "%02x ", b[j])
			} else {
				sb.WriteString("   ")
			}
			if j == i+7 {
				sb.WriteByte(' ')
			}
		}
		sb.WriteString(" |")
		for j := i; j < end; j++ {
			c := b[j]
			if c < 0x20 || c > 0x7e {
				c = '.'
			}
			sb.WriteByte(c)
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}

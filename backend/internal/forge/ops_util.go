package forge

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode/utf16"

	"github.com/analysishub/backend/internal/decode"
	"github.com/analysishub/backend/internal/threatintel"
)

func init() {
	// ── Parsing / decoding aids ───────────────────────────────────────────────
	register(&Operation{
		Name: "JWT Decode", Category: "Parsing",
		Description: "Split a JWT and decode its header and payload (signature is NOT verified).",
		run: func(in []byte, a Args) ([]byte, error) {
			parts := strings.Split(strings.TrimSpace(string(in)), ".")
			if len(parts) < 2 {
				return nil, fmt.Errorf("not a JWT (need at least header.payload)")
			}
			header, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err != nil {
				return nil, fmt.Errorf("header: %w", err)
			}
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				return nil, fmt.Errorf("payload: %w", err)
			}
			var sb strings.Builder
			sb.WriteString("=== HEADER ===\n")
			sb.WriteString(prettyJSON(header))
			sb.WriteString("\n\n=== PAYLOAD ===\n")
			sb.WriteString(prettyJSON(payload))
			if len(parts) >= 3 {
				sb.WriteString("\n\n=== SIGNATURE (not verified) ===\n")
				sb.WriteString(parts[2])
			}
			return []byte(sb.String()), nil
		},
	})
	register(&Operation{
		Name: "PowerShell Decode", Category: "Parsing",
		Description: "Decode a PowerShell -EncodedCommand value (base64 of UTF-16LE).",
		run: func(in []byte, a Args) ([]byte, error) {
			raw, err := b64Encoding("standard").DecodeString(strings.TrimSpace(string(in)))
			if err != nil {
				if raw, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(in))); err != nil {
					return nil, fmt.Errorf("not valid base64")
				}
			}
			return utf16LEtoUTF8(raw), nil
		},
	})
	register(&Operation{
		Name: "Magic (auto-detect)", Category: "Parsing",
		Description: "Recursively auto-detect and peel encodings (base64/hex/url/gzip/zlib/JWT/…) until the value stabilises.",
		run: func(in []byte, a Args) ([]byte, error) {
			r := decode.Analyze(string(in))
			if len(r.Steps) == 0 {
				return []byte("No further encoding detected.\n\n" + r.Final), nil
			}
			var sb strings.Builder
			fmt.Fprintf(&sb, "Peeled %d layer(s):\n", r.Layers)
			for i, s := range r.Steps {
				fmt.Fprintf(&sb, "  %d. %s\n", i+1, s.Label)
			}
			sb.WriteString("\n=== RESULT ===\n")
			sb.WriteString(r.Final)
			return []byte(sb.String()), nil
		},
	})

	// ── IOC helpers ───────────────────────────────────────────────────────────
	register(&Operation{
		Name: "Defang IOCs", Category: "IOC",
		Description: "Neutralise IOCs so they can't be clicked/executed (hxxp, 1[.]2[.]3[.]4, evil[.]com).",
		run: func(in []byte, a Args) ([]byte, error) { return []byte(defang(string(in))), nil },
	})
	register(&Operation{
		Name: "Refang IOCs", Category: "IOC",
		Description: "Reverse defanging back into live IOCs.",
		run: func(in []byte, a Args) ([]byte, error) { return []byte(refang(string(in))), nil },
	})
	register(&Operation{
		Name: "Extract IOCs", Category: "IOC",
		Description: "Pull IPs, hashes, domains, URLs and emails out of the text.",
		run: func(in []byte, a Args) ([]byte, error) {
			iocs := threatintel.ExtractIOCs(string(in))
			b, _ := json.MarshalIndent(iocs, "", "  ")
			return b, nil
		},
	})

	// ── Classic: Morse ────────────────────────────────────────────────────────
	register(&Operation{
		Name: "To Morse", Category: "Cipher", Description: "Encode letters/digits to Morse code.",
		run: func(in []byte, a Args) ([]byte, error) { return []byte(toMorse(string(in))), nil },
	})
	register(&Operation{
		Name: "From Morse", Category: "Cipher", Description: "Decode Morse code (letters space-separated, words with / or 3 spaces).",
		run: func(in []byte, a Args) ([]byte, error) { return []byte(fromMorse(string(in))), nil },
	})

	// ── Analysis ──────────────────────────────────────────────────────────────
	register(&Operation{
		Name: "Entropy", Category: "Analysis",
		Description: "Shannon entropy (bits/byte, 0–8). High values (>7) suggest encryption or compression.",
		run: func(in []byte, a Args) ([]byte, error) {
			e := shannonEntropy(in)
			verdict := "likely plain text or structured data"
			switch {
			case e > 7.5:
				verdict = "very high — encrypted, compressed, or packed"
			case e > 6.5:
				verdict = "high — possibly encoded/compressed"
			case e > 4.5:
				verdict = "moderate"
			}
			return []byte(fmt.Sprintf("Shannon entropy: %.4f bits/byte (%d bytes)\n%s", e, len(in), verdict)), nil
		},
	})

	// ── Text utilities ────────────────────────────────────────────────────────
	register(&Operation{
		Name: "Reverse", Category: "Text", Description: "Reverse the bytes.",
		run: func(in []byte, a Args) ([]byte, error) {
			out := make([]byte, len(in))
			for i := range in {
				out[len(in)-1-i] = in[i]
			}
			return out, nil
		},
	})
	register(&Operation{
		Name: "To Upper Case", Category: "Text", Description: "Uppercase.",
		run: func(in []byte, a Args) ([]byte, error) { return []byte(strings.ToUpper(string(in))), nil },
	})
	register(&Operation{
		Name: "To Lower Case", Category: "Text", Description: "Lowercase.",
		run: func(in []byte, a Args) ([]byte, error) { return []byte(strings.ToLower(string(in))), nil },
	})
	register(&Operation{
		Name: "Remove Whitespace", Category: "Text", Description: "Strip all spaces, tabs and newlines.",
		run: func(in []byte, a Args) ([]byte, error) {
			return []byte(strings.Map(func(r rune) rune {
				if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
					return -1
				}
				return r
			}, string(in))), nil
		},
	})
	register(&Operation{
		Name: "Find / Replace", Category: "Text",
		Description: "Regex find-and-replace (RE2 syntax; use $1 for capture groups).",
		Args: []ArgSpec{
			{Key: "find", Label: "Find (regex)", Type: ArgString, Default: ""},
			{Key: "replace", Label: "Replace", Type: ArgString, Default: ""},
			{Key: "ci", Label: "Case-insensitive", Type: ArgBool, Default: "false"},
		},
		run: func(in []byte, a Args) ([]byte, error) {
			pat := a.str("find", "")
			if pat == "" {
				return in, nil
			}
			if a.boolv("ci") {
				pat = "(?i)" + pat
			}
			re, err := regexp.Compile(pat)
			if err != nil {
				return nil, fmt.Errorf("invalid regex: %w", err)
			}
			return re.ReplaceAll(in, []byte(a.str("replace", ""))), nil
		},
	})
}

func prettyJSON(b []byte) string {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return string(b) // not JSON — show raw
	}
	out, _ := json.MarshalIndent(v, "", "  ")
	return string(out)
}

func utf16LEtoUTF8(b []byte) []byte {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return []byte(string(utf16.Decode(u16)))
}

func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	e := 0.0
	n := float64(len(b))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

// ── Defang / refang ─────────────────────────────────────────────────────────

var (
	reDot    = regexp.MustCompile(`\.`)
	reScheme = regexp.MustCompile(`(?i)\bhttp(s?)://`)
	reAtSign = regexp.MustCompile(`@`)
)

func defang(s string) string {
	s = reScheme.ReplaceAllString(s, "hxxp$1://")
	s = reDot.ReplaceAllString(s, "[.]")
	s = reAtSign.ReplaceAllString(s, "[at]")
	return s
}

func refang(s string) string {
	r := strings.NewReplacer(
		"[.]", ".", "(.)", ".", "[dot]", ".", "(dot)", ".",
		"hxxp", "http", "hXXp", "http",
		"[at]", "@", "(at)", "@", "[:]", ":",
		"[//]", "//",
	)
	return r.Replace(s)
}

// ── Morse ───────────────────────────────────────────────────────────────────

var morseTable = map[rune]string{
	'A': ".-", 'B': "-...", 'C': "-.-.", 'D': "-..", 'E': ".", 'F': "..-.",
	'G': "--.", 'H': "....", 'I': "..", 'J': ".---", 'K': "-.-", 'L': ".-..",
	'M': "--", 'N': "-.", 'O': "---", 'P': ".--.", 'Q': "--.-", 'R': ".-.",
	'S': "...", 'T': "-", 'U': "..-", 'V': "...-", 'W': ".--", 'X': "-..-",
	'Y': "-.--", 'Z': "--..",
	'0': "-----", '1': ".----", '2': "..---", '3': "...--", '4': "....-",
	'5': ".....", '6': "-....", '7': "--...", '8': "---..", '9': "----.",
	'.': ".-.-.-", ',': "--..--", '?': "..--..", '/': "-..-.", '@': ".--.-.",
	'-': "-....-", '=': "-...-",
}

func toMorse(s string) string {
	var out []string
	for _, r := range strings.ToUpper(s) {
		if r == ' ' {
			out = append(out, "/")
			continue
		}
		if code, ok := morseTable[r]; ok {
			out = append(out, code)
		}
	}
	return strings.Join(out, " ")
}

func fromMorse(s string) string {
	rev := map[string]rune{}
	for r, code := range morseTable {
		rev[code] = r
	}
	// Word boundaries: "/" or runs of spaces.
	s = strings.ReplaceAll(s, "/", " / ")
	var b strings.Builder
	for _, tok := range strings.Fields(s) {
		if tok == "/" {
			b.WriteByte(' ')
			continue
		}
		if r, ok := rev[tok]; ok {
			b.WriteRune(r)
		}
	}
	return b.String()
}

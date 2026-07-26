package forge

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rc4"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

func init() {
	// ── ROT / Caesar ──────────────────────────────────────────────────────────
	register(&Operation{
		Name: "ROT13", Category: "Cipher", Description: "Rotate letters by 13 (its own inverse).",
		run: func(in []byte, a Args) ([]byte, error) { return rotN(in, 13), nil },
	})
	register(&Operation{
		Name: "ROT47", Category: "Cipher", Description: "Rotate printable ASCII (33–126) by 47 (its own inverse).",
		run: func(in []byte, a Args) ([]byte, error) {
			out := make([]byte, len(in))
			for i, b := range in {
				if b >= 33 && b <= 126 {
					out[i] = 33 + (b-33+47)%94
				} else {
					out[i] = b
				}
			}
			return out, nil
		},
	})
	register(&Operation{
		Name: "ROT-N (Caesar)", Category: "Cipher", Description: "Rotate letters by N. Use 26-N to decode.",
		Args: []ArgSpec{{Key: "n", Label: "Shift", Type: ArgInt, Default: "13"}},
		run: func(in []byte, a Args) ([]byte, error) {
			n, _ := strconv.Atoi(a.str("n", "13"))
			return rotN(in, n), nil
		},
	})
	register(&Operation{
		Name: "Atbash", Category: "Cipher", Description: "Mirror the alphabet (A↔Z). Its own inverse.",
		run: func(in []byte, a Args) ([]byte, error) {
			out := make([]byte, len(in))
			for i, b := range in {
				switch {
				case b >= 'a' && b <= 'z':
					out[i] = 'z' - (b - 'a')
				case b >= 'A' && b <= 'Z':
					out[i] = 'Z' - (b - 'A')
				default:
					out[i] = b
				}
			}
			return out, nil
		},
	})

	// ── XOR ───────────────────────────────────────────────────────────────────
	register(&Operation{
		Name: "XOR", Category: "Cipher",
		Description: "XOR each byte with a repeating key. XOR is symmetric — the same op decodes.",
		Args: []ArgSpec{
			{Key: "key", Label: "Key", Type: ArgString, Default: "", Help: "The key value."},
			{Key: "format", Label: "Key format", Type: ArgSelect, Default: "utf8", Options: []string{"utf8", "hex", "decimal"}},
		},
		run: func(in []byte, a Args) ([]byte, error) {
			key, err := parseKey(a.str("key", ""), a.str("format", "utf8"))
			if err != nil {
				return nil, err
			}
			if len(key) == 0 {
				return nil, fmt.Errorf("key is required")
			}
			out := make([]byte, len(in))
			for i := range in {
				out[i] = in[i] ^ key[i%len(key)]
			}
			return out, nil
		},
	})
	register(&Operation{
		Name: "XOR Brute (single byte)", Category: "Cipher",
		Description: "Try all 256 single-byte XOR keys and list the ones that produce mostly-printable text.",
		run: func(in []byte, a Args) ([]byte, error) {
			var sb strings.Builder
			hits := 0
			for k := 0; k < 256 && hits < 40; k++ {
				out := make([]byte, len(in))
				for i := range in {
					out[i] = in[i] ^ byte(k)
				}
				if isPrintableUTF8(out) {
					hits++
					preview := out
					if len(preview) > 120 {
						preview = preview[:120]
					}
					fmt.Fprintf(&sb, "0x%02x: %s\n", k, preview)
				}
			}
			if hits == 0 {
				return []byte("no single-byte key produced printable text"), nil
			}
			return []byte(sb.String()), nil
		},
	})

	// ── RC4 ───────────────────────────────────────────────────────────────────
	register(&Operation{
		Name: "RC4", Category: "Cipher",
		Description: "RC4 keystream cipher (symmetric — same op decrypts). Common in older malware.",
		Args: []ArgSpec{
			{Key: "key", Label: "Key", Type: ArgString, Default: ""},
			{Key: "format", Label: "Key format", Type: ArgSelect, Default: "utf8", Options: []string{"utf8", "hex"}},
		},
		run: func(in []byte, a Args) ([]byte, error) {
			key, err := parseKey(a.str("key", ""), a.str("format", "utf8"))
			if err != nil {
				return nil, err
			}
			c, err := rc4.NewCipher(key)
			if err != nil {
				return nil, err
			}
			out := make([]byte, len(in))
			c.XORKeyStream(out, in)
			return out, nil
		},
	})

	// ── AES ───────────────────────────────────────────────────────────────────
	register(&Operation{
		Name: "AES Decrypt", Category: "Cipher",
		Description: "AES decrypt. GCM expects nonce(12)‖ciphertext‖tag; CBC/CTR need an IV. Input is the ciphertext.",
		Args:        aesArgs(true),
		run:         func(in []byte, a Args) ([]byte, error) { return aesRun(in, a, false) },
	})
	register(&Operation{
		Name: "AES Encrypt", Category: "Cipher",
		Description: "AES encrypt. GCM prepends the nonce to the output; CBC/CTR use the supplied IV.",
		Args:        aesArgs(false),
		run:         func(in []byte, a Args) ([]byte, error) { return aesRun(in, a, true) },
	})
}

func rotN(in []byte, n int) []byte {
	n = ((n % 26) + 26) % 26
	out := make([]byte, len(in))
	for i, b := range in {
		switch {
		case b >= 'a' && b <= 'z':
			out[i] = 'a' + (b-'a'+byte(n))%26
		case b >= 'A' && b <= 'Z':
			out[i] = 'A' + (b-'A'+byte(n))%26
		default:
			out[i] = b
		}
	}
	return out
}

// parseKey turns a user key string into bytes per the chosen format.
func parseKey(s, format string) ([]byte, error) {
	switch format {
	case "hex":
		return hex.DecodeString(stripHexDelims(s))
	case "decimal":
		return numbersToBytes(s, 10)
	default:
		return []byte(s), nil
	}
}

func aesArgs(decrypt bool) []ArgSpec {
	inFmt := "hex"
	if !decrypt {
		inFmt = "raw"
	}
	_ = inFmt
	return []ArgSpec{
		{Key: "key", Label: "Key", Type: ArgString, Default: "", Help: "16/24/32 bytes for AES-128/192/256."},
		{Key: "keyfmt", Label: "Key format", Type: ArgSelect, Default: "hex", Options: []string{"hex", "utf8", "base64"}},
		{Key: "mode", Label: "Mode", Type: ArgSelect, Default: "GCM", Options: []string{"GCM", "CBC", "CTR"}},
		{Key: "iv", Label: "IV / Nonce", Type: ArgString, Default: "", Help: "CBC/CTR: 16-byte IV. GCM: leave blank to read a 12-byte nonce from the front of the input."},
		{Key: "ivfmt", Label: "IV format", Type: ArgSelect, Default: "hex", Options: []string{"hex", "utf8", "base64"}},
		{Key: "input", Label: "Ciphertext format", Type: ArgSelect, Default: "hex", Options: []string{"hex", "base64", "raw"}},
	}
}

func aesRun(in []byte, a Args, encrypt bool) ([]byte, error) {
	key, err := decodeKeyArg(a.str("key", ""), a.str("keyfmt", "hex"))
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := strings.ToUpper(a.str("mode", "GCM"))

	// For decryption the ciphertext arrives in the chosen wire format; for
	// encryption the plaintext is the raw previous-stage bytes.
	data := in
	if !encrypt {
		if data, err = decodeInputArg(in, a.str("input", "hex")); err != nil {
			return nil, fmt.Errorf("ciphertext: %w", err)
		}
	}

	switch mode {
	case "GCM":
		g, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		if encrypt {
			nonce, err := decodeKeyArg(a.str("iv", ""), a.str("ivfmt", "hex"))
			if err != nil || len(nonce) != g.NonceSize() {
				return nil, fmt.Errorf("GCM needs a %d-byte nonce (or generate one)", g.NonceSize())
			}
			ct := g.Seal(nil, nonce, data, nil)
			return append(nonce, ct...), nil
		}
		ns := g.NonceSize()
		var nonce []byte
		if iv := a.str("iv", ""); iv != "" {
			if nonce, err = decodeKeyArg(iv, a.str("ivfmt", "hex")); err != nil {
				return nil, err
			}
		} else {
			if len(data) < ns {
				return nil, fmt.Errorf("input shorter than the %d-byte nonce", ns)
			}
			nonce, data = data[:ns], data[ns:]
		}
		return g.Open(nil, nonce, data, nil)

	case "CBC":
		iv, err := decodeKeyArg(a.str("iv", ""), a.str("ivfmt", "hex"))
		if err != nil || len(iv) != block.BlockSize() {
			return nil, fmt.Errorf("CBC needs a %d-byte IV", block.BlockSize())
		}
		if encrypt {
			padded := pkcs7Pad(data, block.BlockSize())
			out := make([]byte, len(padded))
			cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
			return out, nil
		}
		if len(data)%block.BlockSize() != 0 {
			return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
		}
		out := make([]byte, len(data))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
		return pkcs7Unpad(out), nil

	case "CTR":
		iv, err := decodeKeyArg(a.str("iv", ""), a.str("ivfmt", "hex"))
		if err != nil || len(iv) != block.BlockSize() {
			return nil, fmt.Errorf("CTR needs a %d-byte IV", block.BlockSize())
		}
		out := make([]byte, len(data))
		cipher.NewCTR(block, iv).XORKeyStream(out, data)
		return out, nil
	}
	return nil, fmt.Errorf("unknown AES mode %q", mode)
}

func decodeKeyArg(s, format string) ([]byte, error) {
	switch format {
	case "utf8":
		return []byte(s), nil
	case "base64":
		return b64Encoding("standard").DecodeString(strings.TrimSpace(s))
	default:
		return hex.DecodeString(stripHexDelims(s))
	}
}

func decodeInputArg(in []byte, format string) ([]byte, error) {
	switch format {
	case "raw":
		return in, nil
	case "base64":
		for _, enc := range []string{"standard", "url-safe", "standard-nopad", "url-safe-nopad"} {
			if out, err := b64Encoding(enc).DecodeString(strings.TrimSpace(string(in))); err == nil {
				return out, nil
			}
		}
		return nil, fmt.Errorf("not valid base64")
	default:
		return hex.DecodeString(stripHexDelims(string(in)))
	}
}

func pkcs7Pad(b []byte, size int) []byte {
	pad := size - len(b)%size
	return append(b, bytes.Repeat([]byte{byte(pad)}, pad)...)
}

func pkcs7Unpad(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	pad := int(b[len(b)-1])
	if pad == 0 || pad > len(b) {
		return b // not padded the way we expect — return as-is
	}
	return b[:len(b)-pad]
}

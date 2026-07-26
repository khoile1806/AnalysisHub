package forge

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
)

// readCap bounds decompression output so a zip-bomb-style input cannot exhaust
// memory. Matches the engine's per-stage ceiling.
const readCap = maxInput

func init() {
	// ── Compression ───────────────────────────────────────────────────────────
	register(&Operation{
		Name: "Gzip", Category: "Compression", Description: "Compress with gzip.",
		run: func(in []byte, a Args) ([]byte, error) {
			var buf bytes.Buffer
			w := gzip.NewWriter(&buf)
			if _, err := w.Write(in); err != nil {
				return nil, err
			}
			if err := w.Close(); err != nil {
				return nil, err
			}
			return buf.Bytes(), nil
		},
	})
	register(&Operation{
		Name: "Gunzip", Category: "Compression", Description: "Decompress gzip (magic 1f 8b).",
		run: func(in []byte, a Args) ([]byte, error) {
			r, err := gzip.NewReader(bytes.NewReader(in))
			if err != nil {
				return nil, err
			}
			defer r.Close()
			return io.ReadAll(io.LimitReader(r, readCap))
		},
	})
	register(&Operation{
		Name: "Zlib Deflate", Category: "Compression", Description: "Compress with zlib.",
		run: func(in []byte, a Args) ([]byte, error) {
			var buf bytes.Buffer
			w := zlib.NewWriter(&buf)
			if _, err := w.Write(in); err != nil {
				return nil, err
			}
			if err := w.Close(); err != nil {
				return nil, err
			}
			return buf.Bytes(), nil
		},
	})
	register(&Operation{
		Name: "Zlib Inflate", Category: "Compression", Description: "Decompress zlib (magic 0x78).",
		run: func(in []byte, a Args) ([]byte, error) {
			r, err := zlib.NewReader(bytes.NewReader(in))
			if err != nil {
				return nil, err
			}
			defer r.Close()
			return io.ReadAll(io.LimitReader(r, readCap))
		},
	})
	register(&Operation{
		Name: "Raw Inflate", Category: "Compression", Description: "Decompress a raw DEFLATE stream (no zlib/gzip header).",
		run: func(in []byte, a Args) ([]byte, error) {
			r := flate.NewReader(bytes.NewReader(in))
			defer r.Close()
			return io.ReadAll(io.LimitReader(r, readCap))
		},
	})

	// ── Hashing ───────────────────────────────────────────────────────────────
	for _, h := range []struct {
		name string
		mk   func() hash.Hash
	}{
		{"MD5", md5.New},
		{"SHA1", sha1.New},
		{"SHA256", sha256.New},
		{"SHA384", sha512.New384},
		{"SHA512", sha512.New},
	} {
		h := h
		register(&Operation{
			Name: h.name, Category: "Hashing",
			Description: "Hash the input with " + h.name + " (hex digest).",
			run: func(in []byte, a Args) ([]byte, error) {
				d := h.mk()
				d.Write(in)
				return []byte(hex.EncodeToString(d.Sum(nil))), nil
			},
		})
	}
	register(&Operation{
		Name: "CRC32", Category: "Hashing", Description: "CRC32 checksum (IEEE, hex).",
		run: func(in []byte, a Args) ([]byte, error) {
			return []byte(fmt.Sprintf("%08x", crc32.ChecksumIEEE(in))), nil
		},
	})
	register(&Operation{
		Name: "HMAC", Category: "Hashing", Description: "Keyed-hash message authentication code (hex).",
		Args: []ArgSpec{
			{Key: "key", Label: "Key", Type: ArgString, Default: ""},
			{Key: "keyfmt", Label: "Key format", Type: ArgSelect, Default: "utf8", Options: []string{"utf8", "hex"}},
			{Key: "algo", Label: "Algorithm", Type: ArgSelect, Default: "SHA256", Options: []string{"SHA256", "SHA1", "MD5", "SHA512"}},
		},
		run: func(in []byte, a Args) ([]byte, error) {
			key, err := parseKey(a.str("key", ""), a.str("keyfmt", "utf8"))
			if err != nil {
				return nil, err
			}
			var mk func() hash.Hash
			switch a.str("algo", "SHA256") {
			case "SHA1":
				mk = sha1.New
			case "MD5":
				mk = md5.New
			case "SHA512":
				mk = sha512.New
			default:
				mk = sha256.New
			}
			m := hmac.New(mk, key)
			m.Write(in)
			return []byte(hex.EncodeToString(m.Sum(nil))), nil
		},
	})
}

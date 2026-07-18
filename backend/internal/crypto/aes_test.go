package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"strings"
	"testing"
)

// key32 is a valid AES-256 key (exactly 32 bytes).
const key32 = "0123456789abcdef0123456789abcdef"

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	cases := []string{
		"hello world",
		"opencti-api-token-abc123",
		"unicode: tiếng việt 日本語 🔐",
		strings.Repeat("A", 4096), // larger than one GCM block
	}
	for _, pt := range cases {
		ct, err := Encrypt(pt, key32)
		if err != nil {
			t.Fatalf("Encrypt(%q) error: %v", pt, err)
		}
		if ct == pt {
			t.Errorf("ciphertext equals plaintext for %q (not encrypted)", pt)
		}
		got, err := Decrypt(ct, key32)
		if err != nil {
			t.Fatalf("Decrypt error: %v", err)
		}
		if got != pt {
			t.Errorf("round-trip mismatch: got %q, want %q", got, pt)
		}
	}
}

func TestEncrypt_EmptyPlaintext(t *testing.T) {
	ct, err := Encrypt("", key32)
	if err != nil {
		t.Fatalf("Encrypt(\"\") error: %v", err)
	}
	if ct != "" {
		t.Errorf("Encrypt(\"\") = %q, want empty string", ct)
	}
	// Decrypt of empty string is symmetric.
	pt, err := Decrypt("", key32)
	if err != nil || pt != "" {
		t.Errorf("Decrypt(\"\") = (%q, %v), want (\"\", nil)", pt, err)
	}
}

func TestEncrypt_RejectsEmptyKey(t *testing.T) {
	if _, err := Encrypt("data", ""); err == nil {
		t.Error("Encrypt with empty key: expected error, got nil")
	}
	if _, err := Decrypt("dummy", ""); err == nil {
		t.Error("Decrypt with empty key: expected error, got nil")
	}
}

func TestEncrypt_AnyKeyLengthWorks(t *testing.T) {
	// Non-empty keys of ANY length are hashed to 32 bytes, so encryption works
	// (no "must be exactly 32 bytes" failure) and round-trips per key.
	keys := []string{
		"short",
		"0123456789abcdef0123456789abcde",   // 31
		"0123456789abcdef0123456789abcdef0", // 33
		strings.Repeat("k", 100),            // long
	}
	for _, k := range keys {
		ct, err := Encrypt("data", k)
		if err != nil {
			t.Errorf("Encrypt with %d-char key errored: %v", len(k), err)
			continue
		}
		got, err := Decrypt(ct, k)
		if err != nil || got != "data" {
			t.Errorf("round-trip with %d-char key: got (%q, %v), want (\"data\", nil)", len(k), got, err)
		}
	}
}

func TestDecrypt_BackwardCompatRawKey(t *testing.T) {
	// Data encrypted BEFORE key derivation used the raw 32-byte key directly.
	// Decrypt must still recover it via the raw-key fallback.
	block, _ := aes.NewCipher([]byte(key32))
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	legacy := base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte("legacy-secret"), nil))

	got, err := Decrypt(legacy, key32)
	if err != nil || got != "legacy-secret" {
		t.Errorf("backward-compat decrypt: got (%q, %v), want (\"legacy-secret\", nil)", got, err)
	}
}

func TestEncrypt_NonceIsRandom(t *testing.T) {
	// Two encryptions of identical plaintext must differ (random nonce per call),
	// otherwise the scheme leaks equality of plaintexts.
	a, err := Encrypt("same-secret", key32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encrypt("same-secret", key32)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two encryptions produced identical ciphertext; nonce is not random")
	}
}

func TestDecrypt_WrongKeyFails(t *testing.T) {
	ct, err := Encrypt("top-secret", key32)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := "ffffffffffffffffffffffffffffffff" // valid length, wrong value
	if _, err := Decrypt(ct, wrongKey); err == nil {
		t.Error("Decrypt with wrong key succeeded; GCM authentication did not fail")
	}
}

func TestDecrypt_TamperedCiphertextFails(t *testing.T) {
	ct, err := Encrypt("integrity-protected", key32)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a character in the base64 ciphertext body.
	b := []byte(ct)
	last := len(b) - 1
	if b[last] == 'A' {
		b[last] = 'B'
	} else {
		b[last] = 'A'
	}
	if _, err := Decrypt(string(b), key32); err == nil {
		t.Error("Decrypt of tampered ciphertext succeeded; AEAD tag was not verified")
	}
}

func TestDecrypt_InvalidInputs(t *testing.T) {
	// Not valid base64.
	if _, err := Decrypt("!!!not-base64!!!", key32); err == nil {
		t.Error("Decrypt of non-base64 input succeeded, want error")
	}
	// Valid base64 but shorter than a GCM nonce.
	if _, err := Decrypt("AA+=", key32); err == nil {
		t.Error("Decrypt of too-short ciphertext succeeded, want error")
	}
}

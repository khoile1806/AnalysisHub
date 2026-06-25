package crypto

import (
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

func TestEncrypt_RejectsBadKeyLength(t *testing.T) {
	badKeys := []string{
		"",                                  // empty
		"short",                             // too short
		"0123456789abcdef0123456789abcde",   // 31 bytes
		"0123456789abcdef0123456789abcdef0", // 33 bytes
	}
	for _, k := range badKeys {
		if _, err := Encrypt("data", k); err == nil {
			t.Errorf("Encrypt with %d-byte key: expected error, got nil", len(k))
		}
		if _, err := Decrypt("dummy", k); err == nil {
			t.Errorf("Decrypt with %d-byte key: expected error, got nil", len(k))
		}
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

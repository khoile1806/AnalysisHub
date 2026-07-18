package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// deriveKey normalises ANY non-empty key string to a 32-byte AES-256 key via
// SHA-256. This means operators can set AES_ENCRYPTION_KEY to a value of any
// length (a common trap: `openssl rand -hex 32` yields 64 characters, not 32) and
// encryption still works — no "must be exactly 32 bytes" failure on fresh deploys.
func deriveKey(key string) []byte {
	sum := sha256.Sum256([]byte(key))
	return sum[:]
}

// Encrypt encrypts a string using AES-256-GCM and returns a base64 encoded string.
// The key may be any non-empty string (it is hashed to 32 bytes internally).
func Encrypt(plaintext, key string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	if key == "" {
		return "", errors.New("encryption key is empty")
	}
	keyBytes := deriveKey(key)

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64 encoded string using AES-256-GCM. The key may be any
// non-empty string. For backward compatibility with data encrypted before key
// derivation was introduced (a raw 32-byte key), it retries with the raw key.
func Decrypt(encodedCiphertext, key string) (string, error) {
	if encodedCiphertext == "" {
		return "", nil
	}
	if key == "" {
		return "", errors.New("encryption key is empty")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		return "", fmt.Errorf("decode base64: %w", err)
	}

	// Preferred: the derived (SHA-256) key.
	if pt, derr := gcmOpen(deriveKey(key), ciphertext); derr == nil {
		return pt, nil
	}
	// Backward compatibility: data encrypted with a raw 32-byte key.
	if len(key) == 32 {
		if pt, derr := gcmOpen([]byte(key), ciphertext); derr == nil {
			return pt, nil
		}
	}
	return "", errors.New("decrypt: authentication failed (wrong encryption key?)")
}

// gcmOpen opens an AES-256-GCM ciphertext (nonce prefixed) with the given key.
func gcmOpen(keyBytes, ciphertext []byte) (string, error) {
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintextBytes, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(plaintextBytes), nil
}

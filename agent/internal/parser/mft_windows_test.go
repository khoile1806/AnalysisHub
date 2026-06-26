//go:build windows

package parser

import (
	"os"
	"path/filepath"
	"testing"
)

// known hashes of the literal bytes "hello"
const (
	helloMD5    = "5d41402abc4b2a76b9719d911017c592"
	helloSHA1   = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
	helloSHA256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
)

func TestParseMFT_HashesAndMetadata(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(fp, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	res, err := ParseMFT(dir)
	if err != nil {
		t.Fatalf("ParseMFT: %v", err)
	}

	var got *MFTResult
	for i := range res {
		if res[i].Name == "hello.txt" {
			got = &res[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("hello.txt not found in %d results", len(res))
	}
	if !got.Hashed {
		t.Fatal("file should have been hashed")
	}
	if got.MD5 != helloMD5 || got.SHA1 != helloSHA1 || got.SHA256 != helloSHA256 {
		t.Errorf("hash mismatch:\n md5=%s\n sha1=%s\n sha256=%s", got.MD5, got.SHA1, got.SHA256)
	}
	if got.Size != 5 || got.Ext != ".txt" {
		t.Errorf("metadata wrong: size=%d ext=%s", got.Size, got.Ext)
	}
	if got.Modified.IsZero() {
		t.Error("modified time not populated")
	}
}

func TestParseMFT_FlagsSuspiciousDrop(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, "temp")
	_ = os.MkdirAll(tmp, 0755)
	// invoice.pdf.exe inside a "temp" dir → double-extension + temp-dir flags
	fp := filepath.Join(tmp, "invoice.pdf.exe")
	if err := os.WriteFile(fp, []byte("MZ payload"), 0644); err != nil {
		t.Fatal(err)
	}
	res, err := ParseMFT(dir)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range res {
		if r.Name == "invoice.pdf.exe" {
			found = true
			if len(r.Suspicious) == 0 {
				t.Errorf("expected suspicious flags, got none")
			}
		}
	}
	if !found {
		t.Fatal("dropped exe not found")
	}
}

func TestParseMFT_MissingTarget(t *testing.T) {
	if _, err := ParseMFT(`Z:\definitely\not\here\nope`); err == nil {
		t.Error("expected error for missing target")
	}
}

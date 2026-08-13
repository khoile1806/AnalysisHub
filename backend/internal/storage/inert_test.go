package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// A stored sample must not be the malware's bytes: that is the whole point — the
// host antivirus must not match it, and a stray double-click must not run it.
func TestInertSampleIsNotTheOriginalOnDisk(t *testing.T) {
	s := &LocalStorage{BasePath: t.TempDir()}
	original := append([]byte("MZ\x90\x00\x03"), bytes.Repeat([]byte("This program cannot be run in DOS mode."), 20)...)

	rel, err := s.SaveInertSample("sess-1", "invoice.exe", original)
	if err != nil {
		t.Fatalf("SaveInertSample: %v", err)
	}
	onDisk, err := os.ReadFile(filepath.Join(s.BasePath, rel))
	if err != nil {
		t.Fatalf("read stored file: %v", err)
	}
	if bytes.Contains(onDisk, []byte("MZ\x90\x00")) {
		t.Error("the PE header survived to disk — an AV scan would still match it")
	}
	if bytes.Contains(onDisk, []byte("This program cannot be run in DOS mode.")) {
		t.Error("sample content is stored verbatim")
	}
	if !bytes.HasPrefix(onDisk, []byte(inertMagic)) {
		t.Error("stored file is missing the header that marks it as defanged")
	}

	got, err := s.ReadInertSample(rel)
	if err != nil {
		t.Fatalf("ReadInertSample: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Error("round-trip did not return the original bytes")
	}
}

// The hex viewer reads a window from the middle of a large file; decoding must be
// offset-correct, not just correct for the whole file.
func TestInertRandomAccessMatchesOriginal(t *testing.T) {
	s := &LocalStorage{BasePath: t.TempDir()}
	original := make([]byte, 4096)
	for i := range original {
		original[i] = byte(i % 251)
	}
	rel, err := s.SaveInertSample("sess-2", "blob.bin", original)
	if err != nil {
		t.Fatal(err)
	}
	f, err := s.OpenInertSample(rel)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if f.Size() != int64(len(original)) {
		t.Errorf("Size() = %d, want %d (the header must not be counted)", f.Size(), len(original))
	}
	for _, off := range []int64{0, 1, 1023, 2048, 4000} {
		buf := make([]byte, 64)
		n, _ := f.ReadAt(buf, off)
		want := original[off:min64(off+int64(n), int64(len(original)))]
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("ReadAt(%d) returned the wrong bytes", off)
		}
	}
}

// Tools that only accept a path (the YARA CLI) need a real file; it must contain
// the original bytes and must not outlive the caller.
func TestMaterializeInertGivesRealBytesAndCleansUp(t *testing.T) {
	s := &LocalStorage{BasePath: t.TempDir()}
	original := []byte("MZ this is the payload")
	rel, err := s.SaveInertSample("sess-3", "x.exe", original)
	if err != nil {
		t.Fatal(err)
	}
	path, cleanup, err := s.MaterializeInert(rel)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("materialised file unreadable: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Error("materialised file does not hold the original bytes")
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("materialised sample was left on disk after cleanup")
	}
}

// Rows written before defanging must keep working — an upgrade must not orphan
// the evidence already stored.
func TestInertReadFallsBackToPlainFiles(t *testing.T) {
	s := &LocalStorage{BasePath: t.TempDir()}
	dir := filepath.Join(s.BasePath, "analysis-uploads", "old")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	plain := []byte("legacy sample bytes")
	if err := os.WriteFile(filepath.Join(dir, "old.bin"), plain, 0600); err != nil {
		t.Fatal(err)
	}
	rel := filepath.Join("analysis-uploads", "old", "old.bin")

	got, err := s.ReadInertSample(rel)
	if err != nil || !bytes.Equal(got, plain) {
		t.Errorf("legacy plain file not returned as-is: %v %q", err, got)
	}
	f, err := s.OpenInertSample(rel)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.Size() != int64(len(plain)) {
		t.Errorf("legacy Size() = %d, want %d", f.Size(), len(plain))
	}
	buf := make([]byte, 6)
	n, _ := f.ReadAt(buf, 7)
	if string(buf[:n]) != "sample" {
		t.Errorf("legacy ReadAt returned %q", buf[:n])
	}
}

// Two copies of the same sample must not produce identical stored bytes: a fixed
// key would itself be a signature.
func TestInertKeyVariesPerFile(t *testing.T) {
	s := &LocalStorage{BasePath: t.TempDir()}
	data := bytes.Repeat([]byte("A"), 512)
	relA, _ := s.SaveInertSample("a", "s.bin", data)
	relB, _ := s.SaveInertSample("b", "s.bin", data)
	a, _ := os.ReadFile(filepath.Join(s.BasePath, relA))
	b, _ := os.ReadFile(filepath.Join(s.BasePath, relB))
	if bytes.Equal(a, b) {
		t.Error("two stores of the same sample produced identical files (fixed key?)")
	}
	ra, _ := s.ReadInertSample(relA)
	rb, _ := s.ReadInertSample(relB)
	if !bytes.Equal(ra, data) || !bytes.Equal(rb, data) {
		t.Error("per-file keys broke the round-trip")
	}
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

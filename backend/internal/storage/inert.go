package storage

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// inert.go — storage for samples that are, by definition, live malware.
//
// Writing them to disk verbatim causes two real problems, neither hypothetical:
// the host's own antivirus scans the volume, quarantines or deletes the file and
// the evidence is GONE; and anyone who copies the directory has a runnable
// executable sitting there with its original name. Sandboxes solve this by
// storing samples defanged, and so does this: a short header plus a single-byte
// XOR over the body.
//
// The XOR is obfuscation, not cryptography — that is exactly the intent. It must
// be reversible without key management (the file has to outlive any secret in the
// config), cheap enough to apply to a gigabyte, and seekable so the hex viewer can
// read a window from the middle. What it buys is that the stored bytes are not the
// malware's bytes: no AV signature matches, no double-click runs it.

const (
	inertMagic   = "AHINERT1"
	inertHdrSize = len(inertMagic) + 1 // magic + key byte
)

// SaveInertSample writes potentially-malicious bytes in defanged form under
// analysis-uploads/<sessionID>/<filename>, returning the BasePath-relative path.
func (s *LocalStorage) SaveInertSample(sessionID, filename string, data []byte) (string, error) {
	dir := filepath.Join(s.BasePath, "analysis-uploads", sessionID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("create upload dir for session %s: %w", sessionID, err)
	}
	safe := safeBase(filename)
	dest := filepath.Join(dir, safe)

	var keyBuf [1]byte
	if _, err := rand.Read(keyBuf[:]); err != nil || keyBuf[0] == 0 {
		// A per-file key means two copies of the same sample do not produce the same
		// stored bytes either — a fixed 0xFF is itself a recognisable pattern.
		keyBuf[0] = 0xA7
	}
	out := make([]byte, inertHdrSize+len(data))
	copy(out, inertMagic)
	out[len(inertMagic)] = keyBuf[0]
	for i, b := range data {
		out[inertHdrSize+i] = b ^ keyBuf[0]
	}
	if err := os.WriteFile(dest, out, 0600); err != nil {
		return "", fmt.Errorf("save sample %s: %w", filename, err)
	}
	return filepath.Join("analysis-uploads", sessionID, safe), nil
}

// ReadInertSample returns the ORIGINAL bytes of a stored sample. Files written
// before defanging (or by another feature) are returned as-is, so old rows keep
// working.
func (s *LocalStorage) ReadInertSample(relPath string) ([]byte, error) {
	raw, err := os.ReadFile(s.GetAnalysisUploadPath(relPath))
	if err != nil {
		return nil, err
	}
	return decodeInert(raw), nil
}

// decodeInert reverses the defanging when the header is present.
func decodeInert(raw []byte) []byte {
	if len(raw) < inertHdrSize || string(raw[:len(inertMagic)]) != inertMagic {
		return raw // stored before defanging, or not one of ours
	}
	key := raw[len(inertMagic)]
	out := make([]byte, len(raw)-inertHdrSize)
	for i, b := range raw[inertHdrSize:] {
		out[i] = b ^ key
	}
	return out
}

// InertFile is a random-access reader over a stored sample that hands back the
// ORIGINAL bytes, so a viewer can page through a large file without decoding all
// of it into memory.
type InertFile struct {
	f      *os.File
	key    byte
	offset int64 // where the body starts
	size   int64 // size of the original content
}

// OpenInertSample opens a stored sample for random access.
func (s *LocalStorage) OpenInertSample(relPath string) (*InertFile, error) {
	f, err := os.Open(s.GetAnalysisUploadPath(relPath))
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	hdr := make([]byte, inertHdrSize)
	n, _ := io.ReadFull(f, hdr)
	if n == inertHdrSize && string(hdr[:len(inertMagic)]) == inertMagic {
		return &InertFile{f: f, key: hdr[len(inertMagic)], offset: int64(inertHdrSize),
			size: st.Size() - int64(inertHdrSize)}, nil
	}
	return &InertFile{f: f, key: 0, offset: 0, size: st.Size()}, nil // legacy plain file
}

// Size is the length of the original content.
func (i *InertFile) Size() int64 { return i.size }

// ReadAt reads decoded bytes at an offset in the ORIGINAL content.
func (i *InertFile) ReadAt(p []byte, off int64) (int, error) {
	n, err := i.f.ReadAt(p, off+i.offset)
	if i.key != 0 {
		for k := 0; k < n; k++ {
			p[k] ^= i.key
		}
	}
	return n, err
}

// Close releases the file handle.
func (i *InertFile) Close() error { return i.f.Close() }

// StageInert writes the decoded sample into `dir` under `name`. Used to build a
// scan directory for tools that take one target (the YARA CLI scans a DIRECTORY
// to cover many files in one run), with the file name carrying the scan id so
// hits map back without a second lookup.
func (s *LocalStorage) StageInert(relPath, dir, name string) error {
	data, err := s.ReadInertSample(relPath)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("stored sample is empty")
	}
	return os.WriteFile(filepath.Join(dir, safeBase(name)), data, 0600)
}

// MaterializeInert writes the decoded sample to a temporary file and returns its
// path plus a cleanup function. Needed by tools that only accept a path (the YARA
// CLI, for one) — the defanged copy on disk would never match a rule.
func (s *LocalStorage) MaterializeInert(relPath string) (string, func(), error) {
	data, err := s.ReadInertSample(relPath)
	if err != nil {
		return "", func() {}, err
	}
	tmp, err := os.CreateTemp("", "ah-sample-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() {
		tmp.Close()
		_ = os.Remove(tmp.Name())
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return "", func() {}, err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	// Restrict the window in which a live sample sits on disk in the clear.
	_ = os.Chmod(tmp.Name(), 0600)
	return tmp.Name(), func() { _ = os.Remove(tmp.Name()) }, nil
}

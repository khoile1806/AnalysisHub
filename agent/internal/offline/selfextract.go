package offline

import (
	"archive/zip"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// This file turns the offline agent into a single self-contained, click-to-run
// executable. The server appends a ZIP (bundle.json + tools/) to the end of the
// pre-built agent binary; at startup the agent opens its OWN file as a ZIP,
// extracts the payload to a temp working directory, and points bundleDir() there.
// No installer, no loose files - the user double-clicks one .exe.

var (
	// extractedDir, when set, is the temp directory the embedded bundle was
	// unpacked into. bundleDir() returns it in preference to the exe's folder.
	extractedDir string
)

// SetBundleDir overrides the directory bundleDir() returns (used after the
// embedded payload is extracted to a temp folder).
func SetBundleDir(dir string) { extractedDir = dir }

// HasEmbeddedBundle reports whether this executable carries an appended bundle
// payload (i.e. it is a single self-contained .exe rather than a loose binary
// shipped alongside bundle.json/tools).
func HasEmbeddedBundle() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	zr, err := zip.OpenReader(exe)
	if err != nil {
		return false
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name == "bundle.json" {
			return true
		}
	}
	return false
}

// ExtractEmbeddedBundle unpacks the ZIP appended to this executable into a
// per-binary temp directory and returns that directory. It is idempotent: if the
// directory already holds an extracted bundle.json it is reused (so re-running
// the same .exe is instant). Returns ok=false when the executable has no
// appended payload, in which case the caller keeps the legacy on-disk behaviour.
func ExtractEmbeddedBundle() (dir string, ok bool, err error) {
	exe, eerr := os.Executable()
	if eerr != nil {
		return "", false, eerr
	}
	return extractEmbeddedFrom(exe, filepath.Join(os.TempDir(), "analysishub-offline-"+exeFingerprint(exe)))
}

// extractEmbeddedFrom opens file `path` as a ZIP (Go's reader transparently
// ignores any leading non-ZIP bytes, i.e. the agent executable itself), and if
// it contains bundle.json extracts the whole payload into `target`. Idempotent.
// Factored out of ExtractEmbeddedBundle so the append+read round-trip is testable.
func extractEmbeddedFrom(path, target string) (dir string, ok bool, err error) {
	zr, zerr := zip.OpenReader(path)
	if zerr != nil {
		// Not a self-contained exe (no valid appended ZIP) - legacy mode.
		return "", false, nil //nolint:nilerr // absence of payload is not an error
	}
	defer zr.Close()

	hasBundle := false
	for _, f := range zr.File {
		if f.Name == "bundle.json" {
			hasBundle = true
			break
		}
	}
	if !hasBundle {
		return "", false, nil
	}

	if _, statErr := os.Stat(filepath.Join(target, "bundle.json")); statErr == nil {
		return target, true, nil // already extracted
	}
	if mkErr := os.MkdirAll(target, 0o755); mkErr != nil {
		return "", false, mkErr
	}
	for _, f := range zr.File {
		if err := extractZipEntry(f, target); err != nil {
			return "", false, fmt.Errorf("extract %s: %w", f.Name, err)
		}
	}
	return target, true, nil
}

// extractZipEntry writes one zip entry under destRoot, rejecting path traversal.
func extractZipEntry(f *zip.File, destRoot string) error {
	name := strings.ReplaceAll(f.Name, "\\", "/")
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == "." || strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
		return nil // skip unsafe entries
	}
	dest := filepath.Join(destRoot, clean)
	if !strings.HasPrefix(dest, filepath.Clean(destRoot)+string(os.PathSeparator)) && dest != filepath.Clean(destRoot) {
		return nil
	}
	if f.FileInfo().IsDir() {
		return os.MkdirAll(dest, 0o755)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	// Preserve the executable bit for tool binaries on Unix.
	mode := f.Mode()
	if mode == 0 {
		mode = 0o644
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode|0o200)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, rc)
	return err
}

// exeFingerprint returns a short stable id for the executable from its size and
// modtime - enough to separate different generated bundles in the temp folder.
func exeFingerprint(exe string) string {
	info, err := os.Stat(exe)
	if err != nil {
		return "default"
	}
	h := sha1.Sum([]byte(fmt.Sprintf("%s|%d|%d", filepath.Base(exe), info.Size(), info.ModTime().UnixNano())))
	return hex.EncodeToString(h[:])[:12]
}

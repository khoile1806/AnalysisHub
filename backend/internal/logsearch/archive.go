package logsearch

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// innerFile is an entry extracted from an uploaded archive.
type innerFile struct {
	Path string // absolute path on disk (in the temp dir)
	Name string // original display name inside the archive
}

// IsArchive reports whether an upload is a multi-file archive we should unpack
// and ingest recursively. A plain .gz (a single gzipped log) is NOT an archive —
// it is handled transparently by openText.
func IsArchive(name string) bool {
	n := strings.ToLower(name)
	return strings.HasSuffix(n, ".zip") ||
		strings.HasSuffix(n, ".tar") ||
		strings.HasSuffix(n, ".tgz") ||
		strings.HasSuffix(n, ".tar.gz")
}

// extractArchive unpacks path into destDir (flat, basenames only) and returns
// the extracted files. Directory entries and empty files are skipped.
func extractArchive(path, destDir string) ([]innerFile, error) {
	if strings.HasSuffix(strings.ToLower(path), ".zip") {
		return extractZip(path, destDir)
	}
	return extractTar(path, destDir)
}

func extractZip(path, destDir string) ([]innerFile, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var out []innerFile
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		dest := filepath.Join(destDir, safeName(f.Name))
		if writeStream(dest, rc) == nil {
			out = append(out, innerFile{Path: dest, Name: f.Name})
		}
		rc.Close()
	}
	return out, nil
}

func extractTar(path, destDir string) ([]innerFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var reader io.Reader = f
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".tar.gz") {
		gz, gerr := gzip.NewReader(f)
		if gerr != nil {
			return nil, gerr
		}
		defer gz.Close()
		reader = gz
	}

	tr := tar.NewReader(reader)
	var out []innerFile
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		dest := filepath.Join(destDir, safeName(hdr.Name))
		if writeStream(dest, tr) == nil {
			out = append(out, innerFile{Path: dest, Name: hdr.Name})
		}
	}
	return out, nil
}

// safeName flattens an archive entry path to a unique basename, preventing
// path-traversal (zip-slip) by dropping any directory components.
func safeName(name string) string {
	base := filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	if base == "" || base == "." || base == ".." {
		base = "entry"
	}
	// prefix the parent dir (sanitised) so identical basenames don't collide
	dir := filepath.Dir(strings.ReplaceAll(name, "\\", "/"))
	if dir != "." && dir != "/" && dir != "" {
		base = Sanitize(dir) + "__" + base
	}
	return base
}

func writeStream(dest string, r io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, r)
	return err
}

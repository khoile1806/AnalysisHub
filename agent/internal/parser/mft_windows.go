//go:build windows

package parser

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// MFTResult is a single file-system forensic record. Despite the historical
// "MFT" name, this is a deep file metadata + content-hash collector: for every
// file under the target path it captures the full set of NTFS timestamps
// (created / modified / accessed), attributes, and MD5/SHA-1/SHA-256 hashes so
// an analyst can pivot on indicators and spot timestomping / suspicious drops.
type MFTResult struct {
	FilePath   string    `json:"file_path"`
	Name       string    `json:"name"`
	Ext        string    `json:"ext"`
	Size       int64     `json:"size"`
	IsDir      bool      `json:"is_dir"`
	Created    time.Time `json:"created"`
	Modified   time.Time `json:"mod_time"`
	Accessed   time.Time `json:"accessed"`
	Attributes []string  `json:"attributes"`
	MD5        string    `json:"md5,omitempty"`
	SHA1       string    `json:"sha1,omitempty"`
	SHA256     string    `json:"sha256,omitempty"`
	Hashed     bool      `json:"hashed"`
	Signature  string    `json:"signature,omitempty"` // Signed | Unsigned | Untrusted (executables only)
	Suspicious []string  `json:"suspicious,omitempty"`
}

const (
	// mftMaxEntries caps how many files one scan returns, so a scan rooted at a
	// huge tree can't produce an unbounded payload (which would blow the agent
	// WebSocket frame size limit and overwhelm the browser table).
	mftMaxEntries = 15000
	// mftMaxHashBytes caps per-file hashing. Files larger than this are listed
	// with full metadata but Hashed=false (reading multi-GB files is wasteful).
	mftMaxHashBytes int64 = 64 << 20 // 64 MB
	// mftMaxHashFiles / mftMaxTotalHashBytes bound the TOTAL hashing work so a
	// scan of a large tree (e.g. C:\Windows\System32) completes in seconds
	// instead of reading gigabytes and timing the request out. Once either
	// budget is exhausted the remaining files are still listed (full metadata)
	// but with Hashed=false.
	mftMaxHashFiles            = 6000
	mftMaxTotalHashBytes int64 = 1 << 30 // ~1 GB
)

// suspiciousDirs are path fragments where an executable/script is unusual and
// often indicates a dropped payload. Matched case-insensitively.
var suspiciousDirs = []string{
	`\temp\`, `\tmp\`, `\appdata\local\temp\`, `\appdata\roaming\`,
	`\programdata\`, `\users\public\`, `\downloads\`, `$recycle.bin`,
	`\perflogs\`, `\windows\temp\`,
}

var execExts = map[string]bool{
	".exe": true, ".dll": true, ".scr": true, ".bat": true, ".cmd": true,
	".ps1": true, ".vbs": true, ".js": true, ".jar": true, ".hta": true,
	".com": true, ".pif": true, ".msi": true, ".sys": true, ".cpl": true,
}

var lureExts = map[string]bool{
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
	".jpg": true, ".jpeg": true, ".png": true, ".txt": true, ".rtf": true,
	".ppt": true, ".pptx": true,
}

// ParseMFT walks target (default C:\Windows\System32 when empty), returning a
// rich forensic record per file. Runs in the UAC-elevated child process so it
// can read protected directories.
func ParseMFT(target string) ([]MFTResult, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		target = `C:\Windows\System32`
	}
	// Reject obviously bad input early.
	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("cannot access target %q: %v", target, err)
	}

	results := make([]MFTResult, 0, 1024)
	var hashedFiles int
	var hashedBytes int64

	add := func(path string, d fs.DirEntry) {
		fi, statErr := d.Info()
		if statErr != nil {
			return
		}
		rec := MFTResult{
			FilePath: path,
			Name:     fi.Name(),
			Size:     fi.Size(),
			IsDir:    fi.IsDir(),
			Modified: fi.ModTime().UTC(),
		}
		if !rec.IsDir {
			rec.Ext = strings.ToLower(filepath.Ext(path))
		}

		// NTFS timestamps + attributes from the Win32 stat data.
		if wd, ok := fi.Sys().(*syscall.Win32FileAttributeData); ok {
			rec.Created = time.Unix(0, wd.CreationTime.Nanoseconds()).UTC()
			rec.Accessed = time.Unix(0, wd.LastAccessTime.Nanoseconds()).UTC()
			rec.Attributes = decodeAttributes(wd.FileAttributes)
		}

		// Content hashes for regular, reasonably-sized files — bounded by the
		// per-file size cap AND the total file/byte budget so the scan stays fast.
		if !rec.IsDir && rec.Size > 0 && rec.Size <= mftMaxHashBytes &&
			hashedFiles < mftMaxHashFiles && hashedBytes < mftMaxTotalHashBytes {
			if md5h, sha1h, sha256h, herr := hashFile(path); herr == nil {
				rec.MD5, rec.SHA1, rec.SHA256, rec.Hashed = md5h, sha1h, sha256h, true
				hashedFiles++
				hashedBytes += rec.Size
			}
		}

		// Authenticode status for executables (embedded + catalog). Restricted to
		// exec extensions so the catalog lookups don't slow a broad file walk.
		if !rec.IsDir && execExts[rec.Ext] && rec.Size > 0 {
			rec.Signature = fileSignatureStatus(path)
		}

		rec.Suspicious = flagSuspicious(path, rec.Ext, rec.Attributes)
		if rec.Signature == "Untrusted" {
			rec.Suspicious = append(rec.Suspicious, "untrusted signature")
		}
		results = append(results, rec)
	}

	// Single file target.
	if !info.IsDir() {
		add(target, fs.FileInfoToDirEntry(info))
		return results, nil
	}

	walkErr := filepath.WalkDir(target, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries, keep going
		}
		if len(results) >= mftMaxEntries {
			return filepath.SkipAll
		}
		add(path, d)
		return nil
	})
	if walkErr != nil && len(results) == 0 {
		return nil, walkErr
	}
	return results, nil
}

// hashFile computes MD5, SHA-1 and SHA-256 in a single streaming pass.
func hashFile(path string) (md5hex, sha1hex, sha256hex string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", "", err
	}
	defer f.Close()
	m, s1, s256 := md5.New(), sha1.New(), sha256.New()
	if _, err = io.Copy(io.MultiWriter(m, s1, s256), f); err != nil {
		return "", "", "", err
	}
	return hex.EncodeToString(m.Sum(nil)),
		hex.EncodeToString(s1.Sum(nil)),
		hex.EncodeToString(s256.Sum(nil)), nil
}

// decodeAttributes turns the Win32 attribute bitmask into readable flags.
func decodeAttributes(attr uint32) []string {
	type bit struct {
		mask uint32
		name string
	}
	bits := []bit{
		{0x00000001, "ReadOnly"},
		{0x00000002, "Hidden"},
		{0x00000004, "System"},
		{0x00000020, "Archive"},
		{0x00000040, "Device"},
		{0x00000100, "Temporary"},
		{0x00000200, "Sparse"},
		{0x00000400, "ReparsePoint"},
		{0x00000800, "Compressed"},
		{0x00001000, "Offline"},
		{0x00004000, "Encrypted"},
	}
	out := make([]string, 0, 4)
	for _, b := range bits {
		if attr&b.mask != 0 {
			out = append(out, b.name)
		}
	}
	return out
}

// flagSuspicious returns human-readable reasons a file looks noteworthy.
func flagSuspicious(path, ext string, attrs []string) []string {
	var reasons []string
	lower := strings.ToLower(path)
	isExec := execExts[ext]

	if isExec {
		for _, frag := range suspiciousDirs {
			if strings.Contains(lower, frag) {
				reasons = append(reasons, "executable in "+strings.Trim(frag, `\`))
				break
			}
		}
	}

	// Double extension lure, e.g. invoice.pdf.exe
	name := strings.ToLower(filepath.Base(path))
	if isExec {
		for lure := range lureExts {
			if strings.Contains(name, lure+".") {
				reasons = append(reasons, "double extension ("+lure+"+"+ext+")")
				break
			}
		}
	}

	// Hidden / system executable.
	if isExec {
		for _, a := range attrs {
			if a == "Hidden" {
				reasons = append(reasons, "hidden executable")
				break
			}
		}
	}
	return reasons
}

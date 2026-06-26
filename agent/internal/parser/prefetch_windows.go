//go:build windows

package parser

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

// PrefetchResult is a parsed Windows prefetch (.pf) record. It carries the real
// execution evidence decoded from the binary file — run count and the last-run
// timestamps — plus content hashes of the .pf artifact itself.
type PrefetchResult struct {
	Executable   string      `json:"executable"`
	RunCount     int         `json:"run_count"`
	LastRunTime  time.Time   `json:"last_run_time"`
	LastRunTimes []time.Time `json:"last_run_times,omitempty"`
	PrefetchHash string      `json:"hash"`
	Version      string      `json:"version"`
	Compressed   bool        `json:"compressed"`
	PrefetchFile string      `json:"prefetch_file"`
	Size         int64       `json:"size"`
	MD5          string      `json:"md5"`
	SHA256       string      `json:"sha256"`
	PfModTime    time.Time   `json:"pf_mod_time"`
	Parsed       bool        `json:"parsed"`
	Suspicious   bool        `json:"suspicious"`

	// Resolved executable: the .pf references the target binary's full path, which
	// we resolve on disk and hash — this is the real, IOC-usable content hash of
	// the program that ran (the prefetch hash above is only a 32-bit path hash).
	ExePath   string `json:"exe_path,omitempty"`
	ExeMD5    string `json:"exe_md5,omitempty"`
	ExeSHA256 string `json:"exe_sha256,omitempty"`
	ExeHashed bool   `json:"exe_hashed"`
}

var pfSuspicious = []string{
	"mimikatz", "pwdump", "wce", "gsecdump", "procdump", "nc.exe", "ncat",
	"netcat", "nmap", "psexec", "paexec", "cobalt", "rundll32", "regsvr32",
	"mshta", "certutil", "bitsadmin", "wmic", "powershell", "cscript", "wscript",
}

// ParsePrefetch reads C:\Windows\Prefetch and decodes every .pf file. Runs in
// the UAC-elevated child so it can read the protected Prefetch directory.
func ParsePrefetch() ([]PrefetchResult, error) {
	dir := `C:\Windows\Prefetch`
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read prefetch directory (requires admin): %v", err)
	}

	results := make([]PrefetchResult, 0, len(entries))
	exeHashBudget := int64(1 << 30) // ~1 GB total spent hashing referenced executables
	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".pf") {
			continue
		}
		info, ierr := entry.Info()
		if ierr != nil {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			continue
		}

		name := entry.Name()
		res := PrefetchResult{
			PrefetchFile: name,
			Size:         info.Size(),
			PfModTime:    info.ModTime().UTC(),
			MD5:          md5hex(raw),
			SHA256:       sha256hex(raw),
		}

		// Executable name + prefetch hash from the filename (CMD.EXE-087B4001.pf).
		if parts := strings.Split(name, "-"); len(parts) > 1 {
			res.Executable = parts[0]
			res.PrefetchHash = strings.TrimSuffix(strings.ToUpper(parts[len(parts)-1]), ".PF")
		} else {
			res.Executable = strings.TrimSuffix(name, filepath.Ext(name))
		}

		// Decode the binary body for the real execution evidence (+ exe NT path).
		decodePrefetchBody(raw, &res)

		// Resolve the referenced executable on disk and hash it — the real
		// content hash of the program that ran. Bounded by a shared byte budget
		// so a Prefetch dir full of large binaries can't stall the request.
		resolveExeHash(&res, &exeHashBudget)

		// Fall back to the .pf mtime when the binary parse couldn't recover a
		// run time (still a decent "last seen executing" proxy).
		if res.LastRunTime.IsZero() {
			res.LastRunTime = res.PfModTime
		}

		lower := strings.ToLower(res.Executable)
		for _, s := range pfSuspicious {
			if strings.Contains(lower, s) {
				res.Suspicious = true
				break
			}
		}
		results = append(results, res)
	}
	return results, nil
}

// decodePrefetchBody fills Version / RunCount / LastRunTimes from the .pf binary,
// transparently decompressing the Win8+ MAM (XPRESS-Huffman) container first.
// It is defensive: any malformed field is skipped rather than producing garbage.
func decodePrefetchBody(raw []byte, res *PrefetchResult) {
	buf := raw
	if len(raw) >= 8 && string(raw[0:3]) == "MAM" {
		res.Compressed = true
		uncompressedSize := binary.LittleEndian.Uint32(raw[4:8])
		if uncompressedSize == 0 || uncompressedSize > 64<<20 {
			return
		}
		dec, err := xpressHuffmanDecompress(raw[8:], uncompressedSize)
		if err != nil {
			return
		}
		buf = dec
	}

	// Must be an uncompressed SCCA stream now: version(4) + "SCCA".
	if len(buf) < 0x100 || string(buf[4:8]) != "SCCA" {
		return
	}
	version := binary.LittleEndian.Uint32(buf[0:4])

	// Offsets of the "last run time" array and "run count" field within the .pf
	// (absolute, after the 84-byte header). These are the well-documented values
	// for each format version. We validate every decoded value, so an off layout
	// degrades gracefully to "no run history" instead of bogus data.
	var runTimeOff, runCountOff int
	var runTimeCount int
	switch version {
	case 30, 31: // Windows 10 / 11
		res.Version = "Windows 10/11"
		runTimeOff, runTimeCount, runCountOff = 0x80, 8, 0xD0
	case 26: // Windows 8.1
		res.Version = "Windows 8.1"
		runTimeOff, runTimeCount, runCountOff = 0x80, 8, 0xC8
	case 23: // Windows Vista / 7
		res.Version = "Windows Vista/7"
		runTimeOff, runTimeCount, runCountOff = 0x80, 1, 0x98
	case 17: // Windows XP / 2003
		res.Version = "Windows XP/2003"
		runTimeOff, runTimeCount, runCountOff = 0x78, 1, 0x90
	default:
		res.Version = fmt.Sprintf("v%d", version)
		res.Parsed = true
		return
	}

	// Last run times.
	for i := 0; i < runTimeCount; i++ {
		off := runTimeOff + i*8
		if off+8 > len(buf) {
			break
		}
		ft := binary.LittleEndian.Uint64(buf[off : off+8])
		t := filetimeToTime(ft)
		if t.IsZero() {
			continue
		}
		res.LastRunTimes = append(res.LastRunTimes, t)
	}
	if len(res.LastRunTimes) > 0 {
		res.LastRunTime = res.LastRunTimes[0]
	}

	// Run count.
	if runCountOff+4 <= len(buf) {
		rc := binary.LittleEndian.Uint32(buf[runCountOff : runCountOff+4])
		if rc > 0 && rc < 1_000_000 {
			res.RunCount = int(rc)
		}
	}

	// Filename strings section (referenced files incl. the main executable). The
	// "filename strings offset/size" fields sit at a fixed position within the
	// file-information block (which begins at 0x54) for every modern version.
	if len(buf) >= 0x6C {
		fnOff := binary.LittleEndian.Uint32(buf[0x64:0x68])
		fnSize := binary.LittleEndian.Uint32(buf[0x68:0x6C])
		if fnOff > 0 && fnSize > 0 && int(fnOff)+int(fnSize) <= len(buf) && fnSize < 8<<20 {
			res.ExePath = extractMainExePath(buf[fnOff:int(fnOff)+int(fnSize)], res.Executable)
		}
	}
	res.Parsed = true
}

// extractMainExePath finds the referenced path whose basename matches exeName
// in the prefetch filename-strings block (UTF-16LE, NUL-terminated entries).
// Returns the raw NT device path (e.g. \VOLUME{...}\Windows\System32\cmd.exe).
func extractMainExePath(block []byte, exeName string) string {
	target := strings.ToUpper(strings.TrimSpace(exeName))
	if target == "" {
		return ""
	}
	var fallback string
	for i := 0; i+1 < len(block); {
		j := i
		for j+1 < len(block) && !(block[j] == 0 && block[j+1] == 0) {
			j += 2
		}
		if j <= i {
			break
		}
		u16 := make([]uint16, (j-i)/2)
		for k := range u16 {
			u16[k] = binary.LittleEndian.Uint16(block[i+2*k:])
		}
		s := strings.TrimRight(string(utf16.Decode(u16)), "\x00")
		i = j + 2
		if s == "" || !strings.Contains(s, "\\") {
			continue
		}
		up := strings.ToUpper(s)
		base := up
		if idx := strings.LastIndexByte(up, '\\'); idx >= 0 {
			base = up[idx+1:]
		}
		if base == target {
			return s // exact basename match — the main executable
		}
		if fallback == "" && strings.HasSuffix(up, "\\"+target) {
			fallback = s
		}
	}
	return fallback
}

// pfMaxExeHashBytes caps the size of a referenced executable we will hash, so a
// single huge binary can't dominate the scan.
const pfMaxExeHashBytes int64 = 64 << 20 // 64 MB

// resolveExeHash converts the referenced executable's NT path to a drive path,
// then hashes the file on disk. Best-effort: when the file is located it sets
// ExePath; it only computes hashes while the shared byte budget remains and the
// file is within the per-file cap. Leaves hashes empty (keeping the path) when
// the file can't be located, is too large, or the budget is exhausted.
func resolveExeHash(res *PrefetchResult, budget *int64) {
	nt := res.ExePath
	if nt == "" {
		return
	}
	tail := ntPathTail(nt)
	if tail == "" {
		return // unknown volume form — keep NT path, no hash
	}
	for _, drive := range fixedDriveLetters() {
		cand := drive + tail
		fi, err := os.Stat(cand)
		if err != nil || fi.IsDir() {
			continue
		}
		res.ExePath = cand // resolved on disk
		if fi.Size() > 0 && fi.Size() <= pfMaxExeHashBytes && *budget > 0 {
			if md5h, _, sha256h, herr := hashFile(cand); herr == nil {
				res.ExeMD5 = md5h
				res.ExeSHA256 = sha256h
				res.ExeHashed = true
				*budget -= fi.Size()
			}
		}
		return
	}
	// Unresolved: keep the NT path so the analyst still sees the referenced path.
}

// ntPathTail strips the volume/device prefix from an NT path, leaving the
// drive-relative remainder (e.g. "\Windows\System32\cmd.exe").
func ntPathTail(nt string) string {
	up := strings.ToUpper(nt)
	switch {
	case strings.HasPrefix(up, `\VOLUME{`):
		if idx := strings.IndexByte(nt, '}'); idx >= 0 && idx+1 <= len(nt) {
			return nt[idx+1:]
		}
	case strings.HasPrefix(up, `\DEVICE\HARDDISKVOLUME`):
		rest := nt[len(`\DEVICE\HARDDISKVOLUME`):]
		k := 0
		for k < len(rest) && rest[k] >= '0' && rest[k] <= '9' {
			k++
		}
		return rest[k:]
	case strings.HasPrefix(nt, `\`):
		return nt
	}
	return ""
}

// fixedDriveLetters returns drive roots that currently exist, C: first since the
// system volume is the overwhelmingly common case.
func fixedDriveLetters() []string {
	out := make([]string, 0, 4)
	for _, d := range "CDEFGHIJABKLMNOPQRSTUVWXYZ" {
		root := string(d) + `:\`
		if _, err := os.Stat(root); err == nil {
			out = append(out, string(d)+":")
		}
	}
	return out
}

// filetimeToTime converts a Windows FILETIME (100-ns ticks since 1601) to a
// time.Time, returning the zero time for values outside a plausible range.
func filetimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const ticksPerSecond = 10_000_000
	const epochDiff = 11_644_473_600 // seconds between 1601-01-01 and 1970-01-01
	sec := int64(ft)/ticksPerSecond - epochDiff
	nsec := (int64(ft) % ticksPerSecond) * 100
	t := time.Unix(sec, nsec).UTC()
	// Plausibility guard: drop clearly-bogus timestamps from a bad offset.
	if t.Year() < 2000 || t.Year() > time.Now().UTC().Year()+1 {
		return time.Time{}
	}
	return t
}

// ── XPRESS-Huffman (MAM) decompression via ntdll ────────────────────────────
var (
	ntdll                              = syscall.NewLazyDLL("ntdll.dll")
	procRtlGetCompressionWorkSpaceSize = ntdll.NewProc("RtlGetCompressionWorkSpaceSize")
	procRtlDecompressBufferEx          = ntdll.NewProc("RtlDecompressBufferEx")
)

const compressionFormatXpressHuffman = 0x0004

func xpressHuffmanDecompress(compressed []byte, uncompressedSize uint32) ([]byte, error) {
	if len(compressed) == 0 {
		return nil, fmt.Errorf("empty compressed buffer")
	}
	var workSpaceSize, fragmentSize uint32
	r, _, _ := procRtlGetCompressionWorkSpaceSize.Call(
		uintptr(compressionFormatXpressHuffman),
		uintptr(unsafe.Pointer(&workSpaceSize)),
		uintptr(unsafe.Pointer(&fragmentSize)),
	)
	if r != 0 {
		return nil, fmt.Errorf("RtlGetCompressionWorkSpaceSize: 0x%x", r)
	}
	workspace := make([]byte, workSpaceSize)
	out := make([]byte, uncompressedSize)
	var finalSize uint32
	r, _, _ = procRtlDecompressBufferEx.Call(
		uintptr(compressionFormatXpressHuffman),
		uintptr(unsafe.Pointer(&out[0])), uintptr(uncompressedSize),
		uintptr(unsafe.Pointer(&compressed[0])), uintptr(len(compressed)),
		uintptr(unsafe.Pointer(&finalSize)),
		uintptr(unsafe.Pointer(&workspace[0])),
	)
	if r != 0 {
		return nil, fmt.Errorf("RtlDecompressBufferEx: 0x%x", r)
	}
	return out[:finalSize], nil
}

func md5hex(b []byte) string    { s := md5.Sum(b); return hex.EncodeToString(s[:]) }
func sha256hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

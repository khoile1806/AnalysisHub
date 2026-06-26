//go:build windows

package parser

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows/registry"
)

// ScanShimcache parses the AppCompatCache (Shimcache) — the Windows 10/11
// execution-evidence artifact at
// HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache. Each
// record names a binary the OS saw (run or present) plus its file modified time,
// complementing Prefetch for execution triage. Requires elevation (SYSTEM key).
func ScanShimcache() ([]ShimEntry, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`,
		registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return nil, fmt.Errorf("open AppCompatCache key: %w", err)
	}
	defer k.Close()

	buf, _, err := k.GetBinaryValue("AppCompatCache")
	if err != nil {
		return nil, fmt.Errorf("read AppCompatCache value: %w", err)
	}
	return parseShimcacheWin10(buf), nil
}

// parseShimcacheWin10 decodes the Windows 10/11 AppCompatCache format. The first
// DWORD is the offset to the first "10ts"-tagged entry; entries then follow back
// to back until the magic no longer matches.
func parseShimcacheWin10(b []byte) []ShimEntry {
	if len(b) < 48 {
		return nil
	}
	off := int(binary.LittleEndian.Uint32(b[0:4]))
	if off <= 0 || off >= len(b) {
		off = 48 // fall back to the common Win10 header size
	}

	var out []ShimEntry
	for off+12 <= len(b) {
		if string(b[off:off+4]) != "10ts" {
			break
		}
		// off+4: 4 unused bytes; off+8: size of the remainder of this entry.
		ceSize := int(binary.LittleEndian.Uint32(b[off+8 : off+12]))
		body := off + 12
		if ceSize <= 0 || body+ceSize > len(b) {
			break
		}
		p := body
		if p+2 > len(b) {
			break
		}
		pathLen := int(binary.LittleEndian.Uint16(b[p : p+2]))
		p += 2
		if pathLen < 0 || p+pathLen > len(b) {
			break
		}
		path := decodeUTF16LE(b[p : p+pathLen])
		p += pathLen

		var modified string
		if p+8 <= len(b) {
			if ft := binary.LittleEndian.Uint64(b[p : p+8]); ft > 0 {
				modified = filetimeToISO(ft)
			}
		}

		path = strings.TrimPrefix(path, `\??\`)
		e := ShimEntry{Path: path, Name: filepath.Base(path), LastModified: modified}
		e.Suspicious = flagShim(path)
		out = append(out, e)

		off = body + ceSize
	}
	return out
}

func flagShim(path string) []string {
	lp := strings.ToLower(path)
	for _, frag := range suspiciousDirs {
		if strings.Contains(lp, frag) {
			return []string{"path in " + strings.Trim(frag, `\`)}
		}
	}
	return nil
}

func decodeUTF16LE(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, binary.LittleEndian.Uint16(b[i:i+2]))
	}
	return string(utf16.Decode(u))
}

func filetimeToISO(ft uint64) string {
	const epochDiff = 116444736000000000 // 100ns between 1601-01-01 and 1970-01-01
	if ft < epochDiff {
		return ""
	}
	nsec := int64(ft-epochDiff) * 100
	return time.Unix(0, nsec).UTC().Format(time.RFC3339)
}

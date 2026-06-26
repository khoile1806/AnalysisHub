//go:build windows

package parser

import (
	"encoding/binary"
	"testing"
	"time"
	"unicode/utf16"
)

func TestFiletimeToTime(t *testing.T) {
	want := time.Date(2023, 5, 1, 12, 0, 0, 0, time.UTC)
	const epochDiff = 11_644_473_600
	ft := uint64(want.Unix()+epochDiff) * 10_000_000
	got := filetimeToTime(ft)
	if !got.Equal(want) {
		t.Errorf("filetimeToTime = %v, want %v", got, want)
	}
	// Zero and implausible values must collapse to the zero time.
	if !filetimeToTime(0).IsZero() {
		t.Error("ft=0 should be zero time")
	}
	if !filetimeToTime(1).IsZero() {
		t.Error("implausible 1601-era ft should be rejected")
	}
}

// decodePrefetchBody offset logic — build a synthetic uncompressed v30 (.pf)
// stream and confirm version / run count / last-run time are decoded at the
// documented offsets.
func TestDecodePrefetchBody_V30(t *testing.T) {
	buf := make([]byte, 0x200)
	binary.LittleEndian.PutUint32(buf[0:4], 30) // version 30 = Win10/11
	copy(buf[4:8], []byte("SCCA"))

	lastRun := time.Date(2024, 2, 3, 9, 30, 0, 0, time.UTC)
	const epochDiff = 11_644_473_600
	ft := uint64(lastRun.Unix()+epochDiff) * 10_000_000
	binary.LittleEndian.PutUint64(buf[0x80:0x88], ft) // first last-run time
	binary.LittleEndian.PutUint32(buf[0xD0:0xD4], 7)  // run count

	var res PrefetchResult
	decodePrefetchBody(buf, &res)

	if !res.Parsed {
		t.Fatal("expected Parsed=true")
	}
	if res.Version != "Windows 10/11" {
		t.Errorf("version = %q, want Windows 10/11", res.Version)
	}
	if res.RunCount != 7 {
		t.Errorf("run count = %d, want 7", res.RunCount)
	}
	if !res.LastRunTime.Equal(lastRun) {
		t.Errorf("last run = %v, want %v", res.LastRunTime, lastRun)
	}
	if len(res.LastRunTimes) != 1 {
		t.Errorf("expected 1 valid last-run time, got %d", len(res.LastRunTimes))
	}
}

func TestDecodePrefetchBody_RejectsNonSCCA(t *testing.T) {
	buf := make([]byte, 0x200) // all zero — no SCCA signature
	var res PrefetchResult
	decodePrefetchBody(buf, &res)
	if res.Parsed {
		t.Error("non-SCCA buffer should not be marked parsed")
	}
}

// utf16Block encodes paths as a NUL-terminated UTF-16LE concatenation, like the
// prefetch filename-strings section.
func utf16Block(paths ...string) []byte {
	var out []byte
	for _, p := range paths {
		for _, r := range utf16.Encode([]rune(p)) {
			b := []byte{byte(r), byte(r >> 8)}
			out = append(out, b...)
		}
		out = append(out, 0, 0) // NUL terminator
	}
	return out
}

func TestExtractMainExePath(t *testing.T) {
	block := utf16Block(
		`\VOLUME{01d-abc}\WINDOWS\SYSTEM32\NTDLL.DLL`,
		`\VOLUME{01d-abc}\WINDOWS\SYSTEM32\CMD.EXE`,
		`\VOLUME{01d-abc}\WINDOWS\SYSTEM32\KERNEL32.DLL`,
	)
	got := extractMainExePath(block, "CMD.EXE")
	want := `\VOLUME{01d-abc}\WINDOWS\SYSTEM32\CMD.EXE`
	if got != want {
		t.Errorf("extractMainExePath = %q, want %q", got, want)
	}
	if extractMainExePath(block, "NOTHERE.EXE") != "" {
		t.Error("expected empty for absent executable")
	}
}

func TestNtPathTail(t *testing.T) {
	cases := map[string]string{
		`\VOLUME{01d-abc}\Windows\System32\cmd.exe`:        `\Windows\System32\cmd.exe`,
		`\DEVICE\HARDDISKVOLUME2\Windows\System32\cmd.exe`: `\Windows\System32\cmd.exe`,
		`\Windows\System32\cmd.exe`:                        `\Windows\System32\cmd.exe`,
		`C:\plain\path`:                                    ``, // no NT prefix, not leading backslash
	}
	for in, want := range cases {
		if got := ntPathTail(in); got != want {
			t.Errorf("ntPathTail(%q) = %q, want %q", in, got, want)
		}
	}
}

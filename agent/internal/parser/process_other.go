//go:build !windows

package parser

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ProcessRec mirrors the Windows definition so JSON consumers compile on every
// platform. On Linux it is populated from /proc; on other Unixes (no /proc) the
// scan returns an empty set.
type ProcessRec struct {
	PID        int      `json:"pid"`
	PPID       int      `json:"ppid"`
	Name       string   `json:"name"`
	ParentName string   `json:"parent_name"`
	Path       string   `json:"path"`
	Cmdline    string   `json:"cmdline"`
	User       string   `json:"user"`
	MemKB      int      `json:"mem_kb"`
	Created    string   `json:"created"`
	MD5        string   `json:"md5,omitempty"`
	SHA256     string   `json:"sha256,omitempty"`
	Hashed     bool     `json:"hashed"`
	Suspicious []string `json:"suspicious,omitempty"`
}

// ScanProcesses builds a running-process snapshot from /proc (Linux). Hashing is
// skipped for speed/robustness (Hashed=false). Returns an empty set where /proc
// is unavailable (e.g. macOS) rather than erroring, so triage stays usable.
func ScanProcesses() ([]ProcessRec, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return []ProcessRec{}, nil
	}

	uidNames := passwdUIDMap()
	btime := bootTime()
	const clkTck = 100 // sysconf(_SC_CLK_TCK) is 100 on stock Linux kernels

	recs := []ProcessRec{}
	byPID := map[int]int{} // pid → index in recs
	for _, e := range entries {
		pid, perr := strconv.Atoi(e.Name())
		if perr != nil || !e.IsDir() {
			continue
		}
		base := filepath.Join("/proc", e.Name())

		status := readKVFile(filepath.Join(base, "status"))
		name := status["Name"]
		ppid, _ := strconv.Atoi(firstField(status["PPid"]))
		uid := firstField(status["Uid"])
		memKB := 0
		if v := firstField(status["VmRSS"]); v != "" {
			memKB, _ = strconv.Atoi(v)
		}

		exe, _ := os.Readlink(filepath.Join(base, "exe"))
		cmdline := readCmdline(filepath.Join(base, "cmdline"))
		if name == "" {
			if exe != "" {
				name = filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
			} else if cmdline != "" {
				name = filepath.Base(strings.Fields(cmdline)[0])
			}
		}

		created := ""
		if st := procStartTime(filepath.Join(base, "stat")); st > 0 && btime > 0 {
			created = time.Unix(btime+st/clkTck, 0).UTC().Format(time.RFC3339)
		}

		user := uidNames[uid]
		if user == "" {
			user = uid
		}
		recs = append(recs, ProcessRec{
			PID: pid, PPID: ppid, Name: name, Path: exe,
			Cmdline: cmdline, User: user, MemKB: memKB, Created: created,
			Suspicious: flagLinuxProc(exe, cmdline),
		})
		byPID[pid] = len(recs) - 1
	}

	// Second pass: resolve parent names now that all PIDs are indexed.
	for i := range recs {
		if idx, ok := byPID[recs[i].PPID]; ok {
			recs[i].ParentName = recs[idx].Name
		}
	}
	return recs, nil
}

// procStartTime returns field 22 (starttime, in clock ticks) from /proc/pid/stat.
// The comm field (2) is parenthesised and may contain spaces/parens, so we split
// after the final ')'.
func procStartTime(statPath string) int64 {
	b, err := os.ReadFile(statPath)
	if err != nil {
		return 0
	}
	s := string(b)
	rp := strings.LastIndex(s, ")")
	if rp < 0 {
		return 0
	}
	fields := strings.Fields(s[rp+1:]) // fields[0]=state(3) … fields[k]=field(3+k)
	if len(fields) < 20 {              // need field 22 → index 19
		return 0
	}
	v, _ := strconv.ParseInt(fields[19], 10, 64)
	return v
}

func flagLinuxProc(exe, cmdline string) []string {
	var f []string
	if strings.Contains(exe, "(deleted)") {
		f = append(f, "deleted-binary")
	}
	low := strings.ToLower(exe)
	for _, d := range []string{"/tmp/", "/dev/shm/", "/var/tmp/", "/run/"} {
		if strings.HasPrefix(low, d) {
			f = append(f, "exec-from-world-writable")
			break
		}
	}
	return f
}

// ── small /proc helpers (shared by the Linux netconn / dlls collectors too) ──

func readKVFile(path string) map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.IndexByte(line, ':'); i > 0 {
			m[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
		}
	}
	return m
}

func readCmdline(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
}

func firstField(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// passwdUIDMap maps uid → username from /etc/passwd.
func passwdUIDMap() map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return m
	}
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) >= 3 {
			m[parts[2]] = parts[0]
		}
	}
	return m
}

// bootTime returns the system boot time (unix seconds) from /proc/stat btime.
func bootTime() int64 {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "btime ") {
			v, _ := strconv.ParseInt(strings.TrimSpace(line[6:]), 10, 64)
			return v
		}
	}
	return 0
}

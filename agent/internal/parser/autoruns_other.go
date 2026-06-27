//go:build !windows

package parser

import (
	"os"
	"path/filepath"
	"strings"
)

// AutorunEntry mirrors the Windows definition so JSON consumers compile on every
// platform. On Linux it enumerates the common persistence locations (systemd,
// cron, rc.local, XDG autostart, shell init files).
type AutorunEntry struct {
	Category   string   `json:"category"`
	Name       string   `json:"name"`
	Location   string   `json:"location"`
	Command    string   `json:"command"`
	ImagePath  string   `json:"image_path"`
	User       string   `json:"user,omitempty"`
	Enabled    bool     `json:"enabled"`
	MD5        string   `json:"md5,omitempty"`
	SHA256     string   `json:"sha256,omitempty"`
	Hashed     bool     `json:"hashed"`
	Signature  string   `json:"signature,omitempty"`
	Suspicious []string `json:"suspicious,omitempty"`
}

// ScanAutoruns enumerates Linux persistence/autostart locations. Returns an
// empty set (not an error) on platforms without these paths so triage stays
// usable on macOS.
func ScanAutoruns() ([]AutorunEntry, error) {
	out := []AutorunEntry{}
	out = append(out, scanSystemd()...)
	out = append(out, scanCron()...)
	out = append(out, scanRcAndProfile()...)
	out = append(out, scanXDGAutostart()...)
	return out, nil
}

// ── systemd ──────────────────────────────────────────────────────────────────
func scanSystemd() []AutorunEntry {
	enabled := enabledUnits()
	var out []AutorunEntry
	dirs := []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"}
	if h, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(h, ".config", "systemd", "user"))
	}
	seen := map[string]bool{}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			n := e.Name()
			if e.IsDir() || !strings.HasSuffix(n, ".service") || seen[n] {
				continue
			}
			seen[n] = true
			full := filepath.Join(dir, n)
			cmd := iniValue(full, "ExecStart")
			if cmd == "" {
				continue
			}
			out = append(out, AutorunEntry{
				Category: "systemd", Name: n, Location: full,
				Command: cmd, ImagePath: binOf(cmd), Enabled: enabled[n],
				Suspicious: flagPersist(cmd),
			})
		}
	}
	return out
}

// enabledUnits collects unit names symlinked under any *.wants directory.
func enabledUnits() map[string]bool {
	en := map[string]bool{}
	for _, root := range []string{"/etc/systemd/system", "/etc/systemd/user"} {
		wants, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, w := range wants {
			if !strings.HasSuffix(w.Name(), ".wants") {
				continue
			}
			links, _ := os.ReadDir(filepath.Join(root, w.Name()))
			for _, l := range links {
				en[l.Name()] = true
			}
		}
	}
	return en
}

// ── cron ─────────────────────────────────────────────────────────────────────
func scanCron() []AutorunEntry {
	var out []AutorunEntry

	// System crontab + drop-ins: "m h dom mon dow USER command".
	for _, f := range append([]string{"/etc/crontab"}, globDir("/etc/cron.d")...) {
		for _, line := range cronLines(f) {
			fields := strings.Fields(line)
			if len(fields) < 7 {
				continue
			}
			user := fields[5]
			cmd := strings.Join(fields[6:], " ")
			out = append(out, AutorunEntry{
				Category: "cron", Name: filepath.Base(f), Location: f,
				Command: cmd, ImagePath: binOf(cmd), User: user, Enabled: true,
				Suspicious: flagPersist(cmd),
			})
		}
	}

	// Per-user crontabs: "m h dom mon dow command" (user = filename).
	for _, dir := range []string{"/var/spool/cron/crontabs", "/var/spool/cron"} {
		for _, f := range globDir(dir) {
			user := filepath.Base(f)
			for _, line := range cronLines(f) {
				fields := strings.Fields(line)
				if len(fields) < 6 {
					continue
				}
				cmd := strings.Join(fields[5:], " ")
				out = append(out, AutorunEntry{
					Category: "cron", Name: "crontab:" + user, Location: f,
					Command: cmd, ImagePath: binOf(cmd), User: user, Enabled: true,
					Suspicious: flagPersist(cmd),
				})
			}
		}
	}

	// Periodic script dirs.
	for _, dir := range []string{"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"} {
		for _, f := range globDir(dir) {
			out = append(out, AutorunEntry{
				Category: "cron", Name: filepath.Base(dir) + "/" + filepath.Base(f),
				Location: f, Command: f, ImagePath: f, Enabled: true,
				Suspicious: flagPersist(f),
			})
		}
	}
	return out
}

// ── rc.local + shell init files ──────────────────────────────────────────────
func scanRcAndProfile() []AutorunEntry {
	var out []AutorunEntry
	paths := []string{"/etc/rc.local", "/etc/profile"}
	paths = append(paths, globDir("/etc/profile.d")...)
	if h, err := os.UserHomeDir(); err == nil {
		for _, rc := range []string{".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile"} {
			paths = append(paths, filepath.Join(h, rc))
		}
	}
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil || fi.IsDir() {
			continue
		}
		out = append(out, AutorunEntry{
			Category: "shell-init", Name: filepath.Base(p), Location: p,
			Command: p, ImagePath: p, Enabled: true,
		})
	}
	return out
}

// ── XDG desktop autostart ────────────────────────────────────────────────────
func scanXDGAutostart() []AutorunEntry {
	dirs := []string{"/etc/xdg/autostart"}
	if h, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(h, ".config", "autostart"))
	}
	var out []AutorunEntry
	for _, dir := range dirs {
		for _, f := range globDir(dir) {
			if !strings.HasSuffix(f, ".desktop") {
				continue
			}
			cmd := iniValue(f, "Exec")
			if cmd == "" {
				continue
			}
			out = append(out, AutorunEntry{
				Category: "autostart", Name: filepath.Base(f), Location: f,
				Command: cmd, ImagePath: binOf(cmd), Enabled: true,
				Suspicious: flagPersist(cmd),
			})
		}
	}
	return out
}

// ── helpers ──────────────────────────────────────────────────────────────────

// iniValue returns the value of the first "KEY=" line (systemd/.desktop style).
func iniValue(path, key string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, key+"=") {
			return strings.TrimSpace(strings.TrimPrefix(line, key+"="))
		}
	}
	return ""
}

// binOf extracts the executable from a command line, stripping systemd ExecStart
// prefixes (-, @, +, !) and arguments.
func binOf(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return ""
	}
	return strings.TrimLeft(f[0], "-@+!:")
}

// cronLines returns non-comment, non-blank, non-assignment lines from a crontab.
func cronLines(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") || !strings.ContainsAny(l, " \t") {
			continue
		}
		if i := strings.IndexByte(l, '='); i > 0 && i < strings.IndexAny(l+" ", " \t") {
			continue // VAR=value assignment line
		}
		out = append(out, l)
	}
	return out
}

func globDir(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

func flagPersist(cmd string) []string {
	var f []string
	low := strings.ToLower(cmd)
	for _, d := range []string{"/tmp/", "/dev/shm/", "/var/tmp/"} {
		if strings.Contains(low, d) {
			f = append(f, "exec-from-world-writable")
			break
		}
	}
	for _, susp := range []string{"curl ", "wget ", "base64", "nc ", "ncat", "/dev/tcp/", "bash -i", "python -c", "perl -e"} {
		if strings.Contains(low, susp) {
			f = append(f, "suspicious-command")
			break
		}
	}
	return f
}

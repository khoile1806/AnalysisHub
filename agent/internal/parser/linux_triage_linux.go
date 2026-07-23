//go:build linux

package parser

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LinuxArtifact is one host-triage finding (persistence, execution history or a
// privilege-escalation surface). A flat list with a Type column keeps the UI a
// single table, matching the other edge-forensics views.
type LinuxArtifact struct {
	Type       string   `json:"type"` // shell-history | cron | ssh-key | preload | startup | suid | module
	Source     string   `json:"source"`
	User       string   `json:"user"`
	Detail     string   `json:"detail"`
	Modified   string   `json:"modified"`
	Suspicious []string `json:"suspicious"`
}

// ScanLinuxTriage gathers the Linux-specific artifacts that Windows-oriented
// Edge Forensics can't (execution history, Unix persistence, SUID surface). All
// reads are best-effort — a permission error on one path never aborts the rest.
func ScanLinuxTriage() ([]LinuxArtifact, error) {
	var out []LinuxArtifact
	out = append(out, lt_scanShellHistory()...)
	out = append(out, lt_scanCron()...)
	out = append(out, lt_scanSSHKeys()...)
	out = append(out, lt_scanPreloadAndStartup()...)
	out = append(out, lt_scanSUID()...)
	out = append(out, lt_scanKernelModulesLinux()...)
	if out == nil {
		out = []LinuxArtifact{}
	}
	return out, nil
}

// lt_homes returns (user, homeDir) pairs from /root and /home/*.
func lt_homes() [][2]string {
	pairs := [][2]string{{"root", "/root"}}
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				pairs = append(pairs, [2]string{e.Name(), filepath.Join("/home", e.Name())})
			}
		}
	}
	return pairs
}

func lt_modTime(path string) string {
	if fi, err := os.Stat(path); err == nil {
		return fi.ModTime().UTC().Format(time.RFC3339)
	}
	return ""
}

// lt_readTailLines reads a (size-capped) file and returns its last n non-empty lines.
func lt_readTailLines(path string, n, capBytes int) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if len(data) > capBytes {
		data = data[len(data)-capBytes:]
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

// lt_suspiciousCmd flags a shell/cron command that looks like attacker activity.
func lt_suspiciousCmd(line string) []string {
	l := strings.ToLower(line)
	var f []string
	pipeToShell := (strings.Contains(l, "curl") || strings.Contains(l, "wget")) &&
		(strings.Contains(l, "| sh") || strings.Contains(l, "|sh") || strings.Contains(l, "| bash") || strings.Contains(l, "|bash"))
	if pipeToShell {
		f = append(f, "download-pipe-to-shell")
	}
	for marker, flag := range map[string]string{
		"/dev/tcp/": "reverse-shell", "base64 -d": "base64-decode", "base64 --decode": "base64-decode",
		"ncat ": "netcat", "nc -": "netcat", " socat ": "socat", "chattr +i": "immutable-set",
		"history -c": "history-cleared", "insmod ": "kernel-module-load", "modprobe ": "kernel-module-load",
		"/dev/shm/": "shm-staging", "/tmp/": "tmp-execution", "useradd ": "user-added", "chmod +x": "make-executable",
		"python -c": "inline-python", "perl -e": "inline-perl",
	} {
		if strings.Contains(l, marker) {
			f = append(f, flag)
		}
	}
	return f
}

func lt_scanShellHistory() []LinuxArtifact {
	var out []LinuxArtifact
	for _, h := range lt_homes() {
		for _, hist := range []string{".bash_history", ".zsh_history", ".sh_history", ".python_history"} {
			path := filepath.Join(h[1], hist)
			lines := lt_readTailLines(path, 200, 256*1024)
			mt := lt_modTime(path)
			for _, ln := range lines {
				if sus := lt_suspiciousCmd(ln); len(sus) > 0 {
					out = append(out, LinuxArtifact{
						Type: "shell-history", Source: path, User: h[0],
						Detail: truncStr(ln, 400), Modified: mt, Suspicious: sus,
					})
				}
			}
		}
	}
	return out
}

func lt_scanCron() []LinuxArtifact {
	var out []LinuxArtifact
	files := []string{"/etc/crontab"}
	for _, dir := range []string{"/etc/cron.d", "/var/spool/cron/crontabs", "/var/spool/cron"} {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					files = append(files, filepath.Join(dir, e.Name()))
				}
			}
		}
	}
	for _, path := range files {
		mt := lt_modTime(path)
		for _, ln := range lt_readTailLines(path, 300, 256*1024) {
			if strings.HasPrefix(ln, "#") {
				continue
			}
			sus := lt_suspiciousCmd(ln)
			user := ""
			if strings.HasPrefix(path, "/var/spool/cron") {
				user = filepath.Base(path)
			}
			// Any non-comment cron entry is worth listing; flagged ones bubble up.
			out = append(out, LinuxArtifact{
				Type: "cron", Source: path, User: user,
				Detail: truncStr(ln, 400), Modified: mt, Suspicious: sus,
			})
		}
	}
	return out
}

func lt_scanSSHKeys() []LinuxArtifact {
	var out []LinuxArtifact
	for _, h := range lt_homes() {
		path := filepath.Join(h[1], ".ssh", "authorized_keys")
		mt := lt_modTime(path)
		for _, ln := range lt_readTailLines(path, 100, 128*1024) {
			if strings.HasPrefix(ln, "#") {
				continue
			}
			parts := strings.Fields(ln)
			if len(parts) < 2 {
				continue
			}
			// type + comment only — do NOT echo the full key material.
			keyType := parts[0]
			comment := ""
			if len(parts) >= 3 {
				comment = strings.Join(parts[2:], " ")
			}
			out = append(out, LinuxArtifact{
				Type: "ssh-key", Source: path, User: h[0],
				Detail:     "authorized key: " + keyType + " " + truncStr(comment, 120),
				Modified:   mt,
				Suspicious: []string{"ssh-authorized-key"},
			})
		}
	}
	return out
}

func lt_scanPreloadAndStartup() []LinuxArtifact {
	var out []LinuxArtifact
	// ld.so.preload — presence itself is a strong userland-rootkit signal.
	for _, ln := range lt_readTailLines("/etc/ld.so.preload", 20, 8*1024) {
		out = append(out, LinuxArtifact{
			Type: "preload", Source: "/etc/ld.so.preload", Detail: ln,
			Modified: lt_modTime("/etc/ld.so.preload"), Suspicious: []string{"ld-preload-hijack"},
		})
	}
	// Startup scripts that run at boot/login.
	startupFiles := []string{"/etc/rc.local"}
	if entries, err := os.ReadDir("/etc/profile.d"); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".sh") {
				startupFiles = append(startupFiles, filepath.Join("/etc/profile.d", e.Name()))
			}
		}
	}
	for _, path := range startupFiles {
		mt := lt_modTime(path)
		for _, ln := range lt_readTailLines(path, 100, 128*1024) {
			if strings.HasPrefix(ln, "#") || ln == "exit 0" {
				continue
			}
			if sus := lt_suspiciousCmd(ln); len(sus) > 0 {
				out = append(out, LinuxArtifact{
					Type: "startup", Source: path, Detail: truncStr(ln, 400), Modified: mt, Suspicious: sus,
				})
			}
		}
	}
	return out
}

// lt_scanSUID walks a bounded set of directories for SUID/SGID binaries, flagging
// ones in world-writable / user-writable locations (a common privesc / staging
// signal). It never walks the whole filesystem.
func lt_scanSUID() []LinuxArtifact {
	var out []LinuxArtifact
	dirs := []string{"/tmp", "/var/tmp", "/dev/shm", "/home", "/usr/local/bin", "/opt"}
	const maxFiles = 20000
	seen := 0
	for _, root := range dirs {
		filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil || info == nil {
				return nil
			}
			if seen++; seen > maxFiles {
				return filepath.SkipDir
			}
			if info.IsDir() {
				return nil
			}
			mode := info.Mode()
			if mode&os.ModeSetuid == 0 && mode&os.ModeSetgid == 0 {
				return nil
			}
			sus := []string{"suid-binary"}
			if strings.HasPrefix(p, "/tmp") || strings.HasPrefix(p, "/var/tmp") ||
				strings.HasPrefix(p, "/dev/shm") || strings.HasPrefix(p, "/home") {
				sus = append(sus, "suid-in-writable-path")
			}
			out = append(out, LinuxArtifact{
				Type: "suid", Source: p,
				Detail: "mode " + mode.String(), Modified: info.ModTime().UTC().Format(time.RFC3339), Suspicious: sus,
			})
			return nil
		})
	}
	return out
}

// lt_scanKernelModulesLinux reads /proc/modules and flags modules that are not part
// of the distro's on-disk module tree (a rootkit / out-of-tree signal).
func lt_scanKernelModulesLinux() []LinuxArtifact {
	onDisk := lt_moduleSet() // built once
	var out []LinuxArtifact
	for _, ln := range lt_readTailLines("/proc/modules", 2000, 512*1024) {
		fields := strings.Fields(ln)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		if !onDisk[strings.ReplaceAll(name, "_", "-")] && !onDisk[strings.ReplaceAll(name, "-", "_")] {
			out = append(out, LinuxArtifact{
				Type: "module", Source: "/proc/modules", Detail: name,
				Suspicious: []string{"module-not-on-disk"},
			})
		}
	}
	return out
}

// lt_moduleSet returns the set of module names present as .ko files under
// /lib/modules (walked once, bounded).
func lt_moduleSet() map[string]bool {
	set := map[string]bool{}
	const maxFiles = 200000
	seen := 0
	filepath.Walk("/lib/modules", func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if seen++; seen > maxFiles {
			return filepath.SkipDir
		}
		name := filepath.Base(p)
		if strings.HasSuffix(name, ".ko") {
			set[strings.TrimSuffix(name, ".ko")] = true
		} else if strings.HasSuffix(name, ".ko.xz") {
			set[strings.TrimSuffix(name, ".ko.xz")] = true
		} else if strings.HasSuffix(name, ".ko.zst") {
			set[strings.TrimSuffix(name, ".ko.zst")] = true
		}
		return nil
	})
	return set
}

func truncStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

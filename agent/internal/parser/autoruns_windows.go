//go:build windows

package parser

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// AutorunEntry is one persistence / autostart item — the native equivalent of a
// Sysinternals Autoruns row, enriched with content hash and Authenticode status.
type AutorunEntry struct {
	Category   string   `json:"category"`   // Run Key | Service | Scheduled Task | Startup Folder | Winlogon | IFEO | AppInit
	Name       string   `json:"name"`       // value/service/task/file name
	Location   string   `json:"location"`   // registry path or file path
	Command    string   `json:"command"`    // raw command/value
	ImagePath  string   `json:"image_path"` // resolved executable path
	User       string   `json:"user,omitempty"`
	Enabled    bool     `json:"enabled"`
	MD5        string   `json:"md5,omitempty"`
	SHA256     string   `json:"sha256,omitempty"`
	Hashed     bool     `json:"hashed"`
	Signature  string   `json:"signature,omitempty"` // Signed | Unsigned | Untrusted
	Suspicious []string `json:"suspicious,omitempty"`
}

const autorunHashBudget int64 = 1 << 30 // ~1 GB

// ScanAutoruns enumerates the major Windows autostart locations and enriches
// each with the backing executable's hash and signature status. Runs elevated.
func ScanAutoruns() ([]AutorunEntry, error) {
	var entries []AutorunEntry
	entries = append(entries, scanRunKeys()...)
	entries = append(entries, scanWinlogon()...)
	entries = append(entries, scanIFEO()...)
	entries = append(entries, scanAppInit()...)
	entries = append(entries, scanServices()...)
	entries = append(entries, scanScheduledTasks()...)
	entries = append(entries, scanStartupFolders()...)

	// Enrich: resolve image path, hash, signature, suspicion (cache by path).
	hashCache := make(map[string][2]string)
	sigCache := make(map[string]string)
	budget := autorunHashBudget
	for i := range entries {
		e := &entries[i]
		if e.ImagePath == "" {
			e.ImagePath = resolveImagePath(e.Command)
		}
		if e.ImagePath != "" {
			key := strings.ToLower(e.ImagePath)
			if h, ok := hashCache[key]; ok {
				e.MD5, e.SHA256, e.Hashed = h[0], h[1], h[1] != ""
			} else if fi, err := os.Stat(e.ImagePath); err == nil && !fi.IsDir() && fi.Size() > 0 && fi.Size() <= mftMaxHashBytes && budget > 0 {
				if md5h, _, sha256h, herr := hashFile(e.ImagePath); herr == nil {
					e.MD5, e.SHA256, e.Hashed = md5h, sha256h, true
					budget -= fi.Size()
					hashCache[key] = [2]string{md5h, sha256h}
				} else {
					hashCache[key] = [2]string{"", ""}
				}
			} else {
				hashCache[key] = [2]string{"", ""}
			}
			if s, ok := sigCache[key]; ok {
				e.Signature = s
			} else {
				e.Signature = fileSignatureStatus(e.ImagePath)
				sigCache[key] = e.Signature
			}
		}
		e.Suspicious = flagAutorun(e)
	}
	return entries, nil
}

// ── Run / RunOnce keys (HKLM, Wow64, HKCU, all loaded user hives) ────────────
var runKeyPaths = []string{
	`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
	`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
	`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`,
	`SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`,
	`SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`,
}

func scanRunKeys() []AutorunEntry {
	var out []AutorunEntry
	add := func(root registry.Key, rootName, sub, user string) {
		k, err := registry.OpenKey(root, sub, registry.QUERY_VALUE)
		if err != nil {
			return
		}
		defer k.Close()
		names, _ := k.ReadValueNames(-1)
		for _, n := range names {
			v, _, _ := k.GetStringValue(n)
			if strings.TrimSpace(v) == "" {
				continue
			}
			out = append(out, AutorunEntry{
				Category: "Run Key", Name: n, Location: rootName + `\` + sub,
				Command: v, User: user, Enabled: true,
			})
		}
	}
	for _, p := range runKeyPaths {
		add(registry.LOCAL_MACHINE, "HKLM", p, "")
	}
	add(registry.CURRENT_USER, "HKCU", `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "")
	add(registry.CURRENT_USER, "HKCU", `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "")

	// All loaded user hives (HKU\<SID>\...Run) — catches other logged-on users.
	if hku, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS); err == nil {
		defer hku.Close()
		sids, _ := hku.ReadSubKeyNames(-1)
		for _, sid := range sids {
			if strings.HasSuffix(sid, "_Classes") || sid == ".DEFAULT" {
				continue
			}
			add(registry.USERS, "HKU", sid+`\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, sid)
		}
	}
	return out
}

// ── Winlogon (Userinit / Shell) ──────────────────────────────────────────────
func scanWinlogon() []AutorunEntry {
	var out []AutorunEntry
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, registry.QUERY_VALUE)
	if err != nil {
		return out
	}
	defer k.Close()
	for _, n := range []string{"Userinit", "Shell"} {
		if v, _, err := k.GetStringValue(n); err == nil && strings.TrimSpace(v) != "" {
			out = append(out, AutorunEntry{Category: "Winlogon", Name: n,
				Location: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, Command: v, Enabled: true})
		}
	}
	return out
}

// ── Image File Execution Options (Debugger hijack) ───────────────────────────
func scanIFEO() []AutorunEntry {
	var out []AutorunEntry
	base := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return out
	}
	defer k.Close()
	subs, _ := k.ReadSubKeyNames(-1)
	for _, s := range subs {
		sk, err := registry.OpenKey(registry.LOCAL_MACHINE, base+`\`+s, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		if dbg, _, err := sk.GetStringValue("Debugger"); err == nil && strings.TrimSpace(dbg) != "" {
			out = append(out, AutorunEntry{Category: "IFEO Debugger", Name: s,
				Location: `HKLM\` + base + `\` + s, Command: dbg, Enabled: true})
		}
		sk.Close()
	}
	return out
}

// ── AppInit_DLLs ─────────────────────────────────────────────────────────────
func scanAppInit() []AutorunEntry {
	var out []AutorunEntry
	for _, p := range []string{
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
		`SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows`,
	} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		if v, _, err := k.GetStringValue("AppInit_DLLs"); err == nil && strings.TrimSpace(v) != "" {
			out = append(out, AutorunEntry{Category: "AppInit_DLLs", Name: "AppInit_DLLs",
				Location: `HKLM\` + p, Command: v, Enabled: true})
		}
		k.Close()
	}
	return out
}

// ── Services (auto + manual start, with an image path) ───────────────────────
func scanServices() []AutorunEntry {
	var out []AutorunEntry
	base := `SYSTEM\CurrentControlSet\Services`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return out
	}
	defer k.Close()
	subs, _ := k.ReadSubKeyNames(-1)
	for _, s := range subs {
		sk, err := registry.OpenKey(registry.LOCAL_MACHINE, base+`\`+s, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		img, _, _ := sk.GetStringValue("ImagePath")
		start, _, _ := sk.GetIntegerValue("Start")
		sk.Close()
		if strings.TrimSpace(img) == "" {
			continue
		}
		// Start: 0/1=boot/system driver, 2=auto, 3=manual, 4=disabled. Skip disabled.
		if start == 4 {
			continue
		}
		out = append(out, AutorunEntry{Category: "Service", Name: s,
			Location: `HKLM\` + base + `\` + s, Command: img, Enabled: start <= 2})
	}
	return out
}

// ── Scheduled Tasks (parse task XML under System32\Tasks) ────────────────────
type taskXML struct {
	Actions struct {
		Exec []struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

func scanScheduledTasks() []AutorunEntry {
	var out []AutorunEntry
	root := filepath.Join(os.Getenv("SystemRoot"), `System32\Tasks`)
	if root == `System32\Tasks` {
		root = `C:\Windows\System32\Tasks`
	}
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		var t taskXML
		if xml.Unmarshal(b, &t) != nil || len(t.Actions.Exec) == 0 {
			return nil
		}
		rel := strings.TrimPrefix(path, root)
		for _, ex := range t.Actions.Exec {
			cmd := strings.TrimSpace(ex.Command)
			if cmd == "" {
				continue
			}
			full := cmd
			if ex.Arguments != "" {
				full = cmd + " " + ex.Arguments
			}
			out = append(out, AutorunEntry{Category: "Scheduled Task",
				Name: strings.ReplaceAll(rel, `\`, `/`), Location: path,
				Command: full, ImagePath: resolveImagePath(cmd), Enabled: true})
		}
		return nil
	})
	return out
}

// ── Startup folders (all-users + each user profile) ──────────────────────────
func scanStartupFolders() []AutorunEntry {
	var out []AutorunEntry
	dirs := []string{
		filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\Startup`),
	}
	if users := os.Getenv("SystemDrive") + `\Users`; true {
		if profiles, err := os.ReadDir(users); err == nil {
			for _, p := range profiles {
				if p.IsDir() {
					dirs = append(dirs, filepath.Join(users, p.Name(), `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`))
				}
			}
		}
	}
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, f := range ents {
			if f.IsDir() {
				continue
			}
			name := f.Name()
			if strings.EqualFold(name, "desktop.ini") {
				continue
			}
			full := filepath.Join(d, name)
			img := full
			// Plain executables/scripts can be hashed directly; .lnk targets need
			// COM resolution (not done here) so we report the shortcut itself.
			out = append(out, AutorunEntry{Category: "Startup Folder", Name: name,
				Location: d, Command: full, ImagePath: img, Enabled: true})
		}
	}
	return out
}

// resolveImagePath extracts the executable path from a command line: expands
// environment variables, normalises NT / SystemRoot / driver-relative paths,
// strips quotes, arguments and trailing commas.
func resolveImagePath(command string) string {
	s := strings.TrimSpace(command)
	if s == "" {
		return ""
	}
	if e, err := registry.ExpandString(s); err == nil {
		s = strings.TrimSpace(e)
	}
	win := os.Getenv("SystemRoot")
	if win == "" {
		win = `C:\Windows`
	}

	// Quoted path → take the quoted portion verbatim.
	if strings.HasPrefix(s, `"`) {
		if end := strings.IndexByte(s[1:], '"'); end >= 0 {
			s = s[1 : 1+end]
		}
	} else if idx := strings.IndexByte(s, ' '); idx > 0 {
		// Take the first whitespace-delimited token unless the whole string
		// resolves as-is (paths with spaces are normally quoted).
		if _, err := os.Stat(strings.TrimRight(s, `,`)); err != nil {
			s = s[:idx]
		}
	}
	s = strings.Trim(strings.TrimSpace(s), `,"`)

	// Normalise NT / SystemRoot / driver-relative forms to a drive path.
	low := strings.ToLower(s)
	switch {
	case strings.HasPrefix(low, `\??\`):
		s = s[4:]
	case strings.HasPrefix(low, `\systemroot\`):
		s = win + s[len(`\systemroot`):]
	case strings.HasPrefix(low, `systemroot\`):
		s = win + `\` + s[len(`systemroot\`):]
	case strings.HasPrefix(low, `system32\`) || strings.HasPrefix(low, `syswow64\`) || strings.HasPrefix(low, `drivers\`):
		s = win + `\` + s
	}

	// Bare image name (e.g. Winlogon Shell = "explorer.exe") — locate in the
	// usual system directories.
	if !strings.ContainsAny(s, `\/`) {
		for _, dir := range []string{win, filepath.Join(win, "System32")} {
			cand := filepath.Join(dir, s)
			if _, err := os.Stat(cand); err == nil {
				return cand
			}
		}
	}
	return s
}

// autorunRiskyDirs are user-writable staging locations where an autostart image
// is genuinely suspicious. Deliberately tighter than suspiciousDirs: ProgramData
// and AppData\Roaming are excluded because legitimate software (AV, agents,
// updaters) routinely autostarts from there.
var autorunRiskyDirs = []string{
	`\temp\`, `\tmp\`, `\appdata\local\temp\`, `\downloads\`,
	`\users\public\`, `$recycle.bin`, `\windows\temp\`, `\perflogs\`,
}

// flagAutorun returns suspicion reasons for an autostart entry.
func flagAutorun(e *AutorunEntry) []string {
	var r []string
	lp := strings.ToLower(e.ImagePath)
	lc := strings.ToLower(e.Command)

	inRiskyDir := false
	if e.ImagePath != "" {
		for _, frag := range autorunRiskyDirs {
			if strings.Contains(lp, frag) {
				r = append(r, "runs from "+strings.Trim(frag, `\`))
				inRiskyDir = true
				break
			}
		}
	}
	// An untrusted signature is always notable. A plain "Unsigned" result is
	// common for legit third-party apps, so only flag it when the image also
	// lives in a user-writable / staging directory (the real red flag).
	if e.Signature == "Untrusted" {
		r = append(r, "untrusted signature")
	} else if e.Signature == "Unsigned" && inRiskyDir {
		r = append(r, "unsigned binary in a writable location")
	}
	for _, lb := range []string{"powershell", "rundll32", "regsvr32", "mshta", "cmd.exe", "wscript", "cscript", "certutil", "bitsadmin"} {
		if strings.Contains(lc, lb) {
			if strings.Contains(lc, "-enc") || strings.Contains(lc, "http") || strings.Contains(lc, "frombase64") || strings.Contains(lc, "downloadstring") || strings.Contains(lc, "bypass") || strings.Contains(lc, "hidden") {
				r = append(r, "interpreter with suspicious arguments")
			}
			break
		}
	}
	if e.Category == "IFEO Debugger" {
		r = append(r, "IFEO debugger hijack")
	}
	// Absolute image path that doesn't exist on disk — a dangling autostart
	// (deleted payload / typo'd masquerade). Only check absolute drive paths so
	// unresolved relative/bare names aren't mistaken for missing files.
	if e.ImagePath != "" && !e.Hashed && len(e.ImagePath) > 2 && e.ImagePath[1] == ':' &&
		execExts[strings.ToLower(filepath.Ext(e.ImagePath))] {
		if _, err := os.Stat(e.ImagePath); err != nil {
			r = append(r, "image path not found on disk")
		}
	}
	return r
}

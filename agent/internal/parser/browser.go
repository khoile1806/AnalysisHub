package parser

import (
	"database/sql"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go, cgo-free SQLite driver (cross-platform)
)

// BrowserEntry is one URL-visit record recovered from a browser history store
// (Chromium-family `History` SQLite DB or Firefox `places.sqlite`). The model
// and all parsing logic here are platform-neutral; each OS file
// (browser_windows.go / browser_other.go) only enumerates the profile roots.
type BrowserEntry struct {
	Browser    string   `json:"browser"` // Chrome | Edge | Brave | Chromium | Firefox
	Profile    string   `json:"profile"` // "<user>/<profile>" attribution
	URL        string   `json:"url"`
	Title      string   `json:"title,omitempty"`
	VisitCount int      `json:"visit_count"`
	LastVisit  string   `json:"last_visit,omitempty"` // RFC3339 UTC
	Suspicious []string `json:"suspicious,omitempty"`
}

const (
	browserPerDBLimit = 3000  // cap rows read from a single history store
	browserTotalLimit = 12000 // overall cap to keep the artifact payload sane
)

// scanChromiumUserData walks every profile dir under a Chromium "User Data" root
// (Default, Profile 1, …) and reads its History DB. owner is the user the
// profile belongs to (for attribution).
func scanChromiumUserData(userData, browser, owner string) []BrowserEntry {
	profiles, err := os.ReadDir(userData)
	if err != nil {
		return nil
	}
	var out []BrowserEntry
	for _, pf := range profiles {
		if !pf.IsDir() {
			continue
		}
		hist := filepath.Join(userData, pf.Name(), "History")
		if _, e := os.Stat(hist); e != nil {
			continue
		}
		out = append(out, readChromiumHistory(hist, browser, owner+"/"+pf.Name())...)
	}
	return out
}

// scanFirefoxProfiles walks every profile under a Firefox "Profiles" dir and
// reads its places.sqlite.
func scanFirefoxProfiles(profilesDir, owner string) []BrowserEntry {
	profiles, err := os.ReadDir(profilesDir)
	if err != nil {
		return nil
	}
	var out []BrowserEntry
	for _, pf := range profiles {
		if !pf.IsDir() {
			continue
		}
		places := filepath.Join(profilesDir, pf.Name(), "places.sqlite")
		if _, e := os.Stat(places); e != nil {
			continue
		}
		out = append(out, readFirefoxHistory(places, owner+"/"+pf.Name())...)
	}
	return out
}

// readChromiumHistory queries the `urls` table of a Chromium History DB.
func readChromiumHistory(histPath, browser, profile string) []BrowserEntry {
	tmp, cleanup, err := copyForRead(histPath)
	if err != nil {
		return nil
	}
	defer cleanup()

	db, err := sql.Open("sqlite", "file:"+tmp+"?_pragma=busy_timeout(3000)")
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.Query(
		`SELECT url, COALESCE(title,''), visit_count, last_visit_time
		   FROM urls ORDER BY last_visit_time DESC LIMIT ?`, browserPerDBLimit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []BrowserEntry
	for rows.Next() {
		var u, title string
		var visits int
		var ts int64
		if rows.Scan(&u, &title, &visits, &ts) != nil {
			continue
		}
		out = append(out, BrowserEntry{
			Browser: browser, Profile: profile, URL: u, Title: title,
			VisitCount: visits, LastVisit: fmtTime(chromiumTime(ts)), Suspicious: flagURL(u),
		})
	}
	return out
}

// readFirefoxHistory queries the moz_places table of a Firefox places.sqlite.
func readFirefoxHistory(places, profile string) []BrowserEntry {
	tmp, cleanup, err := copyForRead(places)
	if err != nil {
		return nil
	}
	defer cleanup()

	db, err := sql.Open("sqlite", "file:"+tmp+"?_pragma=busy_timeout(3000)")
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.Query(
		`SELECT url, COALESCE(title,''), visit_count, last_visit_date
		   FROM moz_places WHERE last_visit_date IS NOT NULL
		   ORDER BY last_visit_date DESC LIMIT ?`, browserPerDBLimit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []BrowserEntry
	for rows.Next() {
		var u, title string
		var visits int
		var ts int64
		if rows.Scan(&u, &title, &visits, &ts) != nil {
			continue
		}
		out = append(out, BrowserEntry{
			Browser: "Firefox", Profile: profile, URL: u, Title: title,
			VisitCount: visits, LastVisit: fmtTime(firefoxTime(ts)), Suspicious: flagURL(u),
		})
	}
	return out
}

// copyForRead copies a (possibly locked) SQLite DB plus its -wal/-shm sidecars
// into a throwaway temp dir so it can be read without contending with a running
// browser. Returns the copied main path and a cleanup func.
func copyForRead(src string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "fhbrowse_")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { os.RemoveAll(dir) }
	dst := filepath.Join(dir, "h.db")
	if err := copyFile(src, dst); err != nil {
		cleanup()
		return "", func() {}, err
	}
	_ = copyFile(src+"-wal", dst+"-wal") // sidecars best-effort
	_ = copyFile(src+"-shm", dst+"-shm")
	return dst, cleanup, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// chromiumTime converts a Chromium/WebKit timestamp (µs since 1601-01-01 UTC).
func chromiumTime(t int64) time.Time {
	if t <= 0 {
		return time.Time{}
	}
	const epochDiff = 11644473600 // seconds between 1601-01-01 and 1970-01-01
	sec := t/1_000_000 - epochDiff
	if sec < 0 {
		return time.Time{}
	}
	return time.Unix(sec, (t%1_000_000)*1000).UTC()
}

// firefoxTime converts a Firefox timestamp (µs since 1970-01-01 UTC).
func firefoxTime(t int64) time.Time {
	if t <= 0 {
		return time.Time{}
	}
	return time.UnixMicro(t).UTC()
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

// flagURL returns lightweight suspicion markers for an analyst to triage on.
func flagURL(raw string) []string {
	var flags []string
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return flags
	}
	host := strings.ToLower(u.Hostname())

	if net.ParseIP(host) != nil {
		flags = append(flags, "raw-ip-host")
	}
	for _, tld := range []string{".tk", ".top", ".xyz", ".gq", ".ml", ".cf", ".click", ".zip", ".mov"} {
		if strings.HasSuffix(host, tld) {
			flags = append(flags, "suspicious-tld")
			break
		}
	}
	lowerPath := strings.ToLower(u.Path)
	for _, ext := range []string{".exe", ".scr", ".ps1", ".bat", ".hta", ".jar", ".vbs", ".dll", ".msi", ".sh", ".elf"} {
		if strings.HasSuffix(lowerPath, ext) {
			flags = append(flags, "executable-download")
			break
		}
	}
	for _, bad := range []string{"pastebin.com", "anonfiles", "transfer.sh", "ngrok.io", "trycloudflare.com", "mega.nz", "mediafire.com", "cdn.discordapp.com", "telegra.ph", "rentry.co"} {
		if strings.Contains(host, bad) {
			flags = append(flags, "file-share/paste-host")
			break
		}
	}
	if u.Scheme == "file" || u.Scheme == "ftp" {
		flags = append(flags, "non-web-scheme")
	}
	return flags
}

func capEntries(in []BrowserEntry) []BrowserEntry {
	if len(in) > browserTotalLimit {
		return in[:browserTotalLimit]
	}
	return in
}

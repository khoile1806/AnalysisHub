//go:build !windows

package parser

import (
	"os"
	"path/filepath"
	"runtime"
)

// ScanBrowserHistory recovers browser history on Linux/macOS across every user's
// home directory. Reuses the platform-neutral SQLite readers in browser.go; only
// the profile-root layout differs per OS. Reading other users' homes requires
// the agent to run as root.
func ScanBrowserHistory() ([]BrowserEntry, error) {
	var out []BrowserEntry
	for _, home := range homeDirs() {
		owner := filepath.Base(home)
		for _, b := range chromiumRootsFor(home) {
			out = append(out, scanChromiumUserData(b.userData, b.name, owner)...)
			if len(out) >= browserTotalLimit {
				return capEntries(out), nil
			}
		}
		for _, ff := range firefoxRootsFor(home) {
			out = append(out, scanFirefoxProfiles(ff, owner)...)
			if len(out) >= browserTotalLimit {
				return capEntries(out), nil
			}
		}
	}
	return out, nil
}

type chromiumRoot struct {
	name     string // display name
	userData string // path to the "User Data" equivalent
}

// chromiumRootsFor returns the Chromium-family "User Data" roots for one home.
func chromiumRootsFor(home string) []chromiumRoot {
	if runtime.GOOS == "darwin" {
		base := filepath.Join(home, "Library", "Application Support")
		return []chromiumRoot{
			{"Chrome", filepath.Join(base, "Google", "Chrome")},
			{"Edge", filepath.Join(base, "Microsoft Edge")},
			{"Brave", filepath.Join(base, "BraveSoftware", "Brave-Browser")},
			{"Chromium", filepath.Join(base, "Chromium")},
		}
	}
	cfg := filepath.Join(home, ".config")
	return []chromiumRoot{
		{"Chrome", filepath.Join(cfg, "google-chrome")},
		{"Chromium", filepath.Join(cfg, "chromium")},
		{"Brave", filepath.Join(cfg, "BraveSoftware", "Brave-Browser")},
		{"Edge", filepath.Join(cfg, "microsoft-edge")},
	}
}

// firefoxRootsFor returns the Firefox "Profiles" dirs for one home.
func firefoxRootsFor(home string) []string {
	if runtime.GOOS == "darwin" {
		return []string{filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles")}
	}
	return []string{
		filepath.Join(home, ".mozilla", "firefox"),
		filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox"), // Ubuntu snap
	}
}

// homeDirs enumerates user home directories to scan. Running as root sees every
// user under /home (and /Users on macOS); otherwise just the current $HOME.
func homeDirs() []string {
	seen := map[string]bool{}
	var dirs []string
	add := func(p string) {
		if p != "" && !seen[p] {
			if _, err := os.Stat(p); err == nil {
				seen[p] = true
				dirs = append(dirs, p)
			}
		}
	}

	if h, err := os.UserHomeDir(); err == nil {
		add(h)
	}
	root := "/home"
	if runtime.GOOS == "darwin" {
		root = "/Users"
	}
	if entries, err := os.ReadDir(root); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				add(filepath.Join(root, e.Name()))
			}
		}
	}
	add("/root")
	return dirs
}

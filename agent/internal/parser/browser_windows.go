//go:build windows

package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// chromiumBrowsers maps a display name to its "User Data" path relative to a
// user's %LOCALAPPDATA%.
var chromiumBrowsers = map[string]string{
	"Chrome": `Google\Chrome\User Data`,
	"Edge":   `Microsoft\Edge\User Data`,
	"Brave":  `BraveSoftware\Brave-Browser\User Data`,
}

// ScanBrowserHistory walks every local user profile and recovers browser history
// from Chromium-family browsers + Firefox. Reading another user's profile
// requires the agent to be elevated; the caller (runEdgeScan) handles UAC.
func ScanBrowserHistory() ([]BrowserEntry, error) {
	usersRoot := filepath.Join(systemDrive(), "Users")
	userDirs, err := os.ReadDir(usersRoot)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}

	var out []BrowserEntry
	for _, ud := range userDirs {
		if !ud.IsDir() || skipUser(ud.Name()) {
			continue
		}
		user := ud.Name()
		userPath := filepath.Join(usersRoot, user)

		for name, rel := range chromiumBrowsers {
			userData := filepath.Join(userPath, "AppData", "Local", rel)
			out = append(out, scanChromiumUserData(userData, name, user)...)
			if len(out) >= browserTotalLimit {
				return capEntries(out), nil
			}
		}

		ffProfiles := filepath.Join(userPath, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles")
		out = append(out, scanFirefoxProfiles(ffProfiles, user)...)
		if len(out) >= browserTotalLimit {
			return capEntries(out), nil
		}
	}
	return out, nil
}

func systemDrive() string {
	if d := os.Getenv("SystemDrive"); d != "" {
		return d + `\`
	}
	return `C:\`
}

// skipUser filters pseudo-profiles that never hold real browser history.
func skipUser(name string) bool {
	switch strings.ToLower(name) {
	case "public", "default", "default user", "all users", "defaultapppool":
		return true
	}
	return false
}

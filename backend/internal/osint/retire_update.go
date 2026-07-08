package osint

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// retireJSURL is the canonical retire.js vulnerability DB, served via jsDelivr's
// GitHub mirror (raw.githubusercontent is rate-limited). Downloads route through
// the process's default transport, which carries the configured egress proxy.
const retireJSURL = "https://cdn.jsdelivr.net/gh/RetireJS/retire.js@master/repository/jsrepository.json"

// UpdateRetireJS downloads the latest retire.js DB, validates it, hot-reloads it
// into memory, and persists it to destPath so the fresher copy survives a restart.
func UpdateRetireJS(ctx context.Context, destPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, retireJSURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("retire.js download status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	// Validate before swapping: the blob must parse into a non-empty library set.
	libs, err := parseRetire(data)
	if err != nil || len(libs) == 0 {
		return fmt.Errorf("downloaded retire.js DB invalid (%d libs): %v", len(libs), err)
	}
	if _, err := ReloadRetireFromBytes(data); err != nil {
		return err
	}
	if destPath != "" {
		if werr := writeFileAtomic(destPath, data); werr != nil {
			// Reload already succeeded; a persistence failure is non-fatal.
			return nil
		}
	}
	return nil
}

// InitRetireFromDisk loads a previously-downloaded DB from path at boot when
// present (fresher than the embedded copy); otherwise the embedded DB is used.
func InitRetireFromDisk(path string) {
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	_, _ = ReloadRetireFromBytes(data)
}

func writeFileAtomic(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

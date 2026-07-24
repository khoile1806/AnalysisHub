package sigma

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// DefaultSigmaHQURL is the SigmaHQ community ruleset archive. The GitHub branch
// zip contains the full rules/ tree; SyncFromZipURL extracts only the YAML rule
// files from it.
const DefaultSigmaHQURL = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"

// maxSyncDownload bounds the archive size we will pull (defence against an
// attacker-controlled SIGMA_RULES_URL serving an enormous body).
const maxSyncDownload = 200 << 20 // 200 MiB

// SyncResult summarises a rule sync.
type SyncResult struct {
	Source       string `json:"source"`
	RulesWritten int    `json:"rules_written"`
	RulesLoaded  int    `json:"rules_loaded"`
}

// SyncFromZipURL downloads a zip of Sigma rules and extracts every .yml/.yaml
// entry under any "rules" path into destDir (flattened, collisions de-duped by
// their archive path). Path-traversal entries are rejected. After writing, the
// engine reloads destDir. A blank url uses DefaultSigmaHQURL.
func SyncFromZipURL(ctx context.Context, url, destDir string) (*SyncResult, error) {
	if strings.TrimSpace(url) == "" {
		url = DefaultSigmaHQURL
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, fmt.Errorf("create rules dir: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download rules: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download rules: unexpected status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSyncDownload))
	if err != nil {
		return nil, fmt.Errorf("read archive: %w", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open archive: %w", err)
	}

	// Drop the previous sync's output before extracting. Synced files are the
	// ones flattened with "__", so curated rules shipped in the image survive.
	// Without this, rules deleted or renamed upstream lingered forever and the
	// active ruleset only ever grew.
	prunePreviousSync(destDir)

	written := 0
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(f.Name))
		if ext != ".yml" && ext != ".yaml" {
			continue
		}
		// Only take files that live under a rules/ directory in the archive,
		// skipping tests/deprecated trees that ship alongside.
		lower := strings.ToLower(filepath.ToSlash(f.Name))
		if !strings.Contains(lower, "/rules") && !strings.HasPrefix(lower, "rules") {
			continue
		}
		// rules-placeholder/ holds rules whose values are %placeholders% that no
		// event can ever match, and rules-compliance/ is policy auditing rather
		// than detection — both are pure noise in a hunting ruleset.
		if strings.Contains(lower, "rules-placeholder") || strings.Contains(lower, "rules-compliance") {
			continue
		}

		// Flatten to a safe filename derived from the archive path; reject any
		// traversal just in case.
		rel := filepath.ToSlash(f.Name)
		if strings.Contains(rel, "..") {
			continue
		}
		safeName := strings.ReplaceAll(rel, "/", "__")
		out := filepath.Join(destDir, safeName)
		if !strings.HasPrefix(out, filepath.Clean(destDir)+string(os.PathSeparator)) {
			continue
		}

		if err := extractRuleFile(f, out); err != nil {
			log.Printf("sigma sync: skip %s: %v", f.Name, err)
			continue
		}
		written++
	}

	res := &SyncResult{Source: url, RulesWritten: written}
	if DefaultEngine != nil {
		res.RulesLoaded = DefaultEngine.Reload(destDir)
	}
	return res, nil
}

// prunePreviousSync removes the flattened files a previous sync wrote, leaving
// the curated rules that ship with the image untouched.
func prunePreviousSync(destDir string) {
	entries, err := os.ReadDir(destDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.Contains(e.Name(), "__") {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".yml" || ext == ".yaml" {
			os.Remove(filepath.Join(destDir, e.Name()))
		}
	}
}

func extractRuleFile(f *zip.File, out string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	dst, err := os.Create(out)
	if err != nil {
		return err
	}
	defer dst.Close()

	// Per-file cap mirrors the engine's expectation of small rule files.
	_, err = io.Copy(dst, io.LimitReader(rc, 1<<20))
	return err
}

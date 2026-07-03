package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/analysishub/backend/internal/models"
)

// collectMaigret runs the Maigret CLI (https://github.com/soxoj/maigret) to
// search 3000+ sites for a username and turns each found account into a finding
// plus a related-entity pivot. Maigret is an optional external dependency: if
// the binary isn't on PATH the collector skips gracefully (like a missing API
// key) so the rest of the scan still runs.
func collectMaigret(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	bin, err := exec.LookPath("maigret")
	if err != nil {
		return nil, errNoAPIKey // not installed -> recorded as "skipped"
	}

	tmp, err := os.MkdirTemp("", "maigret-")
	if err != nil {
		return nil, fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	// --json simple writes report_<user>_simple.json (found accounts only) into
	// the output folder. --top-sites bounds runtime; --no-recursion keeps it to
	// the requested username; --no-progressbar keeps output clean.
	args := []string{
		env.target,
		"--json", "simple",
		"--folderoutput", tmp,
		"--no-progressbar",
		"--no-recursion",
		"--timeout", "20",
		"--top-sites", "500",
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	// Maigret exits non-zero when nothing is found - ignore the exit code and
	// rely on the report file instead.
	_ = cmd.Run()

	matches, _ := filepath.Glob(filepath.Join(tmp, "*_simple.json"))
	if len(matches) == 0 {
		env.emit("[*] maigret: no accounts found")
		return nil, nil
	}
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		return nil, fmt.Errorf("read maigret report: %w", err)
	}

	// The "simple" report is a map keyed by site name; it only lists FOUND
	// accounts, so any entry with a profile URL is a hit. Parse generically to
	// tolerate Maigret version differences.
	var report map[string]map[string]interface{}
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("parse maigret report: %w", err)
	}

	out := make([]models.OsintFinding, 0, len(report))
	for site, entry := range report {
		url, _ := entry["url_user"].(string)
		if url == "" {
			if u, ok := entry["url_main"].(string); ok {
				url = u
			}
		}
		if url == "" {
			continue
		}
		f := newFinding("maigret", "social",
			fmt.Sprintf("Account found on %s", site), url)
		// Tags (e.g. "porn", "coding", "dating") add useful context if present.
		if tags, ok := entry["tags"].([]interface{}); ok && len(tags) > 0 {
			parts := make([]string, 0, len(tags))
			for _, t := range tags {
				if s, ok := t.(string); ok {
					parts = append(parts, s)
				}
			}
			if len(parts) > 0 {
				f.Data = "tags: " + strings.Join(parts, ", ")
			}
		}
		out = append(out, f)
	}
	env.emit(fmt.Sprintf("[+] maigret: %d account(s) found across sites", len(out)))
	return out, nil
}

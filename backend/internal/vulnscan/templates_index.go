package vulnscan

import (
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Template-id index: nuclei's -id filters by a template's `id`, which for CVE
// templates equals the filename (CVE-YYYY-NNNN.yaml). We index the filenames so a
// per-CVE "Verify" or an ad-hoc -id run can be checked BEFORE launch — otherwise a
// non-existent id makes nuclei exit "no templates provided for scan", producing a
// confusing failed scan (common for JavaScript-library CVEs, which have no nuclei
// template).
var (
	tmplIdxMu   sync.Mutex
	tmplIdx     map[string]bool
	tmplIdxTime time.Time
)

// MissingTemplates returns the subset of ids with no matching template file.
// Best-effort: returns nil (blocks nothing) when the index can't be built or an id
// uses a wildcard.
func (e *Engine) MissingTemplates(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	idx := e.templateIndex()
	if len(idx) == 0 {
		return nil // templates dir unavailable — don't wrongly block
	}
	var missing []string
	for _, id := range ids {
		key := strings.ToLower(strings.TrimSpace(id))
		if key == "" || strings.ContainsAny(key, "*?") {
			continue // empty or wildcard — can't check by filename
		}
		if !idx[key] {
			missing = append(missing, id)
		}
	}
	return missing
}

// templateIndex builds (and caches for 30m) the set of template ids from the
// templates dir filenames.
func (e *Engine) templateIndex() map[string]bool {
	tmplIdxMu.Lock()
	defer tmplIdxMu.Unlock()
	if tmplIdx != nil && time.Since(tmplIdxTime) < 30*time.Minute {
		return tmplIdx
	}
	idx := map[string]bool{}
	if dir := e.nucleiTemplatesDir(); dir != "" {
		_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			name := d.Name()
			if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
				id := strings.TrimSuffix(strings.TrimSuffix(name, ".yml"), ".yaml")
				idx[strings.ToLower(id)] = true
			}
			return nil
		})
	}
	tmplIdx = idx
	tmplIdxTime = time.Now()
	return idx
}

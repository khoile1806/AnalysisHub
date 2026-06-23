package osint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/models"
)

// RelatedEntity is a pivot: an identifier discovered while investigating the
// target that the operator can launch a fresh investigation against.
type RelatedEntity struct {
	Type  string `json:"type"`  // ip|domain|email|phone
	Value string `json:"value"`
}

// newFinding builds an info-severity finding. Callers tweak Severity / Data /
// RelatedEntities afterwards as needed.
func newFinding(source, category, title, value string) models.OsintFinding {
	return models.OsintFinding{
		Source:   source,
		Category: category,
		Title:    title,
		Value:    value,
		Severity: "info",
	}
}

// withSource sets the discovery-source link (where the trace can be verified)
// on a finding and returns it. Empty/whitespace URLs are ignored.
func withSource(f models.OsintFinding, sourceURL string) models.OsintFinding {
	if s := strings.TrimSpace(sourceURL); s != "" {
		f.SourceURL = s
	}
	return f
}

// stampSource sets sourceURL on every finding that doesn't already carry its own
// discovery link, so a whole collector's output is traceable in one call.
func stampSource(fs []models.OsintFinding, sourceURL string) []models.OsintFinding {
	if strings.TrimSpace(sourceURL) == "" {
		return fs
	}
	for i := range fs {
		if fs[i].SourceURL == "" {
			fs[i].SourceURL = sourceURL
		}
	}
	return fs
}

// withRelated attaches pivot entities to a finding and returns it.
func withRelated(f models.OsintFinding, rel ...RelatedEntity) models.OsintFinding {
	cleaned := rel[:0]
	for _, r := range rel {
		r.Value = strings.TrimSpace(r.Value)
		if r.Value != "" {
			cleaned = append(cleaned, r)
		}
	}
	if len(cleaned) == 0 {
		return f
	}
	if b, err := json.Marshal(cleaned); err == nil {
		f.RelatedEntities = string(b)
	}
	return f
}

// dedupeKey is a deterministic identity for a finding within one scan, so the
// same trace surfaced twice (e.g. a hostname seen by both crt.sh and Shodan)
// collapses to a single row.
func dedupeKey(f *models.OsintFinding) string {
	parts := []string{
		strings.ToLower(strings.TrimSpace(f.Source)),
		strings.ToLower(strings.TrimSpace(f.Category)),
		strings.ToLower(strings.TrimSpace(f.Title)),
		strings.ToLower(strings.TrimSpace(f.Value)),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

// persistFindings dedupes in-memory, then skips inserts whose key already
// exists for this scan. Mirrors recon.persistFindings. Returns rows inserted.
func persistFindings(db *gorm.DB, findings []models.OsintFinding) int {
	if len(findings) == 0 {
		return 0
	}

	// 1. In-batch dedupe.
	seen := make(map[string]bool, len(findings))
	uniq := findings[:0]
	for _, f := range findings {
		k := dedupeKey(&f)
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		f.DedupeKey = k
		uniq = append(uniq, f)
	}
	if len(uniq) == 0 {
		return 0
	}

	// 2. Cross-collector dedupe - one query for all keys in this scan.
	scanID := uniq[0].ScanID
	keys := make([]string, 0, len(uniq))
	for _, f := range uniq {
		keys = append(keys, f.DedupeKey)
	}
	var existing []string
	db.Model(&models.OsintFinding{}).
		Where("scan_id = ? AND dedupe_key IN ?", scanID, keys).
		Pluck("dedupe_key", &existing)
	existingSet := make(map[string]bool, len(existing))
	for _, k := range existing {
		existingSet[k] = true
	}

	inserted := 0
	for i := range uniq {
		if existingSet[uniq[i].DedupeKey] {
			continue
		}
		if err := db.Create(&uniq[i]).Error; err == nil {
			inserted++
		}
	}
	return inserted
}

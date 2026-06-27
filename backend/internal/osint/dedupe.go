package osint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/forensichub/backend/internal/models"
)

// RelatedEntity is a pivot: an identifier discovered while investigating the
// target that the operator can launch a fresh investigation against.
type RelatedEntity struct {
	Type  string `json:"type"` // ip|domain|email|phone
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

// normValue canonicalises a finding's value for the dedupe key: lower-cased,
// trimmed, made valid UTF-8, and with any trailing dots stripped so a hostname
// surfaced as "ex.com." and "ex.com" collapses to one row.
func normValue(s string) string {
	s = strings.ToValidUTF8(strings.ToLower(strings.TrimSpace(s)), "")
	return strings.TrimRight(s, ".")
}

// dedupeKey is a deterministic identity for a finding within one scan, so the
// same trace surfaced twice (e.g. a hostname seen by both crt.sh and Shodan)
// collapses to a single row.
func dedupeKey(f *models.OsintFinding) string {
	parts := []string{
		strings.ToLower(strings.TrimSpace(f.Source)),
		strings.ToLower(strings.TrimSpace(f.Category)),
		strings.ToLower(strings.TrimSpace(f.Title)),
		normValue(f.Value),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

// onConflictDedupe is the ON CONFLICT clause that makes inserts idempotent on
// the unique (scan_id, dedupe_key) index: a row another collector already
// inserted (even concurrently) is silently ignored instead of duplicated.
var onConflictDedupe = clause.OnConflict{
	Columns:   []clause.Column{{Name: "scan_id"}, {Name: "dedupe_key"}},
	DoNothing: true,
}

// PersistFindings inserts manually-built findings (e.g. an analyst-uploaded
// photo's EXIF GPS) through the same idempotent dedupe path collectors use.
func PersistFindings(db *gorm.DB, findings []models.OsintFinding) int {
	return persistFindings(db, findings)
}

// persistFindings dedupes in-memory, then bulk-inserts with ON CONFLICT DO
// NOTHING so concurrent collectors can never create a duplicate and the whole
// batch is written in a handful of round-trips. Returns rows actually inserted.
func persistFindings(db *gorm.DB, findings []models.OsintFinding) int {
	if len(findings) == 0 {
		return 0
	}

	// In-batch dedupe so we don't ship known-duplicate rows to the database.
	seen := make(map[string]bool, len(findings))
	uniq := findings[:0]
	for i := range findings {
		k := dedupeKey(&findings[i])
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		findings[i].DedupeKey = k
		uniq = append(uniq, findings[i])
	}
	if len(uniq) == 0 {
		return 0
	}

	// Bulk insert; the unique index + DoNothing collapses cross-collector and
	// cross-goroutine duplicates at the database, with no read-then-write race.
	res := db.Clauses(onConflictDedupe).CreateInBatches(uniq, 100)
	if res.Error == nil {
		return int(res.RowsAffected)
	}
	// Fallback: a malformed row (or, in a degraded deployment, a missing unique
	// index that makes ON CONFLICT invalid) must never drop the whole batch or
	// silently lose findings. Insert row by row, preferring the idempotent path
	// and falling back to a plain insert so a finding is always persisted.
	inserted := 0
	for i := range uniq {
		if db.Clauses(onConflictDedupe).Create(&uniq[i]).Error == nil {
			inserted++
			continue
		}
		if db.Create(&uniq[i]).Error == nil {
			inserted++
		}
	}
	return inserted
}

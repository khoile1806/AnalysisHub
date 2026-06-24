package models

import (
	"time"

	"github.com/google/uuid"
)

// OsintStatus is the lifecycle state of an OSINT investigation.
type OsintStatus string

const (
	OsintPending OsintStatus = "pending"
	OsintRunning OsintStatus = "running"
	OsintDone    OsintStatus = "done"
	OsintStopped OsintStatus = "stopped"
	OsintFailed  OsintStatus = "failed"
)

// OsintCollectorStatus is the per-collector execution state. A collector is
// "skipped" when an optional API key it needs is not configured — distinct
// from "failed" so the UI can tell a missing-key from a real error.
type OsintCollectorStatus string

const (
	OsintCollectorPending OsintCollectorStatus = "pending"
	OsintCollectorRunning OsintCollectorStatus = "running"
	OsintCollectorDone    OsintCollectorStatus = "done"
	OsintCollectorFailed  OsintCollectorStatus = "failed"
	OsintCollectorSkipped OsintCollectorStatus = "skipped"
)

// OsintScan is one entity-footprinting investigation: a single target
// identifier (IP / domain / email / phone) passively profiled against many
// open-source intelligence collectors. It mirrors the shape of ReconScan but
// the work is in-process HTTP/DNS — no external tools, no forensic agent.
type OsintScan struct {
	ID         uuid.UUID   `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Name       string      `gorm:"not null"                                       json:"name"`
	Target     string      `gorm:"not null"                                       json:"target"`
	TargetType string      `gorm:"not null"                                       json:"target_type"` // ip|domain|email|phone
	Status     OsintStatus `gorm:"default:'pending'"                              json:"status"`

	// ── Investigation graph (auto-pivot) ─────────────────────────────────────
	// A scan belongs to an investigation rooted at RootScanID. Auto-pivoted
	// child scans link back via ParentScanID and carry the entity that spawned
	// them in PivotFrom, so the graph endpoint can draw the edges.
	RootScanID   *uuid.UUID `gorm:"type:uuid;index"        json:"root_scan_id,omitempty"`
	ParentScanID *uuid.UUID `gorm:"type:uuid;index"        json:"parent_scan_id,omitempty"`
	Depth        int        `gorm:"default:0"             json:"depth"`
	PivotFrom    string     `                             json:"pivot_from,omitempty"` // related-entity value that spawned this scan
	AutoPivot    bool       `gorm:"default:false"        json:"auto_pivot"`
	MaxDepth     int        `gorm:"default:0"             json:"max_depth"`

	// CaseID optionally files this investigation (and every auto-pivot child,
	// which inherits it) under a DFIR case so the whole graph stays grouped.
	CaseID *uuid.UUID `gorm:"type:uuid;index" json:"case_id,omitempty"`

	// WatchID is set when the scan was launched by a continuous-monitoring watch
	// (A4). Used to diff against the previous run and raise alerts on new traces.
	WatchID *uuid.UUID `gorm:"type:uuid;index" json:"watch_id,omitempty"`

	// ExposureScore (0-100) is the aggregate exposure of the target computed from
	// its findings (reputation + ransomware + breach + stealer). ExposureGrade is
	// the band: minimal | low | elevated | high | critical.
	ExposureScore int    `gorm:"default:0" json:"exposure_score"`
	ExposureGrade string `                 json:"exposure_grade,omitempty"`

	CreatedBy  uuid.UUID   `gorm:"type:uuid"                                      json:"created_by"`
	CreatedAt  time.Time   `                                                      json:"created_at"`
	UpdatedAt  time.Time   `                                                      json:"updated_at"`
	FinishedAt *time.Time  `                                                      json:"finished_at"`
	Collectors []OsintCollector `gorm:"foreignKey:ScanID;constraint:OnDelete:CASCADE" json:"collectors,omitempty"`
}

// OsintWatch is a continuous-monitoring rule (A4): it re-runs an OSINT
// investigation on a fixed interval and raises an alert whenever a NEW trace
// (subdomain, leaked credential, ransomware listing, malicious verdict…) appears
// since the previous run. Turns one-shot footprinting into ongoing surveillance.
type OsintWatch struct {
	ID              uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Name            string     `gorm:"not null"                                       json:"name"`
	Target          string     `gorm:"not null"                                       json:"target"`
	TargetType      string     `gorm:"not null"                                       json:"target_type"`
	IntervalMinutes int        `gorm:"default:1440"                                   json:"interval_minutes"` // default daily
	AutoPivot       bool       `gorm:"default:false"                                  json:"auto_pivot"`
	MaxDepth        int        `gorm:"default:0"                                      json:"max_depth"`
	CaseID          *uuid.UUID `gorm:"type:uuid;index"                                json:"case_id,omitempty"`
	Enabled         bool       `gorm:"default:true;index"                             json:"enabled"`
	LastScanID      *uuid.UUID `gorm:"type:uuid"                                      json:"last_scan_id,omitempty"`
	LastRunAt       *time.Time `                                                      json:"last_run_at"`
	NextRunAt       *time.Time `gorm:"index"                                          json:"next_run_at"`
	AlertCount      int        `gorm:"default:0"                                      json:"alert_count"` // unseen alerts
	CreatedBy       uuid.UUID  `gorm:"type:uuid"                                      json:"created_by"`
	CreatedAt       time.Time  `                                                      json:"created_at"`
	UpdatedAt       time.Time  `                                                      json:"updated_at"`
}

// OsintWatchAlert is a single new trace detected by a watch on a re-run.
type OsintWatchAlert struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	WatchID    uuid.UUID `gorm:"type:uuid;not null;index"                       json:"watch_id"`
	ScanID     uuid.UUID `gorm:"type:uuid;index"                                json:"scan_id"`
	Category   string    `                                                      json:"category"`
	Source     string    `                                                      json:"source"`
	Title      string    `                                                      json:"title"`
	Value      string    `gorm:"type:text"                                      json:"value"`
	Severity   string    `                                                      json:"severity"`
	Confidence string    `                                                      json:"confidence,omitempty"`
	Seen       bool      `gorm:"default:false;index"                            json:"seen"`
	CreatedAt  time.Time `                                                      json:"created_at"`
}

// OsintCollector tracks one data source run for a scan (rdap, dns, geoip, …).
type OsintCollector struct {
	ID            uuid.UUID            `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	ScanID        uuid.UUID            `gorm:"type:uuid;not null;index"                       json:"scan_id"`
	Name          string               `gorm:"not null"                                       json:"name"`
	Status        OsintCollectorStatus `gorm:"default:'pending'"                              json:"status"`
	FindingsCount int                  `gorm:"default:0"                                      json:"findings_count"`
	Error         string               `gorm:"type:text"                                      json:"error,omitempty"` // skip/fail reason
	StartedAt     *time.Time           `                                                      json:"started_at"`
	FinishedAt    *time.Time           `                                                      json:"finished_at"`
}

// OsintFinding is a single trace discovered for the target. RelatedEntities
// holds a JSON array of {type,value} pivots — discovered identifiers the
// operator can launch a fresh investigation against in one click.
type OsintFinding struct {
	ID              uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"                              json:"id"`
	ScanID          uuid.UUID `gorm:"type:uuid;not null;index:idx_osint_finding_scan" json:"scan_id"`
	CollectorID     uuid.UUID `gorm:"type:uuid"                                                                   json:"collector_id"`
	Source          string    `gorm:"not null"                                                                    json:"source"`   // rdap|dns|crtsh|geoip|...
	Category        string    `gorm:"not null"                                                                    json:"category"` // registration|dns|certificate|geolocation|ports|reputation|breach|historical|identity
	Title           string    `gorm:"not null"                                                                    json:"title"`
	Value           string    `gorm:"type:text"                                                                   json:"value"`
	Data            string    `gorm:"type:text"                                                                   json:"data,omitempty"` // optional extra JSON
	// SourceURL is the link to where the trace was discovered (e.g. the breach
	// search that surfaced a leaked credential), so an analyst can open the
	// origin directly. Empty when the source has no addressable location.
	SourceURL string `gorm:"type:text" json:"source_url,omitempty"`
	Severity        string    `                                                                                   json:"severity,omitempty"` // info|low|medium|high|critical
	// Confidence is the tool's self-verification verdict for the finding,
	// computed by cross-checking it against the scan's other collectors:
	// verified | likely | unverified | "" (not applicable). VerifyNote explains
	// what corroborated (or failed to corroborate) it.
	Confidence      string    `                                                                                   json:"confidence,omitempty"`
	VerifyNote      string    `gorm:"type:text"                                                                   json:"verify_note,omitempty"`
	RelatedEntities string    `gorm:"type:text"                                                                   json:"related_entities,omitempty"` // JSON [{type,value}]
	// DedupeKey is sha256 hex of (source|category|title|value) — collapses the
	// same trace surfaced twice within one scan to a single row. The composite
	// UNIQUE index (scan_id, dedupe_key) lets concurrent collectors insert with
	// ON CONFLICT DO NOTHING without ever creating a duplicate. It is created and
	// maintained by raw SQL in database.Init (not an AutoMigrate tag) so that, on
	// an existing database, a pre-existing non-unique index is reliably replaced
	// and a failure to build it can never abort application startup.
	DedupeKey string    `gorm:"type:varchar(64)" json:"-"`
	CreatedAt time.Time `                                                                  json:"created_at"`
}

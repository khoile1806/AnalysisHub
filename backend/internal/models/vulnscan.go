package models

import (
	"time"

	"github.com/google/uuid"
)

// VulnScanStatus is the lifecycle state of a vulnerability scan.
type VulnScanStatus string

const (
	VulnPending VulnScanStatus = "pending"
	VulnRunning VulnScanStatus = "running"
	VulnDone    VulnScanStatus = "done"
	VulnStopped VulnScanStatus = "stopped"
	VulnFailed  VulnScanStatus = "failed"
)

// VulnToolStatus is the per-tool execution state. "skipped" means the tool
// binary was not found on PATH (mirrors OSINT's optional-collector model), so
// the UI can distinguish a not-installed tool from a real failure.
type VulnToolStatus string

const (
	VulnToolPending VulnToolStatus = "pending"
	VulnToolRunning VulnToolStatus = "running"
	VulnToolDone    VulnToolStatus = "done"
	VulnToolFailed  VulnToolStatus = "failed"
	VulnToolSkipped VulnToolStatus = "skipped"
)

// VulnScan is one active vulnerability-scan run against a set of assets
// (IPs / domains / subdomains), typically harvested from an OSINT investigation.
// Unlike OSINT (passive, in-process HTTP/DNS) this runs external scanner binaries
// (httpx, nuclei) and is therefore admin-gated, scope-checked and routed through
// the configured egress proxy.
type VulnScan struct {
	ID     uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Name   string         `gorm:"not null"                                       json:"name"`
	Status VulnScanStatus `gorm:"default:'pending'"                            json:"status"`

	// SourceScanID links back to the OSINT investigation (root scan) whose
	// discovered assets seeded this scan, so the operator can trace provenance.
	SourceScanID *uuid.UUID `gorm:"type:uuid;index" json:"source_scan_id,omitempty"`
	// CaseID optionally files the scan (and its findings) under a DFIR case.
	CaseID *uuid.UUID `gorm:"type:uuid;index" json:"case_id,omitempty"`

	// Targets is the JSON array of asset strings (hosts/IPs) actually scanned,
	// after scope filtering. TargetCount caches its length for list views.
	Targets     string `gorm:"type:text" json:"targets,omitempty"`
	TargetCount int    `gorm:"default:0" json:"target_count"`

	// Tools is the JSON array of tool names in the pipeline (e.g. ["httpx","nuclei"]).
	Tools string `gorm:"type:text" json:"tools,omitempty"`
	// Severities is the CSV of nuclei severities requested (e.g. "low,medium,high,critical").
	Severities string `json:"severities,omitempty"`
	// Profile selects the scan breadth: quick | full | cve-only (maps to nuclei tags).
	Profile string `json:"profile,omitempty"`
	// Tags is an optional CSV of extra nuclei template tags to include.
	Tags string `json:"tags,omitempty"`
	// ProxyChoice is the requested egress route: tor (default) | direct.
	ProxyChoice string `json:"proxy_choice,omitempty"`
	// AllowPrivate opts into scanning private/loopback/link-local targets
	// (localhost, LAN, internal hosts). Off by default; the scope guard refuses
	// such targets unless this is explicitly set. Intended for authorized
	// internal/lab/CTF assessments — pair with Direct egress (a proxy/Tor exit
	// cannot reach your private ranges).
	AllowPrivate bool `json:"allow_private,omitempty"`
	// ProxyMode records how egress was ACTUALLY routed: tor | configured | outbound | direct.
	ProxyMode string `json:"proxy_mode,omitempty"`

	// Summary is a JSON object of severity → count, computed on finalize for fast
	// list rendering without scanning the findings table.
	Summary string `gorm:"type:text" json:"summary,omitempty"`

	CreatedBy  uuid.UUID  `gorm:"type:uuid" json:"created_by"`
	CreatedAt  time.Time  `                 json:"created_at"`
	UpdatedAt  time.Time  `                 json:"updated_at"`
	FinishedAt *time.Time `                 json:"finished_at,omitempty"`

	ToolRuns []VulnTool `gorm:"foreignKey:ScanID;constraint:OnDelete:CASCADE" json:"tool_runs,omitempty"`
}

// VulnTool tracks one scanner tool's run within a scan (httpx, nuclei).
type VulnTool struct {
	ID            uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	ScanID        uuid.UUID      `gorm:"type:uuid;not null;index"                       json:"scan_id"`
	Name          string         `gorm:"not null"                                       json:"name"`
	Status        VulnToolStatus `gorm:"default:'pending'"                              json:"status"`
	FindingsCount int            `gorm:"default:0"                                      json:"findings_count"`
	Error         string         `gorm:"type:text"                                      json:"error,omitempty"`
	// Command is the exact CLI invocation the engine ran for this tool (proxy
	// credentials redacted), so a saved scan can be reviewed/reproduced.
	Command    string     `gorm:"type:text" json:"command,omitempty"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
}

// VulnFinding is a single result emitted by a scanner. The nuclei fields
// (TemplateID, MatchedAt) are empty for httpx "live host" info rows.
type VulnFinding struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"  json:"id"`
	ScanID      uuid.UUID `gorm:"type:uuid;not null;index:idx_vuln_finding_scan" json:"scan_id"`
	ToolID      uuid.UUID `gorm:"type:uuid"                                      json:"tool_id"`
	Tool        string    `gorm:"not null"                                       json:"tool"` // httpx|nuclei
	TemplateID  string    `                                                      json:"template_id,omitempty"`
	Name        string    `gorm:"not null"                                       json:"name"`
	Severity    string    `gorm:"index"                                          json:"severity"` // info|low|medium|high|critical|unknown
	Host        string    `                                                      json:"host"`
	MatchedAt   string    `gorm:"type:text"                                      json:"matched_at,omitempty"`
	Type        string    `                                                      json:"type,omitempty"` // http|dns|tcp|...
	Description string    `gorm:"type:text"                                      json:"description,omitempty"`
	Reference   string    `gorm:"type:text"                                      json:"reference,omitempty"` // JSON array of refs
	Tags        string    `gorm:"type:text"                                      json:"tags,omitempty"`

	// CVE intelligence: when a nuclei finding carries a CVE id we cross-reference
	// the platform's EPSS (exploit-probability) and CISA-KEV (known-exploited)
	// data, so triage can prioritise what is actually being exploited in the wild
	// rather than raw severity alone.
	CVEID     string  `gorm:"index" json:"cve_id,omitempty"`
	EPSSScore float64 `             json:"epss_score,omitempty"` // 0..1 exploit probability
	IsKEV     bool    `gorm:"index" json:"is_kev"`               // in CISA Known-Exploited catalog

	// Confirmed is set by the automated verification pass (the template re-matched
	// on a second independent run) — distinguishes a corroborated finding from a
	// single-shot match, cutting false positives on the high-impact rows.
	Confirmed bool `json:"confirmed"`
	// Status is the operator triage state: open (default) | confirmed |
	// false_positive | fixed. Note is a free-text triage note.
	Status string `gorm:"index;default:'open'" json:"status"`
	Note   string `gorm:"type:text"            json:"note,omitempty"`

	Data string `gorm:"type:text" json:"data,omitempty"` // raw tool JSON line

	// DedupeKey is sha256 hex of (tool|template_id|matched_at|host). The composite
	// UNIQUE index (scan_id, dedupe_key) lets the streaming inserter use
	// ON CONFLICT DO NOTHING so re-emitted matches never duplicate. Built by raw
	// SQL in database.Init (see OsintFinding for the rationale).
	DedupeKey string    `gorm:"type:varchar(64)" json:"-"`
	CreatedAt time.Time `                        json:"created_at"`
}

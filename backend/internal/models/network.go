package models

import (
	"time"

	"github.com/google/uuid"
)

// NetworkScan is one PCAP network-traffic analysis. An uploaded capture is run
// through the Suricata sidecar (offline mode); the distilled result (flows, DNS,
// TLS/JA3, HTTP, ET-Open alerts, a host-flow graph) is stored as JSON, and the
// noteworthy connections are turned into findings (C2 by signature / reputation /
// IOC-store match). The raw pcap is registered in the Evidence Store.
type NetworkScan struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	FileName   string    `gorm:"not null"                                       json:"file_name"`
	StoredPath string    `                                                      json:"-"`
	Size       int64     `                                                      json:"size"`
	Sha256     string    `gorm:"index"                                          json:"sha256,omitempty"`

	Status string `gorm:"default:'pending';index" json:"status"` // pending|running|done|failed
	Error  string `gorm:"type:text"               json:"error,omitempty"`
	Steps  string `gorm:"type:text"               json:"steps"` // JSON []ChainStep

	Result   string `gorm:"type:text" json:"result,omitempty"`   // JSON distilled summary (stats/flows/dns/tls/http/files/graph)
	Findings string `gorm:"type:text" json:"findings,omitempty"` // JSON []NetworkFinding (alerts + C2)
	// NetworkAI is the on-demand AI analysis of the capture (its own verdict +
	// kill-chain narrative + ATT&CK + score card), separate from the deterministic
	// Suricata verdict — mirrors the malware feature's per-stage AI opinion.
	NetworkAI       string `gorm:"type:text" json:"network_ai,omitempty"`        // JSON NetVerdict
	NetworkAIStatus string `gorm:"index"     json:"network_ai_status,omitempty"` // ""|running|done|failed

	// AutoSummary is a plain-language narrative of the capture generated
	// automatically during the normal analysis (who talked to whom, when, how
	// often, what actions). AI-written when a provider is configured, otherwise a
	// deterministic template. Distinct from the on-demand NetworkAI verdict.
	AutoSummary     string `gorm:"type:text" json:"auto_summary,omitempty"`
	AutoSummaryKind string `json:"auto_summary_kind,omitempty"` // ai|heuristic

	Verdict     string `gorm:"index" json:"verdict"` // malicious|suspicious|benign|unknown
	ThreatScore int    `             json:"threat_score"`
	Summary     string `gorm:"type:text" json:"summary,omitempty"`
	AlertCount  int    `             json:"alert_count"`
	C2Count     int    `             json:"c2_count"`
	FlowCount   int    `             json:"flow_count"`

	CaseID     *uuid.UUID `gorm:"type:uuid;index" json:"case_id,omitempty"`
	CreatedBy  uuid.UUID  `gorm:"type:uuid"       json:"created_by"`
	CreatedAt  time.Time  `                       json:"created_at"`
	UpdatedAt  time.Time  `                       json:"updated_at"`
	FinishedAt *time.Time `                      json:"finished_at,omitempty"`
}

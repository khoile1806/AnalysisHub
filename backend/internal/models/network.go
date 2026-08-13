package models

import (
	"time"

	"github.com/google/uuid"
)

// NetworkSuricataRule is an operator-managed Suricata ruleset, the network-side
// twin of MalwareYaraRule. Intel arrives after the capture does, so a ruleset is
// compile-checked on upload and then replayed over the captures already stored —
// a rule that only ever applies to future traffic answers the wrong question.
type NetworkSuricataRule struct {
	ID      uint   `gorm:"primaryKey"         json:"id"`
	Name    string `gorm:"not null"           json:"name"`
	Content string `gorm:"type:text"          json:"content,omitempty"`
	Enabled bool   `gorm:"default:true;index" json:"enabled"`
	// SIDs / Msgs are the signature ids and messages declared by the ruleset,
	// extracted at upload time for the listing.
	SIDs string `gorm:"type:text" json:"sids,omitempty"` // JSON []string
	Msgs string `gorm:"type:text" json:"msgs,omitempty"` // JSON []string
	// Validated records whether Suricata itself accepted the ruleset. A rule that
	// does not parse is dropped silently at runtime, which reads like clean traffic.
	Validated bool       `                 json:"validated"`
	Source    string     `                 json:"source,omitempty"` // upload | paste
	Note      string     `gorm:"type:text" json:"note,omitempty"`
	CreatedBy uuid.UUID  `gorm:"type:uuid" json:"created_by"`
	CreatedAt time.Time  `                 json:"created_at"`
	UpdatedAt time.Time  `                 json:"updated_at"`
	HuntedAt  *time.Time `                 json:"hunted_at,omitempty"`
}

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

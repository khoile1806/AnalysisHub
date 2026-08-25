package models

import (
	"time"

	"github.com/google/uuid"
)

// AITokenUsage is one completion's token consumption.
//
// It exists because the previous accounting read `analysis_sessions.tokens_used`,
// which only the AI Analysis session ever wrote. Every other AI feature — malware
// synthesis, the dynamic re-synthesis, AI reverse engineering, whole-drop campaign
// analysis, OSINT triage, timeline extraction, compliance, case summaries — spent
// tokens that no panel could see. A per-completion ledger answers the questions an
// operator actually has about cost: which FEATURE is spending, on which provider,
// and is anything failing repeatedly (a failed call still bills its input).
type AITokenUsage struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`

	// ProviderID is a plain string, not a foreign key: the ledger is an accounting
	// record and must survive the provider being deleted or re-created. A total
	// that silently drops history when someone rotates a provider is worse than
	// useless for cost review.
	ProviderID string `gorm:"index"                                          json:"provider_id"`

	// Feature is "package.Function" of the code that asked — "malware.Synthesize",
	// "handlers.TriageOsintScan". Derived automatically so a new feature is
	// attributed without anyone remembering to register it.
	Feature string `gorm:"index" json:"feature"`

	InputTokens     int `json:"input_tokens"`
	OutputTokens    int `json:"output_tokens"`
	CacheReadTokens int `json:"cache_read_tokens"`
	// TotalTokens is stored rather than summed on read so the aggregate queries
	// that back the health panel stay a single indexed scan.
	TotalTokens int `gorm:"index" json:"total_tokens"`

	Success    bool `gorm:"index" json:"success"`
	DurationMS int  `             json:"duration_ms"`

	CreatedAt time.Time `gorm:"index" json:"created_at"`
}

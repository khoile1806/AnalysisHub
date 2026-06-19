package models

import (
	"time"

	"github.com/google/uuid"
)

// ELKHuntResult persists the output of a single ELK threat-hunt run so that
// results can be reviewed later and sent to AI analysis. Previously, hunt
// results were streamed via SSE and lost when the connection closed.
type ELKHuntResult struct {
	ID         uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	ConfigID   uint       `gorm:"index"                                          json:"config_id"`
	Title      string     `                                                      json:"title"`
	IOCsUsed   int        `                                                      json:"iocs_used"`
	TotalHits  int        `                                                      json:"total_hits"`
	Results    string     `gorm:"type:text"                                      json:"results"` // JSON array of hit batches
	Status     string     `gorm:"default:'running'"                              json:"status"` // running|done|failed
	// Triage holds the AI-generated triage (ranked clusters) as a JSON string.
	// It is an assessment layer on top of the deterministic hits in Results —
	// never a substitute for them. Empty until /triage is run.
	Triage     string     `gorm:"type:text"                                      json:"triage,omitempty"`
	TriagedAt  *time.Time `                                                      json:"triaged_at,omitempty"`
	CreatedBy  uuid.UUID  `gorm:"type:uuid"                                      json:"created_by"`
	CreatedAt  time.Time  `                                                      json:"created_at"`
	FinishedAt *time.Time `                                                      json:"finished_at,omitempty"`
}

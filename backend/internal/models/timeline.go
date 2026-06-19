package models

import (
	"time"

	"github.com/google/uuid"
)

// TimelineEvent is a single point on a case's reconstructed attack timeline.
// Unlike the operational "activity timeline" (when WE collected evidence), each
// event here carries EventTime — the real time the attacker activity occurred,
// extracted from the evidence itself (ELK log hits, AI analysis, or manual entry).
type TimelineEvent struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	CaseID    uuid.UUID `gorm:"type:uuid;not null;index"                       json:"case_id"`
	EventTime time.Time `gorm:"not null;index"                                 json:"event_time"`

	// Source: where the event came from — "manual" | "elk" | "ai" | "job".
	Source string `gorm:"not null;default:'manual'" json:"source"`
	// SourceRef links back to the origin record (ELK hit id, AI session id, job id).
	SourceRef string `json:"source_ref,omitempty"`

	Host string `json:"host,omitempty"` // endpoint the activity was observed on

	// MITRE ATT&CK mapping (optional).
	Tactic    string `json:"tactic,omitempty"`    // e.g. "initial-access", "execution", "persistence"
	Technique string `json:"technique,omitempty"` // e.g. "T1059"

	// Severity: critical | high | medium | low | info.
	Severity string `gorm:"default:'info'" json:"severity"`

	Title  string `gorm:"not null" json:"title"`
	Detail string `gorm:"type:text" json:"detail,omitempty"`

	// Attachments: JSON array of evidence files / images / links enriching the
	// node. Element shape: { "type": "evidence"|"link", "evidence_id": "...",
	// "url": "...", "label": "...", "is_image": true }.
	Attachments string `gorm:"type:text" json:"attachments,omitempty"`

	CreatedBy uuid.UUID `gorm:"type:uuid" json:"created_by"`
	CreatedAt time.Time `                 json:"created_at"`
	UpdatedAt time.Time `                 json:"updated_at"`
}

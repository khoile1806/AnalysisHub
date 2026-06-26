package models

import (
	"time"

	"github.com/google/uuid"
)

// AgentBaseline stores a known-good snapshot of an endpoint artifact (e.g. its
// autoruns / persistence set) so later scans can be diffed against it to surface
// DRIFT — new autostart entries that appeared since the baseline, a classic
// persistence-detection signal. One baseline per (agent, kind); re-saving
// overwrites it.
type AgentBaseline struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	AgentID   uuid.UUID `gorm:"type:uuid;index:idx_agent_baseline,unique;not null" json:"agent_id"`
	Kind      string    `gorm:"index:idx_agent_baseline,unique;not null" json:"kind"` // e.g. "autoruns"
	Data      string    `gorm:"type:text" json:"data"`                               // JSON snapshot
	CreatedBy uuid.UUID `gorm:"type:uuid" json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

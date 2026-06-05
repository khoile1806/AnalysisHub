package models

import (
	"time"

	"github.com/google/uuid"
)

// ChecklistRun represents one Evidence Collection session dispatched to an agent.
type ChecklistRun struct {
	ID        uuid.UUID        `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	AgentID   uuid.UUID        `gorm:"type:uuid;not null;index"                       json:"agent_id"`
	Label     string           `                                                      json:"label"`
	Platform  string           `                                                      json:"platform"`  // "win" | "linux"
	CaseID    string           `                                                      json:"case_id"`
	Analyst   string           `                                                      json:"analyst"`
	Status    string           `gorm:"default:'running'"                              json:"status"`    // running|done|failed
	Batches   []ChecklistBatch `gorm:"foreignKey:RunID"                               json:"batches,omitempty"`
	CreatedBy uuid.UUID        `gorm:"type:uuid"                                      json:"created_by"`
	CreatedAt time.Time        `                                                      json:"created_at"`
	UpdatedAt time.Time        `                                                      json:"updated_at"`
}

// ChecklistBatch is one subsection group (e.g. "1.2 Network State") dispatched
// as a single cmd_exec command. Multiple batches from the same run are dispatched
// simultaneously for parallel execution on the agent.
type ChecklistBatch struct {
	ID         uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	RunID      uuid.UUID  `gorm:"type:uuid;not null;index"                       json:"run_id"`
	AgentID    uuid.UUID  `gorm:"type:uuid;not null"                             json:"agent_id"`
	BatchKey   string     `                                                      json:"batch_key"`   // "1.2"
	BatchLabel string     `                                                      json:"batch_label"` // "Network State"
	ItemIDs    string     `gorm:"type:text"                                      json:"item_ids"`    // JSON array of item IDs
	Command    string     `gorm:"type:text"                                      json:"command"`     // combined command sent to agent
	Platform   string     `                                                      json:"platform"`
	Status     string     `gorm:"default:'pending'"                              json:"status"` // pending|running|done|failed|stopped
	Output     string     `gorm:"type:text"                                      json:"output,omitempty"`
	StartedAt  *time.Time `                                                      json:"started_at"`
	FinishedAt *time.Time `                                                      json:"finished_at"`
	CreatedAt  time.Time  `                                                      json:"created_at"`
	UpdatedAt  time.Time  `                                                      json:"updated_at"`
}

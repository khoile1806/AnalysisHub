package models

import (
	"time"

	"github.com/google/uuid"
)

// ScheduledCollection runs a forensic collection (an EdgeForensics command)
// against a fleet selection on a fixed interval — e.g. "every morning collect a
// process+autoruns snapshot from all servers" — so drift from a known-good
// baseline is caught without manual per-host work.
type ScheduledCollection struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Name       string    `gorm:"not null"                                       json:"name"`
	Collection string    `gorm:"not null"                                       json:"collection"` // mft|prefetch|processes|autoruns|netconn|dlls|shimcache|registry|evtx

	// Selector — agents matched by ANY of: explicit IDs, group, or a tag.
	// All stored as JSON/text so one schedule can target a whole group.
	AgentIDs string `gorm:"type:text" json:"agent_ids"` // JSON array of UUID strings
	Group    string `                 json:"group"`
	Tag      string `                 json:"tag"`

	IntervalMinutes int        `gorm:"not null;default:1440" json:"interval_minutes"` // default daily
	Enabled         bool       `gorm:"default:true"          json:"enabled"`
	LastRun         *time.Time `                             json:"last_run"`
	NextRun         *time.Time `                             json:"next_run"`

	CreatedBy uuid.UUID `gorm:"type:uuid" json:"created_by"`
	CreatedAt time.Time `                 json:"created_at"`
	UpdatedAt time.Time `                 json:"updated_at"`
}

// FleetCollectionResult is the outcome of one collection dispatched to one agent
// (by a bulk operation or a ScheduledCollection). It persists the agent's
// returned artifact JSON so results can be reviewed asynchronously rather than
// being streamed once and lost.
type FleetCollectionResult struct {
	ID          uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	ScheduledID *uuid.UUID `gorm:"type:uuid;index"                                json:"scheduled_id,omitempty"`
	AgentID     uuid.UUID  `gorm:"type:uuid;index;not null"                       json:"agent_id"`
	AgentName   string     `                                                      json:"agent_name"`
	Collection  string     `gorm:"not null"                                       json:"collection"`
	Status      string     `gorm:"default:'pending'"                              json:"status"` // pending|done|error|offline|timeout
	Error       string     `                                                      json:"error,omitempty"`
	Data        string     `gorm:"type:text"                                      json:"data,omitempty"` // raw artifact JSON (omitted from list views)
	StartedAt   time.Time  `                                                      json:"started_at"`
	FinishedAt  *time.Time `                                                      json:"finished_at,omitempty"`
}

package models

import (
	"time"

	"github.com/google/uuid"
)

// SystemEvent is a persisted record of a self-healing / health signal — an
// updater failure, a recovered worker panic, an auto-failed stuck job, an agent
// resource threshold breach, a retention prune, etc. It survives restarts (unlike
// the in-memory updater status) so the System Health view can show what the
// platform detected and auto-remediated. Repeated identical events are collapsed
// (Count is incremented) to avoid flooding.
type SystemEvent struct {
	ID       uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Category string    `gorm:"index"                                         json:"category"` // updater|worker|job|agent|retention|security
	Severity string    `gorm:"index"                                         json:"severity"` // info|warn|error
	Source   string    `                                                     json:"source"`   // component / worker / agent name
	Message  string    `                                                     json:"message"`
	Detail   string    `gorm:"type:text"                                     json:"detail,omitempty"`
	Count    int       `gorm:"default:1"                                     json:"count"` // number of collapsed repeats

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

package models

import (
	"time"

	"github.com/google/uuid"
)

// LogIngestJob tracks one uploaded log file as it is parsed and bulk-indexed
// into the built-in Elasticsearch store. One row per file; the frontend polls
// the list while any job is queued/running.
type LogIngestJob struct {
	ID           uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Case         string     `gorm:"index"                                          json:"case"`
	CaseID       *uuid.UUID `gorm:"type:uuid;index"                                json:"case_id,omitempty"` // optional link to a Case
	Filename     string     `                                                      json:"filename"`
	LogType      string     `                                                      json:"log_type"`      // requested type (auto|evtx|…)
	Timezone     string     `                                                      json:"timezone"`      // source TZ for undated logs (syslog)
	DetectedType string     `                                                      json:"detected_type"` // resolved after detection
	Index        string     `                                                      json:"index"`         // target hunt-* index(es)
	FileHash     string     `gorm:"index"                                          json:"file_hash"`     // sha256 of upload (dedup)
	Status       string     `gorm:"default:'queued';index"                         json:"status"`        // queued|running|done|error|skipped
	DocsIndexed  int        `                                                      json:"docs_indexed"`
	DocsFailed   int        `                                                      json:"docs_failed"`
	Message      string     `gorm:"type:text"                                      json:"message"`
	StoredPath   string     `                                                      json:"-"` // relative path in storage
	CreatedBy    uuid.UUID  `gorm:"type:uuid"                                      json:"created_by"`
	CreatedAt    time.Time  `                                                      json:"created_at"`
	FinishedAt   *time.Time `                                                      json:"finished_at,omitempty"`
}

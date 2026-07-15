package models

import (
	"time"

	"github.com/google/uuid"
)

// ToolResult is a single result file collected from an agent after a tool job
// ran, plus the outcome of the server-side raw-data processing step. One row per
// collected file so each can be selected (or not) for AI analysis independently.
type ToolResult struct {
	ID       uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	JobID    uuid.UUID `gorm:"type:uuid;index;not null"                       json:"job_id"`
	AgentID  uuid.UUID `gorm:"type:uuid;index"                                json:"agent_id"`
	ToolID   uuid.UUID `gorm:"type:uuid"                                      json:"tool_id"`
	ToolName string    `                                                      json:"tool_name"`

	FileName  string `gorm:"not null"     json:"file_name"`  // original result filename on the endpoint
	Kind      string `                    json:"kind"`       // report|table|json|text-log|image|archive|other
	Processor string `                    json:"processor"`  // parser used (text|csv|json|loki|redline|kape|none)
	SizeBytes int64  `                    json:"size_bytes"`
	Sha256    string `gorm:"index"        json:"sha256"`     // integrity hash computed by the agent

	// Async processing status (the raw-data processing step runs off-request).
	ProcessStatus string `gorm:"default:'queued';index" json:"process_status"` // queued|processing|done|error
	ProcessError  string `gorm:"type:text"              json:"process_error"`

	RawStoredPath    string `gorm:"column:raw_stored_path"    json:"-"` // relative path to the raw uploaded file
	ParsedStoredPath string `gorm:"column:parsed_stored_path" json:"-"` // relative path to normalized output (empty if none)
	RowCount         int    `                                 json:"row_count"`
	Summary          string `gorm:"type:text"                 json:"summary"` // short human/AI preview

	ForAI    bool   `                json:"for_ai"`    // include in AI analysis
	AIStatus string `gorm:"default:'pending'" json:"ai_status"` // pending|done|skipped|error

	// Provenance (chain-of-custody): what produced this file.
	Cmdline     string `gorm:"type:text" json:"cmdline,omitempty"`      // resolved command the agent ran
	ExitCode    int    `                 json:"exit_code"`              // 0 = completed, non-zero = executor error
	ToolVersion string `                 json:"tool_version,omitempty"`  // filled server-side from the Tool record

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

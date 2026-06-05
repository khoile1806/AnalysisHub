package models

import (
	"time"

	"github.com/google/uuid"
)

// JobStatus represents the lifecycle state of a job.
type JobStatus string

const (
	JobPending JobStatus = "pending"
	JobReady   JobStatus = "ready"
	JobRunning JobStatus = "running"
	JobDone    JobStatus = "done"
	JobFailed  JobStatus = "failed"
	JobStopped JobStatus = "stopped"
)

// Job represents a task dispatched to an agent to execute a tool.
type Job struct {
	ID           uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	AgentID      uuid.UUID  `gorm:"type:uuid;not null"                             json:"agent_id"`
	Agent        Agent      `gorm:"foreignKey:AgentID"                             json:"agent,omitempty"`
	ToolID       uuid.UUID  `gorm:"type:uuid;not null"                             json:"tool_id"`
	Tool         Tool       `gorm:"foreignKey:ToolID"                              json:"tool,omitempty"`
	Args         string     `                                                      json:"args"`
	DeploymentID *uuid.UUID `gorm:"type:uuid;index"                                json:"deployment_id,omitempty"` // set when job is part of a hunting scenario batch deploy
	Status       JobStatus  `gorm:"default:'pending'"                              json:"status"`
	Output       string     `gorm:"type:text"                                      json:"output,omitempty"`
	ArtifactPath string     `                                                      json:"artifact_path,omitempty"` // path to uploaded artifact
	StartedAt     *time.Time `                                                      json:"started_at"`
	FinishedAt    *time.Time `                                                      json:"finished_at"`
	CreatedBy     uuid.UUID  `gorm:"type:uuid"                                      json:"created_by"`
	CreatedByUser *User      `gorm:"foreignKey:CreatedBy"                           json:"created_by_user,omitempty"`
	CreatedAt     time.Time  `                                                      json:"created_at"`
	UpdatedAt     time.Time  `                                                      json:"updated_at"`
}

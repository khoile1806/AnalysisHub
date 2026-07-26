package models

import (
	"time"

	"github.com/google/uuid"
)

// AuditLog records every significant action performed by users or agents.
type AuditLog struct {
	ID        uint       `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID    *uuid.UUID `gorm:"type:uuid"                json:"user_id"`
	AgentID   *uuid.UUID `gorm:"type:uuid"                json:"agent_id"`
	Action    string     `gorm:"not null"                 json:"action"`   // e.g. "tool.upload", "job.create", "agent.register"
	Resource  string     `                                json:"resource"`
	Detail    string     `gorm:"type:text"                json:"detail"`
	IP        string     `                                json:"ip"`
	// UserAgent identifies the client the action came from (browser/tool), and
	// Forwarded preserves the raw X-Forwarded-For chain so the real origin is
	// recoverable even when a proxy sits in front and IP resolves to the gateway.
	UserAgent string     `gorm:"type:text"                json:"user_agent,omitempty"`
	Forwarded string     `                                json:"forwarded,omitempty"`
	CreatedAt time.Time  `                                json:"created_at"`
}

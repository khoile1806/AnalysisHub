package models

import (
	"time"

	"github.com/google/uuid"
)

// Tool represents a forensic tool binary stored on the server.
type Tool struct {
	ID             uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Name           string    `gorm:"not null"                                       json:"name"`
	Category       string    `gorm:"not null"                                       json:"category"` // memory|triage|process|network|disk|log|other
	Platform       string    `gorm:"not null"                                       json:"platform"` // windows|linux|both
	Version        string    `                                                      json:"version"`
	Description    string    `                                                      json:"description"`
	FileName       string    `gorm:"not null"                                       json:"file_name"` // stored filename on disk
	FileSize       int64     `                                                      json:"file_size"`
	Args           string    `                                                      json:"args"`             // default CLI args
	ExecutablePath string    `gorm:"column:entrypoint"                              json:"executable_path"` // relative path to executable within tool dir
	CreatedBy      uuid.UUID `gorm:"type:uuid"                                      json:"created_by"`
	CreatedAt      time.Time `                                                      json:"created_at"`
	UpdatedAt      time.Time `                                                      json:"updated_at"`
}
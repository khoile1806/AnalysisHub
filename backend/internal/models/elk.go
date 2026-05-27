package models

import (
	"time"
)

// ELKConfig holds the integration configuration for an Elasticsearch/ELK
// cluster. Multiple profiles may exist; exactly one is marked IsActive and
// used by hunts. Passwords and API keys are encrypted before saving.
type ELKConfig struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Name        string    `json:"name" gorm:"not null"`
	Description string    `json:"description"`
	URL         string    `json:"url"`
	Username    string    `json:"username"`
	Password    string    `json:"-"` // Encrypted, never sent raw to client
	APIKey      string    `json:"-"` // Encrypted, never sent raw to client
	IsActive    bool      `json:"is_active" gorm:"index;default:false"`
	HasAuth     bool      `json:"has_auth" gorm:"-"` // Sent to client to indicate auth exists
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

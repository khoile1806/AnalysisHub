package models

import (
	"time"
)

// ELKConfig holds the integration configuration for Elasticsearch/ELK.
// Passwords and API keys are encrypted before saving.
type ELKConfig struct {
	ID        uint      `json:"-" gorm:"primaryKey"`
	URL       string    `json:"url"`
	Username  string    `json:"username"`
	Password  string    `json:"-"`     // Encrypted, never sent raw to client
	APIKey    string    `json:"-"`     // Encrypted, never sent raw to client
	HasAuth   bool      `json:"has_auth" gorm:"-"` // Sent to client to indicate auth exists
	UpdatedAt time.Time `json:"updated_at"`
}

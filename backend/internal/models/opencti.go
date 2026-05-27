package models

import (
	"time"
)

// OpenCTIConfig holds the integration configuration for an OpenCTI instance.
// Multiple profiles may exist; exactly one is marked IsActive and used by the
// Sync endpoint. Passwords and Tokens are encrypted before saving.
type OpenCTIConfig struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Name        string    `json:"name" gorm:"not null"`
	Description string    `json:"description"`
	URL         string    `json:"url"`
	Username    string    `json:"username"`
	Password    string    `json:"-"` // Encrypted, never sent raw to client
	Token       string    `json:"-"` // Encrypted, never sent raw to client
	IsActive    bool      `json:"is_active" gorm:"index;default:false"`
	HasAuth     bool      `json:"has_auth" gorm:"-"` // Sent to client to indicate auth exists
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// IOC represents an Indicator of Compromise synced from OpenCTI or other sources.
type IOC struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Value       string    `json:"value" gorm:"uniqueIndex:idx_ioc_value_type;not null"`
	Type        string    `json:"type" gorm:"uniqueIndex:idx_ioc_value_type;not null"` // e.g. IPv4-Addr, Domain-Name, File-Hash
	Source      string    `json:"source"`                                              // e.g. OpenCTI
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

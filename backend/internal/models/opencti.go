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

	// ── Provenance and trust ────────────────────────────────────────────────
	// Confidence is 0-100. An indicator pulled from a public blocklist and one
	// carved out of a confirmed incident are not equally actionable, and without
	// a number to separate them every match arrives with the same weight.
	Confidence int `json:"confidence" gorm:"default:50"`
	// TLP governs onward sharing. The malware exports already carry one; the
	// store did not, so an indicator's sharing terms were lost the moment it was
	// stored.
	TLP string `json:"tlp" gorm:"default:'amber'"`
	// Reference is where this came from — a report URL, a case ID, a pulse.
	Reference string `json:"reference"`
	// Campaign and ATTCK link the indicator to what it belongs to, which is what
	// turns a list of strings into intelligence.
	Campaign string `json:"campaign"`
	ATTCK    string `json:"attck"` // comma-separated technique IDs

	// ── Lifecycle ───────────────────────────────────────────────────────────
	// FirstSeen/LastSeen bracket the observation window. CreatedAt only recorded
	// when the row was written, which says nothing about when the indicator was
	// active.
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// ExpiresAt ages an indicator out. A C2 address is reassigned within weeks
	// and then belongs to somebody else; without expiry the store keeps matching
	// on it forever and every match is a false positive that costs an analyst
	// real time.
	ExpiresAt *time.Time `json:"expires_at" gorm:"index"`
	// Enabled lets an indicator be retired without losing the record of it —
	// deleting a noisy IOC also deletes the evidence of why it was added.
	Enabled bool `json:"enabled" gorm:"default:true;index"`

	// ── Value in practice ───────────────────────────────────────────────────
	// HitCount and LastHitAt say which indicators actually earn their place. A
	// store nobody prunes is mostly indicators that have never matched anything,
	// and there was no way to tell those from the ones that do the work.
	HitCount  int        `json:"hit_count" gorm:"default:0;index"`
	LastHitAt *time.Time `json:"last_hit_at"`
}

// Active reports whether the indicator should still be matched against.
func (i IOC) Active(now time.Time) bool {
	if !i.Enabled {
		return false
	}
	return i.ExpiresAt == nil || i.ExpiresAt.After(now)
}

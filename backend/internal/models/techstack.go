package models

import (
	"time"

	"github.com/google/uuid"
)

// TechStackSession persists one Tech-Stack lookup so each run becomes browsable
// history instead of being lost when the page changes. It is keyed (per user) by
// URL + options, so re-running a target refreshes its session rather than piling
// up duplicates. Result holds the full JSON response, replayed when reopened.
type TechStackSession struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	CreatedBy uuid.UUID `gorm:"type:uuid;index"                                json:"created_by"`
	URL       string    `gorm:"not null"                                       json:"url"`
	Host      string    `gorm:"index"                                          json:"host"`
	Title     string    `                                                      json:"title"`
	Active    bool      `                                                      json:"active"`
	Deep      bool      `                                                      json:"deep"`

	// Summary columns shown in the session list without loading the full result.
	RiskScore int    `json:"risk_score"`
	RiskLevel string `json:"risk_level"`
	TechCount int    `json:"tech_count"`
	CVETotal  int    `json:"cve_total"`
	Critical  int    `json:"critical"`
	KEV       int    `json:"kev"`
	Exploit   int    `json:"exploit"`

	// Result is the full techStackResponse JSON, returned when a session is opened.
	Result string `gorm:"type:jsonb" json:"-"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

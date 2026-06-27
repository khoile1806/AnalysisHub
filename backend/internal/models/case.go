package models

import (
	"time"

	"github.com/google/uuid"
)

// Case represents an investigation case.
type Case struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Name        string    `gorm:"not null"                                       json:"name"`
	Description string    `                                                      json:"description"`
	Status      string    `gorm:"default:'open'"                                 json:"status"` // open | closed
	// Summary is the latest AI-drafted executive narrative for the incident
	// report (regenerated on demand); empty until generated.
	Summary     string    `gorm:"type:text"                                      json:"summary,omitempty"`
	CreatedBy   uuid.UUID `gorm:"type:uuid"                                      json:"created_by"`
	CreatedAt   time.Time `                                                      json:"created_at"`
	UpdatedAt   time.Time `                                                      json:"updated_at"`

	Agents []Agent `gorm:"foreignKey:CaseID" json:"agents,omitempty"`
}

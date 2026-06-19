package models

import (
	"time"

	"github.com/google/uuid"
)

// CaseEvidence is a result/evidence file uploaded into a case for timeline
// reconstruction. Each file is attributed to a specific host (machine) so the
// extracted timeline events carry correct host context.
type CaseEvidence struct {
	ID       uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	CaseID   uuid.UUID `gorm:"type:uuid;not null;index"                       json:"case_id"`
	Host     string    `gorm:"not null"                                       json:"host"` // machine the result belongs to
	FileName string    `gorm:"not null"                                       json:"file_name"`
	StoredPath string  `                                                      json:"-"` // relative path on disk
	Size       int64   `                                                      json:"size"`
	Notes      string  `                                                      json:"notes,omitempty"`

	// Extracted: how many timeline events have been pulled from this file (info).
	Extracted bool `gorm:"default:false" json:"extracted"`

	UploadedBy uuid.UUID `gorm:"type:uuid" json:"uploaded_by"`
	CreatedAt  time.Time `                 json:"created_at"`
}

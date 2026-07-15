package models

import (
	"time"

	"github.com/google/uuid"
)

// CaseEvidence is a result/evidence file in the central Evidence Store. Files
// enter the store from several sources (manual upload, auto-collected tool
// results, checklist runs, edge-forensics scans); each is attributed to a host
// so extracted timeline events carry correct host context. CaseID is optional —
// the store holds agent evidence even before it is tied to an investigation.
type CaseEvidence struct {
	ID      uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	CaseID  *uuid.UUID `gorm:"type:uuid;index"                                json:"case_id,omitempty"`
	AgentID *uuid.UUID `gorm:"type:uuid;index"                                json:"agent_id,omitempty"`
	Host    string     `                                                      json:"host"` // machine the result belongs to

	// Kind classifies the origin of the evidence so the store can be filtered:
	// upload | tool-result | checklist | edge-forensics.
	Kind   string `gorm:"default:'upload';index" json:"kind"`
	Source string `                              json:"source,omitempty"` // e.g. "edge-forensics:processes", "checklist:<label>", tool name

	FileName   string `gorm:"not null" json:"file_name"`
	StoredPath string `                json:"-"` // relative path on disk
	Size       int64  `                json:"size"`
	Sha256     string `gorm:"index"    json:"sha256,omitempty"`
	Notes      string `                json:"notes,omitempty"`

	// Extracted: whether timeline events have been pulled from this file (info).
	Extracted bool `gorm:"default:false" json:"extracted"`

	UploadedBy uuid.UUID `gorm:"type:uuid" json:"uploaded_by"`
	CreatedAt  time.Time `                 json:"created_at"`
}

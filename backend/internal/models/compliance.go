package models

import (
	"time"

	"github.com/google/uuid"
)

// ComplianceFinding is one assessed control for a case: the result of an AI (or
// manual) evaluation of a compliance check's output against its expected
// baseline. Findings power the coverage matrix and the compliance report.
type ComplianceFinding struct {
	ID     uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	CaseID uuid.UUID `gorm:"type:uuid;not null;index"                       json:"case_id"`

	ItemID     string `json:"item_id"`              // checklist item id (e.g. "c-iam-w1")
	Control    string `json:"control"`              // control mapping (e.g. "ISO A.9.4.3 · PCI 8.2")
	Frameworks string `json:"frameworks"`           // comma-joined (e.g. "ISO 27001,PCI-DSS")
	Title      string `gorm:"not null" json:"title"` // the check label
	Host       string `json:"host,omitempty"`

	// Status: compliant | non_compliant | partial | na
	Status string `gorm:"default:'na'" json:"status"`
	// Severity: critical | high | medium | low | info
	Severity    string `gorm:"default:'info'" json:"severity"`
	Rationale   string `gorm:"type:text"      json:"rationale"`   // why this verdict
	Remediation string `gorm:"type:text"      json:"remediation"` // how to fix
	Evidence    string `gorm:"type:text"      json:"evidence"`     // captured output (truncated)

	// #4 Evidence integrity — SHA-256 of the evidence at assessment time.
	EvidenceHash string `json:"evidence_hash,omitempty"`

	// #6 POA&M (Plan of Action & Milestones) — remediation tracking.
	Owner             string     `json:"owner,omitempty"`
	DueDate           *time.Time `json:"due_date,omitempty"`
	RemediationStatus string     `gorm:"default:'open'" json:"remediation_status"` // open | in_progress | resolved | accepted_risk

	// Source: "ai" | "manual"
	Source    string    `gorm:"default:'ai'" json:"source"`
	CreatedBy uuid.UUID `gorm:"type:uuid"    json:"created_by"`
	CreatedAt time.Time `                    json:"created_at"`
	UpdatedAt time.Time `                    json:"updated_at"`
}

// ComplianceSnapshot captures the aggregate posture of a case at one assessment
// point, enabling drift detection (score trend across periodic audits).
type ComplianceSnapshot struct {
	ID      uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	CaseID  uuid.UUID `gorm:"type:uuid;not null;index"                       json:"case_id"`
	Total   int       `json:"total"`
	Pass    int       `json:"pass"`
	Fail    int       `json:"fail"`
	Partial int       `json:"partial"`
	NA      int       `json:"na"`
	Score   int       `json:"score"`
	CreatedAt time.Time `json:"created_at"`
}

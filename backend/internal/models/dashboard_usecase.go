package models

import (
	"time"

	"github.com/google/uuid"
)

// DashboardUsecase is a saved, incident-type-specific dashboard view. It lets an
// analyst switch the Overview screen to a layout tailored to the kind of
// incident being worked (webshell, ransomware, …): which widgets to show plus a
// short playbook of what to collect/analyse.
type DashboardUsecase struct {
	ID           uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Name         string    `gorm:"not null"                                       json:"name"`
	Slug         string    `gorm:"uniqueIndex"                                    json:"slug"`
	IncidentType string    `                                                      json:"incident_type"` // webshell | ransomware | data-breach | generic | custom
	Description  string    `                                                      json:"description"`
	Icon         string    `                                                      json:"icon"`  // lucide icon name
	Color        string    `                                                      json:"color"` // tailwind token

	// Widgets: JSON array of enabled widget keys (see frontend widget catalog).
	Widgets string `gorm:"type:text" json:"widgets"`
	// Playbook: free-form markdown — what evidence to collect / how to analyse.
	Playbook string `gorm:"type:text" json:"playbook"`

	SortOrder int       `gorm:"default:0" json:"sort_order"`
	CreatedBy uuid.UUID `gorm:"type:uuid" json:"created_by"`
	CreatedAt time.Time `                 json:"created_at"`
	UpdatedAt time.Time `                 json:"updated_at"`
}

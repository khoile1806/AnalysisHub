package models

import (
	"time"

	"github.com/google/uuid"
)

// Agent represents a remote forensic agent installed on an endpoint.
type Agent struct {
	ID          uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Name        string     `gorm:"not null"                                       json:"name"`
	Token       string     `gorm:"uniqueIndex;not null"                           json:"token,omitempty"` // pre-shared auth token; omitted after creation
	Hostname    string     `                                                      json:"hostname"`
	OS          string     `                                                      json:"os"`
	IPAddress   string     `                                                      json:"ip_address"`
	Status      string     `gorm:"default:'offline'"                              json:"status"` // online | offline
	Source      string     `gorm:"default:'online'"                               json:"source"` // online | offline-import
	LastSeen    *time.Time `                                                      json:"last_seen"`
	Description string     `                                                      json:"description"`

	// Fleet management — group an agent into a logical set (e.g. "Finance",
	// "DMZ-servers") and tag it freely. Tags is a JSON string array. GroupName
	// is indexed so a group can be selected cheaply for bulk operations.
	GroupName string `gorm:"index"             json:"group_name"`
	Tags      string `gorm:"type:text"         json:"tags"` // JSON array of strings

	// Resource telemetry — updated via resource_report WebSocket messages
	CPUPercent  float64 `gorm:"default:0" json:"cpu_percent"`
	MemUsedMB   int64   `gorm:"default:0" json:"mem_used_mb"`
	MemTotalMB  int64   `gorm:"default:0" json:"mem_total_mb"`
	DiskUsedGB  float64 `gorm:"default:0" json:"disk_used_gb"`
	DiskTotalGB float64 `gorm:"default:0" json:"disk_total_gb"`
	CaseID      *uuid.UUID `gorm:"type:uuid;index"                                json:"case_id,omitempty"`
	Case        *Case      `gorm:"foreignKey:CaseID"                              json:"case,omitempty"`
	CreatedAt   time.Time  `                                                      json:"created_at"`
	UpdatedAt   time.Time  `                                                      json:"updated_at"`
}

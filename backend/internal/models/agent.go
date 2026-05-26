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
	LastSeen    *time.Time `                                                      json:"last_seen"`
	Description string     `                                                      json:"description"`
	CreatedAt   time.Time  `                                                      json:"created_at"`
	UpdatedAt   time.Time  `                                                      json:"updated_at"`
}

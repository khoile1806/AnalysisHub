package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents a platform user (admin or analyst).
type User struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Email     string    `gorm:"uniqueIndex;not null"                           json:"email"`
	Password  string    `gorm:"not null"                                       json:"-"` // bcrypt hash; never serialised
	Role      string    `gorm:"default:'analyst'"                              json:"role"` // admin | analyst
	CreatedAt time.Time `                                                      json:"created_at"`
	UpdatedAt time.Time `                                                      json:"updated_at"`
}

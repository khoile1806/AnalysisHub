package models

import (
	"time"

	"github.com/google/uuid"
)

// AIProvider stores a configured AI API endpoint with an encrypted key.
// ProviderType controls which HTTP client is used:
//   - "openai"    → OpenAI-compatible REST (Groq, Together, Mistral, OpenRouter, Cerebras, etc.)
//   - "anthropic" → Anthropic native Messages API
//   - "google"    → Google Gemini generateContent API
type AIProvider struct {
	ID           uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Name         string    `gorm:"not null"                                       json:"name"`
	ProviderType string    `gorm:"not null;default:'openai'"                      json:"provider_type"`
	BaseURL      string    `                                                      json:"base_url"`
	APIKey       string    `gorm:"type:text"                                      json:"-"`       // AES-encrypted, never sent to client
	HasKey       bool      `gorm:"-"                                              json:"has_key"` // computed: tells client a key exists
	Model        string    `                                                      json:"model"`
	MaxTokens    int       `gorm:"default:0"                                      json:"max_tokens"` // 0 = provider default
	IsActive     bool      `gorm:"default:true"                                   json:"is_active"`
	CreatedBy    uuid.UUID `gorm:"type:uuid"                                      json:"created_by"`
	CreatedAt    time.Time `                                                      json:"created_at"`
	UpdatedAt    time.Time `                                                      json:"updated_at"`
}

// AnalysisSession records one AI analysis run. A session ties a data source
// (job output, checklist run, ELK result, or uploaded file) to an AIProvider
// and stores the chain progress and final markdown report.
type AnalysisSession struct {
	ID         uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	ProviderID uuid.UUID  `gorm:"type:uuid;not null;index"                       json:"provider_id"`
	Provider   *AIProvider `gorm:"foreignKey:ProviderID"                         json:"provider,omitempty"`
	Title      string     `                                                      json:"title"`
	// SourceType: "job" | "checklist_run" | "elk_result" | "upload"
	SourceType string    `gorm:"not null"                                       json:"source_type"`
	SourceID   string    `                                                      json:"source_id"` // UUID of source, empty for uploads
	UploadPath string    `                                                      json:"upload_path,omitempty"`
	UploadName string    `                                                      json:"upload_name,omitempty"`
	// Status: pending | running | done | failed
	Status     string    `gorm:"default:'pending'"                              json:"status"`
	// Steps: JSON array of ChainStep objects persisted for display after reload
	Steps      string    `gorm:"type:text"                                      json:"steps"`
	// Result: final markdown report from AI
	Result     string    `gorm:"type:text"                                      json:"result"`
	TokensUsed int       `                                                      json:"tokens_used"`
	CreatedBy  uuid.UUID `gorm:"type:uuid"                                      json:"created_by"`
	CreatedAt  time.Time `                                                      json:"created_at"`
	FinishedAt *time.Time `                                                     json:"finished_at,omitempty"`
}

// ChainStep is the JSON element stored in AnalysisSession.Steps.
// Status: "pending" | "running" | "done" | "failed"
type ChainStep struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

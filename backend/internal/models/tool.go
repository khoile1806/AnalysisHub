package models

import (
	"time"

	"github.com/google/uuid"
)

// Tool represents a forensic tool binary stored on the server.
type Tool struct {
	ID             uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Name           string    `gorm:"not null"                                       json:"name"`
	Category       string    `gorm:"not null"                                       json:"category"` // memory|triage|process|network|disk|log|other
	Platform       string    `gorm:"not null"                                       json:"platform"` // windows|linux|both
	Version        string    `                                                      json:"version"`
	Description    string    `                                                      json:"description"`
	FileName       string    `gorm:"not null"                                       json:"file_name"` // stored filename on disk
	FileSize       int64     `                                                      json:"file_size"`
	Args           string    `                                                      json:"args"`             // default CLI args
	ExecutablePath string    `gorm:"column:entrypoint"                              json:"executable_path"` // relative path to executable within tool dir

	// ── Result collection spec ──────────────────────────────────────────────
	// Declares how the agent should auto-collect the tool's output files after a
	// run and how the server should pre-process them. Empty/false = no auto
	// collection (backward-compatible; legacy tools keep their behaviour).
	CollectResult   bool   `                                              json:"collect_result"`   // auto-pull result files back
	OutputGlobs     string `                                              json:"output_globs"`     // comma-separated globs, e.g. "*.txt,*.csv,report/*.html"
	OutputScope     string `                                              json:"output_scope"`     // tooldir | outdir | both (default both)
	ResultProcessor string `                                              json:"result_processor"` // server-side parser: text|csv|json|loki|redline|kape|none
	AIDefault       bool   `                                              json:"ai_default"`       // default: send collected results to AI analysis
	AutoAnalyze     bool   `                                              json:"auto_analyze"`     // auto-run AI findings→timeline when this tool's job finishes (opt-in)
	MaxResultMB     int    `                                              json:"max_result_mb"`    // per-file size cap for collection (0 = server default)

	CreatedBy uuid.UUID `gorm:"type:uuid"                              json:"created_by"`
	CreatedAt time.Time `                                              json:"created_at"`
	UpdatedAt time.Time `                                              json:"updated_at"`
}
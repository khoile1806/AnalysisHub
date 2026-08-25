// Package aiusage persists the token ledger that backs the System Health
// "Token Usage" panel. It is separate from internal/ai so the client layer keeps
// no database dependency, and separate from the handlers so anything that builds
// an AI client can record without importing the HTTP layer.
package aiusage

import (
	"log/slog"
	"time"

	"gorm.io/gorm"

	ai "github.com/analysishub/backend/internal/ai"
	"github.com/analysishub/backend/internal/models"
)

// retention bounds how long individual completions are kept. The panel reports
// rolling totals, and an unbounded per-call ledger on a busy deployment grows
// without ever being read.
const retention = 90 * 24 * time.Hour

// DBSink writes each completion to ai_token_usages.
type DBSink struct{ db *gorm.DB }

// New returns a sink, or nil when there is no database (which makes ai.Meter a
// no-op rather than a crash).
func New(db *gorm.DB) *DBSink {
	if db == nil {
		return nil
	}
	return &DBSink{db: db}
}

// RecordUsage stores one completion.
//
// A provider that reports no usage still gets a row: the call happened, it took
// time, and it may have failed — all of which the health panel should show. Only
// the token columns are zero.
func (s *DBSink) RecordUsage(providerID, feature string, u ai.Usage, ok bool, elapsed time.Duration) {
	if s == nil || s.db == nil {
		return
	}
	row := models.AITokenUsage{
		ProviderID:      providerID,
		Feature:         feature,
		InputTokens:     u.InputTokens,
		OutputTokens:    u.OutputTokens,
		CacheReadTokens: u.CacheReadTokens,
		TotalTokens:     u.Total(),
		Success:         ok,
		DurationMS:      int(elapsed.Milliseconds()),
	}
	// Accounting must never break the analysis it is accounting for: a failed
	// insert is logged and dropped, not returned.
	if err := s.db.Create(&row).Error; err != nil {
		slog.Warn("could not record AI token usage", "feature", feature, "error", err)
	}
}

// Prune deletes ledger rows past the retention window. Called on start-up; the
// table is append-only otherwise.
func Prune(db *gorm.DB) {
	if db == nil {
		return
	}
	cutoff := time.Now().Add(-retention)
	if err := db.Where("created_at < ?", cutoff).
		Delete(&models.AITokenUsage{}).Error; err != nil {
		slog.Warn("could not prune the AI token ledger", "error", err)
	}
}

// Ensure DBSink satisfies the interface the client layer expects.
var _ ai.UsageSink = (*DBSink)(nil)

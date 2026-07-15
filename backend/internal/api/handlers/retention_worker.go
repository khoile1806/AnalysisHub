package handlers

import (
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/config"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/storage"
)

const retentionTick = 12 * time.Hour

// StartRetentionWorker runs the periodic data-retention sweep. Internal telemetry
// (agent resource history, system events) is always pruned with safe defaults to
// keep those tables bounded. EVIDENCE pruning is destructive, so it is opt-in
// (RetentionEnabled), dry-run by default (RetentionDryRun), and NEVER touches
// evidence attached to an OPEN case.
func StartRetentionWorker(db *gorm.DB, store *storage.LocalStorage, cfg *config.Config) {
	if db == nil || cfg == nil {
		return
	}
	log.Println("[retention] starting...")
	go runWorker("retention", retentionTick, func() { runRetention(db, store, cfg) })
}

func runRetention(db *gorm.DB, store *storage.LocalStorage, cfg *config.Config) {
	now := time.Now()

	// Housekeeping (always on, non-evidence): bound internal telemetry tables.
	if d := cfg.RetentionResourceSampleDays; d > 0 {
		res := db.Where("created_at < ?", now.AddDate(0, 0, -d)).Delete(&models.AgentResourceSample{})
		if res.RowsAffected > 0 {
			log.Printf("[retention] pruned %d agent resource sample(s)", res.RowsAffected)
		}
	}
	if d := cfg.RetentionEventDays; d > 0 {
		res := db.Where("updated_at < ?", now.AddDate(0, 0, -d)).Delete(&models.SystemEvent{})
		if res.RowsAffected > 0 {
			log.Printf("[retention] pruned %d system event(s)", res.RowsAffected)
		}
	}

	// Evidence prune: opt-in, guarded, dry-run by default.
	if !cfg.RetentionEnabled || cfg.RetentionEvidenceDays <= 0 {
		return
	}
	cutoff := now.AddDate(0, 0, -cfg.RetentionEvidenceDays)

	// Candidates: old evidence that is NOT tied to an open case — either unlinked
	// (case_id NULL) or belonging to a case whose status is 'closed'.
	var candidates []models.CaseEvidence
	db.Where("created_at < ?", cutoff).
		Where("case_id IS NULL OR case_id IN (SELECT id FROM cases WHERE status = ?)", "closed").
		Find(&candidates)
	if len(candidates) == 0 {
		return
	}

	if cfg.RetentionDryRun {
		log.Printf("[retention] DRY-RUN: %d evidence file(s) older than %d days would be pruned", len(candidates), cfg.RetentionEvidenceDays)
		RecordSystemEvent("retention", "info", "retention", "evidence prune (dry-run)",
			formatPruneDetail(len(candidates), cfg.RetentionEvidenceDays, true))
		return
	}

	deleted := 0
	for i := range candidates {
		ev := &candidates[i]
		if store != nil && ev.StoredPath != "" {
			_ = store.RemoveByRelPath(ev.StoredPath)
		}
		if db.Delete(ev).Error == nil {
			deleted++
		}
	}
	log.Printf("[retention] pruned %d evidence file(s) older than %d days", deleted, cfg.RetentionEvidenceDays)
	RecordSystemEvent("retention", "warn", "retention", "evidence pruned",
		formatPruneDetail(deleted, cfg.RetentionEvidenceDays, false))
}

func formatPruneDetail(n, days int, dryRun bool) string {
	verb := "deleted"
	if dryRun {
		verb = "would delete"
	}
	return fmt.Sprintf("%s closed/unlinked evidence file(s) older than %d days", verb+" "+fmt.Sprint(n), days)
}

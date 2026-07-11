package handlers

import (
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/models"
)

// RecoverStuckWork fails any work that was genuinely mid-execution when the
// process died so the UI never shows a job/collection wedged in "running"
// forever. It mirrors vulnscan's recoverStuckScans.
//
// Scope is deliberately narrow to avoid regressing recoverable states:
//   - Only RUNNING agent jobs are failed — a running job's process (and its live
//     WS output stream) cannot survive a restart. PENDING jobs may still resolve
//     to "ready" when the agent reconnects and reports download completion, and
//     READY jobs are parked awaiting a user "Run" and survive a restart intact —
//     failing either would break a working flow, so they are left untouched.
//   - Fleet collection results awaiting an agent reply that will never arrive
//     (the dispatch was a one-shot WS send) are failed.
//   - OSINT scans are NOT handled here — the OSINT engine has its own
//     recoverStuckScans/resumePendingScans that REQUEUE and re-run interrupted
//     investigations (better than failing them).
//
// Runs once at startup, BEFORE the hub accepts agent reconnects, to avoid racing
// live work.
func RecoverStuckWork(db *gorm.DB) {
	if db == nil {
		return
	}
	now := time.Now()

	// Only jobs that were actively executing — their process is gone after a
	// restart and no reconnect resumes a job mid-run.
	jobs := db.Model(&models.Job{}).
		Where("status = ?", models.JobRunning).
		Updates(map[string]interface{}{"status": models.JobFailed, "finished_at": now})

	// Fleet collection results awaiting an agent reply that will never arrive.
	fleet := db.Model(&models.FleetCollectionResult{}).
		Where("status IN ?", []string{"pending", "running"}).
		Updates(map[string]interface{}{
			"status": "error", "error": "interrupted by server restart", "finished_at": now,
		})

	if jobs.RowsAffected+fleet.RowsAffected > 0 {
		log.Printf("[startup-recovery] finalized stuck work: %d jobs, %d fleet results",
			jobs.RowsAffected, fleet.RowsAffected)
	}
}

package handlers

import (
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/models"
)

const (
	// stuckJobTick is how often running jobs are checked for being wedged.
	stuckJobTick = 2 * time.Minute
	// stuckJobHardTimeout: a job running longer than this is treated as runaway
	// and auto-failed (no legitimate tool run should exceed it).
	stuckJobHardTimeout = 6 * time.Hour
	// stuckJobAgentGrace: how long a running job whose agent has gone offline is
	// given before it is auto-failed (covers brief reconnect blips).
	stuckJobAgentGrace = 5 * time.Minute
)

// StartStuckJobWatcher periodically auto-fails jobs that can no longer complete —
// the running counterpart to the one-shot RecoverStuckWork. Two cases are
// remediated: a job whose executing agent has gone offline (its process and live
// output stream cannot return), and a runaway job running past a hard cap.
func StartStuckJobWatcher(db *gorm.DB) {
	if db == nil {
		return
	}
	log.Println("[stuck-job-watcher] starting...")
	go runWorker("stuck-job-watcher", stuckJobTick, func() { sweepStuckJobs(db) })
}

func sweepStuckJobs(db *gorm.DB) {
	now := time.Now()

	// Runaway: running far longer than any tool should take.
	runaway := db.Model(&models.Job{}).
		Where("status = ? AND started_at IS NOT NULL AND started_at < ?",
			models.JobRunning, now.Add(-stuckJobHardTimeout)).
		Updates(map[string]interface{}{"status": models.JobFailed, "finished_at": now})

	// Agent gone: the agent that was executing the job is no longer online, so
	// the job cannot make progress or report completion.
	var offlineIDs []uuid.UUID
	db.Model(&models.Agent{}).Where("status <> ?", "online").Pluck("id", &offlineIDs)
	var agentGone int64
	if len(offlineIDs) > 0 {
		res := db.Model(&models.Job{}).
			Where("status = ? AND started_at IS NOT NULL AND started_at < ? AND agent_id IN ?",
				models.JobRunning, now.Add(-stuckJobAgentGrace), offlineIDs).
			Updates(map[string]interface{}{"status": models.JobFailed, "finished_at": now})
		agentGone = res.RowsAffected
	}

	if runaway.RowsAffected+agentGone > 0 {
		log.Printf("[stuck-job-watcher] auto-failed stuck jobs: %d runaway, %d agent-offline",
			runaway.RowsAffected, agentGone)
		RecordSystemEvent("job", "warn", "stuck-job-watcher", "auto-failed stuck job(s)",
			fmt.Sprintf("%d runaway (>%s), %d agent-offline (>%s)",
				runaway.RowsAffected, stuckJobHardTimeout, agentGone, stuckJobAgentGrace))
	}
}

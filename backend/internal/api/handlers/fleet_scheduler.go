package handlers

import (
	"log"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/ws"
)

// fleetSchedulerTick is how often due schedules are checked.
const fleetSchedulerTick = 1 * time.Minute

// StartFleetScheduler runs a background loop that dispatches due
// ScheduledCollections to their selected agents. It is interval-based (not
// cron) for simplicity: a schedule fires when now >= NextRun, then NextRun is
// advanced by IntervalMinutes.
func StartFleetScheduler(db *gorm.DB, hub *ws.Hub) {
	log.Println("[fleet-scheduler] starting...")
	go runWorker("fleet-scheduler", fleetSchedulerTick, func() { runDueSchedules(db, hub) })
}

func runDueSchedules(db *gorm.DB, hub *ws.Hub) {
	now := time.Now().UTC()
	var due []models.ScheduledCollection
	db.Where("enabled = ? AND (next_run IS NULL OR next_run <= ?)", true, now).Find(&due)

	for i := range due {
		sc := &due[i]
		agents := selectFleetAgents(db, parseTags(sc.AgentIDs), sc.Group, sc.Tag)
		dispatched := 0
		for j := range agents {
			if _, status := dispatchCollection(db, hub, &agents[j], sc.Collection, &sc.ID); status == "dispatched" {
				dispatched++
			}
		}
		next := nextScheduleRun(sc, now)
		db.Model(&models.ScheduledCollection{}).Where("id = ?", sc.ID).Updates(map[string]interface{}{
			"last_run": now,
			"next_run": next,
		})
		log.Printf("[fleet-scheduler] %q (%s): dispatched to %d/%d agents, next %s",
			sc.Name, sc.Collection, dispatched, len(agents), next.Format(time.RFC3339))
	}
}

// nextScheduleRun computes the next fire time for a schedule. It preserves the
// original cadence (advancing from the previous slot rather than "now", so the
// schedule doesn't drift by dispatch latency), catches up past any slots missed
// during downtime in a single step (no burst of back-to-back runs), and adds a
// small deterministic jitter so many same-interval schedules don't stampede on
// the same minute.
func nextScheduleRun(sc *models.ScheduledCollection, now time.Time) time.Time {
	interval := time.Duration(sc.IntervalMinutes) * time.Minute
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	// Start from the previous scheduled slot when it is recent enough to still be
	// a meaningful anchor; otherwise (new schedule or long downtime) anchor to now.
	base := now
	if sc.NextRun != nil && sc.NextRun.After(now.Add(-interval)) {
		base = *sc.NextRun
	}
	next := base.Add(interval)
	for !next.After(now) {
		next = next.Add(interval)
	}
	return next.Add(scheduleJitter(sc.ID, interval))
}

// scheduleJitter derives a deterministic ±10%-of-interval offset from a schedule
// ID (no PRNG, so restarts are reproducible and testable).
func scheduleJitter(id uuid.UUID, interval time.Duration) time.Duration {
	span := interval / 10
	if span <= 0 {
		return 0
	}
	var seed uint64
	for _, b := range id {
		seed = seed*131 + uint64(b)
	}
	return time.Duration(int64(seed%uint64(2*span))) - span
}

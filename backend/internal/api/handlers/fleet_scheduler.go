package handlers

import (
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/models"
	"github.com/forensichub/backend/internal/ws"
)

// fleetSchedulerTick is how often due schedules are checked.
const fleetSchedulerTick = 1 * time.Minute

// StartFleetScheduler runs a background loop that dispatches due
// ScheduledCollections to their selected agents. It is interval-based (not
// cron) for simplicity: a schedule fires when now >= NextRun, then NextRun is
// advanced by IntervalMinutes.
func StartFleetScheduler(db *gorm.DB, hub *ws.Hub) {
	log.Println("[fleet-scheduler] starting...")
	ticker := time.NewTicker(fleetSchedulerTick)
	go func() {
		for range ticker.C {
			runDueSchedules(db, hub)
		}
	}()
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
		next := now.Add(time.Duration(sc.IntervalMinutes) * time.Minute)
		db.Model(&models.ScheduledCollection{}).Where("id = ?", sc.ID).Updates(map[string]interface{}{
			"last_run": now,
			"next_run": next,
		})
		log.Printf("[fleet-scheduler] %q (%s): dispatched to %d/%d agents",
			sc.Name, sc.Collection, dispatched, len(agents))
	}
}

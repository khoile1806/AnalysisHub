package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/updater"
)

// GetMetrics exposes core platform gauges in Prometheus text exposition format,
// without pulling in the prometheus client library. Behind the same auth as the
// rest of /system, so it is not a public scrape target — point an internal
// Prometheus at it with the bearer token.
//
// GET /api/v1/system/metrics
func (h *SystemHandler) GetMetrics(c *gin.Context) {
	var b strings.Builder
	gauge := func(name, help string, val float64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", name, help, name, name, val)
	}

	// Agents.
	var agentsTotal int64
	h.db.Model(&models.Agent{}).Count(&agentsTotal)
	online := 0
	if h.hub != nil {
		online = h.hub.ConnectedAgentCount()
	}
	gauge("analysishub_agents_total", "Registered agents", float64(agentsTotal))
	gauge("analysishub_agents_online", "Currently connected agents", float64(online))

	// Jobs by status.
	fmt.Fprintf(&b, "# HELP analysishub_jobs Jobs by status\n# TYPE analysishub_jobs gauge\n")
	for _, s := range []string{"running", "pending", "ready", "done", "failed", "stopped"} {
		var n int64
		h.db.Model(&models.Job{}).Where("status = ?", s).Count(&n)
		fmt.Fprintf(&b, "analysishub_jobs{status=%q} %d\n", s, n)
	}

	// Updaters currently failing.
	fails := 0
	for _, u := range updater.Default.Statuses() {
		if u.LastRun != nil && !u.LastSuccess {
			fails++
		}
	}
	gauge("analysishub_updaters_failing", "Auto-updaters currently in a failed state", float64(fails))

	// Error-severity system events in the last 24h.
	var errEvents int64
	h.db.Model(&models.SystemEvent{}).
		Where("severity = ? AND updated_at > ?", "error", time.Now().Add(-24*time.Hour)).
		Count(&errEvents)
	gauge("analysishub_error_events_24h", "Error-severity system events in the last 24h", float64(errEvents))

	c.Header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	c.String(http.StatusOK, b.String())
}

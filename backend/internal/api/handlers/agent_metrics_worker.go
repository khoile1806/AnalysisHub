package handlers

import (
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/models"
)

const (
	// agentMetricsTick throttles history sampling well below the 30s report
	// cadence so the time-series table stays small.
	agentMetricsTick = 5 * time.Minute
	agentDiskWarnPct = 90.0
	agentRAMWarnPct  = 90.0
)

// StartAgentMetricsWorker periodically snapshots each online agent's reported
// utilization into a history table and raises a (deduped) system event when an
// agent's disk or memory crosses a warning threshold. Reads the last-write
// snapshot maintained by the resource_report handler — it never touches the WS
// hot path.
func StartAgentMetricsWorker(db *gorm.DB) {
	if db == nil {
		return
	}
	log.Println("[agent-metrics] starting...")
	go runWorker("agent-metrics", agentMetricsTick, func() { sampleAgentMetrics(db) })
}

func sampleAgentMetrics(db *gorm.DB) {
	var agents []models.Agent
	db.Where("status = ?", "online").Find(&agents)
	now := time.Now()
	for i := range agents {
		a := &agents[i]
		// Skip agents that have not reported resources yet (all zero).
		if a.MemTotalMB == 0 && a.DiskTotalGB == 0 {
			continue
		}
		db.Create(&models.AgentResourceSample{
			AgentID:     a.ID,
			CPUPercent:  a.CPUPercent,
			MemUsedMB:   a.MemUsedMB,
			MemTotalMB:  a.MemTotalMB,
			DiskUsedGB:  a.DiskUsedGB,
			DiskTotalGB: a.DiskTotalGB,
			CreatedAt:   now,
		})

		if a.DiskTotalGB > 0 {
			if pct := a.DiskUsedGB / a.DiskTotalGB * 100; pct >= agentDiskWarnPct {
				RecordSystemEvent("agent", "warn", agentLabel(a), "agent disk almost full",
					fmt.Sprintf("%.0f%% used (%.0f/%.0f GB)", pct, a.DiskUsedGB, a.DiskTotalGB))
			}
		}
		if a.MemTotalMB > 0 {
			if pct := float64(a.MemUsedMB) / float64(a.MemTotalMB) * 100; pct >= agentRAMWarnPct {
				RecordSystemEvent("agent", "warn", agentLabel(a), "agent memory almost exhausted",
					fmt.Sprintf("%.0f%% used (%d/%d MB)", pct, a.MemUsedMB, a.MemTotalMB))
			}
		}
	}
}

func agentLabel(a *models.Agent) string {
	if a.Hostname != "" {
		return a.Hostname
	}
	return a.Name
}

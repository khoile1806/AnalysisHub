package models

import (
	"time"

	"github.com/google/uuid"
)

// AgentResourceSample is a time-series data point of an agent's host utilization.
// Unlike the last-write snapshot on Agent, these rows accumulate a short history
// (throttled + pruned by retention) so the UI can chart CPU/RAM/disk trends and
// the threshold detector can reason over recent samples.
type AgentResourceSample struct {
	ID          uint      `gorm:"primaryKey"                 json:"id"`
	AgentID     uuid.UUID `gorm:"type:uuid;index"            json:"agent_id"`
	CPUPercent  float64   `                                  json:"cpu_percent"`
	MemUsedMB   int64     `                                  json:"mem_used_mb"`
	MemTotalMB  int64     `                                  json:"mem_total_mb"`
	DiskUsedGB  float64   `                                  json:"disk_used_gb"`
	DiskTotalGB float64   `                                  json:"disk_total_gb"`
	CreatedAt   time.Time `gorm:"index"                      json:"created_at"`
}

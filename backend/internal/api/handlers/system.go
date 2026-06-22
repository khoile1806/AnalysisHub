package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/config"
	"github.com/forensichub/backend/internal/models"
	"github.com/forensichub/backend/internal/sysinfo"
	"github.com/forensichub/backend/internal/storage"
	"github.com/forensichub/backend/internal/ws"
)

// SystemHandler serves system health and usage-statistics endpoints.
type SystemHandler struct {
	db        *gorm.DB
	rdb       *redis.Client
	store     *storage.LocalStorage
	hub       *ws.Hub
	startTime time.Time

	// CPU delta tracking — two consecutive /proc/stat samples give us usage %.
	cpuMu     sync.Mutex
	prevCPU   sysinfo.CPUSample
	prevCPUOK bool
}

func NewSystemHandler(db *gorm.DB, rdb *redis.Client, store *storage.LocalStorage, hub *ws.Hub) *SystemHandler {
	return &SystemHandler{
		db:        db,
		rdb:       rdb,
		store:     store,
		hub:       hub,
		startTime: time.Now(),
	}
}

// componentStatus is a single checked subsystem.
type componentStatus struct {
	Name      string `json:"name"`
	Status    string `json:"status"`    // "ok" | "warn" | "error"
	LatencyMs int64  `json:"latency_ms"`
	Detail    string `json:"detail"`
}

// GetHealth GET /api/v1/system/health
// Returns live status of every subsystem, server resource usage, and per-agent resource telemetry.
func (h *SystemHandler) GetHealth(c *gin.Context) {
	components := make([]componentStatus, 0, 4)
	overallOK := true

	// ── 1. PostgreSQL ────────────────────────────────────────────
	{
		t0 := time.Now()
		err := h.db.Raw("SELECT 1").Error
		lat := time.Since(t0).Milliseconds()
		comp := componentStatus{Name: "PostgreSQL", LatencyMs: lat}
		if err != nil {
			comp.Status = "error"
			comp.Detail = err.Error()
			overallOK = false
		} else {
			comp.Status = "ok"
			comp.Detail = "connected"
		}
		components = append(components, comp)
	}

	// ── 2. Redis ─────────────────────────────────────────────────
	{
		t0 := time.Now()
		ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
		defer cancel()
		_, err := h.rdb.Ping(ctx).Result()
		lat := time.Since(t0).Milliseconds()
		comp := componentStatus{Name: "Redis", LatencyMs: lat}
		if err != nil {
			// Redis is optional — the system runs without it (CVE cache disabled)
			comp.Status = "warn"
			comp.Detail = "unavailable — CVE cache disabled"
		} else {
			comp.Status = "ok"
			comp.Detail = "connected"
		}
		components = append(components, comp)
	}

	// ── 3. Storage ───────────────────────────────────────────────
	{
		t0 := time.Now()
		info, err := os.Stat(h.store.BasePath)
		lat := time.Since(t0).Milliseconds()
		comp := componentStatus{Name: "Storage", LatencyMs: lat}
		if err != nil || !info.IsDir() {
			comp.Status = "error"
			comp.Detail = "path inaccessible: " + h.store.BasePath
			overallOK = false
		} else {
			comp.Status = "ok"
			comp.Detail = h.store.BasePath
		}
		components = append(components, comp)
	}

	// ── 4. WebSocket Hub ─────────────────────────────────────────
	{
		n := h.hub.ConnectedAgentCount()
		components = append(components, componentStatus{
			Name:   "WebSocket Hub",
			Status: "ok",
			Detail: fmt.Sprintf("%d agent(s) connected", n),
		})
	}

	// ── Quick counters from DB ────────────────────────────────────
	var agentsTotal, agentsOnline, jobsTotal, jobsRunning, sessionsTotal int64
	h.db.Model(&models.Agent{}).Count(&agentsTotal)
	h.db.Model(&models.Agent{}).Where("status = ?", "online").Count(&agentsOnline)
	h.db.Model(&models.Job{}).Count(&jobsTotal)
	h.db.Model(&models.Job{}).Where("status = ?", models.JobRunning).Count(&jobsRunning)
	h.db.Model(&models.AnalysisSession{}).Count(&sessionsTotal)

	// ── Server resource stats ─────────────────────────────────────
	ramTotal, ramUsed, ramPercent := sysinfo.ReadMemInfo()
	diskUsed, diskTotal, diskPercent := sysinfo.ReadDiskInfo(h.store.BasePath)
	cpuCount := sysinfo.CPUCount()

	// CPU usage = delta between previous sample and current sample
	var cpuPercent float64
	if curr, ok := sysinfo.ReadCPUSample(); ok {
		h.cpuMu.Lock()
		if h.prevCPUOK {
			cpuPercent = sysinfo.CalcCPUPercent(h.prevCPU, curr)
		}
		h.prevCPU = curr
		h.prevCPUOK = true
		h.cpuMu.Unlock()
	}

	// ── Per-agent resource telemetry ─────────────────────────────
	type agentResource struct {
		ID          string  `json:"id"`
		Name        string  `json:"name"`
		Hostname    string  `json:"hostname"`
		OS          string  `json:"os"`
		CPUPercent  float64 `json:"cpu_percent"`
		MemUsedMB   int64   `json:"mem_used_mb"`
		MemTotalMB  int64   `json:"mem_total_mb"`
		DiskUsedGB  float64 `json:"disk_used_gb"`
		DiskTotalGB float64 `json:"disk_total_gb"`
	}
	var onlineAgents []models.Agent
	h.db.Where("status = 'online'").
		Select("id, name, hostname, os, cpu_percent, mem_used_mb, mem_total_mb, disk_used_gb, disk_total_gb").
		Find(&onlineAgents)

	agentResources := make([]agentResource, 0, len(onlineAgents))
	for _, a := range onlineAgents {
		agentResources = append(agentResources, agentResource{
			ID:          a.ID.String(),
			Name:        a.Name,
			Hostname:    a.Hostname,
			OS:          a.OS,
			CPUPercent:  a.CPUPercent,
			MemUsedMB:   a.MemUsedMB,
			MemTotalMB:  a.MemTotalMB,
			DiskUsedGB:  a.DiskUsedGB,
			DiskTotalGB: a.DiskTotalGB,
		})
	}

	overallStatus := "ok"
	if !overallOK {
		overallStatus = "degraded"
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"status":         overallStatus,
			"uptime_seconds": int64(time.Since(h.startTime).Seconds()),
			"components":     components,

			// DB counters
			"agents_online":    h.hub.ConnectedAgentCount(),
			"agents_total":     agentsTotal,
			"agents_db_online": agentsOnline,
			"jobs_total":       jobsTotal,
			"jobs_running":     jobsRunning,
			"sessions_total":   sessionsTotal,
			"checked_at":       time.Now(),

			// Server resources
			"server": gin.H{
				"cpu_count":    cpuCount,
				"cpu_percent":  cpuPercent,
				"ram_total_mb": ramTotal,
				"ram_used_mb":  ramUsed,
				"ram_percent":  ramPercent,
				"disk_total_gb": diskTotal,
				"disk_used_gb":  diskUsed,
				"disk_percent":  diskPercent,
			},

			// Per-agent resource telemetry
			"agent_resources": agentResources,
		},
	})
}

// maskProxyURL strips any credentials from a proxy URL so the status endpoint
// never leaks a username/password. Returns "" for empty, the scheme://host:port
// form on success, or "configured" if it cannot be parsed.
func maskProxyURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "configured"
	}
	u.User = nil // drop userinfo entirely
	return u.Scheme + "://" + u.Host
}

// GetProxyStatus GET /api/v1/system/proxy
// Reports the EFFECTIVE egress-proxy configuration (read from the process env
// applied at startup) without exposing any secret. Lets the test suite verify
// the project-wide proxy plumbing is in place and safely masked.
func (h *SystemHandler) GetProxyStatus(c *gin.Context) {
	getEnvAny := func(keys ...string) string {
		for _, k := range keys {
			if v := strings.TrimSpace(os.Getenv(k)); v != "" {
				return v
			}
		}
		return ""
	}

	outbound := getEnvAny("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")
	tor := getEnvAny("OSINT_TOR_PROXY")

	darkSources := 0
	if v := strings.TrimSpace(os.Getenv("OSINT_DARKWEB_SOURCES")); v != "" {
		for _, p := range strings.Split(v, ",") {
			if strings.TrimSpace(p) != "" {
				darkSources++
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"outbound_configured": outbound != "",
			"outbound_proxy":      maskProxyURL(outbound),
			"no_proxy":            getEnvAny("NO_PROXY", "no_proxy"),
			"tor_configured":      tor != "",
			"tor_proxy":           maskProxyURL(tor),
			"darkweb_sources":     darkSources,
		},
	})
}

// ValidateProxy POST /api/v1/system/proxy/validate
// Exercises the egress-proxy masking + NO_PROXY composition on a SAMPLE input
// (not the live config), so the test suite can verify the logic deterministically
// even when no real proxy is configured. Pure function — changes nothing.
func (h *SystemHandler) ValidateProxy(c *gin.Context) {
	var req struct {
		ProxyURL string `json:"proxy_url"`
		NoProxy  string `json:"no_proxy"`
	}
	_ = c.ShouldBindJSON(&req)

	masked := maskProxyURL(req.ProxyURL)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"masked_proxy":       masked,
			"effective_no_proxy": config.EffectiveNoProxy(req.NoProxy),
			"leaked":             strings.Contains(masked, "@"), // true would mean credentials survived masking
		},
	})
}

// GetTokenStats GET /api/v1/system/token-stats
// Aggregates AI token usage from AnalysisSession records.
func (h *SystemHandler) GetTokenStats(c *gin.Context) {
	// ── Grand totals ─────────────────────────────────────────────
	type totals struct {
		Sessions    int64 `json:"sessions"`
		TotalTokens int64 `json:"total_tokens"`
	}
	var t totals
	h.db.Raw(`
		SELECT
			COUNT(*) AS sessions,
			COALESCE(SUM(tokens_used), 0) AS total_tokens
		FROM analysis_sessions
		WHERE status = 'done'
	`).Scan(&t)

	// ── Per-provider breakdown ────────────────────────────────────
	type provRow struct {
		ProviderID  string     `json:"provider_id"`
		Sessions    int64      `json:"sessions"`
		TotalTokens int64      `json:"total_tokens"`
		AvgTokens   float64    `json:"avg_tokens"`
		LastUsed    *time.Time `json:"last_used"`
	}
	var provRows []provRow
	h.db.Raw(`
		SELECT
			provider_id::text                                  AS provider_id,
			COUNT(*)                                           AS sessions,
			COALESCE(SUM(tokens_used), 0)                     AS total_tokens,
			COALESCE(ROUND(AVG(NULLIF(tokens_used, 0))), 0)   AS avg_tokens,
			MAX(finished_at)                                   AS last_used
		FROM analysis_sessions
		WHERE status = 'done'
		GROUP BY provider_id
		ORDER BY total_tokens DESC
	`).Scan(&provRows)

	type enrichedRow struct {
		ProviderID   string     `json:"provider_id"`
		ProviderName string     `json:"provider_name"`
		Model        string     `json:"model"`
		ProviderType string     `json:"provider_type"`
		Sessions     int64      `json:"sessions"`
		TotalTokens  int64      `json:"total_tokens"`
		AvgTokens    float64    `json:"avg_tokens"`
		LastUsed     *time.Time `json:"last_used"`
	}
	enriched := make([]enrichedRow, 0, len(provRows))
	for _, row := range provRows {
		var p models.AIProvider
		h.db.First(&p, "id = ?", row.ProviderID)
		name := p.Name
		if name == "" {
			suffix := row.ProviderID
			if len(suffix) > 8 {
				suffix = suffix[:8]
			}
			name = suffix + "… (deleted)"
		}
		enriched = append(enriched, enrichedRow{
			ProviderID:   row.ProviderID,
			ProviderName: name,
			Model:        p.Model,
			ProviderType: p.ProviderType,
			Sessions:     row.Sessions,
			TotalTokens:  row.TotalTokens,
			AvgTokens:    row.AvgTokens,
			LastUsed:     row.LastUsed,
		})
	}

	// ── Recent 15 completed sessions ─────────────────────────────
	type recentRow struct {
		ID         string     `json:"id"`
		Title      string     `json:"title"`
		SourceType string     `json:"source_type"`
		TokensUsed int        `json:"tokens_used"`
		FinishedAt *time.Time `json:"finished_at"`
		ProviderID string     `json:"provider_id"`
	}
	var recent []recentRow
	h.db.Raw(`
		SELECT
			id::text,
			title,
			source_type,
			tokens_used,
			finished_at,
			provider_id::text
		FROM analysis_sessions
		WHERE status = 'done'
		ORDER BY finished_at DESC
		LIMIT 15
	`).Scan(&recent)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"total_sessions": t.Sessions,
			"total_tokens":   t.TotalTokens,
			"by_provider":    enriched,
			"recent":         recent,
		},
	})
}

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/config"
	"github.com/analysishub/backend/internal/egress"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/storage"
	"github.com/analysishub/backend/internal/sysinfo"
	"github.com/analysishub/backend/internal/ws"
)

// AppVersion is the build version surfaced on the health endpoint. Override at
// build time with -ldflags "-X .../handlers.AppVersion=x.y.z".
var AppVersion = "2.0"

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
	Status    string `json:"status"` // "ok" | "warn" | "error"
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

	// ── Counters (combined per-table with FILTER, fewer round-trips) ──
	var agentC struct{ Total, Online int64 }
	h.db.Model(&models.Agent{}).
		Select("COUNT(*) AS total, COUNT(*) FILTER (WHERE status = 'online') AS online").Scan(&agentC)
	var jobC struct{ Total, Running, Pending int64 }
	h.db.Model(&models.Job{}).
		Select("COUNT(*) AS total, COUNT(*) FILTER (WHERE status = ?) AS running, COUNT(*) FILTER (WHERE status = ?) AS pending",
			models.JobRunning, models.JobPending).Scan(&jobC)
	agentsTotal, agentsOnline := agentC.Total, agentC.Online
	jobsTotal, jobsRunning := jobC.Total, jobC.Running
	var sessionsTotal int64
	h.db.Model(&models.AnalysisSession{}).Count(&sessionsTotal)

	// Activity / queue depth — live work in flight.
	var osintRunning int64
	h.db.Model(&models.OsintScan{}).Where("status = ?", "running").Count(&osintRunning)

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

	// ── Resource pressure → warn (before anything actually fails) ──
	resourceWarn := false
	if diskPercent >= 90 || ramPercent >= 90 {
		resourceWarn = true
		components = append(components, componentStatus{
			Name:   "Resources",
			Status: "warn",
			Detail: fmt.Sprintf("disk %.0f%%, RAM %.0f%% — running low", diskPercent, ramPercent),
		})
	}

	// ── DB connection-pool stats (diagnose saturation) ──
	dbPool := gin.H{}
	if sqlDB, derr := h.db.DB(); derr == nil {
		s := sqlDB.Stats()
		dbPool = gin.H{
			"max_open": s.MaxOpenConnections, "open": s.OpenConnections,
			"in_use": s.InUse, "idle": s.Idle,
			"wait_count": s.WaitCount, "wait_ms": s.WaitDuration.Milliseconds(),
		}
		// A persistently saturated pool with waits is a warning sign.
		if s.MaxOpenConnections > 0 && s.WaitCount > 0 && s.InUse >= s.MaxOpenConnections {
			resourceWarn = true
		}
	}

	// ── Go runtime ──
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	runtimeInfo := gin.H{
		"go_version": runtime.Version(),
		"goroutines": runtime.NumGoroutine(),
		"heap_mb":    ms.HeapAlloc / (1024 * 1024),
	}

	// ── Integrations wired (active configs / providers) ──
	activeCount := func(model interface{}) int64 {
		var n int64
		h.db.Model(model).Where("is_active = ?", true).Count(&n)
		return n
	}
	integrations := gin.H{
		"elk":          activeCount(&models.ELKConfig{}),
		"splunk":       activeCount(&models.SplunkConfig{}),
		"qradar":       activeCount(&models.QRadarConfig{}),
		"opencti":      activeCount(&models.OpenCTIConfig{}),
		"ai_providers": activeCount(&models.AIProvider{}),
	}

	overallStatus := "ok"
	switch {
	case !overallOK:
		overallStatus = "degraded"
	case resourceWarn:
		overallStatus = "warn"
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"status":         overallStatus,
			"version":        AppVersion,
			"uptime_seconds": int64(time.Since(h.startTime).Seconds()),
			"components":     components,
			"db_pool":        dbPool,
			"runtime":        runtimeInfo,
			"integrations":   integrations,
			"activity": gin.H{
				"jobs_pending":   jobC.Pending,
				"jobs_running":   jobsRunning,
				"osint_running":  osintRunning,
				"sessions_total": sessionsTotal,
			},

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
				"cpu_count":     cpuCount,
				"cpu_percent":   cpuPercent,
				"ram_total_mb":  ramTotal,
				"ram_used_mb":   ramUsed,
				"ram_percent":   ramPercent,
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

// proxyStatusData builds the masked, live egress-proxy + health snapshot.
func proxyStatusData() gin.H {
	proxy, noProxy, fallback, health := egress.Status()
	tor := strings.TrimSpace(os.Getenv("OSINT_TOR_PROXY"))

	darkSources := 0
	if v := strings.TrimSpace(os.Getenv("OSINT_DARKWEB_SOURCES")); v != "" {
		for _, p := range strings.Split(v, ",") {
			if strings.TrimSpace(p) != "" {
				darkSources++
			}
		}
	}

	return gin.H{
		"outbound_configured": proxy != "",
		"outbound_proxy":      maskProxyURL(proxy),
		"no_proxy":            noProxy,
		"fallback_direct":     fallback,
		"health":              health, // {healthy, last_check, latency_ms, error}
		"tor_configured":      tor != "",
		"tor_proxy":           maskProxyURL(tor),
		"darkweb_sources":     darkSources,
	}
}

// GetProxyStatus GET /api/v1/system/proxy
// Reports the LIVE egress-proxy configuration + latest health probe, secrets
// masked.
func (h *SystemHandler) GetProxyStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"success": true, "data": proxyStatusData()})
}

// SetProxy PATCH /api/v1/system/proxy
// Updates the egress proxy at RUNTIME (no restart) — every outbound client picks
// it up on its next request. Admin only.
func (h *SystemHandler) SetProxy(c *gin.Context) {
	if middleware.GetRole(c) != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "admin role required"})
		return
	}
	var req struct {
		ProxyURL       string `json:"proxy_url"`
		NoProxy        string `json:"no_proxy"`
		FallbackDirect bool   `json:"fallback_direct"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	p := strings.TrimSpace(req.ProxyURL)
	if p != "" {
		u, err := url.Parse(p)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5") {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "proxy URL must be http(s) or socks5"})
			return
		}
	}
	egress.Set(p, config.EffectiveNoProxy(req.NoProxy), req.FallbackDirect)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": proxyStatusData()})
}

// CheckProxy POST /api/v1/system/proxy/check
// Runs the proxy health probe immediately and returns the fresh result.
func (h *SystemHandler) CheckProxy(c *gin.Context) {
	egress.CheckNow()
	c.JSON(http.StatusOK, gin.H{"success": true, "data": proxyStatusData()})
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

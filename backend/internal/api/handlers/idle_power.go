package handlers

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/analysishub/backend/internal/logsearch"
)

// idle_power.go — idle auto-shutdown for the RAM-heavy, intermittently-used
// containers: ELK (Elasticsearch + Kibana) and the volatility Sandbox. They boot
// with the stack (default ON); a background reaper stops them once they go unused
// for the configured number of minutes, and they auto-start again the moment an
// analyst opens the relevant page (a keepalive heartbeat). An admin can still
// force either state by hand — a manual STOP is respected (auto-start is
// suppressed) until the admin manually starts it again.
//
// "Used" is recorded via markELKActivity / markSandboxActivity, bumped from the
// keepalive heartbeat, the sandbox reverse-proxy, and log ingest. All state is
// in-memory (a restart brings the containers back per compose and clears flags).

type idleService struct {
	last      time.Time // last recorded activity
	manualOff bool      // admin stopped it by hand → don't auto-start
}

var idleState = struct {
	mu      sync.Mutex
	elk     idleService
	sandbox idleService
	inited  bool
}{}

const (
	svcELK     = "elk"
	svcSandbox = "sandbox"
)

func idleInit() {
	idleState.mu.Lock()
	defer idleState.mu.Unlock()
	if !idleState.inited {
		now := time.Now()
		idleState.elk.last = now
		idleState.sandbox.last = now
		idleState.inited = true
	}
}

// markELKActivity records that the ELK stack is being used (resets its idle timer).
func markELKActivity() {
	idleState.mu.Lock()
	idleState.elk.last = time.Now()
	idleState.mu.Unlock()
}

// markSandboxActivity records that the sandbox is being used.
func markSandboxActivity() {
	idleState.mu.Lock()
	idleState.sandbox.last = time.Now()
	idleState.mu.Unlock()
}

func (h *LogSearchHandler) elkIdleTimeout() time.Duration {
	return time.Duration(h.ELKIdleTimeoutMin) * time.Minute
}
func (h *LogSearchHandler) sandboxIdleTimeout() time.Duration {
	return time.Duration(h.SandboxIdleTimeoutMin) * time.Minute
}

// StartIdlePowerWorker launches the reaper. No-op when disabled or when docker
// control is unavailable (nothing to stop through).
func (h *LogSearchHandler) StartIdlePowerWorker() {
	if !h.IdlePowerEnabled || !h.controlEnabled() {
		log.Printf("[idle-power] disabled (enabled=%v control=%v)", h.IdlePowerEnabled, h.controlEnabled())
		return
	}
	idleInit()
	log.Printf("[idle-power] started — ELK idle=%dm, sandbox idle=%dm", h.ELKIdleTimeoutMin, h.SandboxIdleTimeoutMin)
	go runWorker("idle-power", 30*time.Second, func() { h.idlePowerTick() })
}

// idlePowerTick stops any managed container that has been running and idle past
// its timeout. An idle auto-stop does NOT set manualOff, so the next page open
// brings it straight back.
func (h *LogSearchHandler) idlePowerTick() {
	client := dockerHTTP()
	now := time.Now()

	if to := h.elkIdleTimeout(); to > 0 {
		idleState.mu.Lock()
		idle := now.Sub(idleState.elk.last)
		idleState.mu.Unlock()
		if idle >= to && h.inspect(client, elkESContainer).Running {
			log.Printf("[idle-power] ELK idle for %s ≥ %s → stopping", idle.Round(time.Second), to)
			// Stop Kibana before Elasticsearch.
			_ = h.action(client, elkKibanaContainer, "stop")
			_ = h.action(client, elkESContainer, "stop")
		}
	}

	if to := h.sandboxIdleTimeout(); to > 0 {
		idleState.mu.Lock()
		idle := now.Sub(idleState.sandbox.last)
		idleState.mu.Unlock()
		if idle >= to && h.inspect(client, sandboxContainer).Running {
			log.Printf("[idle-power] sandbox idle for %s ≥ %s → stopping", idle.Round(time.Second), to)
			_ = h.action(client, sandboxContainer, "stop")
		}
	}
}

// autoShutdownInfo describes the idle policy + countdown for a service, for the
// status endpoints so the UI can show "auto-stops in N s".
func (h *LogSearchHandler) autoShutdownInfo(svc string) gin.H {
	var timeout time.Duration
	var last time.Time
	var manualOff bool
	idleState.mu.Lock()
	switch svc {
	case svcELK:
		timeout = h.elkIdleTimeout()
		last = idleState.elk.last
		manualOff = idleState.elk.manualOff
	case svcSandbox:
		timeout = h.sandboxIdleTimeout()
		last = idleState.sandbox.last
		manualOff = idleState.sandbox.manualOff
	}
	idleState.mu.Unlock()

	info := gin.H{
		"enabled":     h.IdlePowerEnabled && h.controlEnabled() && timeout > 0,
		"timeout_sec": int(timeout.Seconds()),
		"manual_off":  manualOff,
	}
	if h.IdlePowerEnabled && timeout > 0 && !last.IsZero() {
		idleSec := int(time.Since(last).Seconds())
		info["idle_sec"] = idleSec
		stopsIn := int(timeout.Seconds()) - idleSec
		if stopsIn < 0 {
			stopsIn = 0
		}
		info["stops_in_sec"] = stopsIn
	}
	return info
}

// Keepalive records that a managed service is in use and, when it is stopped and
// not admin-disabled, auto-starts it. Called by the frontend on page open and as
// a periodic heartbeat while the ELK / Sandbox page is mounted.
//
// POST /api/v1/logsearch/keepalive/:svc   (svc = elk | sandbox)
func (h *LogSearchHandler) Keepalive(c *gin.Context) {
	svc := c.Param("svc")
	if svc != svcELK && svc != svcSandbox {
		c.JSON(http.StatusBadRequest, gin.H{"error": "svc must be elk or sandbox"})
		return
	}
	// Record usage.
	if svc == svcELK {
		markELKActivity()
	} else {
		markSandboxActivity()
	}

	if !h.controlEnabled() {
		c.JSON(http.StatusOK, gin.H{"ok": true, "control_enabled": false})
		return
	}

	idleState.mu.Lock()
	manualOff := idleState.elk.manualOff
	if svc == svcSandbox {
		manualOff = idleState.sandbox.manualOff
	}
	idleState.mu.Unlock()

	client := dockerHTTP()
	names := []string{elkESContainer, elkKibanaContainer}
	if svc == svcSandbox {
		names = []string{sandboxContainer}
	}

	// If the admin turned it off by hand, don't auto-start — report that.
	if manualOff {
		c.JSON(http.StatusOK, gin.H{"ok": true, "manual_off": true, "starting": false})
		return
	}

	// Auto-start any managed container that isn't running.
	starting := false
	for _, name := range names {
		if !h.inspect(client, name).Running {
			starting = true
			if err := h.action(client, name, "start"); err != nil {
				log.Printf("[idle-power] auto-start %s: %v", name, err)
			}
		}
	}
	if starting && svc == svcELK && h.KibanaURL != "" {
		go logsearch.EnsureKibanaDataView(h.KibanaURL)
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "starting": starting})
}

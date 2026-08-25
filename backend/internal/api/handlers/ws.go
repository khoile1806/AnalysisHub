package handlers

import (
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/models"
	appws "github.com/analysishub/backend/internal/ws"
)

// allowedWSOrigins is the set of browser origins permitted to initiate a
// WebSocket upgrade. It is populated by SetAllowedOrigins during router
// construction. Requests with no Origin header (non-browser clients such as
// the Go agent) are always accepted — the browser same-origin policy is what
// CheckOrigin is designed to enforce.
var allowedWSOrigins = map[string]struct{}{}

// SetAllowedOrigins configures the WebSocket upgrader's origin allowlist.
// Call once at startup before any requests are served.
func SetAllowedOrigins(origins []string) {
	m := make(map[string]struct{}, len(origins))
	for _, o := range origins {
		if o != "" {
			m[o] = struct{}{}
		}
	}
	allowedWSOrigins = m
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			// Non-browser client (e.g. the Go agent) — no Origin header is
			// sent, so there is no cross-site hijacking risk.
			return true
		}
		if _, ok := allowedWSOrigins[origin]; ok {
			return true
		}
		// Same-origin is always allowed, whatever address the server was reached
		// by. What this check exists to stop is a page on ANOTHER site opening a
		// socket here; a page served by this very host is not that. Requiring the
		// operator to enumerate every IP and hostname in ALLOWED_ORIGINS meant a
		// fresh deployment reached at http://<server-ip>:3000 served HTTP fine and
		// then failed every WebSocket — a silent, confusing half-broken state.
		//
		// Both nginx proxy blocks forward `Host: $http_host`, so r.Host is the
		// authority the browser actually typed, port included.
		if u, err := url.Parse(origin); err == nil && u.Host != "" &&
			strings.EqualFold(u.Host, r.Host) {
			return true
		}
		return false
	},
}

// AgentWebSocket upgrades the HTTP connection to a WebSocket and registers
// the agent with the hub.
//
// GET /ws/agent
// Auth: X-Agent-Token header or ?token= query param (validated by AgentAuthMiddleware)
func AgentWebSocket(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	hub, ok := mustGetHub(c)
	if !ok {
		return
	}

	agentIDStr := middleware.GetAgentID(c)
	if agentIDStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "not authenticated"})
		return
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("[ws] upgrade error for agent %s: %v", agentIDStr, err)
		return
	}

	client := appws.NewClient(hub, conn, agentIDStr)

	// OnRegister: update agent metadata in the database when the agent announces itself.
	client.OnRegister = func(hostname, agentOS, ip string) {
		agentID, parseErr := uuid.Parse(client.AgentID)
		if parseErr != nil {
			log.Printf("[ws] invalid agent ID on register: %v", parseErr)
			return
		}
		now := time.Now()
		updates := map[string]interface{}{
			"hostname":   hostname,
			"os":         agentOS,
			"ip_address": ip,
			"status":     "online",
			"last_seen":  now,
		}
		if updateErr := db.Model(&models.Agent{}).Where("id = ?", agentID).Updates(updates).Error; updateErr != nil {
			log.Printf("[ws] update agent on register: %v", updateErr)
		}
		writeAudit(c, db, nil, &agentID, "agent.connect", agentID.String(),
			"agent connected via WebSocket")
	}

	// OnArtifact: log artifact notification signalled over WebSocket.
	// Actual file storage happens via the REST artifact upload endpoint.
	client.OnArtifact = func(jobID, filename string, size int64) {
		log.Printf("[ws] agent %s signals artifact for job %s: %s (%d bytes)", agentIDStr, jobID, filename, size)
	}

	// OnResourceReport: persist CPU/RAM/Disk telemetry sent by the agent. Runs the
	// DB write off the per-connection read loop so a slow write can never stall
	// reading (which would starve ping/pong and flap the connection).
	client.OnResourceReport = func(cpu float64, memUsed, memTotal int64, diskUsed, diskTotal float64) {
		agentID, parseErr := uuid.Parse(client.AgentID)
		if parseErr != nil {
			return
		}
		go db.Model(&models.Agent{}).Where("id = ?", agentID).Updates(map[string]interface{}{
			"cpu_percent":   cpu,
			"mem_used_mb":   memUsed,
			"mem_total_mb":  memTotal,
			"disk_used_gb":  diskUsed,
			"disk_total_gb": diskTotal,
			"last_seen":     time.Now(),
		})
	}

	// Start the client lifecycle in a goroutine; mark agent offline on disconnect.
	go func() {
		client.Start()

		agentID, parseErr := uuid.Parse(agentIDStr)
		if parseErr != nil {
			return
		}
		now := time.Now()
		offlineUpdates := map[string]interface{}{
			"status":    "offline",
			"last_seen": now,
		}
		if updateErr := db.Model(&models.Agent{}).Where("id = ?", agentID).Updates(offlineUpdates).Error; updateErr != nil {
			log.Printf("[ws] update agent offline: %v", updateErr)
		}
		writeAudit(c, db, nil, &agentID, "agent.disconnect", agentID.String(),
			"agent disconnected from WebSocket")
	}()

	// Keep the hub reference alive for the compiler — it is used inside goroutine above.
	_ = hub
}

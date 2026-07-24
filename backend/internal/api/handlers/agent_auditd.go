package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/analysishub/backend/internal/ws"
)

// linuxEventsRequest bounds a Linux event-stream collection. All fields are
// optional; the agent clamps them (default max 2000, hard cap 20000).
type linuxEventsRequest struct {
	Hours   int    `json:"hours"`
	Max     int    `json:"max"`
	Keyword string `json:"keyword"`
}

// AgentLinuxEventsParse collects a normalized process / security event stream
// from a (Linux) agent — auditd records merged into whole events, falling back
// to journald and then the auth log. This is the Linux counterpart of the EVTX
// feed and is what gives the Sigma engine something to evaluate on Linux hosts.
//
// POST /api/v1/agents/:id/linux-events  body: {"hours":24,"max":2000,"keyword":""}
func AgentLinuxEventsParse(c *gin.Context) {
	hub, ok := mustGetHub(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid agent ID"})
		return
	}
	if !hub.IsAgentOnline(id.String()) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": "agent is offline"})
		return
	}

	var body linuxEventsRequest
	_ = c.ShouldBindJSON(&body) // optional; empty → agent uses its defaults

	args, err := json.Marshal(body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid options"})
		return
	}

	reqID := uuid.New().String()
	outCh := hub.SubscribeJobOutput(reqID)
	defer hub.UnsubscribeJobOutput(reqID, outCh)

	if err := hub.SendJobToAgent(id.String(), ws.AgentCommand{
		Type:  "edge_parse_linux_events",
		JobID: reqID,
		Args:  string(args),
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to send request"})
		return
	}

	awaitEdgeJSONResult(c, hub, outCh, id.String(), "linux-events")
}

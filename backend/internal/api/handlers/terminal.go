package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/forensichub/backend/internal/api/middleware"
	"github.com/forensichub/backend/internal/models"
	appws "github.com/forensichub/backend/internal/ws"
)

// allowedShells is the fixed list of shells admins may request. Restricting
// the input prevents the agent from being coerced into executing arbitrary
// binaries through the shell field.
var allowedShells = map[string]bool{
	"cmd":        true,
	"powershell": true,
	"bash":       true,
	"zsh":        true,
	"sh":         true,
}

// browserMsg is the wire format for messages received from the web terminal.
type browserMsg struct {
	Type string `json:"type"` // "input" | "resize"
	Data string `json:"data,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

// serverMsg is the wire format for messages pushed to the web terminal.
type serverMsg struct {
	Type     string `json:"type"` // "output" | "closed" | "error"
	Data     string `json:"data,omitempty"`
	ExitCode int    `json:"exit_code,omitempty"`
	Message  string `json:"message,omitempty"`
}

// TerminalWebSocket opens an interactive PTY session on the target agent and
// bridges it to the browser via a WebSocket.
//
// GET /ws/terminal?agent_id=<uuid>&shell=cmd|powershell|bash|sh&cols=&rows=&token=<jwt>
// Auth: JWT (shared AuthMiddleware via ?token= query param).
func TerminalWebSocket(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	hub, ok := mustGetHub(c)
	if !ok {
		return
	}

	// Validate parameters before upgrading so HTTP errors are visible to the
	// browser (an upgraded WebSocket can only report structured errors).
	agentIDStr := c.Query("agent_id")
	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid agent_id"})
		return
	}
	shell := c.Query("shell")
	if !allowedShells[shell] {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "unsupported shell"})
		return
	}
	cols, _ := strconv.Atoi(c.DefaultQuery("cols", "120"))
	rows, _ := strconv.Atoi(c.DefaultQuery("rows", "30"))
	if cols <= 0 {
		cols = 120
	}
	if rows <= 0 {
		rows = 30
	}

	var agent models.Agent
	if err := db.First(&agent, "id = ?", agentID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "agent not found"})
		return
	}

	if !hub.IsAgentOnline(agentIDStr) {
		c.JSON(http.StatusConflict, gin.H{"success": false, "error": "agent is offline"})
		return
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("[terminal] upgrade error: %v", err)
		return
	}

	sessionID := uuid.NewString()
	var writeMu sync.Mutex
	writeToBrowser := func(m serverMsg) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		return conn.WriteJSON(m)
	}

	closeOnce := sync.Once{}
	closeSession := func() {
		closeOnce.Do(func() {
			hub.UnregisterTerminalSession(sessionID)
			_ = hub.SendJobToAgent(agentIDStr, appws.AgentCommand{
				Type:      "shell_close",
				SessionID: sessionID,
			})
		})
	}

	hub.RegisterTerminalSession(&appws.TerminalSession{
		ID:      sessionID,
		AgentID: agentIDStr,
		OnData: func(b64 string) {
			if b64 == "" {
				return
			}
			_ = writeToBrowser(serverMsg{Type: "output", Data: b64})
		},
		OnClosed: func(exitCode int) {
			if exitCode == -1 {
				// Agent disconnected unexpectedly — tell the browser before closing.
				_ = writeToBrowser(serverMsg{Type: "error", Message: "agent disconnected"})
			}
			_ = writeToBrowser(serverMsg{Type: "closed", ExitCode: exitCode})
			// Give the browser a moment to flush the final frame.
			time.Sleep(100 * time.Millisecond)
			_ = conn.Close()
		},
	})

	// Ask the agent to spawn the shell. Any failure on the agent side surfaces
	// as a shell_closed message routed through the session callback above.
	if err := hub.SendJobToAgent(agentIDStr, appws.AgentCommand{
		Type:      "shell_open",
		SessionID: sessionID,
		Shell:     shell,
		Cols:      cols,
		Rows:      rows,
	}); err != nil {
		_ = writeToBrowser(serverMsg{Type: "error", Message: "failed to open shell: " + err.Error()})
		hub.UnregisterTerminalSession(sessionID)
		_ = conn.Close()
		return
	}

	// Audit the session open. Detail includes the shell choice.
	userID, _ := middleware.GetUserID(c)
	writeAudit(c, db, &userID, &agentID, "agent.shell", sessionID, "open shell="+shell)

	// Read loop — translate browser messages into AgentCommands for the agent.
	// Connection closes (client gone, network error) trigger closeSession().
	defer closeSession()
	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var m browserMsg
		if err := json.Unmarshal(raw, &m); err != nil {
			continue
		}
		switch m.Type {
		case "input":
			_ = hub.SendJobToAgent(agentIDStr, appws.AgentCommand{
				Type:      "shell_input",
				SessionID: sessionID,
				Data:      m.Data,
			})
		case "resize":
			if m.Cols <= 0 || m.Rows <= 0 {
				continue
			}
			_ = hub.SendJobToAgent(agentIDStr, appws.AgentCommand{
				Type:      "shell_resize",
				SessionID: sessionID,
				Cols:      m.Cols,
				Rows:      m.Rows,
			})
		}
	}
}

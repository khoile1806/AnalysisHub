package handlers

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/api/middleware"
	"github.com/forensichub/backend/internal/models"
	"github.com/forensichub/backend/internal/ws"
)

// agentNameRe limits agent names to a safe character set so values that flow
// into install-script templates (rendered via text/template, not html/template,
// and interpreted by PowerShell / bash) cannot break out of their string
// context. Allowed: letters, digits, space, dot, underscore, hyphen.
var agentNameRe = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,64}$`)

// createAgentRequest is the JSON body for registering a new agent.
type createAgentRequest struct {
	Name        string `json:"name"        binding:"required"`
	Description string `json:"description"`
	CaseID      string `json:"case_id"`
}

// ListAgents returns all registered agents with their current status.
//
// GET /api/v1/agents
func ListAgents(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}

	var agents []models.Agent
	if err := db.Order("created_at desc").Find(&agents).Error; err != nil {
		log.Printf("[agents] list error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to list agents"})
		return
	}

	// Clear token field from all returned agents — it must never be sent post-creation.
	for i := range agents {
		agents[i].Token = ""
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": agents})
}

// CreateAgent registers a new agent and generates a unique pre-shared token.
// The token is returned only once in this response; it is not retrievable later.
//
// POST /api/v1/agents
// Body: {"name":"...","description":"..."}
func CreateAgent(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetUserID(c)

	var req createAgentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if !agentNameRe.MatchString(req.Name) {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "name must be 1-64 chars using letters, digits, space, '.', '_' or '-'",
		})
		return
	}

	token, err := generateAgentToken()
	if err != nil {
		log.Printf("[agents] token generation: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to generate agent token"})
		return
	}

	agent := models.Agent{
		Name:        req.Name,
		Token:       token,
		Status:      "offline",
		Description: req.Description,
	}
	if req.CaseID != "" {
		if cid, err := uuid.Parse(req.CaseID); err == nil {
			agent.CaseID = &cid
		}
	}

	if err := db.Create(&agent).Error; err != nil {
		log.Printf("[agents] db create: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to create agent"})
		return
	}

	writeAudit(c, db, &userID, &agent.ID, "agent.create", agent.ID.String(), fmt.Sprintf("created agent %q", req.Name))

	// Return the full agent including token (shown only once).
	c.JSON(http.StatusCreated, gin.H{"success": true, "data": agent})
}

// UpdateAgent updates an agent's description and/or case association.
//
// PATCH /api/v1/agents/:id
func UpdateAgent(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid agent ID"})
		return
	}

	var agent models.Agent
	if err := db.First(&agent, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "agent not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	var req struct {
		Description *string `json:"description"`
		CaseID      *string `json:"case_id"` // "" to unlink, UUID string to link
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	updates := map[string]interface{}{}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.CaseID != nil {
		if *req.CaseID == "" {
			updates["case_id"] = nil
		} else if cid, err := uuid.Parse(*req.CaseID); err == nil {
			updates["case_id"] = cid
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case_id"})
			return
		}
	}

	if len(updates) > 0 {
		db.Model(&agent).Updates(updates)
	}

	db.First(&agent, "id = ?", id)
	agent.Token = ""
	c.JSON(http.StatusOK, gin.H{"success": true, "data": agent})
}

// GetAgent returns a single agent by UUID.
//
// GET /api/v1/agents/:id
func GetAgent(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid agent ID"})
		return
	}

	var agent models.Agent
	if err := db.First(&agent, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "agent not found"})
			return
		}
		log.Printf("[agents] get error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	// Never expose token outside creation endpoint.
	agent.Token = ""
	c.JSON(http.StatusOK, gin.H{"success": true, "data": agent})
}

// DeleteAgent removes an agent and marks any pending/running jobs as failed.
//
// DELETE /api/v1/agents/:id
func DeleteAgent(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetUserID(c)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid agent ID"})
		return
	}

	var agent models.Agent
	if err := db.First(&agent, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "agent not found"})
			return
		}
		log.Printf("[agents] delete fetch error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	// If the agent is online, send a cleanup command so it uninstalls itself from the target machine.
	hub, ok := mustGetHub(c)
	if ok && hub.IsAgentOnline(id.String()) {
		log.Printf("[agents] triggering remote cleanup for agent %s before deletion", id)
		_ = hub.SendJobToAgent(id.String(), ws.AgentCommand{Type: "cleanup"})
	}

	// Cancel outstanding jobs for this agent.
	db.Model(&models.Job{}).
		Where("agent_id = ? AND status IN ?", id, []string{"pending", "running"}).
		Updates(map[string]interface{}{"status": models.JobFailed, "output": "agent deleted"})

	if err := db.Delete(&agent).Error; err != nil {
		log.Printf("[agents] db delete error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to delete agent"})
		return
	}

	writeAudit(c, db, &userID, &id, "agent.delete", id.String(), fmt.Sprintf("deleted agent %q", agent.Name))

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"id": id}})
}

// GetAgentInstaller returns a JSON configuration payload that an installer
// script can use to bootstrap a new agent on a target host.
//
// GET /api/v1/agents/:id/installer
func GetAgentInstaller(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid agent ID"})
		return
	}

	var agent models.Agent
	if err := db.First(&agent, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "agent not found"})
			return
		}
		log.Printf("[agents] installer fetch error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	serverURL := getServerURL(c)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"agent_id":   agent.ID,
			"agent_name": agent.Name,
			"token":      agent.Token,
			"server_url": serverURL,
			"ws_url":     buildWSURL(serverURL) + "/ws/agent",
		},
	})
}

// DownloadAgentBinary serves the pre-compiled agent binary for a given platform.
// Available under two routes:
//   - GET /api/v1/agents/binary/:platform  (JWT auth — admin download)
//   - GET /api/v1/agent/binary/:platform   (agent-token auth — used by install scripts)
func DownloadAgentBinary(c *gin.Context) {
	platform := c.Param("platform")

	agentBinsPath := os.Getenv("AGENT_BINS_PATH")
	if agentBinsPath == "" {
		agentBinsPath = "/app/agent-bins"
	}

	var filename string
	switch platform {
	case "windows":
		filename = "forensichub-agent.exe"
	case "linux":
		filename = "forensichub-agent-linux"
	default:
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "platform must be 'windows' or 'linux'"})
		return
	}

	filePath := filepath.Join(agentBinsPath, filename)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "agent binary not available"})
		return
	}

	c.FileAttachment(filePath, filename)
}

// GetAgentInstallScript returns a PowerShell (.ps1) or Bash (.sh) one-click install
// script with the agent credentials embedded. Authentication is performed inline
// using the agent token supplied via the ?token= query parameter so that the
// generated URL is fully self-contained (no JWT required on the target machine).
//
// GET /api/v1/agents/:id/install.ps1?token=<agent_token>
// GET /api/v1/agents/:id/install.sh?token=<agent_token>
func GetAgentInstallScript(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid agent ID"})
		return
	}

	// Inline token validation — intentionally NOT using AgentAuthMiddleware so
	// that fetching the script does not update last_seen / mark the agent online.
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "token query parameter required"})
		return
	}

	var agent models.Agent
	if err := db.First(&agent, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "agent not found"})
			return
		}
		log.Printf("[agents] install script fetch error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	if agent.Token != token {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "invalid token"})
		return
	}

	serverURL := getServerURL(c)

	data := struct {
		AgentID   string
		AgentName string
		Token     string
		ServerURL string
	}{
		AgentID:   agent.ID.String(),
		AgentName: agent.Name,
		Token:     agent.Token,
		ServerURL: serverURL,
	}

	var scriptTmpl string
	var filename string
	if strings.HasSuffix(c.Request.URL.Path, ".ps1") {
		scriptTmpl = powershellInstallScript
		filename = "install.ps1"
	} else {
		scriptTmpl = bashInstallScript
		filename = "install.sh"
	}

	tmpl, err := template.New("script").Parse(scriptTmpl)
	if err != nil {
		log.Printf("[agents] template parse error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "script generation failed"})
		return
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		log.Printf("[agents] template execute error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "script generation failed"})
		return
	}

	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	c.Data(http.StatusOK, "text/plain; charset=utf-8", buf.Bytes())
}

// GetAgentMonitor streams real-time agent telemetry (process list or netstat)
// to the caller using Server-Sent Events. The agent pushes snapshots every few
// seconds via its WebSocket connection; this handler fans them out to dashboard
// clients.
//
// GET /api/v1/agents/:id/monitor?type=processes|netstat
func GetAgentMonitor(c *gin.Context) {
	hub, ok := mustGetHub(c)
	if !ok {
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid agent ID"})
		return
	}

	dataType := c.Query("type")
	if dataType != "processes" && dataType != "netstat" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "type must be 'processes' or 'netstat'"})
		return
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	c.Writer.WriteHeader(http.StatusOK)

	// Send latest cached snapshot immediately if available.
	if latest, ok := hub.GetLatestRealtime(id.String(), dataType); ok {
		fmt.Fprintf(c.Writer, "data: %s\n\n", latest)
		c.Writer.Flush()
	}

	ch := hub.SubscribeRealtime(id.String(), dataType)
	defer hub.UnsubscribeRealtime(id.String(), dataType, ch)

	clientGone := c.Request.Context().Done()
	for {
		select {
		case <-clientGone:
			return
		case payload, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(c.Writer, "data: %s\n\n", payload)
			c.Writer.Flush()
		}
	}
}

// CleanupAgent instructs the agent to wipe every file it created (tools,
// work directory, config) and then self-delete its own binary — restoring
// the target machine to its pre-install state. The agent will disconnect
// as part of the cleanup; the DB record and any outstanding jobs for the
// agent are also purged so the UI does not keep a zombie entry.
//
// POST /api/v1/agents/:id/cleanup
func CleanupAgent(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	hub, ok := mustGetHub(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetUserID(c)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid agent ID"})
		return
	}

	var agent models.Agent
	if err := db.First(&agent, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "agent not found"})
			return
		}
		log.Printf("[agents] cleanup fetch error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	if !hub.IsAgentOnline(agent.ID.String()) {
		c.JSON(http.StatusConflict, gin.H{"success": false, "error": "agent is offline — cannot dispatch cleanup"})
		return
	}

	if err := hub.SendJobToAgent(agent.ID.String(), ws.AgentCommand{Type: "cleanup"}); err != nil {
		log.Printf("[agents] cleanup dispatch error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to dispatch cleanup command"})
		return
	}

	// Mark any outstanding jobs as failed and remove the agent record. The
	// agent will not reconnect — it is deleting its own binary.
	db.Model(&models.Job{}).
		Where("agent_id = ? AND status IN ?", id, []string{"pending", "running"}).
		Updates(map[string]interface{}{"status": models.JobFailed, "output": "agent cleaned up"})
	if err := db.Delete(&agent).Error; err != nil {
		log.Printf("[agents] cleanup db delete error: %v", err)
	}

	writeAudit(c, db, &userID, &id, "agent.cleanup", id.String(), fmt.Sprintf("cleanup dispatched to agent %q", agent.Name))

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"id": id}})
}

// generateAgentToken produces a cryptographically random 32-byte hex string.
func generateAgentToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rand read: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// buildWSURL converts an http/https server URL to its ws/wss equivalent.
func buildWSURL(serverURL string) string {
	if len(serverURL) >= 5 && serverURL[:5] == "https" {
		return "wss" + serverURL[5:]
	}
	if len(serverURL) >= 4 && serverURL[:4] == "http" {
		return "ws" + serverURL[4:]
	}
	return serverURL
}

// ── Install script templates ──────────────────────────────────────────────── //

const powershellInstallScript = `# ForensicHub Agent - Windows Installer
# Agent : {{.AgentName}}
# Server: {{.ServerURL}}

$ErrorActionPreference = "Stop"
$InstallDir  = "C:\ForensicHub"
$AgentBinary = Join-Path $InstallDir "forensichub-agent.exe"
$ConfigFile  = Join-Path $InstallDir "forensichub-agent.conf"
$BinaryUrl   = "{{.ServerURL}}/api/v1/agent/binary/windows"
$AgentToken  = "{{.Token}}"

Write-Host "[*] ForensicHub Agent Installer" -ForegroundColor Cyan
Write-Host "    Agent : {{.AgentName}}"
Write-Host "    Server: {{.ServerURL}}"
Write-Host ""

# 1. Create install directory
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Host "[+] Created $InstallDir"
}

# 2. Download agent binary
Write-Host "[*] Downloading agent binary..."
try {
    Invoke-WebRequest -Uri ($BinaryUrl + "?token=" + $AgentToken) -OutFile $AgentBinary -UseBasicParsing
    Write-Host "[+] Binary saved to $AgentBinary"
} catch {
    Write-Host "[!] Download failed: $_" -ForegroundColor Red
    exit 1
}

# 3. Write configuration
@"
SERVER_URL={{.ServerURL}}
AGENT_TOKEN={{.Token}}
AGENT_NAME={{.AgentName}}
"@ | Set-Content -Path $ConfigFile -Encoding ASCII
Write-Host "[+] Configuration written to $ConfigFile"

# 4. Start agent (standard window — for visibility/debugging)
Write-Host "[*] Starting agent..."
Start-Process -FilePath $AgentBinary -WorkingDirectory $InstallDir
Write-Host ""
Write-Host "[+] Done! Agent '{{.AgentName}}' should appear online in the dashboard shortly." -ForegroundColor Green
`

const bashInstallScript = `#!/usr/bin/env bash
# ForensicHub Agent - Linux Installer
# Agent : {{.AgentName}}
# Server: {{.ServerURL}}

set -euo pipefail

INSTALL_DIR="/opt/forensichub"
BINARY_URL="{{.ServerURL}}/api/v1/agent/binary/linux"
AGENT_TOKEN="{{.Token}}"

echo "[*] ForensicHub Agent Installer"
echo "    Agent : {{.AgentName}}"
echo "    Server: {{.ServerURL}}"
echo ""

# 1. Create install directory
mkdir -p "$INSTALL_DIR"

# 2. Download agent binary
echo "[*] Downloading agent binary..."
curl -fsSL "${BINARY_URL}?token=${AGENT_TOKEN}" -o "$INSTALL_DIR/forensichub-agent"
chmod +x "$INSTALL_DIR/forensichub-agent"
echo "[+] Binary saved to $INSTALL_DIR/forensichub-agent"

# 3. Write configuration
cat > "$INSTALL_DIR/forensichub-agent.conf" << CONF
SERVER_URL={{.ServerURL}}
AGENT_TOKEN={{.Token}}
AGENT_NAME={{.AgentName}}
CONF
echo "[+] Configuration written to $INSTALL_DIR/forensichub-agent.conf"

# 4. Start agent — prefer systemd (auto-restart on crash/reboot), fall back to nohup
echo "[*] Starting agent..."
if command -v systemctl &>/dev/null && [ "$(id -u)" -eq 0 ]; then
    cat > /etc/systemd/system/forensichub-agent.service << SERVICE
[Unit]
Description=ForensicHub Agent
After=network.target

[Service]
ExecStart=$INSTALL_DIR/forensichub-agent
WorkingDirectory=$INSTALL_DIR
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE
    systemctl daemon-reload
    systemctl enable --now forensichub-agent.service
    echo "[+] Agent installed as systemd service (auto-restart enabled)"
else
    nohup "$INSTALL_DIR/forensichub-agent" > "$INSTALL_DIR/agent.log" 2>&1 &
    echo "[+] Agent started via nohup (PID $!)"
    echo "    Note: run as root for systemd auto-restart support"
fi
echo ""
echo "[+] Done! Agent '{{.AgentName}}' should appear online in the dashboard shortly."
`

package handlers

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/ws"
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

	writeTotalCount(c, db.Model(&models.Agent{}))

	query := applyLimitOffset(c, db.Order("created_at desc"))

	var agents []models.Agent
	if err := query.Find(&agents).Error; err != nil {
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

	serverURL := installServerURL(c)

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
		filename = "analysishub-agent.exe"
	case "linux":
		filename = "analysishub-agent-linux"
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

// installServerURL resolves the server URL to embed in a generated agent
// installer. Priority:
//  1. explicit ?server=http://host:port override (multi-homed servers);
//  2. the host the installer was fetched through (so a LAN-IP install talks to
//     the LAN IP and a public-domain install talks to the domain);
//  3. PUBLIC_URL as a last resort when no request host is available.
//
// This is deliberately NOT plain getServerURL: pinning every installer to
// PUBLIC_URL breaks LAN installs on hosts that cannot reach the public domain.
func installServerURL(c *gin.Context) string {
	if s := strings.TrimSpace(c.Query("server")); s != "" {
		if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
			return strings.TrimRight(s, "/")
		}
	}
	// requestBaseURL returns "scheme://host"; if the host is empty it ends with
	// "://" — only trust it when a real host is present.
	if base := requestBaseURL(c); !strings.HasSuffix(base, "://") {
		return base
	}
	return getServerURL(c)
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

	serverURL := installServerURL(c)

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
	if dataType != "processes" && dataType != "netstat" && dataType != "netconn" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "type must be 'processes', 'netstat' or 'netconn'"})
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

const powershellInstallScript = `# AnalysisHub Agent - Windows Installer
# Agent : {{.AgentName}}
# Server: {{.ServerURL}}

$ErrorActionPreference = "Stop"
$InstallDir  = Join-Path $env:LOCALAPPDATA "AnalysisHub"
$AgentBinary = Join-Path $InstallDir "analysishub-agent.exe"
$ConfigFile  = Join-Path $InstallDir "analysishub-agent.conf"
$BinaryUrl   = "{{.ServerURL}}/api/v1/agent/binary/windows"
$AgentToken  = "{{.Token}}"

Write-Host "[*] AnalysisHub Agent Installer" -ForegroundColor Cyan
Write-Host "    Agent : {{.AgentName}}"
Write-Host "    Server: {{.ServerURL}}"
Write-Host ""

# 1. Create install directory
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Host "[+] Created $InstallDir"
}

# 2. Download agent binary
Write-Host "[*] Downloading agent binary from $BinaryUrl"
try {
    Invoke-WebRequest -Uri ($BinaryUrl + "?token=" + $AgentToken) -OutFile $AgentBinary -UseBasicParsing
    Write-Host "[+] Binary saved to $AgentBinary"
} catch {
    Write-Host ""
    Write-Host "[!] Download failed from: $BinaryUrl" -ForegroundColor Red
    Write-Host "    $_" -ForegroundColor Red
    Write-Host "    This machine could not reach the server URL above." -ForegroundColor Yellow
    Write-Host "    Re-run the installer pointing at a URL this machine CAN reach, e.g. the LAN address:" -ForegroundColor Yellow
    Write-Host "    iex (irm '<installer-url>&server=http://<server-ip>:3000')" -ForegroundColor Yellow
    return   # NOT 'exit' — 'exit' would close the whole PowerShell window under iex
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
# AnalysisHub Agent - Linux Installer
# Agent : {{.AgentName}}
# Server: {{.ServerURL}}

set -euo pipefail

INSTALL_DIR="$HOME/.analysishub"
BINARY_URL="{{.ServerURL}}/api/v1/agent/binary/linux"
AGENT_TOKEN="{{.Token}}"

echo "[*] AnalysisHub Agent Installer"
echo "    Agent : {{.AgentName}}"
echo "    Server: {{.ServerURL}}"
echo ""

# 1. Create install directory
mkdir -p "$INSTALL_DIR"

# 2. Download agent binary
echo "[*] Downloading agent binary..."
curl -fsSL "${BINARY_URL}?token=${AGENT_TOKEN}" -o "$INSTALL_DIR/analysishub-agent"
chmod +x "$INSTALL_DIR/analysishub-agent"
echo "[+] Binary saved to $INSTALL_DIR/analysishub-agent"

# 3. Write configuration
cat > "$INSTALL_DIR/analysishub-agent.conf" << CONF
SERVER_URL={{.ServerURL}}
AGENT_TOKEN={{.Token}}
AGENT_NAME={{.AgentName}}
CONF
echo "[+] Configuration written to $INSTALL_DIR/analysishub-agent.conf"

# 4. Start agent — prefer systemd (auto-restart on crash/reboot), fall back to nohup
echo "[*] Starting agent..."
if command -v systemctl &>/dev/null && [ "$(id -u)" -eq 0 ]; then
    cat > /etc/systemd/system/analysishub-agent.service << SERVICE
[Unit]
Description=AnalysisHub Agent
After=network.target

[Service]
ExecStart=$INSTALL_DIR/analysishub-agent
WorkingDirectory=$INSTALL_DIR
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE
    systemctl daemon-reload
    systemctl enable --now analysishub-agent.service
    echo "[+] Agent installed as systemd service (auto-restart enabled)"
else
    nohup "$INSTALL_DIR/analysishub-agent" > "$INSTALL_DIR/agent.log" 2>&1 &
    echo "[+] Agent started via nohup (PID $!)"
    echo "    Note: run as root for systemd auto-restart support"
fi
echo ""
echo "[+] Done! Agent '{{.AgentName}}' should appear online in the dashboard shortly."
`

// AgentRegistryParse triggers the edge_parse_registry command on the agent.
//
// POST /api/v1/agents/:id/registry
// Body: {"root": "HKLM", "path": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"}
func AgentRegistryParse(c *gin.Context) {
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

	var req struct {
		Root string `json:"root" binding:"required"`
		Path string `json:"path" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	// Create a virtual job ID to subscribe to output
	reqID := uuid.New().String()
	outCh := hub.SubscribeJobOutput(reqID)
	defer hub.UnsubscribeJobOutput(reqID, outCh)

	err = hub.SendJobToAgent(id.String(), ws.AgentCommand{
		Type:   "edge_parse_registry",
		JobID:  reqID,
		FsPath: req.Root + "\\" + req.Path,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to send request"})
		return
	}

	// Wait for the JSON response or error
	select {
	case result := <-outCh:
		if strings.HasPrefix(result, "[agent error]") {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": strings.TrimPrefix(result, "[agent error] ")})
			return
		}
		c.Data(http.StatusOK, "application/json", []byte(result))
	case <-c.Request.Context().Done():
		c.JSON(http.StatusRequestTimeout, gin.H{"success": false, "error": "request timed out"})
	}
}

// AgentEvtxParse triggers the edge_parse_evtx command on the agent.
//
// POST /api/v1/agents/:id/evtx
// Body: {"log_name": "Security", "event_id": "4624"}
func AgentEvtxParse(c *gin.Context) {
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

	var req struct {
		LogName  string `json:"log_name" binding:"required"`
		EventID  string `json:"event_id"`  // legacy: single or comma-separated IDs
		EventIDs []int  `json:"event_ids"` // preferred: explicit list
		Hours    int    `json:"hours"`     // time window (0 = all)
		Max      int    `json:"max"`       // max events (default 500 on the agent)
		Keyword  string `json:"keyword"`   // substring filter on the rendered message
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	// Merge legacy comma string + explicit list into one ID slice.
	ids := append([]int{}, req.EventIDs...)
	for _, p := range strings.Split(req.EventID, ",") {
		if n, perr := strconv.Atoi(strings.TrimSpace(p)); perr == nil {
			ids = append(ids, n)
		}
	}

	argsJSON, _ := json.Marshal(map[string]interface{}{
		"log":     req.LogName,
		"ids":     ids,
		"hours":   req.Hours,
		"max":     req.Max,
		"keyword": req.Keyword,
	})

	// Create a virtual job ID to subscribe to output
	reqID := uuid.New().String()
	outCh := hub.SubscribeJobOutput(reqID)
	defer hub.UnsubscribeJobOutput(reqID, outCh)

	err = hub.SendJobToAgent(id.String(), ws.AgentCommand{
		Type:  "edge_parse_evtx",
		JobID: reqID,
		Args:  string(argsJSON),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to send request"})
		return
	}

	// Wait for the JSON response or error
	select {
	case result := <-outCh:
		if strings.HasPrefix(result, "[agent error]") {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": strings.TrimPrefix(result, "[agent error] ")})
			return
		}
		c.Data(http.StatusOK, "application/json", []byte(result))
	case <-c.Request.Context().Done():
		c.JSON(http.StatusRequestTimeout, gin.H{"success": false, "error": "request timed out"})
	}
}

// awaitEdgeJSONResult waits for an EdgeForensics command's JSON result on outCh
// and writes the HTTP response. It also polls agent liveness so a mid-scan
// disconnect fails fast with a clear error instead of hanging until the deadline.
func awaitEdgeJSONResult(c *gin.Context, hub *ws.Hub, outCh chan string, agentID string, kind string) {
	if data, ok := awaitEdgeJSONBytes(c, hub, outCh, agentID); ok {
		// Snapshot the scan into the Evidence Store (best-effort, never blocks the
		// response) so every edge-forensics scan leaves a marked evidence trail.
		if kind != "" {
			recordEdgeScanEvidence(c, agentID, kind, data)
		}
		c.Data(http.StatusOK, "application/json", data)
	}
}

// awaitEdgeJSONBytes waits for the agent's edge-scan artifact and RETURNS the raw
// JSON bytes instead of writing the HTTP response, so callers (e.g. IOC sweep)
// can post-process the data server-side. On any failure it writes the error
// response itself and returns ok=false.
func awaitEdgeJSONBytes(c *gin.Context, hub *ws.Hub, outCh chan string, agentID string) ([]byte, bool) {
	var finalData string
	var agentError string
	offline := time.NewTicker(8 * time.Second)
	defer offline.Stop()
	for {
		select {
		case result := <-outCh:
			if result == "__DONE__" {
				if agentError != "" {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": agentError})
					return nil, false
				}
				if finalData == "" {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "no data returned"})
					return nil, false
				}
				return []byte(finalData), true
			}
			if strings.HasPrefix(result, "[agent error]") {
				agentError = strings.TrimPrefix(result, "[agent error] ")
			} else if json.Valid([]byte(result)) {
				finalData = result
			}
		case <-offline.C:
			if !hub.IsAgentOnline(agentID) {
				c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": "agent disconnected during scan"})
				return nil, false
			}
		case <-c.Request.Context().Done():
			c.JSON(http.StatusRequestTimeout, gin.H{"success": false, "error": "request timed out"})
			return nil, false
		}
	}
}

// AgentMFTParse triggers the edge_parse_mft command on the agent.
func AgentMFTParse(c *gin.Context) {
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

	reqID := uuid.New().String()
	outCh := hub.SubscribeJobOutput(reqID)
	defer hub.UnsubscribeJobOutput(reqID, outCh)

	err = hub.SendJobToAgent(id.String(), ws.AgentCommand{
		Type:   "edge_parse_mft",
		JobID:  reqID,
		FsPath: strings.TrimSpace(c.Query("path")), // optional target dir/file to scan
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to send request"})
		return
	}

	awaitEdgeJSONResult(c, hub, outCh, id.String(), "mft")
}

// AgentPrefetchParse triggers the edge_parse_prefetch command on the agent.
func AgentPrefetchParse(c *gin.Context) {
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

	reqID := uuid.New().String()
	outCh := hub.SubscribeJobOutput(reqID)
	defer hub.UnsubscribeJobOutput(reqID, outCh)

	err = hub.SendJobToAgent(id.String(), ws.AgentCommand{
		Type:  "edge_parse_prefetch",
		JobID: reqID,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to send request"})
		return
	}

	awaitEdgeJSONResult(c, hub, outCh, id.String(), "prefetch")
}

// AgentAutorunsParse triggers a native autostart / persistence enumeration on
// the agent (Run keys, services, scheduled tasks, startup folders, Winlogon,
// IFEO …) with executable hashes and Authenticode signature status.
//
// POST /api/v1/agents/:id/autoruns
func AgentAutorunsParse(c *gin.Context) {
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

	reqID := uuid.New().String()
	outCh := hub.SubscribeJobOutput(reqID)
	defer hub.UnsubscribeJobOutput(reqID, outCh)

	err = hub.SendJobToAgent(id.String(), ws.AgentCommand{
		Type:  "edge_parse_autoruns",
		JobID: reqID,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to send request"})
		return
	}

	awaitEdgeJSONResult(c, hub, outCh, id.String(), "autoruns")
}

// AgentNetworkParse triggers a native network-connection snapshot on the agent
// (TCP/UDP endpoints with owning process + image path + reverse DNS, plus the
// DNS resolver cache) — the NetworkMiner-style host/session/DNS view. No UAC is
// required: the IP Helper socket tables are readable in the agent's normal user
// context, which is also why the Network tab can stream live.
//
// POST /api/v1/agents/:id/netscan
func AgentNetworkParse(c *gin.Context) {
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

	reqID := uuid.New().String()
	outCh := hub.SubscribeJobOutput(reqID)
	defer hub.UnsubscribeJobOutput(reqID, outCh)

	err = hub.SendJobToAgent(id.String(), ws.AgentCommand{
		Type:  "edge_parse_netconn",
		JobID: reqID,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to send request"})
		return
	}

	awaitEdgeJSONResult(c, hub, outCh, id.String(), "network")
}

// AgentShimcacheParse triggers an AppCompatCache (Shimcache) parse on the agent
// — execution-evidence records (binary path + file modified time).
//
// POST /api/v1/agents/:id/shimcache
func AgentShimcacheParse(c *gin.Context) {
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

	reqID := uuid.New().String()
	outCh := hub.SubscribeJobOutput(reqID)
	defer hub.UnsubscribeJobOutput(reqID, outCh)

	if err := hub.SendJobToAgent(id.String(), ws.AgentCommand{Type: "edge_parse_shimcache", JobID: reqID}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to send request"})
		return
	}

	awaitEdgeJSONResult(c, hub, outCh, id.String(), "shimcache")
}

// AgentBrowserParse recovers browser history (Chrome/Edge/Brave/Firefox) across
// all local user profiles on the endpoint.
//
// POST /api/v1/agents/:id/browser
func AgentBrowserParse(c *gin.Context) {
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

	reqID := uuid.New().String()
	outCh := hub.SubscribeJobOutput(reqID)
	defer hub.UnsubscribeJobOutput(reqID, outCh)

	if err := hub.SendJobToAgent(id.String(), ws.AgentCommand{Type: "edge_parse_browser", JobID: reqID}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to send request"})
		return
	}

	awaitEdgeJSONResult(c, hub, outCh, id.String(), "browser")
}

// AgentTriageCollect runs a 1-click triage collection (KAPE-style): a curated set
// of collectors gathered in a SINGLE elevated pass (one UAC prompt) and returned
// as one combined bundle. The caller (frontend) can then persist that bundle to a
// case as evidence via the existing evidence-upload path.
//
// POST /api/v1/agents/:id/triage   body: { "types": ["processes","browser",…] }
func AgentTriageCollect(c *gin.Context) {
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

	var body struct {
		Types []string `json:"types"`
	}
	_ = c.ShouldBindJSON(&body) // optional; empty → agent uses its default set

	reqID := uuid.New().String()
	outCh := hub.SubscribeJobOutput(reqID)
	defer hub.UnsubscribeJobOutput(reqID, outCh)

	if err := hub.SendJobToAgent(id.String(), ws.AgentCommand{
		Type:  "edge_parse_triage",
		JobID: reqID,
		Args:  strings.Join(body.Types, ","),
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to send request"})
		return
	}

	awaitEdgeJSONResult(c, hub, outCh, id.String(), "triage")
}

// AgentKillProcess instructs the agent to terminate a process (containment).
// Elevates on the endpoint when needed so it can kill other users' / elevated
// processes.
//
// POST /api/v1/agents/:id/kill  { "pid": 1234 }
func AgentKillProcess(c *gin.Context) {
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
	var req struct {
		Pid int `json:"pid" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Pid <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "valid pid required"})
		return
	}
	if !hub.IsAgentOnline(id.String()) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": "agent is offline"})
		return
	}

	reqID := uuid.New().String()
	outCh := hub.SubscribeJobOutput(reqID)
	defer hub.UnsubscribeJobOutput(reqID, outCh)

	if err := hub.SendJobToAgent(id.String(), ws.AgentCommand{Type: "kill_process", JobID: reqID, Pid: req.Pid}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to send request"})
		return
	}
	writeAudit(c, db, &userID, &id, "agent.kill_process", id.String(), fmt.Sprintf("pid=%d", req.Pid))

	var agentErr, lastLine string
	for {
		select {
		case result := <-outCh:
			if result == "__DONE__" {
				if agentErr != "" {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": agentErr})
				} else {
					c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"pid": req.Pid, "message": lastLine}})
				}
				return
			}
			if strings.HasPrefix(result, "[agent error]") {
				agentErr = strings.TrimPrefix(result, "[agent error] ")
			} else if result != "" {
				lastLine = result
			}
		case <-c.Request.Context().Done():
			c.JSON(http.StatusRequestTimeout, gin.H{"success": false, "error": "request timed out"})
			return
		}
	}
}

// AgentDllsParse triggers a native loaded-module enumeration on the agent
// (ListDLLs-style: every process's DLLs, deduped, hashed + Authenticode-checked,
// with DLL-hijack / injection flags).
//
// POST /api/v1/agents/:id/dlls
func AgentDllsParse(c *gin.Context) {
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

	reqID := uuid.New().String()
	outCh := hub.SubscribeJobOutput(reqID)
	defer hub.UnsubscribeJobOutput(reqID, outCh)

	err = hub.SendJobToAgent(id.String(), ws.AgentCommand{Type: "edge_parse_dlls", JobID: reqID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to send request"})
		return
	}

	awaitEdgeJSONResult(c, hub, outCh, id.String(), "dlls")
}

// AgentProcessParse triggers a detailed running-process snapshot on the agent
// (lineage + owner + command line + executable hashes).
//
// POST /api/v1/agents/:id/processes-scan
func AgentProcessParse(c *gin.Context) {
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

	reqID := uuid.New().String()
	outCh := hub.SubscribeJobOutput(reqID)
	defer hub.UnsubscribeJobOutput(reqID, outCh)

	err = hub.SendJobToAgent(id.String(), ws.AgentCommand{
		Type:  "edge_parse_processes",
		JobID: reqID,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to send request"})
		return
	}

	awaitEdgeJSONResult(c, hub, outCh, id.String(), "processes")
}

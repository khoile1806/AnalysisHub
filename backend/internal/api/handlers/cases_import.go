package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/models"
)

// ImportOfflineReport ingests a report.json produced by the offline agent and
// materialises it inside a case: a virtual "offline-import" Agent represents
// the endpoint, and each tool execution becomes a Job (status + output filled).
// The results then appear in the case timeline exactly like online jobs.
//
// POST /api/v1/cases/:id/import-offline-report   (multipart/form-data: file)
func (h *CasesHandler) ImportOfflineReport(c *gin.Context) {
	caseID := c.Param("id")
	caseUUID, err := uuid.Parse(caseID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case id"})
		return
	}

	var caseObj models.Case
	if err := h.DB.First(&caseObj, "id = ?", caseUUID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "case not found"})
		return
	}

	fh, ferr := c.FormFile("file")
	if ferr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "report file is required"})
		return
	}
	f, openErr := fh.Open()
	if openErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to open upload"})
		return
	}
	defer f.Close()

	raw, readErr := io.ReadAll(io.LimitReader(f, 64<<20)) // 64 MB cap
	if readErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to read upload"})
		return
	}

	var rep models.OfflineReport
	if jerr := json.Unmarshal(raw, &rep); jerr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "not a valid offline report JSON"})
		return
	}
	if len(rep.Jobs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "report contains no tool results"})
		return
	}

	userID := ""
	if v, ok := c.Get("userID"); ok {
		userID, _ = v.(string)
	}
	var userUUID uuid.UUID
	if uid, perr := uuid.Parse(userID); perr == nil {
		userUUID = uid
	}

	// Find or create the virtual agent representing this offline endpoint.
	agent, agErr := h.findOrCreateOfflineAgent(caseUUID, rep)
	if agErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to register offline endpoint: " + agErr.Error()})
		return
	}

	// Create one Job per reported tool execution.
	imported := 0
	for _, rj := range rep.Jobs {
		toolID := h.resolveToolID(rj.ToolID, rj.ToolName, rep.OS)

		status := strings.ToLower(rj.Status)
		switch status {
		case "done", "failed", "stopped", "running", "pending":
			// valid
		default:
			status = "done"
		}

		job := models.Job{
			AgentID:   agent.ID,
			ToolID:    toolID,
			Args:      rj.Args,
			Status:    models.JobStatus(status),
			Output:    rj.Output,
			CreatedBy: userUUID,
		}
		if !rj.StartedAt.IsZero() {
			t := rj.StartedAt
			job.StartedAt = &t
		}
		if !rj.FinishedAt.IsZero() {
			t := rj.FinishedAt
			job.FinishedAt = &t
		}
		if err := h.DB.Create(&job).Error; err != nil {
			continue
		}
		imported++
	}

	// Touch the agent's last_seen to reflect the import time.
	now := time.Now()
	h.DB.Model(agent).Updates(map[string]interface{}{"last_seen": now})

	if userUUID != uuid.Nil {
		writeAudit(c, h.DB, &userUUID, nil, "import", "case",
			fmt.Sprintf("Imported offline report (%d tools) from %s into case %s", imported, rep.Hostname, caseObj.Name))
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"agent_id":      agent.ID,
			"agent_name":    agent.Name,
			"imported_jobs": imported,
			"bundle_name":   rep.BundleName,
			"hostname":      rep.Hostname,
		},
	})
}

// findOrCreateOfflineAgent reuses an existing offline-import agent for the same
// case + hostname, or creates a new one. This keeps re-imports of the same
// endpoint under a single agent rather than spawning duplicates.
func (h *CasesHandler) findOrCreateOfflineAgent(caseUUID uuid.UUID, rep models.OfflineReport) (*models.Agent, error) {
	hostname := rep.Hostname
	if hostname == "" {
		hostname = "unknown-host"
	}
	name := hostname + " (offline)"

	var existing models.Agent
	err := h.DB.Where("case_id = ? AND source = ? AND hostname = ?", caseUUID, "offline-import", hostname).
		First(&existing).Error
	if err == nil {
		// Update volatile fields and reuse.
		h.DB.Model(&existing).Updates(map[string]interface{}{
			"ip_address": rep.IP,
			"os":         rep.OS,
		})
		return &existing, nil
	}
	if err != gorm.ErrRecordNotFound {
		return nil, err
	}

	agent := models.Agent{
		Name:        name,
		Token:       "offline-" + uuid.NewString(), // satisfies unique-not-null; never used for auth
		Hostname:    hostname,
		OS:          rep.OS,
		IPAddress:   rep.IP,
		Status:      "offline",
		Source:      "offline-import",
		CaseID:      &caseUUID,
		Description: "Imported from offline bundle: " + rep.BundleName,
	}
	if err := h.DB.Create(&agent).Error; err != nil {
		return nil, err
	}
	return &agent, nil
}

// resolveToolID maps a reported tool to a Tool row. It prefers the original
// tool UUID from the report, falls back to a case-insensitive name match, and
// finally creates a lightweight placeholder so the Job foreign key is satisfied.
func (h *CasesHandler) resolveToolID(reportToolID, toolName, platform string) uuid.UUID {
	// 1. By original UUID.
	if id, err := uuid.Parse(reportToolID); err == nil {
		var t models.Tool
		if h.DB.First(&t, "id = ?", id).Error == nil {
			return t.ID
		}
	}
	// 2. By name.
	if toolName != "" {
		var t models.Tool
		if h.DB.Where("LOWER(name) = LOWER(?)", toolName).First(&t).Error == nil {
			return t.ID
		}
	}
	// 3. Placeholder.
	p := platform
	if p != "windows" && p != "linux" && p != "both" {
		p = "both"
	}
	name := toolName
	if name == "" {
		name = "Imported Tool"
	}
	t := models.Tool{
		Name:        name,
		Category:    "other",
		Platform:    p,
		Description: "Auto-created from an imported offline report",
		FileName:    "",
	}
	if err := h.DB.Create(&t).Error; err != nil {
		return uuid.Nil
	}
	return t.ID
}

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	ai "github.com/forensichub/backend/internal/ai"
	"github.com/forensichub/backend/internal/analysis"
	"github.com/forensichub/backend/internal/models"
)

// TriageOsintScan summarizes an OSINT scan's findings with AI from a defensive
// angle (what the entity is, malicious or not, pivots, DFIR next steps). It
// reuses the shared inference seam (analysis.Chat) and the AI provider config.
//
// POST /api/v1/osint/:id/triage  { "provider_id": "<uuid>" }
func (h *AIHandler) TriageOsintScan(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scan id"})
		return
	}

	var input struct {
		ProviderID string `json:"provider_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	providerID, err := uuid.Parse(input.ProviderID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid provider_id"})
		return
	}
	var provider models.AIProvider
	if err := h.db.First(&provider, "id = ?", providerID).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "provider not found"})
		return
	}
	client, clientErr := h.newDecryptedClient(&provider)
	if clientErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": clientErr.Error()})
		return
	}

	var scan models.OsintScan
	if err := h.db.First(&scan, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "scan not found"})
		return
	}
	var findings []models.OsintFinding
	h.db.Where("scan_id = ?", id).Order("category, severity").Find(&findings)
	if len(findings) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "scan has no findings to triage"})
		return
	}

	text := formatOsintFindings(findings)
	prompt := analysis.BuildOsintTriagePrompt(scan.Target, scan.TargetType, text)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 180*time.Second)
	defer cancel()

	out, usage, aiErr := analysis.Chat(ctx, client, prompt, ai.Options{MaxTokens: provider.MaxTokens})
	if aiErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "AI error: " + aiErr.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"summary": stripThinkBlocks(out),
		"tokens":  usage.Total(),
	}})
}

// formatOsintFindings renders findings as compact lines for the AI prompt,
// bounded by the shared content budget.
func formatOsintFindings(findings []models.OsintFinding) string {
	budget := analysis.EnvIntKB("AI_CONTENT_CAP_KB", 128) * 1024
	var sb strings.Builder
	for _, f := range findings {
		if sb.Len() > budget {
			sb.WriteString("\n... [truncated]\n")
			break
		}
		sev := f.Severity
		if sev == "" {
			sev = "info"
		}
		fmt.Fprintf(&sb, "[%s] %s/%s - %s", strings.ToUpper(sev), f.Source, f.Category, f.Title)
		if f.Value != "" {
			fmt.Fprintf(&sb, ": %s", f.Value)
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

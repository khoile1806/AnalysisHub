package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/analysishub/backend/internal/ai"
	"github.com/analysishub/backend/internal/analysis"
	"github.com/analysishub/backend/internal/models"
)

// GenerateCaseSummary asks an AI provider to draft an executive incident
// narrative from the case's timeline + endpoints, then saves it on the case so
// it appears in the incident report. Returns the narrative text.
//
// POST /api/v1/cases/:id/report/ai-summary   { "provider_id": "..." }
func (h *AIHandler) GenerateCaseSummary(c *gin.Context) {
	caseID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case id"})
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
	var caseObj models.Case
	if err := h.db.First(&caseObj, "id = ?", caseID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "case not found"})
		return
	}
	client, clientErr := h.newDecryptedClient(&provider)
	if clientErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": clientErr.Error()})
		return
	}

	prompt := buildCaseSummaryPrompt(h, caseObj)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 120*time.Second)
	defer cancel()
	out, _, aiErr := analysis.Chat(ctx, client, prompt, ai.Options{MaxTokens: provider.MaxTokens})
	if aiErr != nil {
		c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": "AI request failed: " + aiErr.Error()})
		return
	}
	summary := strings.TrimSpace(out)
	if summary == "" {
		c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": "AI returned an empty summary"})
		return
	}

	h.db.Model(&models.Case{}).Where("id = ?", caseID).Update("summary", summary)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"summary": summary}})
}

// buildCaseSummaryPrompt assembles a compact, factual context for the model.
func buildCaseSummaryPrompt(h *AIHandler, caseObj models.Case) string {
	var b strings.Builder
	b.WriteString("You are a DFIR analyst writing the EXECUTIVE SUMMARY of an incident report. ")
	b.WriteString("Write 2-4 concise paragraphs in plain professional English: what happened, the ")
	b.WriteString("scope (hosts/accounts affected), the likely attacker actions in chronological order, ")
	b.WriteString("and recommended next steps. Base it ONLY on the facts below; do not invent details. ")
	b.WriteString("Do not use markdown headers.\n\n")
	b.WriteString("CASE: " + caseObj.Name + "\n")
	if caseObj.Description != "" {
		b.WriteString("DESCRIPTION: " + caseObj.Description + "\n")
	}

	var agents []models.Agent
	h.db.Where("case_id = ?", caseObj.ID).Find(&agents)
	if len(agents) > 0 {
		names := make([]string, 0, len(agents))
		for _, a := range agents {
			names = append(names, a.Name)
		}
		b.WriteString("ENDPOINTS: " + strings.Join(names, ", ") + "\n")
	}

	var events []models.TimelineEvent
	h.db.Where("case_id = ?", caseObj.ID).Order("event_time asc").Find(&events)
	b.WriteString(fmt.Sprintf("\nTIMELINE (%d events, chronological):\n", len(events)))
	const cap = 120 // keep the prompt bounded
	for i, e := range events {
		if i >= cap {
			b.WriteString(fmt.Sprintf("... (%d more events omitted)\n", len(events)-cap))
			break
		}
		line := fmt.Sprintf("- %s [%s] %s", e.EventTime.UTC().Format("2006-01-02 15:04"),
			strings.ToUpper(firstNonBlank(e.Severity, "info")), e.Title)
		if e.Host != "" {
			line += " (host " + e.Host + ")"
		}
		if e.Technique != "" {
			line += " {" + e.Technique + "}"
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

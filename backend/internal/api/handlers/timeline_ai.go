package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	ai "github.com/analysishub/backend/internal/ai"
	"github.com/analysishub/backend/internal/analysis"
	"github.com/analysishub/backend/internal/models"
)

// ExtractTimelineFromEvidence reads an uploaded evidence file and asks AI to
// extract time-stamped attack events. Events inherit the evidence's host.
//
// POST /api/v1/cases/:id/evidence/:evidenceId/extract-timeline  { provider_id }
func (h *AIHandler) ExtractTimelineFromEvidence(c *gin.Context) {
	caseUUID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case id"})
		return
	}
	evidenceID, err := uuid.Parse(c.Param("evidenceId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid evidence id"})
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

	var ev models.CaseEvidence
	if err := h.db.First(&ev, "id = ? AND case_id = ?", evidenceID, caseUUID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "evidence not found"})
		return
	}

	raw, rerr := os.ReadFile(h.store.GetEvidencePath(ev.StoredPath))
	if rerr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to read evidence file"})
		return
	}
	content := string(raw)
	const contentCap = 24 * 1024
	if len(content) > contentCap {
		content = content[:contentCap]
	}

	prompt := analysis.BuildTimelinePrompt(content, ev.Host)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 120*time.Second)
	defer cancel()
	aiOut, _, aiErr := analysis.Chat(ctx, client, prompt, ai.Options{MaxTokens: provider.MaxTokens, JSON: true})
	if aiErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "AI error: " + aiErr.Error()})
		return
	}

	events := parseAITimeline(aiOut)
	var userUUID uuid.UUID
	if v, ok := c.Get("userID"); ok {
		if uid, perr := uuid.Parse(v.(string)); perr == nil {
			userUUID = uid
		}
	}

	imported := 0
	for _, e := range events {
		ts := parseFlexibleTime(e.Time)
		if ts.IsZero() {
			continue
		}
		sev := strings.ToLower(strings.TrimSpace(e.Severity))
		if !validSeverity(sev) {
			sev = "medium"
		}
		host := strings.TrimSpace(e.Host)
		if host == "" {
			host = ev.Host // attribute to the evidence's machine
		}
		tev := models.TimelineEvent{
			CaseID:    caseUUID,
			EventTime: ts,
			Source:    "ai",
			SourceRef: ev.ID.String(),
			Host:      host,
			Tactic:    strings.TrimSpace(e.Tactic),
			Technique: strings.TrimSpace(e.Technique),
			Severity:  sev,
			Title:     strings.TrimSpace(e.Title),
			Detail:    strings.TrimSpace(e.Detail),
			CreatedBy: userUUID,
		}
		if tev.Title == "" {
			continue
		}
		if err := h.db.Create(&tev).Error; err != nil {
			continue
		}
		imported++
	}
	h.db.Model(&ev).Update("extracted", true)

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"imported": imported, "host": ev.Host}})
}

// aiTimelineEvent mirrors the JSON object the AI is asked to emit per event.
type aiTimelineEvent struct {
	Time      string `json:"time"`
	Host      string `json:"host"`
	Severity  string `json:"severity"`
	Tactic    string `json:"tactic"`
	Technique string `json:"technique"`
	Title     string `json:"title"`
	Detail    string `json:"detail"`
}

// ExtractTimeline asks an AI provider to read a job's output (which includes
// offline-imported tool results) and emit a structured attack timeline. The
// extracted events are saved to the case timeline with source="ai".
//
// POST /api/v1/cases/:id/timeline/ai-extract
//
//	{ "provider_id": "...", "job_id": "..." }
func (h *AIHandler) ExtractTimeline(c *gin.Context) {
	caseUUID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case id"})
		return
	}

	var input struct {
		ProviderID string `json:"provider_id" binding:"required"`
		JobID      string `json:"job_id"      binding:"required"`
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

	// Collect evidence text from the job (covers offline-imported jobs too).
	content, collectErr := analysis.NewPipeline(h.db, h.store).Collect(analysis.Source{Type: "job", ID: input.JobID})
	if collectErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": collectErr.Error()})
		return
	}
	const contentCap = 24 * 1024
	if len(content) > contentCap {
		content = content[:contentCap]
	}

	host := ""
	var job models.Job
	if h.db.Preload("Agent").First(&job, "id = ?", input.JobID).Error == nil {
		host = job.Agent.Hostname
		if host == "" {
			host = job.Agent.Name
		}
	}

	prompt := analysis.BuildTimelinePrompt(content, host)

	// Accumulate the full AI response (non-streaming use of StreamChat).
	ctx, cancel := context.WithTimeout(c.Request.Context(), 120*time.Second)
	defer cancel()

	aiOut, _, aiErr := analysis.Chat(ctx, client, prompt, ai.Options{MaxTokens: provider.MaxTokens, JSON: true})
	if aiErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "AI error: " + aiErr.Error()})
		return
	}

	events := parseAITimeline(aiOut)
	if len(events) == 0 {
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"imported": 0, "note": "AI returned no parseable events"}})
		return
	}

	var userUUID uuid.UUID
	if v, ok := c.Get("userID"); ok {
		if uid, perr := uuid.Parse(v.(string)); perr == nil {
			userUUID = uid
		}
	}

	imported := 0
	for _, e := range events {
		ts := parseFlexibleTime(e.Time)
		if ts.IsZero() {
			continue // an attack timeline event without a real time is not useful
		}
		sev := strings.ToLower(strings.TrimSpace(e.Severity))
		if !validSeverity(sev) {
			sev = "medium"
		}
		evHost := e.Host
		if evHost == "" {
			evHost = host
		}
		ev := models.TimelineEvent{
			CaseID:    caseUUID,
			EventTime: ts,
			Source:    "ai",
			SourceRef: input.JobID,
			Host:      evHost,
			Tactic:    strings.TrimSpace(e.Tactic),
			Technique: strings.TrimSpace(e.Technique),
			Severity:  sev,
			Title:     strings.TrimSpace(e.Title),
			Detail:    strings.TrimSpace(e.Detail),
			CreatedBy: userUUID,
		}
		if ev.Title == "" {
			continue
		}
		if err := h.db.Create(&ev).Error; err != nil {
			continue
		}
		imported++
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"imported": imported}})
}

// RebuildTimeline reviews EVERYTHING in a case — all collected tool/job output
// plus the analyst's existing timeline events (which may be rough or
// inconsistent) — and asks the AI to synthesise a single clean, deduplicated,
// chronologically correct, professionally-worded attack timeline.
//
// POST /api/v1/cases/:id/timeline/ai-rebuild
//
//	{ "provider_id": "...", "mode": "replace" | "append" }
func (h *AIHandler) RebuildTimeline(c *gin.Context) {
	caseUUID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case id"})
		return
	}

	var input struct {
		ProviderID string `json:"provider_id" binding:"required"`
		Mode       string `json:"mode"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	if input.Mode != "append" {
		input.Mode = "replace"
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

	// Gather all jobs in the case (online + offline-imported, via agent membership).
	var agents []models.Agent
	h.db.Where("case_id = ?", caseUUID).Find(&agents)
	agentIDs := make([]uuid.UUID, 0, len(agents))
	for _, a := range agents {
		agentIDs = append(agentIDs, a.ID)
	}

	var jobs []models.Job
	if len(agentIDs) > 0 {
		h.db.Preload("Tool").Preload("Agent").
			Where("agent_id IN ?", agentIDs).
			Order("created_at asc").Find(&jobs)
	}

	// Existing analyst/imported timeline events to be refined.
	var events []models.TimelineEvent
	h.db.Where("case_id = ?", caseUUID).Order("event_time asc").Find(&events)

	if len(jobs) == 0 && len(events) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "case has no evidence or events to rebuild from"})
		return
	}

	evidence := aggregateCaseEvidence(jobs)
	existing := formatExistingEvents(events)

	prompt := analysis.BuildRebuildPrompt(evidence, existing)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 180*time.Second)
	defer cancel()

	aiOut, _, aiErr := analysis.Chat(ctx, client, prompt, ai.Options{MaxTokens: provider.MaxTokens, JSON: true})
	if aiErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "AI error: " + aiErr.Error()})
		return
	}

	parsed := parseAITimeline(aiOut)
	if len(parsed) == 0 {
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"imported": 0, "replaced": false, "note": "AI returned no parseable events — existing timeline kept"}})
		return
	}

	var userUUID uuid.UUID
	if v, ok := c.Get("userID"); ok {
		if uid, perr := uuid.Parse(v.(string)); perr == nil {
			userUUID = uid
		}
	}

	// Only destroy the old timeline once we know we have a valid replacement.
	replaced := false
	if input.Mode == "replace" {
		h.db.Where("case_id = ?", caseUUID).Delete(&models.TimelineEvent{})
		replaced = true
	}

	imported := 0
	for _, e := range parsed {
		ts := parseFlexibleTime(e.Time)
		if ts.IsZero() {
			continue
		}
		sev := strings.ToLower(strings.TrimSpace(e.Severity))
		if !validSeverity(sev) {
			sev = "medium"
		}
		ev := models.TimelineEvent{
			CaseID:    caseUUID,
			EventTime: ts,
			Source:    "ai",
			Host:      strings.TrimSpace(e.Host),
			Tactic:    strings.TrimSpace(e.Tactic),
			Technique: strings.TrimSpace(e.Technique),
			Severity:  sev,
			Title:     strings.TrimSpace(e.Title),
			Detail:    strings.TrimSpace(e.Detail),
			CreatedBy: userUUID,
		}
		if ev.Title == "" {
			continue
		}
		if err := h.db.Create(&ev).Error; err != nil {
			continue
		}
		imported++
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"imported": imported, "replaced": replaced}})
}

// aggregateCaseEvidence builds a bounded text blob from all job outputs.
func aggregateCaseEvidence(jobs []models.Job) string {
	const perJobCap = 4 * 1024
	const totalCap = 28 * 1024
	var sb strings.Builder
	for _, j := range jobs {
		if sb.Len() > totalCap {
			sb.WriteString("\n... [more evidence truncated]\n")
			break
		}
		toolName := "Tool"
		if j.Tool.Name != "" {
			toolName = j.Tool.Name
		}
		host := ""
		if j.Agent.Hostname != "" {
			host = j.Agent.Hostname
		} else {
			host = j.Agent.Name
		}
		fmt.Fprintf(&sb, "\n--- TOOL: %s | host: %s | status: %s ---\n", toolName, host, j.Status)
		out := j.Output
		if len(out) > perJobCap {
			out = out[:perJobCap] + "\n... [truncated]"
		}
		sb.WriteString(out)
		sb.WriteString("\n")
	}
	return sb.String()
}

// formatExistingEvents renders the current timeline events as a compact list.
func formatExistingEvents(events []models.TimelineEvent) string {
	if len(events) == 0 {
		return "(none)"
	}
	var sb strings.Builder
	for _, e := range events {
		fmt.Fprintf(&sb, "- [%s] (%s", e.EventTime.UTC().Format(time.RFC3339), e.Severity)
		if e.Host != "" {
			fmt.Fprintf(&sb, ", host=%s", e.Host)
		}
		if e.Tactic != "" {
			fmt.Fprintf(&sb, ", tactic=%s", e.Tactic)
		}
		fmt.Fprintf(&sb, ") %s", e.Title)
		if e.Detail != "" {
			fmt.Fprintf(&sb, " — %s", e.Detail)
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// parseAITimeline extracts the JSON array from the model response — tolerating
// reasoning-model think blocks and markdown fences via the shared extractor —
// and unmarshals it. The request also asks for JSON mode (ai.Options.JSON).
func parseAITimeline(raw string) []aiTimelineEvent {
	var events []aiTimelineEvent
	if err := json.Unmarshal([]byte(ai.ExtractJSON(stripThinkBlocks(raw))), &events); err != nil {
		return nil
	}
	return events
}

// parseFlexibleTime tries several common timestamp layouts.
func parseFlexibleTime(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	layouts := []string{
		time.RFC3339Nano, time.RFC3339,
		"2006-01-02T15:04:05.000Z", "2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05", "2006-01-02 15:04:05",
		"2006-01-02 15:04", "01/02/2006 15:04:05",
		"2006-01-02",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, v); err == nil {
			return t
		}
	}
	return time.Time{}
}

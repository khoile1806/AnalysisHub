package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	ai "github.com/forensichub/backend/internal/ai"
	"github.com/forensichub/backend/internal/models"
)

// dueOffsetBySeverity returns the standard remediation deadline offset.
// Critical 72h · High 7d · Medium 30d · Low 90d.
func dueOffsetBySeverity(sev string) time.Duration {
	switch sev {
	case "critical":
		return 72 * time.Hour
	case "high":
		return 7 * 24 * time.Hour
	case "medium":
		return 30 * 24 * time.Hour
	default:
		return 90 * 24 * time.Hour
	}
}

// assessItem is one check sent by the client for AI evaluation.
type assessItem struct {
	ItemID    string   `json:"item_id"`
	Control   string   `json:"control"`
	Frameworks []string `json:"frameworks"`
	Title     string   `json:"title"`
	Purpose   string   `json:"purpose"`
	Output    string   `json:"output"`
	Host      string   `json:"host"`
}

// aiVerdict is one element of the AI's JSON response.
type aiVerdict struct {
	ItemID      string `json:"item_id"`
	Status      string `json:"status"`
	Severity    string `json:"severity"`
	Rationale   string `json:"rationale"`
	Remediation string `json:"remediation"`
}

// AssessCompliance evaluates compliance check outputs against their expected
// baseline using AI, producing pass/fail findings stored on the case.
//
// POST /api/v1/cases/:id/compliance/assess
//
//	{ "provider_id": "...", "replace": true, "items": [ { item_id, control, frameworks, title, purpose, output, host } ] }
func (h *AIHandler) AssessCompliance(c *gin.Context) {
	caseUUID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case id"})
		return
	}

	var input struct {
		ProviderID string       `json:"provider_id" binding:"required"`
		Replace    bool         `json:"replace"`
		Items      []assessItem `json:"items" binding:"required,min=1"`
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

	// Cap items + output size to stay within token budgets.
	const maxItems = 60
	const perOutputCap = 2 * 1024
	if len(input.Items) > maxItems {
		input.Items = input.Items[:maxItems]
	}
	for i := range input.Items {
		if len(input.Items[i].Output) > perOutputCap {
			input.Items[i].Output = input.Items[i].Output[:perOutputCap] + "\n... [truncated]"
		}
	}

	prompt := buildAssessPrompt(input.Items)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 180*time.Second)
	defer cancel()

	tokenCh := make(chan string, 256)
	var sb strings.Builder
	errCh := make(chan error, 1)
	go func() {
		errCh <- client.StreamChat(ctx, []ai.Message{{Role: "user", Content: prompt}}, ai.Options{MaxTokens: provider.MaxTokens}, tokenCh)
		close(tokenCh)
	}()
	for tok := range tokenCh {
		sb.WriteString(tok)
	}
	if aiErr := <-errCh; aiErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "AI error: " + aiErr.Error()})
		return
	}

	verdicts := parseAssessVerdicts(sb.String())
	if len(verdicts) == 0 {
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"assessed": 0, "note": "AI returned no parseable verdicts"}})
		return
	}
	verdictMap := make(map[string]aiVerdict, len(verdicts))
	for _, v := range verdicts {
		verdictMap[v.ItemID] = v
	}

	var userUUID uuid.UUID
	if v, ok := c.Get("userID"); ok {
		if uid, perr := uuid.Parse(v.(string)); perr == nil {
			userUUID = uid
		}
	}

	if input.Replace {
		h.db.Where("case_id = ?", caseUUID).Delete(&models.ComplianceFinding{})
	}

	assessed := 0
	for _, it := range input.Items {
		v, ok := verdictMap[it.ItemID]
		if !ok {
			continue
		}
		status := normalizeStatus(v.Status)
		sev := strings.ToLower(strings.TrimSpace(v.Severity))
		if !validSeverity(sev) {
			sev = "info"
		}
		ev := it.Output
		if len(ev) > perOutputCap {
			ev = ev[:perOutputCap]
		}
		// #4 Evidence integrity: SHA-256 of the captured output.
		sum := sha256.Sum256([]byte(it.Output))
		hash := hex.EncodeToString(sum[:])

		f := models.ComplianceFinding{
			CaseID:       caseUUID,
			ItemID:       it.ItemID,
			Control:      it.Control,
			Frameworks:   strings.Join(it.Frameworks, ","),
			Title:        it.Title,
			Host:         it.Host,
			Status:       status,
			Severity:     sev,
			Rationale:    strings.TrimSpace(v.Rationale),
			Remediation:  strings.TrimSpace(v.Remediation),
			Evidence:     ev,
			EvidenceHash: hash,
			Source:       "ai",
			CreatedBy:    userUUID,
		}
		// #6 POA&M: auto-set a remediation deadline for issues that need fixing.
		if status == "non_compliant" || status == "partial" {
			f.RemediationStatus = "open"
			due := time.Now().Add(dueOffsetBySeverity(sev))
			f.DueDate = &due
		} else {
			f.RemediationStatus = "resolved"
		}
		if err := h.db.Create(&f).Error; err != nil {
			continue
		}
		assessed++
	}

	// #5 Drift detection: snapshot the aggregate posture for trend tracking.
	h.saveComplianceSnapshot(caseUUID)

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"assessed": assessed}})
}

// saveComplianceSnapshot records the current aggregate posture for the case.
func (h *AIHandler) saveComplianceSnapshot(caseID uuid.UUID) {
	var findings []models.ComplianceFinding
	h.db.Where("case_id = ?", caseID).Find(&findings)
	snap := models.ComplianceSnapshot{CaseID: caseID, Total: len(findings)}
	for _, f := range findings {
		switch f.Status {
		case "compliant":
			snap.Pass++
		case "non_compliant":
			snap.Fail++
		case "partial":
			snap.Partial++
		default:
			snap.NA++
		}
	}
	if snap.Total > 0 {
		snap.Score = (snap.Pass*100 + snap.Partial*50) / snap.Total
	}
	h.db.Create(&snap)
}

func buildAssessPrompt(items []assessItem) string {
	var sb strings.Builder
	sb.WriteString(`You are a security compliance auditor (ISO 27001 / SOC 2 / PCI-DSS / NIST / CIS).
For EACH check below you are given: its purpose (the expected secure baseline) and the ACTUAL command output collected from the host. Decide whether the host meets the control.

Return ONLY a JSON array (no markdown, no prose, no code fences). One element per check:
{
  "item_id": "<the id given>",
  "status": "compliant | non_compliant | partial | na",
  "severity": "critical | high | medium | low | info",
  "rationale": "one concise sentence explaining the verdict, citing the evidence",
  "remediation": "short concrete fix if not compliant, else empty"
}

Rules:
- "compliant" = output clearly meets the secure baseline.
- "non_compliant" = output clearly violates it (assign severity by impact).
- "partial" = partially meets / needs review.
- "na" = output empty/insufficient or check not applicable.
- Base the verdict ONLY on the actual output; do not assume.

CHECKS:
`)
	for i, it := range items {
		fmt.Fprintf(&sb, "\n[%d] item_id=%s | control=%s\n", i+1, it.ItemID, it.Control)
		fmt.Fprintf(&sb, "check: %s\n", it.Title)
		if it.Purpose != "" {
			fmt.Fprintf(&sb, "expected/purpose: %s\n", it.Purpose)
		}
		out := it.Output
		if strings.TrimSpace(out) == "" {
			out = "(no output)"
		}
		fmt.Fprintf(&sb, "actual output:\n%s\n", out)
	}
	return sb.String()
}

func parseAssessVerdicts(raw string) []aiVerdict {
	s := stripThinkBlocks(raw)
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		if i := strings.Index(s, "\n"); i >= 0 {
			s = s[i+1:]
		}
		s = strings.TrimSuffix(strings.TrimSpace(s), "```")
		s = strings.TrimSpace(s)
	}
	start := strings.Index(s, "[")
	end := strings.LastIndex(s, "]")
	if start < 0 || end <= start {
		return nil
	}
	s = s[start : end+1]
	var v []aiVerdict
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil
	}
	return v
}

func normalizeStatus(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, " ", "_")
	switch s {
	case "compliant", "pass", "passed":
		return "compliant"
	case "non_compliant", "noncompliant", "fail", "failed":
		return "non_compliant"
	case "partial", "partially_compliant":
		return "partial"
	default:
		return "na"
	}
}

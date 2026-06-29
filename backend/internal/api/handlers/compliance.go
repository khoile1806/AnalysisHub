package handlers

import (
	"fmt"
	"html"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/models"
)

// ComplianceHandler serves compliance findings + reports (no AI needed).
type ComplianceHandler struct {
	DB *gorm.DB
}

func NewComplianceHandler(db *gorm.DB) *ComplianceHandler {
	return &ComplianceHandler{DB: db}
}

// ListFindings GET /api/v1/cases/:id/compliance/findings
func (h *ComplianceHandler) ListFindings(c *gin.Context) {
	caseID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case id"})
		return
	}
	var findings []models.ComplianceFinding
	h.DB.Where("case_id = ?", caseID).Order("created_at asc").Find(&findings)
	sortFindings(findings) // worst-first ordering done in Go
	c.JSON(http.StatusOK, gin.H{"success": true, "data": findings})
}

// UpdateFinding PATCH /api/v1/compliance/findings/:id — analyst override.
func (h *ComplianceHandler) UpdateFinding(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	var f models.ComplianceFinding
	if err := h.DB.First(&f, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "finding not found"})
		return
	}
	var input struct {
		Status            *string    `json:"status"`
		Severity          *string    `json:"severity"`
		Remediation       *string    `json:"remediation"`
		Owner             *string    `json:"owner"`
		DueDate           *time.Time `json:"due_date"`
		RemediationStatus *string    `json:"remediation_status"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	updates := map[string]interface{}{"source": "manual"}
	if input.Status != nil {
		updates["status"] = normalizeStatus(*input.Status)
	}
	if input.Severity != nil && validSeverity(*input.Severity) {
		updates["severity"] = *input.Severity
	}
	if input.Remediation != nil {
		updates["remediation"] = *input.Remediation
	}
	if input.Owner != nil {
		updates["owner"] = *input.Owner
	}
	if input.DueDate != nil {
		updates["due_date"] = *input.DueDate
	}
	if input.RemediationStatus != nil && validRemediationStatus(*input.RemediationStatus) {
		updates["remediation_status"] = *input.RemediationStatus
	}
	h.DB.Model(&f).Updates(updates)
	h.DB.First(&f, "id = ?", id)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": f})
}

func validRemediationStatus(s string) bool {
	switch s {
	case "open", "in_progress", "resolved", "accepted_risk":
		return true
	}
	return false
}

// ListSnapshots GET /api/v1/cases/:id/compliance/snapshots — score trend (drift).
func (h *ComplianceHandler) ListSnapshots(c *gin.Context) {
	caseID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case id"})
		return
	}
	var snaps []models.ComplianceSnapshot
	h.DB.Where("case_id = ?", caseID).Order("created_at asc").Limit(50).Find(&snaps)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": snaps})
}

// DeleteFindings DELETE /api/v1/cases/:id/compliance/findings — clear all.
func (h *ComplianceHandler) DeleteFindings(c *gin.Context) {
	caseID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case id"})
		return
	}
	h.DB.Where("case_id = ?", caseID).Delete(&models.ComplianceFinding{})
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// GetReport GET /api/v1/cases/:id/compliance/report — self-contained HTML download.
func (h *ComplianceHandler) GetReport(c *gin.Context) {
	caseID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case id"})
		return
	}
	var caseObj models.Case
	if err := h.DB.First(&caseObj, "id = ?", caseID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "case not found"})
		return
	}
	var findings []models.ComplianceFinding
	h.DB.Where("case_id = ?", caseID).Find(&findings)
	sortFindings(findings)

	body := renderComplianceReport(caseObj, findings)
	fname := fmt.Sprintf("compliance-report-%s-%s.html", safeZipName(caseObj.Name), time.Now().Format("20060102"))
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fname))
	c.String(http.StatusOK, body)
}

// ── helpers ─────────────────────────────────────────────────────────────────

func severityRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

func statusRank(s string) int {
	switch s {
	case "non_compliant":
		return 0
	case "partial":
		return 1
	case "na":
		return 2
	case "compliant":
		return 3
	default:
		return 4
	}
}

// sortFindings: worst first (non-compliant + high severity at top).
func sortFindings(f []models.ComplianceFinding) {
	sort.SliceStable(f, func(i, j int) bool {
		if statusRank(f[i].Status) != statusRank(f[j].Status) {
			return statusRank(f[i].Status) < statusRank(f[j].Status)
		}
		return severityRank(f[i].Severity) < severityRank(f[j].Severity)
	})
}

func renderComplianceReport(caseObj models.Case, findings []models.ComplianceFinding) string {
	total := len(findings)
	var compliant, nonCompliant, partial, na int
	for _, f := range findings {
		switch f.Status {
		case "compliant":
			compliant++
		case "non_compliant":
			nonCompliant++
		case "partial":
			partial++
		default:
			na++
		}
	}
	score := 0
	if total > 0 {
		score = (compliant*100 + partial*50) / total
	}

	statusColor := map[string]string{
		"compliant":     "#22c55e",
		"non_compliant": "#ef4444",
		"partial":       "#f59e0b",
		"na":            "#6b7280",
	}
	statusLabel := map[string]string{
		"compliant":     "PASS",
		"non_compliant": "FAIL",
		"partial":       "PARTIAL",
		"na":            "N/A",
	}

	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Compliance Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;font-size:14px;padding:0 0 40px}
header{background:#1e293b;border-bottom:1px solid #334155;padding:20px 28px}
header h1{font-size:20px;color:#f1f5f9}
header .sub{font-size:13px;color:#94a3b8;margin-top:4px}
.summary{display:flex;gap:14px;padding:20px 28px;flex-wrap:wrap}
.stat{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:14px 22px;text-align:center;min-width:96px}
.stat .n{font-size:26px;font-weight:700}
.stat .l{font-size:11px;color:#64748b;margin-top:3px;text-transform:uppercase;letter-spacing:.05em}
.score{background:linear-gradient(135deg,#1e293b,#0f172a);border:1px solid #334155;border-radius:10px;padding:14px 28px;text-align:center;min-width:140px}
.score .n{font-size:34px;font-weight:800}
h2{font-size:15px;color:#cbd5e1;padding:8px 28px;margin-top:10px;border-top:1px solid #1e293b}
table{width:calc(100% - 56px);margin:8px 28px;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:9px 12px;border:1px solid #334155;vertical-align:top}
th{background:#1e293b;color:#cbd5e1;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
td{color:#cbd5e1}
.badge{display:inline-block;font-size:10px;font-weight:700;padding:2px 8px;border-radius:9999px;color:#fff;white-space:nowrap}
.sev{font-size:10px;font-weight:700;text-transform:uppercase}
.mono{font-family:monospace;font-size:11px;color:#94a3b8}
.rem{color:#fca5a5;font-size:12px}
footer{text-align:center;color:#475569;font-size:12px;padding:24px}
</style></head><body>
<header>
  <h1>Compliance Assessment Report</h1>
  <div class="sub">Case: ` + html.EscapeString(caseObj.Name) + ` &middot; Generated: ` + time.Now().Format("2006-01-02 15:04 UTC") + `</div>
</header>
<div class="summary">`)
	sb.WriteString(fmt.Sprintf(`<div class="score"><div class="n" style="color:%s">%d%%</div><div class="l">Compliance Score</div></div>`, scoreColor(score), score))
	stats := []struct {
		n    int
		l, c string
	}{
		{total, "Total", "#6366f1"},
		{compliant, "Pass", statusColor["compliant"]},
		{nonCompliant, "Fail", statusColor["non_compliant"]},
		{partial, "Partial", statusColor["partial"]},
		{na, "N/A", statusColor["na"]},
	}
	for _, s := range stats {
		sb.WriteString(fmt.Sprintf(`<div class="stat"><div class="n" style="color:%s">%d</div><div class="l">%s</div></div>`, s.c, s.n, s.l))
	}
	sb.WriteString(`</div>`)

	// Coverage matrix per framework.
	sb.WriteString(`<h2>Coverage Matrix (per framework)</h2>`)
	sb.WriteString(`<table><tr><th>Framework</th><th>Total</th><th>Pass</th><th>Fail</th><th>Partial</th><th>N/A</th><th>Score</th></tr>`)
	for _, fw := range frameworkBreakdown(findings) {
		fwScore := 0
		if fw.total > 0 {
			fwScore = (fw.pass*100 + fw.partial*50) / fw.total
		}
		sb.WriteString(fmt.Sprintf(`<tr><td><strong>%s</strong></td><td>%d</td><td style="color:#22c55e">%d</td><td style="color:#ef4444">%d</td><td style="color:#f59e0b">%d</td><td>%d</td><td><strong style="color:%s">%d%%</strong></td></tr>`,
			html.EscapeString(fw.name), fw.total, fw.pass, fw.fail, fw.partial, fw.na, scoreColor(fwScore), fwScore))
	}
	sb.WriteString(`</table>`)

	// Technical findings (worst first).
	sb.WriteString(`<h2>Technical Findings</h2>`)
	sb.WriteString(`<table><tr><th>Status</th><th>Sev</th><th>Control / Check</th><th>Evidence & Rationale</th><th>Integrity (SHA-256)</th></tr>`)
	for _, f := range findings {
		col := statusColor[f.Status]
		if col == "" {
			col = "#6b7280"
		}
		ev := f.Rationale
		if f.Host != "" {
			ev = "host=" + f.Host + " · " + ev
		}
		shortHash := f.EvidenceHash
		if len(shortHash) > 16 {
			shortHash = shortHash[:16] + "…"
		}
		sb.WriteString(fmt.Sprintf(`<tr>
  <td><span class="badge" style="background:%s">%s</span></td>
  <td class="sev" style="color:%s">%s</td>
  <td><strong>%s</strong><br><span class="mono">%s</span></td>
  <td>%s</td>
  <td class="mono" title="%s">%s</td>
</tr>`,
			col, statusLabel[f.Status],
			sevColor(f.Severity), html.EscapeString(f.Severity),
			html.EscapeString(f.Title), html.EscapeString(f.Control),
			html.EscapeString(ev),
			html.EscapeString(f.EvidenceHash), html.EscapeString(shortHash)))
	}
	sb.WriteString(`</table>`)

	// Remediation Roadmap (POA&M) — only items needing action.
	remStatusLabel := map[string]string{"open": "OPEN", "in_progress": "IN PROGRESS", "resolved": "RESOLVED", "accepted_risk": "ACCEPTED RISK"}
	var todo []models.ComplianceFinding
	for _, f := range findings {
		if f.Status == "non_compliant" || f.Status == "partial" {
			todo = append(todo, f)
		}
	}
	sb.WriteString(`<h2>Remediation Roadmap (POA&amp;M)</h2>`)
	if len(todo) == 0 {
		sb.WriteString(`<p style="padding:0 28px;color:#22c55e">No outstanding remediation items.</p>`)
	} else {
		sb.WriteString(`<table><tr><th>Sev</th><th>Control / Check</th><th>Remediation</th><th>Owner</th><th>Deadline</th><th>Status</th></tr>`)
		for _, f := range todo {
			owner := f.Owner
			if owner == "" {
				owner = "—"
			}
			due := "—"
			if f.DueDate != nil {
				due = f.DueDate.Format("2006-01-02")
				if f.DueDate.Before(time.Now()) && f.RemediationStatus != "resolved" {
					due = `<span style="color:#ef4444">` + due + ` (overdue)</span>`
				}
			}
			rs := remStatusLabel[f.RemediationStatus]
			if rs == "" {
				rs = "OPEN"
			}
			sb.WriteString(fmt.Sprintf(`<tr>
  <td class="sev" style="color:%s">%s</td>
  <td><strong>%s</strong><br><span class="mono">%s</span></td>
  <td class="rem">%s</td>
  <td>%s</td>
  <td>%s</td>
  <td>%s</td>
</tr>`,
				sevColor(f.Severity), html.EscapeString(f.Severity),
				html.EscapeString(f.Title), html.EscapeString(f.Control),
				html.EscapeString(f.Remediation),
				html.EscapeString(owner), due, html.EscapeString(rs)))
		}
		sb.WriteString(`</table>`)
	}

	sb.WriteString(`<footer>Generated by ForensicHub — Compliance Assessment &middot; Evidence integrity verified by SHA-256</footer></body></html>`)
	return sb.String()
}

type fwRow struct {
	name                           string
	total, pass, fail, partial, na int
}

func frameworkBreakdown(findings []models.ComplianceFinding) []fwRow {
	m := map[string]*fwRow{}
	order := []string{}
	for _, f := range findings {
		for _, fw := range strings.Split(f.Frameworks, ",") {
			fw = strings.TrimSpace(fw)
			if fw == "" {
				continue
			}
			if _, ok := m[fw]; !ok {
				m[fw] = &fwRow{name: fw}
				order = append(order, fw)
			}
			r := m[fw]
			r.total++
			switch f.Status {
			case "compliant":
				r.pass++
			case "non_compliant":
				r.fail++
			case "partial":
				r.partial++
			default:
				r.na++
			}
		}
	}
	sort.Strings(order)
	out := make([]fwRow, 0, len(order))
	for _, k := range order {
		out = append(out, *m[k])
	}
	return out
}

func scoreColor(score int) string {
	switch {
	case score >= 80:
		return "#22c55e"
	case score >= 50:
		return "#f59e0b"
	default:
		return "#ef4444"
	}
}

func sevColor(sev string) string {
	switch sev {
	case "critical":
		return "#ef4444"
	case "high":
		return "#f97316"
	case "medium":
		return "#f59e0b"
	case "low":
		return "#3b82f6"
	default:
		return "#6b7280"
	}
}

package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/config"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/vulnscan"
)

func mustGetVulnEngine(c *gin.Context) (*vulnscan.Engine, bool) {
	v, exists := c.Get("vulnEngine")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "vuln-scan engine not available"})
		return nil, false
	}
	e, ok := v.(*vulnscan.Engine)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "vuln-scan engine type assertion failed"})
		return nil, false
	}
	return e, true
}

// requireVulnAdmin enforces that active vulnerability scanning (intrusive) is
// limited to admin operators. Returns false (and writes 403) when not allowed.
func requireVulnAdmin(c *gin.Context) bool {
	if middleware.GetRole(c) != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "admin role required to run vulnerability scans"})
		return false
	}
	return true
}

func vulnScanEnabled(c *gin.Context) bool {
	if v, ok := c.Get("config"); ok {
		if cfg, ok := v.(*config.Config); ok {
			return cfg.VulnScanEnabled
		}
	}
	return true
}

// vulnScanMaxTargets returns the per-run asset cap (0 = unlimited).
func vulnScanMaxTargets(c *gin.Context) int {
	if v, ok := c.Get("config"); ok {
		if cfg, ok := v.(*config.Config); ok {
			return cfg.VulnScanMaxTargets
		}
	}
	return 0
}

// CreateVulnScan starts a new scan against either an OSINT investigation's
// discovered assets (source_scan_id) and/or an explicit target list. Admin-only.
func CreateVulnScan(c *gin.Context) {
	if !requireVulnAdmin(c) {
		return
	}
	if !vulnScanEnabled(c) {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "vulnerability scanning is disabled"})
		return
	}
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	engine, ok := mustGetVulnEngine(c)
	if !ok {
		return
	}

	var req struct {
		Name         string   `json:"name"`
		SourceScanID string   `json:"source_scan_id"`
		Targets      []string `json:"targets"`
		CaseID       string   `json:"case_id"`
		Severities   string   `json:"severities"`
		Profile      string   `json:"profile"`       // quick | full | cve-only
		Tags         string   `json:"tags"`          // extra nuclei tags (CSV)
		ProxyChoice  string   `json:"proxy_choice"`  // tor (default) | direct
		AllowPrivate bool     `json:"allow_private"` // allow private/loopback/LAN targets
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	profile := strings.TrimSpace(req.Profile)
	switch profile {
	case "full", "cve-only", "quick", "deep", "aggressive":
	default:
		profile = "quick"
	}
	proxyChoice := "tor"
	if req.ProxyChoice == "direct" {
		proxyChoice = "direct"
	}
	scan := models.VulnScan{
		Name:         strings.TrimSpace(req.Name),
		Status:       models.VulnPending,
		Severities:   strings.TrimSpace(req.Severities),
		Profile:      profile,
		Tags:         strings.TrimSpace(req.Tags),
		ProxyChoice:  proxyChoice,
		AllowPrivate: req.AllowPrivate,
	}
	if uid, ok := middleware.GetUserID(c); ok {
		scan.CreatedBy = uid
	}

	// Gather targets: OSINT-discovered assets + any explicit targets.
	uniq := map[string]bool{}
	var targets []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v != "" && !uniq[v] {
			uniq[v] = true
			targets = append(targets, v)
		}
	}

	if req.SourceScanID != "" {
		sid, err := uuid.Parse(req.SourceScanID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid source_scan_id"})
			return
		}
		scan.SourceScanID = &sid
		// Inherit the OSINT scan's case linkage when present.
		var src models.OsintScan
		if db.First(&src, "id = ?", sid).Error == nil && src.CaseID != nil {
			scan.CaseID = src.CaseID
		}
		// Auto-pull ALL discovered assets only when the caller didn't hand us an
		// explicit (operator-reviewed) subset — otherwise the source scan just
		// provides provenance/case and we scan exactly what was selected.
		if len(req.Targets) == 0 {
			assets, err := vulnscan.ExtractAssets(db, sid)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "could not load OSINT assets: " + err.Error()})
				return
			}
			for _, a := range assets {
				add(a.Value)
			}
		}
	}
	for _, t := range req.Targets {
		add(t)
	}

	if req.CaseID != "" {
		cid, err := uuid.Parse(req.CaseID)
		if err == nil {
			scan.CaseID = &cid
		}
	}

	if len(targets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "no targets — provide source_scan_id with discovered assets or an explicit target list"})
		return
	}

	// Hard cap on assets per run: a huge OSINT tree could otherwise feed thousands
	// of hosts into one scan and run for hours / exhaust the box. Truncate loudly.
	var truncated int
	if max := vulnScanMaxTargets(c); max > 0 && len(targets) > max {
		truncated = len(targets) - max
		targets = targets[:max]
	}

	if scan.Name == "" {
		scan.Name = fmt.Sprintf("Vuln scan (%d assets)", len(targets))
	}

	tj, _ := json.Marshal(targets)
	scan.Targets = string(tj)
	scan.TargetCount = len(targets)
	toolsJSON, _ := json.Marshal([]string{"subfinder", "dnsx", "cdncheck", "naabu", "httpx", "tlsx", "ffuf", "katana", "gau", "nuclei", "nuclei-dast", "dalfox", "wpscan", "nmap"})
	scan.Tools = string(toolsJSON)

	if err := db.Create(&scan).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "could not create scan"})
		return
	}
	writeAudit(c, db, &scan.CreatedBy, nil, "vulnscan.create", scan.ID.String(),
		fmt.Sprintf("targets=%d source=%s", len(targets), req.SourceScanID))

	if err := engine.StartScan(&scan, targets); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	resp := gin.H{"success": true, "data": scan}
	if truncated > 0 {
		resp["warning"] = fmt.Sprintf("target list capped to %d assets — %d dropped (raise VULNSCAN_MAX_TARGETS to scan more)", scan.TargetCount, truncated)
	}
	c.JSON(http.StatusOK, resp)
}

// PreviewVulnAssets returns the assets that WOULD be scanned for an OSINT scan,
// so the operator can review scope before launching. Admin-only.
func PreviewVulnAssets(c *gin.Context) {
	if !requireVulnAdmin(c) {
		return
	}
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	engine, ok := mustGetVulnEngine(c)
	if !ok {
		return
	}
	sid, err := uuid.Parse(c.Query("osint_scan_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid osint_scan_id"})
		return
	}
	assets, err := vulnscan.ExtractAssets(db, sid)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	// Classify each asset's scope (in / private / mixed / unresolved) so the
	// operator sees up front what will actually be scanned and WHY anything is
	// excluded — the same strict policy the engine enforces at scan time.
	values := make([]string, len(assets))
	for i, a := range assets {
		values[i] = a.Value
	}
	allowPrivate := c.Query("allow_private") == "true" || c.Query("allow_private") == "1"
	verdicts := map[string]vulnscan.ScopeVerdict{}
	for _, v := range engine.ClassifyForPreview(values, allowPrivate) {
		verdicts[v.Value] = v
	}
	type previewAsset struct {
		Value  string `json:"value"`
		Type   string `json:"type"`
		Scope  string `json:"scope"`
		Keep   bool   `json:"keep"`
		Reason string `json:"reason,omitempty"`
	}
	out := make([]previewAsset, 0, len(assets))
	for _, a := range assets {
		v := verdicts[a.Value]
		out = append(out, previewAsset{Value: a.Value, Type: a.Type, Scope: v.Scope, Keep: v.Keep, Reason: v.Reason})
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": out})
}

// osintTreeScanIDs returns every OSINT scan id in the investigation that the
// given scan belongs to (root + all auto-pivot children) — the set vuln scans
// are matched against to gather "all vulns for this investigation".
func osintTreeScanIDs(db *gorm.DB, osintScanID uuid.UUID) ([]uuid.UUID, error) {
	var scan models.OsintScan
	if err := db.Select("id, root_scan_id").First(&scan, "id = ?", osintScanID).Error; err != nil {
		return nil, err
	}
	root := scan.ID
	if scan.RootScanID != nil {
		root = *scan.RootScanID
	}
	var ids []uuid.UUID
	db.Model(&models.OsintScan{}).Where("root_scan_id = ? OR id = ?", root, root).Pluck("id", &ids)
	return ids, nil
}

// ListOsintVulnScans returns the vuln scans launched from anywhere in an OSINT
// investigation (route GET /osint/:id/vulnscans) — powers the investigation's
// Vulnerabilities tab.
func ListOsintVulnScans(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scan ID"})
		return
	}
	tree, err := osintTreeScanIDs(db, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "investigation not found"})
		return
	}
	var scans []models.VulnScan
	db.Where("source_scan_id IN ?", tree).Order("created_at DESC").Limit(200).Find(&scans)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": scans})
}

// vulnHostAgg is the per-host vulnerability roll-up for an investigation.
type vulnHostAgg struct {
	Host        string `json:"host"`
	Count       int    `json:"count"`
	KEV         bool   `json:"kev"`
	MaxSeverity string `json:"max_severity"`
}

// GetOsintVulnFindings returns per-host vulnerability aggregates across an OSINT
// investigation (route GET /osint/:id/vuln-findings) — powers the "vulns: N"
// badges on discovered hosts + graph nodes. Only real nuclei findings count
// (httpx "live host" info rows are excluded).
func GetOsintVulnFindings(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scan ID"})
		return
	}
	tree, err := osintTreeScanIDs(db, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "investigation not found"})
		return
	}
	var rows []struct {
		Host    string
		Count   int
		Kev     bool
		SevRank int
	}
	db.Model(&models.VulnFinding{}).
		Select(`host, count(*) as count, bool_or(is_kev) as kev,
			min(CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END) as sev_rank`).
		Joins("JOIN vuln_scans s ON s.id = vuln_findings.scan_id").
		Where("s.source_scan_id IN ? AND vuln_findings.tool = ?", tree, "nuclei").
		Group("host").Scan(&rows)

	sevName := []string{"critical", "high", "medium", "low", "info", "unknown"}
	// Collapse by normalised host (a host may appear as several URLs).
	merged := map[string]*vulnHostAgg{}
	for _, r := range rows {
		h := normalizeVulnHost(r.Host)
		if h == "" {
			continue
		}
		a := merged[h]
		if a == nil {
			a = &vulnHostAgg{Host: h, MaxSeverity: "info"}
			merged[h] = a
		}
		a.Count += r.Count
		a.KEV = a.KEV || r.Kev
		if r.SevRank >= 0 && r.SevRank < len(sevName) {
			if sevRankOf(a.MaxSeverity) > r.SevRank {
				a.MaxSeverity = sevName[r.SevRank]
			}
		}
	}
	out := make([]vulnHostAgg, 0, len(merged))
	for _, a := range merged {
		out = append(out, *a)
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": out})
}

func sevRankOf(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "info":
		return 4
	}
	return 5
}

// normalizeVulnHost strips scheme/port/path so a VulnFinding.Host matches an
// OSINT target value (domain / ip).
func normalizeVulnHost(h string) string {
	h = strings.TrimSpace(h)
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?"); i >= 0 {
		h = h[:i]
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(h)
}

// ListVulnScans returns recent scans (optionally filtered by case_id).
func ListVulnScans(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	q := db.Model(&models.VulnScan{}).Order("created_at DESC").Limit(200)
	if cid := c.Query("case_id"); cid != "" {
		if id, err := uuid.Parse(cid); err == nil {
			q = q.Where("case_id = ?", id)
		}
	}
	var scans []models.VulnScan
	q.Find(&scans)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": scans})
}

// GetVulnScan returns a scan with its tool runs.
func GetVulnScan(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scan ID"})
		return
	}
	var scan models.VulnScan
	if err := db.Preload("ToolRuns").First(&scan, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "scan not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": scan})
}

// GetVulnFindings returns a scan's findings, optionally filtered by severity/tool.
func GetVulnFindings(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scan ID"})
		return
	}
	q := db.Model(&models.VulnFinding{}).Where("scan_id = ?", id)
	if sev := c.Query("severity"); sev != "" {
		q = q.Where("severity = ?", sev)
	}
	if tool := c.Query("tool"); tool != "" {
		q = q.Where("tool = ?", tool)
	}
	var findings []models.VulnFinding
	q.Order("CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END, created_at DESC").
		Limit(5000).Find(&findings)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": findings})
}

// ExportVulnFindings streams a scan's findings as CSV for offline triage /
// reporting. Honors the same severity/tool filters as GetVulnFindings.
//
// GET /api/v1/vulnscan/:id/findings/export
func ExportVulnFindings(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scan ID"})
		return
	}
	q := db.Model(&models.VulnFinding{}).Where("scan_id = ?", id)
	if sev := c.Query("severity"); sev != "" {
		q = q.Where("severity = ?", sev)
	}
	if tool := c.Query("tool"); tool != "" {
		q = q.Where("tool = ?", tool)
	}
	rows, err := q.Order("CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END, created_at DESC").Rows()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	defer rows.Close()

	c.Header("Content-Disposition", `attachment; filename="vuln-findings-`+id.String()+`.csv"`)
	c.Header("Content-Type", "text/csv; charset=utf-8")
	cw := csv.NewWriter(c.Writer)
	_ = cw.Write([]string{"severity", "tool", "name", "host", "matched_at", "cve_id", "epss", "kev", "confirmed", "status", "template_id", "tags", "note", "created_at"})
	n := 0
	for rows.Next() {
		var f models.VulnFinding
		if db.ScanRows(rows, &f) != nil {
			continue
		}
		epss := ""
		if f.EPSSScore > 0 {
			epss = fmt.Sprintf("%.4f", f.EPSSScore)
		}
		_ = cw.Write([]string{
			f.Severity, f.Tool, f.Name, f.Host, f.MatchedAt, f.CVEID, epss,
			fmt.Sprintf("%t", f.IsKEV), fmt.Sprintf("%t", f.Confirmed), f.Status,
			f.TemplateID, f.Tags, f.Note, f.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
		n++
		if n%500 == 0 {
			cw.Flush()
		}
	}
	cw.Flush()
}

// UpdateVulnFinding sets the operator triage state (status + note) on a finding.
// Status: open | confirmed | false_positive | fixed.
func UpdateVulnFinding(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid finding ID"})
		return
	}
	var req struct {
		Status string  `json:"status"`
		Note   *string `json:"note"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	updates := map[string]interface{}{}
	switch req.Status {
	case "open", "confirmed", "false_positive", "fixed":
		updates["status"] = req.Status
	case "":
		// leave status unchanged
	default:
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid status"})
		return
	}
	if req.Note != nil {
		updates["note"] = strings.TrimSpace(*req.Note)
	}
	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "nothing to update"})
		return
	}
	if err := db.Model(&models.VulnFinding{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "update failed"})
		return
	}
	var f models.VulnFinding
	db.First(&f, "id = ?", id)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": f})
}

// StreamVulnOutput streams the scan's live log over SSE.
func StreamVulnOutput(c *gin.Context) {
	engine, ok := mustGetVulnEngine(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scan ID"})
		return
	}
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	c.Writer.WriteHeader(http.StatusOK)
	c.Writer.Flush()

	ch := engine.Subscribe(id.String())
	defer engine.Unsubscribe(id.String(), ch)

	clientGone := c.Request.Context().Done()
	for {
		select {
		case <-clientGone:
			return
		case line, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(c.Writer, "data: %s\n\n", line)
			c.Writer.Flush()
			if line == "__DONE__" {
				return
			}
		}
	}
}

// StopVulnScan cancels a running scan. Admin-only.
func StopVulnScan(c *gin.Context) {
	if !requireVulnAdmin(c) {
		return
	}
	engine, ok := mustGetVulnEngine(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scan ID"})
		return
	}
	stopped := engine.StopScan(id.String())
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"stopped": stopped}})
}

// DeleteVulnScan removes a scan and its findings (cascade). Admin-only.
func DeleteVulnScan(c *gin.Context) {
	if !requireVulnAdmin(c) {
		return
	}
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	engine, _ := mustGetVulnEngine(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scan ID"})
		return
	}
	if engine != nil {
		engine.StopScan(id.String())
		engine.DeleteHistory(id.String())
	}
	db.Where("scan_id = ?", id).Delete(&models.VulnFinding{})
	db.Where("scan_id = ?", id).Delete(&models.VulnTool{})
	db.Delete(&models.VulnScan{}, "id = ?", id)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

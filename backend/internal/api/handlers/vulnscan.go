package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/forensichub/backend/internal/api/middleware"
	"github.com/forensichub/backend/internal/config"
	"github.com/forensichub/backend/internal/models"
	"github.com/forensichub/backend/internal/vulnscan"
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
		Profile      string   `json:"profile"`      // quick | full | cve-only
		Tags         string   `json:"tags"`         // extra nuclei tags (CSV)
		ProxyChoice  string   `json:"proxy_choice"` // tor (default) | direct
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	profile := strings.TrimSpace(req.Profile)
	switch profile {
	case "full", "cve-only", "quick":
	default:
		profile = "quick"
	}
	proxyChoice := "tor"
	if req.ProxyChoice == "direct" {
		proxyChoice = "direct"
	}
	scan := models.VulnScan{
		Name:        strings.TrimSpace(req.Name),
		Status:      models.VulnPending,
		Severities:  strings.TrimSpace(req.Severities),
		Profile:     profile,
		Tags:        strings.TrimSpace(req.Tags),
		ProxyChoice: proxyChoice,
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
	if scan.Name == "" {
		scan.Name = fmt.Sprintf("Vuln scan (%d assets)", len(targets))
	}

	tj, _ := json.Marshal(targets)
	scan.Targets = string(tj)
	scan.TargetCount = len(targets)
	toolsJSON, _ := json.Marshal([]string{"httpx", "nuclei"})
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
	c.JSON(http.StatusOK, gin.H{"success": true, "data": scan})
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
	c.JSON(http.StatusOK, gin.H{"success": true, "data": assets})
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

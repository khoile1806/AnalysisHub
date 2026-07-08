package handlers

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/osint"
)

// mustGetOsintEngine retrieves the *osint.Engine from the Gin context.
func mustGetOsintEngine(c *gin.Context) (*osint.Engine, bool) {
	v, exists := c.Get("osintEngine")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "osint engine not available"})
		return nil, false
	}
	e, ok := v.(*osint.Engine)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "osint engine type assertion failed"})
		return nil, false
	}
	return e, true
}

// createOsintScanRequest is the POST body for starting an investigation.
// Name is optional - it defaults to "<type>: <target>".
type createOsintScanRequest struct {
	Name      string  `json:"name"`
	Target    string  `json:"target" binding:"required"`
	AutoPivot bool    `json:"auto_pivot"` // recursively investigate discovered entities
	MaxDepth  int     `json:"max_depth"`  // pivot depth limit (default 2 when auto_pivot)
	CaseID    *string `json:"case_id"`    // optional: file this investigation under a DFIR case
	// ScopeOverride optionally tightens the admin scope policy for this one scan
	// (all | passive_only | block). It may only make the scan MORE restrictive
	// than the policy allows, and only when the policy permits overrides.
	ScopeOverride string `json:"scope_override"`
	// AuthorizedActive lifts a passive-only decision to full active scanning when
	// the operator confirms authorization to touch the target directly (accepting
	// IP exposure). Admin-only; never overrides a Block decision.
	AuthorizedActive bool `json:"authorized_active"`
}

// DetectOsintTarget classifies a target string without creating a scan, so the
// UI can preview the detected type and collector list.
// POST /api/v1/osint/detect
func DetectOsintTarget(c *gin.Context) {
	var req struct {
		Target string `json:"target" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	target := strings.TrimSpace(req.Target)
	ttype, err := osint.DetectTargetType(target)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	if err := osint.ValidateTarget(target, ttype); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	names := osint.CollectorNamesFor(ttype)
	// Surface which collectors will be skipped for lack of an optional API key so
	// the UI can preview the real coverage before the scan starts.
	var skipped []string
	if v, exists := c.Get("osintEngine"); exists {
		if engine, ok := v.(*osint.Engine); ok {
			skipped = engine.UnavailableCollectors(names)
		}
	}
	// Evaluate the admin scope policy so the launch UI can show, before the scan
	// starts, whether active collectors will run for this target.
	var policy *osint.ScopeDecision
	var allowOverride bool
	if db, ok := mustGetDBSilent(c); ok {
		d := osint.DecideScope(db, target, ttype)
		policy = &d
		_, settings := osint.LoadScopePolicy(db)
		allowOverride = settings.Enforce && settings.AllowOverride
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"target_type":    ttype,
		"collectors":     names,
		"skipped_no_key": skipped,
		"policy":         policy,
		"allow_override": allowOverride,
	}})
}

// CreateOsintScan creates an investigation and starts it immediately.
// POST /api/v1/osint
func CreateOsintScan(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	engine, ok := mustGetOsintEngine(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetUserID(c)

	var req createOsintScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	target := strings.TrimSpace(req.Target)
	ttype, err := osint.DetectTargetType(target)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	if err := osint.ValidateTarget(target, ttype); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = fmt.Sprintf("%s: %s", ttype, target)
	}

	maxDepth := req.MaxDepth
	if req.AutoPivot && maxDepth <= 0 {
		maxDepth = 2
	}
	if maxDepth > 4 {
		maxDepth = 4 // hard cap - guards against runaway graph expansion
	}

	var caseID *uuid.UUID
	if req.CaseID != nil && strings.TrimSpace(*req.CaseID) != "" {
		cid, err := uuid.Parse(strings.TrimSpace(*req.CaseID))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case_id"})
			return
		}
		// Verify the case exists before tying the investigation to it.
		if err := db.First(&models.Case{}, "id = ?", cid).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "case not found"})
			return
		}
		caseID = &cid
	}

	scan := models.OsintScan{
		Name:       name,
		Target:     target,
		TargetType: ttype,
		Status:     models.OsintPending,
		Depth:      0,
		AutoPivot:  req.AutoPivot,
		MaxDepth:   maxDepth,
		CaseID:     caseID,
		CreatedBy:  userID,
	}
	if err := db.Create(&scan).Error; err != nil {
		log.Printf("[osint] create scan error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to create scan"})
		return
	}
	// A root scan is its own investigation root.
	rootSelf := scan.ID
	db.Model(&scan).Update("root_scan_id", rootSelf)
	scan.RootScanID = &rootSelf

	// Apply the admin scope policy: it decides which collectors may run for this
	// target (all / passive-only / block). An operator may additionally tighten
	// (never loosen) the decision via ScopeOverride when the policy allows it.
	decision := osint.DecideScope(db, target, ttype)
	if strings.TrimSpace(req.ScopeOverride) != "" {
		if _, settings := osint.LoadScopePolicy(db); settings.Enforce && settings.AllowOverride {
			decision = osint.ApplyOverride(decision, req.ScopeOverride, osint.CollectorNamesFor(ttype))
		}
	}
	// Admin operators may authorise active scanning of a passive-only target
	// (direct-egress IP exposure accepted). Never lifts a Block decision.
	if req.AuthorizedActive && decision.Mode == osint.ModePassiveOnly && middleware.GetRole(c) == "admin" {
		decision = osint.LiftPassiveToActive(decision, osint.CollectorNamesFor(ttype))
		writeAudit(c, db, &userID, nil, "osint.authorize_active", scan.ID.String(),
			fmt.Sprintf("target=%s type=%s — operator authorised active scan on direct egress", target, ttype))
	}
	db.Model(&scan).Updates(map[string]interface{}{
		"scope_mode": string(decision.Mode),
		"scope_rule": decision.MatchedRule,
	})
	scan.ScopeMode = string(decision.Mode)
	scan.ScopeRule = decision.MatchedRule

	// block mode: nothing may run — record the scan as finished with no collectors
	// rather than starting an empty pipeline.
	if decision.Mode == osint.ModeBlock {
		db.Model(&scan).Update("status", models.OsintDone)
		writeAudit(c, db, &userID, nil, "osint.create", scan.ID.String(),
			fmt.Sprintf("target=%s type=%s BLOCKED by scope policy (%s)", target, ttype, decision.MatchedRule))
		db.Preload("Collectors").First(&scan, "id = ?", scan.ID)
		c.JSON(http.StatusCreated, gin.H{"success": true, "data": scan, "policy": decision})
		return
	}

	names := decision.Allowed
	collectors := make([]models.OsintCollector, len(names))
	for i, n := range names {
		collectors[i] = models.OsintCollector{
			ScanID: scan.ID,
			Name:   n,
			Status: models.OsintCollectorPending,
		}
		db.Create(&collectors[i])
	}

	if err := engine.StartScan(&scan, collectors); err != nil {
		log.Printf("[osint] start scan error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": fmt.Sprintf("failed to start scan: %v", err)})
		return
	}

	writeAudit(c, db, &userID, nil, "osint.create", scan.ID.String(),
		fmt.Sprintf("target=%s type=%s scope=%s rule=%q", target, ttype, decision.Mode, decision.MatchedRule))

	db.Preload("Collectors").First(&scan, "id = ?", scan.ID)
	c.JSON(http.StatusCreated, gin.H{"success": true, "data": scan})
}

// ListOsintScans returns all scans, newest first.
// GET /api/v1/osint
func ListOsintScans(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	caseID := strings.TrimSpace(c.Query("case_id"))
	rootOnly := c.Query("root") == "1"

	// ?case_id= filters to one case's investigations; ?root=1 returns only the
	// root scans (hides auto-pivot children for a cleaner top-level list).
	// filter applies the same conditions to a fresh chain for count vs. fetch.
	filter := func(qq *gorm.DB) *gorm.DB {
		if caseID != "" {
			qq = qq.Where("case_id = ?", caseID)
		}
		if rootOnly {
			qq = qq.Where("parent_scan_id IS NULL")
		}
		return qq
	}

	writeTotalCount(c, filter(db.Model(&models.OsintScan{})))

	q := applyLimitOffset(c, filter(db.Model(&models.OsintScan{})).Order("created_at desc"))

	var scans []models.OsintScan
	if err := q.Find(&scans).Error; err != nil {
		log.Printf("[osint] list error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to list scans"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": scans})
}

// GetOsintScan returns one scan with its collectors.
// GET /api/v1/osint/:id
func GetOsintScan(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scan ID"})
		return
	}
	var scan models.OsintScan
	if err := db.Preload("Collectors", func(db *gorm.DB) *gorm.DB {
		return db.Order("name asc")
	}).First(&scan, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "scan not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": scan})
}

// GetOsintFindings returns findings for a scan, optionally filtered.
// GET /api/v1/osint/:id/findings?source=dns&category=reputation
func GetOsintFindings(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scan ID"})
		return
	}
	query := db.Where("scan_id = ?", id)
	if s := c.Query("source"); s != "" {
		query = query.Where("source = ?", s)
	}
	if cat := c.Query("category"); cat != "" {
		query = query.Where("category = ?", cat)
	}
	var findings []models.OsintFinding
	if err := query.Order("created_at asc").Find(&findings).Error; err != nil {
		log.Printf("[osint] findings query error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to fetch findings"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": findings})
}

// StopOsintScan cancels a running scan.
// POST /api/v1/osint/:id/stop
func StopOsintScan(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	engine, ok := mustGetOsintEngine(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetUserID(c)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scan ID"})
		return
	}
	var scan models.OsintScan
	if err := db.First(&scan, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "scan not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}
	// A scan that is running, OR queued for an execution slot (still "pending" in
	// the DB but accepted by the engine), can be stopped. Only a truly terminal
	// scan is rejected.
	if scan.Status != models.OsintRunning && !engine.IsRunning(id.String()) {
		c.JSON(http.StatusConflict, gin.H{"success": false, "error": fmt.Sprintf("scan is not running (status: %s)", scan.Status)})
		return
	}
	engine.StopScan(id.String())
	writeAudit(c, db, &userID, nil, "osint.stop", scan.ID.String(), fmt.Sprintf("target=%s", scan.Target))
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"message": "stop signal sent"}})
}

// DeleteOsintScan removes a scan and all its data.
// DELETE /api/v1/osint/:id
func DeleteOsintScan(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	engine, ok := mustGetOsintEngine(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetUserID(c)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scan ID"})
		return
	}
	var scan models.OsintScan
	if err := db.First(&scan, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "scan not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}
	if engine.IsRunning(id.String()) {
		c.JSON(http.StatusConflict, gin.H{"success": false, "error": "stop the scan before deleting"})
		return
	}

	db.Where("scan_id = ?", id).Delete(&models.OsintFinding{})
	db.Where("scan_id = ?", id).Delete(&models.OsintCollector{})
	db.Delete(&scan)
	engine.DeleteHistory(id.String())

	writeAudit(c, db, &userID, nil, "osint.delete", id.String(), fmt.Sprintf("target=%s", scan.Target))
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"message": "scan deleted"}})
}

// OsintReport renders a self-contained HTML report and serves it as a download.
// GET /api/v1/osint/:id/report
func OsintReport(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scan ID"})
		return
	}

	var scan models.OsintScan
	if err := db.Preload("Collectors", func(db *gorm.DB) *gorm.DB {
		return db.Order("name asc")
	}).First(&scan, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "scan not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	var findings []models.OsintFinding
	db.Where("scan_id = ?", id).Order("category, created_at").Find(&findings)

	html := osint.GenerateHTMLReport(&scan, findings)

	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, scan.Name)
	filename := fmt.Sprintf("osint-%s-%s.html", safe, scan.CreatedAt.Format("2006-01-02"))

	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}

// OsintExport serves a scan's findings in a machine-readable interchange format
// for IOC sharing / TIP ingestion. ?format=stix (STIX 2.1 bundle, default), csv,
// or json.
// GET /api/v1/osint/:id/export?format=stix|csv|json
func OsintExport(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scan ID"})
		return
	}
	var scan models.OsintScan
	if err := db.First(&scan, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "scan not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}
	var findings []models.OsintFinding
	db.Where("scan_id = ?", id).Order("category, created_at").Find(&findings)

	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, scan.Name)
	stamp := scan.CreatedAt.Format("2006-01-02")

	switch strings.ToLower(c.DefaultQuery("format", "stix")) {
	case "csv":
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="osint-%s-%s.csv"`, safe, stamp))
		c.Data(http.StatusOK, "text/csv; charset=utf-8", osint.GenerateCSV(&scan, findings))
	case "json":
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="osint-%s-%s.json"`, safe, stamp))
		c.JSON(http.StatusOK, gin.H{"scan": scan, "findings": findings})
	default: // stix
		bundle, gerr := osint.GenerateSTIXBundle(&scan, findings)
		if gerr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to build STIX bundle"})
			return
		}
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="osint-%s-%s-stix.json"`, safe, stamp))
		c.Data(http.StatusOK, "application/json; charset=utf-8", bundle)
	}
}

// StreamOsintOutput streams live progress for a scan via SSE.
// GET /api/v1/osint/:id/stream
func StreamOsintOutput(c *gin.Context) {
	engine, ok := mustGetOsintEngine(c)
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

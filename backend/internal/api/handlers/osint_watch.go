package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/forensichub/backend/internal/api/middleware"
	"github.com/forensichub/backend/internal/models"
	"github.com/forensichub/backend/internal/osint"
)

// ListOsintWatches returns all continuous-monitoring watches.
// GET /api/v1/osint/watches
func ListOsintWatches(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	q := db.Order("created_at desc")
	if cid := strings.TrimSpace(c.Query("case_id")); cid != "" {
		q = q.Where("case_id = ?", cid)
	}
	var watches []models.OsintWatch
	if err := q.Find(&watches).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to list watches"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": watches})
}

// CreateOsintWatch creates a watch and schedules its first run immediately.
// POST /api/v1/osint/watches
func CreateOsintWatch(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetUserID(c)

	var req struct {
		Name            string  `json:"name"`
		Target          string  `json:"target" binding:"required"`
		IntervalMinutes int     `json:"interval_minutes"`
		AutoPivot       bool    `json:"auto_pivot"`
		MaxDepth        int     `json:"max_depth"`
		CaseID          *string `json:"case_id"`
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

	interval := req.IntervalMinutes
	if interval < 5 {
		interval = 1440 // default daily
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = target
	}

	var caseID *uuid.UUID
	if req.CaseID != nil && strings.TrimSpace(*req.CaseID) != "" {
		cid, err := uuid.Parse(strings.TrimSpace(*req.CaseID))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case_id"})
			return
		}
		if err := db.First(&models.Case{}, "id = ?", cid).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "case not found"})
			return
		}
		caseID = &cid
	}

	w := models.OsintWatch{
		Name:            name,
		Target:          target,
		TargetType:      ttype,
		IntervalMinutes: interval,
		AutoPivot:       req.AutoPivot,
		MaxDepth:        req.MaxDepth,
		CaseID:          caseID,
		Enabled:         true,
		CreatedBy:       userID,
	}
	if err := db.Create(&w).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to create watch"})
		return
	}

	// Fire the first run now so a baseline is captured immediately.
	if engine, ok := mustGetOsintEngine(c); ok {
		_ = engine.TriggerWatch(w.ID)
	}
	writeAudit(c, db, &userID, nil, "osint.watch.create", w.ID.String(), "target="+target)
	c.JSON(http.StatusCreated, gin.H{"success": true, "data": w})
}

// UpdateOsintWatch toggles enabled / changes interval or name.
// PATCH /api/v1/osint/watches/:id
func UpdateOsintWatch(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid watch id"})
		return
	}
	var req struct {
		Name            *string `json:"name"`
		Enabled         *bool   `json:"enabled"`
		IntervalMinutes *int    `json:"interval_minutes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	updates := map[string]interface{}{}
	if req.Name != nil {
		updates["name"] = strings.TrimSpace(*req.Name)
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}
	if req.IntervalMinutes != nil && *req.IntervalMinutes >= 5 {
		updates["interval_minutes"] = *req.IntervalMinutes
	}
	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "no updatable fields"})
		return
	}
	if err := db.Model(&models.OsintWatch{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to update watch"})
		return
	}
	var w models.OsintWatch
	db.First(&w, "id = ?", id)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": w})
}

// DeleteOsintWatch removes a watch and its alerts.
// DELETE /api/v1/osint/watches/:id
func DeleteOsintWatch(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid watch id"})
		return
	}
	db.Where("watch_id = ?", id).Delete(&models.OsintWatchAlert{})
	if err := db.Delete(&models.OsintWatch{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to delete watch"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// RunOsintWatchNow fires a watch immediately.
// POST /api/v1/osint/watches/:id/run
func RunOsintWatchNow(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid watch id"})
		return
	}
	engine, ok := mustGetOsintEngine(c)
	if !ok {
		return
	}
	if err := engine.TriggerWatch(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "watch not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// ListOsintWatchAlerts returns a watch's alerts (newest first).
// GET /api/v1/osint/watches/:id/alerts?unseen=1
func ListOsintWatchAlerts(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid watch id"})
		return
	}
	q := db.Where("watch_id = ?", id).Order("created_at desc")
	if c.Query("unseen") == "1" {
		q = q.Where("seen = ?", false)
	}
	var alerts []models.OsintWatchAlert
	if err := q.Limit(500).Find(&alerts).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to fetch alerts"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": alerts})
}

// MarkOsintWatchAlertsSeen clears the unseen-alert badge for a watch.
// POST /api/v1/osint/watches/:id/alerts/seen
func MarkOsintWatchAlertsSeen(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid watch id"})
		return
	}
	db.Model(&models.OsintWatchAlert{}).Where("watch_id = ? AND seen = ?", id, false).
		Update("seen", true)
	db.Model(&models.OsintWatch{}).Where("id = ?", id).Update("alert_count", 0)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/forensichub/backend/internal/models"
)

// ListOobRules returns a session's conditional response rules, ordered.
//
// GET /api/v1/osint/oob/clients/:id/rules
func ListOobRules(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	var rules []models.OobResponseRule
	if err := db.Where("client_id = ?", id).Order("priority ASC, created_at ASC").Find(&rules).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": rules})
}

type oobRulePayload struct {
	Name            string            `json:"name"`
	Priority        int               `json:"priority"`
	MatchMethod     string            `json:"match_method"`
	MatchPathPrefix string            `json:"match_path_prefix"`
	MatchPathSub    string            `json:"match_path_sub"`
	Status          int               `json:"status"`
	ContentType     string            `json:"content_type"`
	Body            string            `json:"body"`
	Headers         map[string]string `json:"headers"`
	DelayMs         int               `json:"delay_ms"`
}

func (p oobRulePayload) apply(r *models.OobResponseRule) error {
	r.Name = strings.TrimSpace(p.Name)
	r.Priority = p.Priority
	r.MatchMethod = strings.ToUpper(strings.TrimSpace(p.MatchMethod))
	r.MatchPathPrefix = p.MatchPathPrefix
	r.MatchPathSub = p.MatchPathSub
	r.Status = p.Status
	if r.Status < 100 || r.Status > 599 {
		r.Status = 200
	}
	r.ContentType = strings.TrimSpace(p.ContentType)
	if r.ContentType == "" {
		r.ContentType = "text/plain"
	}
	r.Body = p.Body
	r.DelayMs = p.DelayMs
	if r.DelayMs < 0 {
		r.DelayMs = 0
	}
	if r.DelayMs > 30000 {
		r.DelayMs = 30000
	}
	if len(p.Headers) > 0 {
		b, _ := json.Marshal(p.Headers)
		r.Headers = string(b)
	} else {
		r.Headers = ""
	}
	return nil
}

// CreateOobRule adds a response rule to a session.
//
// POST /api/v1/osint/oob/clients/:id/rules
func CreateOobRule(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	var p oobRulePayload
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	rule := models.OobResponseRule{ClientID: id}
	_ = p.apply(&rule)
	if err := db.Create(&rule).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": rule})
}

// UpdateOobRule edits a response rule.
//
// PATCH /api/v1/osint/oob/clients/:id/rules/:rid
func UpdateOobRule(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	rid, err := uuid.Parse(c.Param("rid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid rule id"})
		return
	}
	var rule models.OobResponseRule
	if err := db.First(&rule, "id = ?", rid).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "rule not found"})
		return
	}
	var p oobRulePayload
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	_ = p.apply(&rule)
	if err := db.Save(&rule).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": rule})
}

// DeleteOobRule removes a response rule.
//
// DELETE /api/v1/osint/oob/clients/:id/rules/:rid
func DeleteOobRule(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	rid, err := uuid.Parse(c.Param("rid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid rule id"})
		return
	}
	if err := db.Delete(&models.OobResponseRule{}, "id = ?", rid).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

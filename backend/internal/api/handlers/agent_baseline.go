package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/api/middleware"
	"github.com/forensichub/backend/internal/models"
)

// SetAgentBaseline stores (upserts) a known-good snapshot of an artifact for an
// agent, so later scans can be diffed against it for drift detection.
//
// POST /api/v1/agents/:id/baseline  { "kind": "autoruns", "data": "<json>" }
func SetAgentBaseline(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetUserID(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid agent ID"})
		return
	}
	var req struct {
		Kind string `json:"kind" binding:"required"`
		Data string `json:"data" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "kind and data required"})
		return
	}
	kind := strings.TrimSpace(req.Kind)

	bl := models.AgentBaseline{AgentID: id, Kind: kind}
	// Upsert one baseline per (agent, kind).
	err = db.Where("agent_id = ? AND kind = ?", id, kind).
		Assign(models.AgentBaseline{Data: req.Data, CreatedBy: userID}).
		FirstOrCreate(&bl).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to save baseline"})
		return
	}
	writeAudit(c, db, &userID, &id, "agent.baseline.set", id.String(), "kind="+kind)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"created_at": bl.CreatedAt, "updated_at": bl.UpdatedAt}})
}

// GetAgentBaseline returns the stored baseline snapshot for an agent + kind.
//
// GET /api/v1/agents/:id/baseline?kind=autoruns
func GetAgentBaseline(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid agent ID"})
		return
	}
	kind := strings.TrimSpace(c.Query("kind"))
	if kind == "" {
		kind = "autoruns"
	}
	var bl models.AgentBaseline
	if err := db.Where("agent_id = ? AND kind = ?", id, kind).First(&bl).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "no baseline set"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": bl})
}

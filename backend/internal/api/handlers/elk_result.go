package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/models"
)

// ListELKHuntResults returns all persisted hunt results, newest first.
// GET /api/v1/elk/hunt/results
func ListELKHuntResults(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)

	writeTotalCount(c, db.Model(&models.ELKHuntResult{}))

	query := applyLimitOffset(c, db.Order("created_at desc"))

	var results []models.ELKHuntResult
	if err := query.Find(&results).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to list hunt results"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": results})
}

// GetELKHuntResult returns a single hunt result including the full hits payload.
// GET /api/v1/elk/hunt/results/:id
func GetELKHuntResult(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid result ID"})
		return
	}

	var result models.ELKHuntResult
	if err := db.First(&result, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "result not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "db error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": result})
}

// DeleteELKHuntResult removes a persisted hunt result.
// DELETE /api/v1/elk/hunt/results/:id
func DeleteELKHuntResult(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid result ID"})
		return
	}

	if err := db.Delete(&models.ELKHuntResult{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to delete"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

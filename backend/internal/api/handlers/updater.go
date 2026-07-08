package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/updater"
)

// ListUpdaters returns the status of every registered auto-updating tool/data
// source (last run, next run, success/error, cadence).
//
// GET /api/v1/system/updaters
func ListUpdaters(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"success": true, "data": updater.Default.Statuses()})
}

// RunUpdater triggers an immediate refresh of one component. Admin-only, since it
// launches outbound tool/data downloads.
//
// POST /api/v1/system/updaters/:name/run
func RunUpdater(c *gin.Context) {
	if middleware.GetRole(c) != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "admin role required"})
		return
	}
	name := c.Param("name")
	if err := updater.Default.RunNow(name); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "refresh triggered for " + name})
}

package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/models"
)

// eventDB is a package-level handle used by the fire-and-forget RecordSystemEvent
// so background code (worker panics, the updater result hook, retention) can log
// health events without threading a *gorm.DB through every call site. Installed
// once at startup via SetEventDB. Mirrors the workerCtx pattern.
var eventDB *gorm.DB

// SetEventDB installs the DB handle used by RecordSystemEvent. Call once at startup.
func SetEventDB(db *gorm.DB) { eventDB = db }

// eventDedupWindow is how long an identical event is collapsed into the existing
// row (Count++) instead of inserting a new one.
const eventDedupWindow = time.Hour

// RecordSystemEvent persists one self-healing / health signal. Best-effort: it
// never returns an error and no-ops when the DB is unavailable, so instrumenting
// a code path can never change its behaviour. Repeated identical events within
// eventDedupWindow are collapsed (Count incremented).
func RecordSystemEvent(category, severity, source, message, detail string) {
	db := eventDB
	if db == nil {
		return
	}
	detail = truncEvent(detail, 4000)
	cutoff := time.Now().Add(-eventDedupWindow)

	var ev models.SystemEvent
	err := db.Where("category = ? AND source = ? AND message = ? AND updated_at > ?",
		category, source, message, cutoff).
		Order("updated_at desc").First(&ev).Error
	if err == nil {
		db.Model(&ev).Updates(map[string]interface{}{
			"count":      ev.Count + 1,
			"severity":   severity,
			"detail":     detail,
			"updated_at": time.Now(),
		})
		return
	}
	db.Create(&models.SystemEvent{
		Category: category, Severity: severity, Source: source, Message: message, Detail: detail, Count: 1,
	})
}

func truncEvent(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// ListSystemEvents returns recent self-healing / health events, newest first.
//
// GET /api/v1/system/events?category=&severity=&limit=&offset=
func ListSystemEvents(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	q := db.Model(&models.SystemEvent{})
	if cat := strings.TrimSpace(c.Query("category")); cat != "" {
		q = q.Where("category = ?", cat)
	}
	if sev := strings.TrimSpace(c.Query("severity")); sev != "" {
		q = q.Where("severity = ?", sev)
	}

	var total int64
	q.Count(&total)

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if offset < 0 {
		offset = 0
	}

	var events []models.SystemEvent
	q.Order("updated_at desc").Limit(limit).Offset(offset).Find(&events)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": events, "total": total})
}

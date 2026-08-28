package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/analysishub/backend/internal/news"
)

// PluginWatchStatusHandler exposes whether plugin releases are still arriving.
//
// GET /api/v1/news/plugin-watch/status
//
// The pipeline's failure mode is silence: if the watcher service stops, the news
// list simply has no new plugin releases and nothing distinguishes that from a
// quiet week. This turns that into an answerable question.
func PluginWatchStatusHandler(c *gin.Context) {
	h := news.PluginWatchStatus(news.PluginWatchReportPath())
	status := http.StatusOK
	c.JSON(status, gin.H{"success": true, "data": h})
}

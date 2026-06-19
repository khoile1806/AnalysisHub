package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/models"
)

func groupQRadarIOCs(iocs []string) [][]string {
	var batches [][]string
	batchSize := 20

	var current []string
	for _, val := range iocs {
		current = append(current, val)
		if len(current) == batchSize {
			batches = append(batches, current)
			current = nil
		}
	}
	if len(current) > 0 {
		batches = append(batches, current)
	}
	return batches
}

func StreamQRadarAutoHunt(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	aesKey := c.GetString("aesEncryptionKey")

	config, authHeader, err := loadQRadarAuth(db, aesKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	timeRange := c.Query("timeRange")

	var iocModels []models.IOC
	db.Select("value").Find(&iocModels)
	var iocStrings []string
	for _, ioc := range iocModels {
		iocStrings = append(iocStrings, ioc.Value)
	}

	streamQRadarHunts(c, config, authHeader, iocStrings, timeRange)
}

func StreamQRadarFileHunt(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	aesKey := c.GetString("aesEncryptionKey")

	config, authHeader, err := loadQRadarAuth(db, aesKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var req struct {
		IOCs      []string `json:"iocs"`
		TimeRange string   `json:"timeRange"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	streamQRadarHunts(c, config, authHeader, req.IOCs, req.TimeRange)
}

func streamQRadarHunts(c *gin.Context, config models.QRadarConfig, authHeader string, iocs []string, timeRange string) {
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Flush()

	batches := groupQRadarIOCs(iocs)
	totalBatches := len(batches)
	totalHits := 0
	start := time.Now()

	sendSSE := func(event string, data interface{}) {
		b, _ := json.Marshal(data)
		fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", event, string(b))
		c.Writer.Flush()
	}

	for i, batch := range batches {
		query := "SELECT * FROM events WHERE "

		var quoted []string
		for _, val := range batch {
			quoted = append(quoted, fmt.Sprintf(`UTF8(payload) ILIKE '%%%s%%'`, strings.ReplaceAll(val, `'`, `''`)))
		}
		query += strings.Join(quoted, " OR ")

		hits, _, err := qradarSearch(config.URL, authHeader, query, timeRange, 60*time.Second)
		if err != nil {
			sendSSE("error", gin.H{"batch": i + 1, "error": err.Error()})
		} else {
			formattedHits := make([]map[string]interface{}, len(hits))
			for j, h := range hits {
				formattedHits[j] = map[string]interface{}{
					"_id":     fmt.Sprintf("qradar-auto-%d-%d", i, j),
					"_index":  "events",
					"_source": h,
				}
			}
			if len(formattedHits) > 0 {
				totalHits += len(formattedHits)
				sendSSE("hits", gin.H{"hits": formattedHits})
			}
		}

		sendSSE("progress", gin.H{
			"batch":         i + 1,
			"total_batches": totalBatches,
			"bucket":        fmt.Sprintf("batch-%d", i+1),
			"total_hits":    totalHits,
		})

		select {
		case <-c.Request.Context().Done():
			return
		default:
		}
	}

	sendSSE("done", gin.H{
		"total_hits": totalHits,
		"total_iocs": len(iocs),
		"took_ms":    time.Since(start).Milliseconds(),
	})
}

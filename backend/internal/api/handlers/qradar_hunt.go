package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/models"
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

// StreamQRadarFileHunt streams a hunt over a client-supplied IOC list.
//
// POST /api/v1/qradar/hunt/file-stream  (JSON body: {iocs:[]string, timeRange})
// GET  /api/v1/qradar/hunt/file-stream?iocs=<base64-json>&token=<jwt>  (for EventSource)
//
// The GET form accepts the IOC list as a URL-safe base64 JSON payload
// ({"iocs":[{value,type,...}]}) — identical to the ELK file-hunt contract — so
// the frontend can stream directly via EventSource.
func StreamQRadarFileHunt(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	aesKey := c.GetString("aesEncryptionKey")

	config, authHeader, err := loadQRadarAuth(db, aesKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var iocs []string
	var timeRange string

	if c.Request.Method == http.MethodGet {
		raw := c.Query("iocs")
		if raw == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "iocs query parameter is required"})
			return
		}
		decoded, derr := decodeIOCsParam(raw)
		if derr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid iocs param: " + derr.Error()})
			return
		}
		for _, fi := range decoded {
			if v := strings.TrimSpace(fi.Value); v != "" {
				iocs = append(iocs, v)
			}
		}
		timeRange = c.Query("timeRange")
	} else {
		var req struct {
			IOCs      []string `json:"iocs"`
			TimeRange string   `json:"timeRange"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		iocs = req.IOCs
		timeRange = req.TimeRange
	}

	if len(iocs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no IOCs supplied"})
		return
	}

	streamQRadarHunts(c, config, authHeader, iocs, timeRange)
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

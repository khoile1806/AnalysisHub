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

func groupSplunkIOCs(iocs []string) [][]string {
	var batches [][]string
	batchSize := 50

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

func StreamSplunkAutoHunt(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	aesKey := c.GetString("aesEncryptionKey")

	config, authHeader, err := loadSplunkAuth(db, aesKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	timeRange := c.Query("timeRange")
	indices := c.Query("indices")

	var iocModels []models.IOC
	db.Select("value").Find(&iocModels)
	var iocStrings []string
	for _, ioc := range iocModels {
		iocStrings = append(iocStrings, ioc.Value)
	}

	streamSplunkHunts(c, config, authHeader, iocStrings, indices, timeRange)
}

// StreamSplunkFileHunt streams a hunt over a client-supplied IOC list.
//
// POST /api/v1/splunk/hunt/file-stream  (JSON body: {iocs:[]string, indices, timeRange})
// GET  /api/v1/splunk/hunt/file-stream?iocs=<base64-json>&token=<jwt>  (for EventSource)
//
// EventSource cannot send a request body, so the GET form accepts the IOC list
// as a URL-safe base64 JSON payload ({"iocs":[{value,type,...}]}) — identical to
// the ELK file-hunt contract — and uses only the indicator values.
func StreamSplunkFileHunt(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	aesKey := c.GetString("aesEncryptionKey")

	config, authHeader, err := loadSplunkAuth(db, aesKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var iocs []string
	var indices, timeRange string

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
		indices = c.Query("indices")
		timeRange = c.Query("timeRange")
	} else {
		var req struct {
			IOCs      []string `json:"iocs"`
			Indices   string   `json:"indices"`
			TimeRange string   `json:"timeRange"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		iocs = req.IOCs
		indices = req.Indices
		timeRange = req.TimeRange
	}

	if len(iocs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no IOCs supplied"})
		return
	}

	streamSplunkHunts(c, config, authHeader, iocs, indices, timeRange)
}

func streamSplunkHunts(c *gin.Context, config models.SplunkConfig, authHeader string, iocs []string, indices string, timeRange string) {
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Flush()

	batches := groupSplunkIOCs(iocs)
	totalBatches := len(batches)
	totalHits := 0
	start := time.Now()

	sendSSE := func(event string, data interface{}) {
		b, _ := json.Marshal(data)
		fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", event, string(b))
		c.Writer.Flush()
	}

	for i, batch := range batches {
		query := "search "
		if indices != "" && indices != "*" {
			query += fmt.Sprintf("index=%s ", indices)
		}

		var quoted []string
		for _, val := range batch {
			quoted = append(quoted, fmt.Sprintf(`"%s"`, strings.ReplaceAll(val, `"`, `\"`)))
		}
		query += strings.Join(quoted, " OR ")

		hits, _, err := splunkSearch(config.URL, authHeader, query, timeRange, 60*time.Second)
		if err != nil {
			sendSSE("error", gin.H{"batch": i + 1, "error": err.Error()})
		} else {
			formattedHits := make([]map[string]interface{}, len(hits))
			for j, h := range hits {
				formattedHits[j] = map[string]interface{}{
					"_id":     fmt.Sprintf("splunk-auto-%d-%d", i, j),
					"_index":  h["index"],
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

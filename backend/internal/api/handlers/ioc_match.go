package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/analysishub/backend/internal/models"
)

// iocMatchMaxValues caps how many values one match request may carry.
const iocMatchMaxValues = 5000

// MatchIOCs checks a batch of raw values (hashes, IPs, domains, …) against the
// IOC store and returns the ones that are already known indicators. Any scan
// view (Edge Forensics, hunts, OSINT) can call this to highlight hits against
// the organisation's existing IOC database.
//
// POST /api/v1/iocs/match   { "values": ["<sha256>", "1.2.3.4", ...] }
// Response: { "count": N, "matches": { "<lowercased value>": {type, source, description} } }
func MatchIOCs(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}

	var req struct {
		Values []string `json:"values"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	seen := make(map[string]bool, len(req.Values))
	lowered := make([]string, 0, len(req.Values))
	for _, v := range req.Values {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		lowered = append(lowered, v)
		if len(lowered) >= iocMatchMaxValues {
			break
		}
	}

	matches := gin.H{}
	if len(lowered) > 0 {
		var iocs []models.IOC
		// Case-insensitive match so a SHA-256 stored uppercase still hits.
		db.Where("lower(value) IN ?", lowered).Find(&iocs)
		for _, ioc := range iocs {
			matches[strings.ToLower(ioc.Value)] = gin.H{
				"type":        ioc.Type,
				"source":      ioc.Source,
				"description": ioc.Description,
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "count": len(matches), "matches": matches})
}

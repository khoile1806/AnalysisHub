package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/analysishub/backend/internal/models"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// ioc_store.go — CRUD extensions for the IOC store (the `iocs` table managed
// alongside the OpenCTI integration). Complements ListIOCs / CreateManualIOC
// (opencti.go) with delete + bulk import so the dedicated IOC Management page
// can add/remove/import indicators from many sources.

// IOCFacets returns distinct type/source values with counts + the grand total —
// lets the management UI build filter dropdowns + stats WITHOUT pulling rows.
// One aggregate query per facet (GROUP BY) instead of loading the table.
//
// GET /api/v1/iocs/facets
func IOCFacets(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	type kv struct {
		K string
		N int64
	}
	facet := func(col string) []gin.H {
		var rows []kv
		db.Model(&models.IOC{}).
			Select(col + " as k, count(*) as n").
			Where(col + " <> ''").
			Group(col).Order("n desc").Scan(&rows)
		out := make([]gin.H, 0, len(rows))
		for _, r := range rows {
			out = append(out, gin.H{"value": r.K, "count": r.N})
		}
		return out
	}
	var total int64
	db.Model(&models.IOC{}).Count(&total)
	c.JSON(http.StatusOK, gin.H{"total": total, "types": facet("type"), "sources": facet("source")})
}

// DeleteIOC removes one indicator from the store.
//
// DELETE /api/v1/iocs/:id
func DeleteIOC(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	res := db.Delete(&models.IOC{}, id)
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "IOC not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

// BulkCreateIOCs ingests many indicators at once from free-form text and/or an
// explicit list, auto-classifying each (reusing classifyIOC: handles defang,
// URL/email/IP/hash/domain/MAC) and de-duplicating against the store.
//
// POST /api/v1/iocs/bulk   { "text": "...", "values": [...], "source": "Import" }
func BulkCreateIOCs(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)

	var body struct {
		Text   string   `json:"text"`
		Values []string `json:"values"`
		Source string   `json:"source"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	source := strings.TrimSpace(body.Source)
	if source == "" {
		source = "Import"
	}

	// Gather candidate lines from both `text` (split on newlines/commas/semicolons/whitespace) and `values`.
	raw := append([]string{}, body.Values...)
	if strings.TrimSpace(body.Text) != "" {
		raw = append(raw, strings.FieldsFunc(body.Text, func(r rune) bool {
			return r == '\n' || r == '\r' || r == ',' || r == ';' || r == ' ' || r == '\t'
		})...)
	}

	created, skipped, unrecognized := 0, 0, 0
	seen := map[string]bool{}
	for _, line := range raw {
		value, iocType := classifyIOC(line)
		if value == "" || iocType == "" {
			if strings.TrimSpace(line) != "" {
				unrecognized++
			}
			continue
		}
		key := iocType + "|" + value
		if seen[key] {
			continue
		}
		seen[key] = true

		ioc := models.IOC{Value: value, Type: iocType, Source: source}
		res := db.Where("value = ? AND type = ?", value, iocType).FirstOrCreate(&ioc)
		if res.Error != nil {
			continue
		}
		if res.RowsAffected == 0 {
			skipped++ // already existed
		} else {
			created++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"created":      created,
		"skipped":      skipped, // duplicates already in store
		"unrecognized": unrecognized,
	})
}

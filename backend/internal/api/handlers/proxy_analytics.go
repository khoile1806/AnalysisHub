package handlers

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/models"
)

// proxy_analytics.go — aggregate views + export over the persisted flow history.

type hostCount struct {
	Host  string `json:"host"`
	N     int64  `json:"count"`
	Bytes int64  `json:"bytes"`
}

type proxyAgg struct {
	ProxyLabel string  `json:"proxy_label"`
	N          int64   `json:"count"`
	Errors     int64   `json:"errors"`
	BytesIn    int64   `json:"bytes_in"`
	BytesOut   int64   `json:"bytes_out"`
	AvgMs      float64 `json:"avg_ms"`
	P50Ms      float64 `json:"p50_ms"`
	P95Ms      float64 `json:"p95_ms"`
}

// ProxyAnalytics GET /api/v1/system/proxy/analytics?since_hours=24
// Aggregates over the persisted flow window: top hosts, per-proxy totals, status
// distribution, and the leak count — all computed in SQL, no rows shipped.
func ProxyAnalytics(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	since := 24
	if v := c.Query("since_hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			since = n
		}
	}
	cutoff := time.Now().Add(-time.Duration(since) * time.Hour)
	base := func() *gorm.DB {
		return db.Model(&models.ProxyFlow{}).Where("created_at >= ?", cutoff)
	}

	var topHosts []hostCount
	base().Select("host, count(*) as n, coalesce(sum(bytes_in + bytes_out),0) as bytes").
		Group("host").Order("n desc").Limit(15).Scan(&topHosts)

	var perProxy []proxyAgg
	base().Select(`proxy_label,
		count(*) as n,
		coalesce(sum(case when error <> '' or status >= 400 then 1 else 0 end),0) as errors,
		coalesce(sum(bytes_in),0) as bytes_in,
		coalesce(sum(bytes_out),0) as bytes_out,
		coalesce(avg(duration_ms),0) as avg_ms,
		coalesce(percentile_cont(0.5) within group (order by duration_ms),0) as p50_ms,
		coalesce(percentile_cont(0.95) within group (order by duration_ms),0) as p95_ms`).
		Group("proxy_label").Order("n desc").Scan(&perProxy)

	var total, proxied, leaked, loopbackDirect int64
	base().Count(&total)
	base().Where("via_proxy = ?", true).Count(&proxied)
	base().Where("leaked = ?", true).Count(&leaked)
	// Loopback/intended-direct traffic (localhost SIEM, sandbox) is excluded from
	// the coverage denominator — it can never be anonymised, so counting it would
	// understate real anonymity coverage.
	base().Where("via_proxy = ? AND host IN ?", false, []string{"127.0.0.1", "localhost", "::1"}).Count(&loopbackDirect)

	coverage := 100.0
	if den := total - loopbackDirect; den > 0 {
		coverage = float64(proxied) * 100.0 / float64(den)
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"since_hours":  since,
		"total":        total,
		"proxied":      proxied,
		"leaked":       leaked,
		"coverage_pct": coverage,
		"top_hosts":    topHosts,
		"per_proxy":    perProxy,
	}})
}

// ExportProxyFlows GET /api/v1/system/proxy/flows/export?limit=&host=&leaked=
// Streams the persisted flow history as CSV.
func ExportProxyFlows(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	limit := 10000
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 100000 {
			limit = n
		}
	}
	q := db.Model(&models.ProxyFlow{})
	if host := c.Query("host"); host != "" {
		q = q.Where("host ILIKE ?", "%"+host+"%")
	}
	if c.Query("leaked") == "true" {
		q = q.Where("leaked = ?", true)
	}
	var flows []models.ProxyFlow
	q.Order("id desc").Limit(limit).Find(&flows)

	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=proxy-flows-%d.csv", time.Now().Unix()))
	w := csv.NewWriter(c.Writer)
	defer w.Flush()
	_ = w.Write([]string{"time", "proxy", "via_proxy", "leaked", "source", "method", "scheme", "host", "url", "status", "content_type", "tls", "bytes_out", "bytes_in", "duration_ms", "error"})
	for _, f := range flows {
		_ = w.Write([]string{
			f.CreatedAt.Format(time.RFC3339), f.ProxyLabel, strconv.FormatBool(f.ViaProxy),
			strconv.FormatBool(f.Leaked), f.Source, f.Method, f.Scheme, f.Host, f.URL,
			strconv.Itoa(f.Status), f.ContentType, f.TLSVersion,
			strconv.FormatInt(f.BytesOut, 10), strconv.FormatInt(f.BytesIn, 10),
			strconv.FormatInt(f.DurationMs, 10), f.Error,
		})
	}
}

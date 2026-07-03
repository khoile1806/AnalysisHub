package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/egress"
	"github.com/analysishub/backend/internal/models"
)

// proxy_flows.go — records every egress request/response (the "flow") into a
// bounded in-memory ring (live view) and asynchronously into Postgres (history,
// rolling window). The recorder is registered as egress's flow sink at startup.

const (
	flowRingCap    = 2000  // live-view ring size
	flowDBKeep     = 50000 // rolling history retained in Postgres
	flowChanSize   = 4096  // async DB write buffer; overflow is dropped, never blocks egress
	flowPruneEvery = 1000  // prune old rows every N inserts
)

// ProxyFlowRecorder fans a flow into the ring (sync) and the DB writer (async).
type ProxyFlowRecorder struct {
	db   *gorm.DB
	ch   chan models.ProxyFlow
	mu   sync.Mutex
	ring []models.ProxyFlow // oldest first; newest appended at the end
}

// flowRecorder is the process-wide recorder, set by NewProxyFlowRecorder and read
// by the flow API handlers.
var flowRecorder *ProxyFlowRecorder

// NewProxyFlowRecorder builds the recorder and starts its background DB writer.
func NewProxyFlowRecorder(db *gorm.DB) *ProxyFlowRecorder {
	r := &ProxyFlowRecorder{
		db:   db,
		ch:   make(chan models.ProxyFlow, flowChanSize),
		ring: make([]models.ProxyFlow, 0, flowRingCap),
	}
	flowRecorder = r
	go r.writer()
	return r
}

// Sink is registered with egress.SetFlowSink. It must never block the caller
// (an outbound request), so the DB write is best-effort and dropped on overflow.
func (r *ProxyFlowRecorder) Sink(f egress.Flow) {
	rec := models.ProxyFlow{
		CreatedAt:   f.Time,
		ProxyLabel:  f.ProxyLabel,
		ViaProxy:    f.ViaProxy,
		Leaked:      f.Leaked,
		Source:      f.Source,
		Method:      f.Method,
		Scheme:      f.Scheme,
		Host:        f.Host,
		URL:         f.URL,
		Status:      f.Status,
		ContentType: f.ContentType,
		TLSVersion:  f.TLSVersion,
		BytesOut:    f.BytesOut,
		BytesIn:     f.BytesIn,
		DurationMs:  f.DurationMs,
		DNSMs:       f.DNSMs,
		ConnectMs:   f.ConnectMs,
		TLSMs:       f.TLSMs,
		TTFBMs:      f.TTFBMs,
		Error:       f.Error,
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now()
	}

	r.mu.Lock()
	if len(r.ring) >= flowRingCap {
		r.ring = append(r.ring[:0], r.ring[1:]...) // drop oldest
	}
	r.ring = append(r.ring, rec)
	r.mu.Unlock()

	select {
	case r.ch <- rec:
	default: // writer backed up — skip persistence rather than stall egress
	}
}

func (r *ProxyFlowRecorder) writer() {
	n := 0
	for rec := range r.ch {
		rec.ID = 0 // let the DB assign
		if err := r.db.Create(&rec).Error; err != nil {
			continue
		}
		if n++; n%flowPruneEvery == 0 {
			r.prune()
		}
	}
}

// prune keeps only the newest flowDBKeep rows.
func (r *ProxyFlowRecorder) prune() {
	var cutoff models.ProxyFlow
	if err := r.db.Order("id desc").Offset(flowDBKeep).First(&cutoff).Error; err == nil {
		r.db.Where("id <= ?", cutoff.ID).Delete(&models.ProxyFlow{})
	}
}

// recent returns up to limit most-recent flows from the ring, newest first.
func (r *ProxyFlowRecorder) recent(limit int) []models.ProxyFlow {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(r.ring)
	if limit > n {
		limit = n
	}
	out := make([]models.ProxyFlow, 0, limit)
	for i := n - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, r.ring[i])
	}
	return out
}

func (r *ProxyFlowRecorder) clearRing() {
	r.mu.Lock()
	r.ring = r.ring[:0]
	r.mu.Unlock()
}

// GetProxyFlows GET /api/v1/system/proxy/flows?limit=&history=true&host=
// Default: the live ring. history=true reads the persisted rolling window.
func GetProxyFlows(c *gin.Context) {
	limit := 200
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 1000 {
		limit = 1000
	}

	leakedOnly := c.Query("leaked") == "true"

	if c.Query("history") == "true" {
		db, ok := mustGetDB(c)
		if !ok {
			return
		}
		q := db.Model(&models.ProxyFlow{})
		if host := strings.TrimSpace(c.Query("host")); host != "" {
			q = q.Where("host ILIKE ?", "%"+host+"%")
		}
		if leakedOnly {
			q = q.Where("leaked = ?", true)
		}
		var flows []models.ProxyFlow
		q.Order("id desc").Limit(limit).Find(&flows)
		c.JSON(http.StatusOK, gin.H{"success": true, "source": "history", "data": flows})
		return
	}

	if flowRecorder == nil {
		c.JSON(http.StatusOK, gin.H{"success": true, "source": "live", "data": []models.ProxyFlow{}})
		return
	}
	flows := flowRecorder.recent(limit)
	if leakedOnly {
		filtered := flows[:0]
		for _, f := range flows {
			if f.Leaked {
				filtered = append(filtered, f)
			}
		}
		flows = filtered
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "source": "live", "data": flows})
}

// ClearProxyFlows DELETE /api/v1/system/proxy/flows — clears ring + history.
func ClearProxyFlows(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	db.Where("1 = 1").Delete(&models.ProxyFlow{})
	if flowRecorder != nil {
		flowRecorder.clearRing()
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "flows cleared"})
}

// ProxyFlowStats GET /api/v1/system/proxy/flows/stats — quick aggregates over the
// live ring (count, bytes, error rate, per-proxy breakdown).
func ProxyFlowStats(c *gin.Context) {
	if flowRecorder == nil {
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{}})
		return
	}
	flows := flowRecorder.recent(flowRingCap)
	var bytesIn, bytesOut int64
	errs, proxied, direct, leaked := 0, 0, 0, 0
	byProxy := map[string]int{}
	for _, f := range flows {
		bytesIn += f.BytesIn
		bytesOut += f.BytesOut
		if f.Error != "" || f.Status >= 400 {
			errs++
		}
		if f.ViaProxy {
			proxied++
		} else {
			direct++
		}
		if f.Leaked {
			leaked++
		}
		byProxy[f.ProxyLabel]++
	}
	// Anonymity coverage: share of traffic that actually went through a proxy.
	coverage := 100.0
	if n := proxied + direct; n > 0 {
		coverage = float64(proxied) * 100.0 / float64(n)
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"count":        len(flows),
		"bytes_in":     bytesIn,
		"bytes_out":    bytesOut,
		"errors":       errs,
		"proxied":      proxied,
		"direct":       direct,
		"leaked":       leaked,
		"coverage_pct": coverage,
		"by_proxy":     byProxy,
	}})
}

package handlers

import (
	"net"
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

// isLoopbackFlowHost reports whether a flow's host is loopback (localhost SIEM,
// sandbox, etc.) — intentional direct traffic that is never anonymisable and so
// is excluded from the anonymity-coverage denominator.
func isLoopbackFlowHost(h string) bool {
	if h == "" || h == "localhost" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

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
// The ring is a fixed-size circular buffer: writes are O(1) even at the cap,
// since a full ring overwrites the oldest slot in place instead of shifting.
type ProxyFlowRecorder struct {
	db    *gorm.DB
	ch    chan models.ProxyFlow
	mu    sync.Mutex
	ring  []models.ProxyFlow // fixed length flowRingCap
	head  int                // index of the oldest element
	count int                // number of valid elements (0..flowRingCap)

	// Running aggregates over the ring, maintained incrementally on insert/evict
	// so the stats endpoint is O(1) instead of re-scanning the whole ring on every
	// (3-second) poll.
	aggBytesIn, aggBytesOut                                int64
	aggErrs, aggProxied, aggDirect, aggLeaked, aggDirectEx int
	aggByProxy                                             map[string]int
}

// flowAgg is an O(1) snapshot of the ring's running aggregates.
type flowAgg struct {
	count                                         int
	bytesIn, bytesOut                             int64
	errs, proxied, direct, leaked, directExternal int
	byProxy                                       map[string]int
}

// applyStats adds (sign +1) or removes (sign -1) a flow's contribution to the
// running aggregates. Caller holds r.mu.
func (r *ProxyFlowRecorder) applyStats(f models.ProxyFlow, sign int) {
	r.aggBytesIn += int64(sign) * f.BytesIn
	r.aggBytesOut += int64(sign) * f.BytesOut
	if f.Error != "" || f.Status >= 400 {
		r.aggErrs += sign
	}
	if f.ViaProxy {
		r.aggProxied += sign
	} else {
		r.aggDirect += sign
		if !isLoopbackFlowHost(f.Host) {
			r.aggDirectEx += sign
		}
	}
	if f.Leaked {
		r.aggLeaked += sign
	}
	if r.aggByProxy != nil {
		r.aggByProxy[f.ProxyLabel] += sign
		if r.aggByProxy[f.ProxyLabel] <= 0 {
			delete(r.aggByProxy, f.ProxyLabel)
		}
	}
}

// snapshot returns a copy of the running aggregates.
func (r *ProxyFlowRecorder) snapshot() flowAgg {
	r.mu.Lock()
	defer r.mu.Unlock()
	byProxy := make(map[string]int, len(r.aggByProxy))
	for k, v := range r.aggByProxy {
		byProxy[k] = v
	}
	return flowAgg{
		count: r.count, bytesIn: r.aggBytesIn, bytesOut: r.aggBytesOut,
		errs: r.aggErrs, proxied: r.aggProxied, direct: r.aggDirect,
		leaked: r.aggLeaked, directExternal: r.aggDirectEx, byProxy: byProxy,
	}
}

// flowRecorder is the process-wide recorder, set by NewProxyFlowRecorder and read
// by the flow API handlers.
var flowRecorder *ProxyFlowRecorder

// NewProxyFlowRecorder builds the recorder and starts its background DB writer.
func NewProxyFlowRecorder(db *gorm.DB) *ProxyFlowRecorder {
	r := &ProxyFlowRecorder{
		db:         db,
		ch:         make(chan models.ProxyFlow, flowChanSize),
		ring:       make([]models.ProxyFlow, flowRingCap),
		aggByProxy: map[string]int{},
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
	if r.count < flowRingCap {
		r.ring[(r.head+r.count)%flowRingCap] = rec
		r.count++
		r.applyStats(rec, +1)
	} else {
		// Ring full: evict the oldest (subtract its stats), overwrite in place, and
		// advance head — all O(1).
		r.applyStats(r.ring[r.head], -1)
		r.ring[r.head] = rec
		r.head = (r.head + 1) % flowRingCap
		r.applyStats(rec, +1)
	}
	r.mu.Unlock()

	select {
	case r.ch <- rec:
	default: // writer backed up — skip persistence rather than stall egress
	}

	// An anonymity leak (direct while a proxy was expected) fires a throttled
	// out-of-band alert. Non-blocking — the send runs in its own goroutine.
	if rec.Leaked {
		maybeAlertLeak(f)
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
	if limit > r.count {
		limit = r.count
	}
	out := make([]models.ProxyFlow, 0, limit)
	// Walk backwards from the newest element (head+count-1) toward the oldest.
	for i := 0; i < limit; i++ {
		idx := (r.head + r.count - 1 - i) % flowRingCap
		if idx < 0 {
			idx += flowRingCap
		}
		out = append(out, r.ring[idx])
	}
	return out
}

func (r *ProxyFlowRecorder) clearRing() {
	r.mu.Lock()
	r.head, r.count = 0, 0
	r.aggBytesIn, r.aggBytesOut = 0, 0
	r.aggErrs, r.aggProxied, r.aggDirect, r.aggLeaked, r.aggDirectEx = 0, 0, 0, 0, 0
	r.aggByProxy = map[string]int{}
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
	a := flowRecorder.snapshot()
	// Anonymity coverage: share of EXTERNAL traffic that went through a proxy.
	// Loopback/intended-direct is excluded from the denominator.
	coverage := 100.0
	if n := a.proxied + a.directExternal; n > 0 {
		coverage = float64(a.proxied) * 100.0 / float64(n)
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"count":        a.count,
		"bytes_in":     a.bytesIn,
		"bytes_out":    a.bytesOut,
		"errors":       a.errs,
		"proxied":      a.proxied,
		"direct":       a.direct,
		"leaked":       a.leaked,
		"coverage_pct": coverage,
		"by_proxy":     a.byProxy,
	}})
}

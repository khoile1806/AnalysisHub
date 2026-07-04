package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/egress"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/notify"
)

// proxy_extra.go — Proxy Manager extensions: bulk import, test-all, per-profile
// health history, an exit-consistency leak test, plus the outbound leak alerter
// and the background exit-identity drift watcher.

// ─── Leak alerting (#11) ────────────────────────────────────────────────────

var (
	leakNotifier  *notify.Notifier
	leakAlertMu   sync.Mutex
	lastLeakAlert time.Time
	leakThrottle  = 5 * time.Minute
)

// SetLeakNotifier wires the notifier used to alert on anonymity leaks. Called
// once at startup; a nil/disabled notifier makes alerting a no-op.
func SetLeakNotifier(n *notify.Notifier) { leakNotifier = n }

// maybeAlertLeak fires a throttled out-of-band alert when a flow leaked (went
// direct while a proxy was expected). Safe to call from the flow sink — it never
// blocks (the send runs in its own goroutine).
func maybeAlertLeak(f egress.Flow) {
	n := leakNotifier
	if n == nil || !n.Enabled() {
		return
	}
	leakAlertMu.Lock()
	if time.Since(lastLeakAlert) < leakThrottle {
		leakAlertMu.Unlock()
		return
	}
	lastLeakAlert = time.Now()
	leakAlertMu.Unlock()

	host, source := f.Host, f.Source
	go n.Send(context.Background(), "AnalysisHub: anonymity leak detected",
		fmt.Sprintf("A request to %q went DIRECT while a proxy was expected (source: %s). Check the Proxy Manager flow log.", host, source))
}

// ─── Bulk import (#16) ──────────────────────────────────────────────────────

// BulkCreateProxies POST /api/v1/system/proxies/bulk
// Body: {"text": "<one proxy per line, optional 'name url'>", "lane": "osint"}.
func BulkCreateProxies(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	var body struct {
		Text string `json:"text"`
		Lane string `json:"lane"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	lane := laneOf(body.Lane)
	if !validLanes[lane] {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "lane must be default, osint, or vulnscan"})
		return
	}

	created, errs := 0, []string{}
	for _, raw := range strings.Split(body.Text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// "name url" (two+ fields) or just "url"; a name is derived from the host.
		name, rawURL := "", line
		if fields := strings.Fields(line); len(fields) >= 2 && !strings.Contains(fields[0], "://") {
			name = fields[0]
			rawURL = strings.Join(fields[1:], " ")
		}
		normalized, err := normalizeProxyURL(rawURL)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", line, err))
			continue
		}
		if name == "" {
			if u, e := url.Parse(normalized); e == nil {
				name = u.Host
			} else {
				name = normalized
			}
		}
		p := models.ProxyProfile{Name: name, URL: normalized, Lane: lane}
		if err := db.Create(&p).Error; err != nil {
			errs = append(errs, fmt.Sprintf("%s: save failed", line))
			continue
		}
		created++
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"created": created, "errors": errs}})
}

// ─── Test-all (#16) ─────────────────────────────────────────────────────────

// CheckAllProxies POST /api/v1/system/proxies/check-all — probe every profile
// concurrently (bounded) and persist the results.
func CheckAllProxies(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	var profiles []models.ProxyProfile
	db.Find(&profiles)

	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i := range profiles {
		wg.Add(1)
		sem <- struct{}{}
		go func(p *models.ProxyProfile) {
			defer wg.Done()
			defer func() { <-sem }()
			updateProfileHealth(db, p, egress.Probe(p.URL))
		}(&profiles[i])
	}
	wg.Wait()

	for i := range profiles {
		withMask(&profiles[i])
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": profiles})
}

// ─── Health history (#13) ───────────────────────────────────────────────────

// GetProxyHealthHistory GET /api/v1/system/proxies/:id/health-history?hours=24
func GetProxyHealthHistory(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	hours := 24
	if v := c.Query("hours"); v != "" {
		if n, e := strconv.Atoi(v); e == nil && n > 0 && n <= 720 {
			hours = n
		}
	}
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	var samples []models.ProxyHealthSample
	db.Where("profile_id = ? AND created_at >= ?", id, cutoff).
		Order("created_at asc").Limit(2000).Find(&samples)

	var up, total int
	for _, s := range samples {
		total++
		if s.Healthy {
			up++
		}
	}
	uptime := 100.0
	if total > 0 {
		uptime = float64(up) * 100.0 / float64(total)
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"samples": samples, "uptime_pct": uptime, "count": total,
	}})
}

// ─── Exit-consistency leak test (#14) ───────────────────────────────────────

// LeakTestProxy POST /api/v1/system/proxies/:id/leak-test — asks several echo
// services through the proxy what exit IP they see and reports whether they agree.
func LeakTestProxy(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	var p models.ProxyProfile
	if err := db.First(&p, "id = ?", c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "proxy not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": egress.LeakTest(p.URL)})
}

// ─── Exit-identity drift watcher (#12) ──────────────────────────────────────

// quota alerts are throttled per profile name so a proxy that stays over budget
// doesn't spam the operator.
var (
	quotaAlertMu   sync.Mutex
	lastQuotaAlert = map[string]time.Time{}
)

// checkProxyQuotas alerts (throttled, 6h) on any profile whose attributed bytes
// have reached its soft quota. Soft by design — traffic is not blocked, only
// surfaced — so a metered residential proxy doesn't silently run up a bill.
func checkProxyQuotas(db *gorm.DB) {
	n := leakNotifier
	if n == nil || !n.Enabled() {
		return
	}
	var profiles []models.ProxyProfile
	db.Where("quota_bytes > 0").Find(&profiles)
	if len(profiles) == 0 {
		return
	}
	type row struct {
		ProxyLabel string
		Bytes      int64
	}
	var rows []row
	db.Model(&models.ProxyFlow{}).
		Select("proxy_label, coalesce(sum(bytes_in + bytes_out),0) as bytes").
		Group("proxy_label").Scan(&rows)
	usage := map[string]int64{}
	for _, r := range rows {
		usage[r.ProxyLabel] = r.Bytes
	}
	for i := range profiles {
		p := profiles[i]
		used := usage[p.Name]
		if used < p.QuotaBytes {
			continue
		}
		// Hard-stop: auto-deactivate the over-budget profile so it stops spending.
		if p.QuotaHardStop && p.IsActive {
			db.Model(&models.ProxyProfile{}).Where("id = ?", p.ID).Update("is_active", false)
			clearProxyLane(p.Lane)
		}
		quotaAlertMu.Lock()
		if time.Since(lastQuotaAlert[p.Name]) < 6*time.Hour {
			quotaAlertMu.Unlock()
			continue
		}
		lastQuotaAlert[p.Name] = time.Now()
		quotaAlertMu.Unlock()
		verb := "over its"
		if p.QuotaHardStop {
			verb = "auto-deactivated at its"
		}
		go n.Send(context.Background(), "AnalysisHub: proxy quota exceeded",
			fmt.Sprintf("Proxy %q has used %d bytes, %s %d-byte quota.", p.Name, used, verb, p.QuotaBytes))
	}
}

// StartProxyIdentityRefresh periodically re-probes the exit identity of every
// active profile (drift detection) and checks per-proxy data quotas. When a
// profile's exit IP changes unexpectedly it records the drift and fires a
// throttled alert — an early signal that a proxy died and traffic fell back, or
// that the exit rotated under the operator.
func StartProxyIdentityRefresh(db *gorm.DB, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			checkProxyQuotas(db)
			var actives []models.ProxyProfile
			db.Where("is_active = ?", true).Find(&actives)
			for i := range actives {
				p := &actives[i]
				id := egress.ProbeIdentity(p.URL)
				if id.IP == "" {
					continue
				}
				drift := p.ExitIP != "" && id.IP != p.ExitIP
				now := id.CheckedAt
				updates := map[string]interface{}{
					"exit_ip": id.IP, "exit_country": id.Country, "exit_org": id.Org,
					"is_tor": id.IsTor, "exit_checked_at": &now, "identity_drift": drift,
				}
				if drift {
					updates["exit_ip_prev"] = p.ExitIP
					if n := leakNotifier; n != nil && n.Enabled() {
						go n.Send(context.Background(), "AnalysisHub: proxy exit IP changed",
							fmt.Sprintf("Proxy %q exit IP changed from %s to %s.", p.Name, p.ExitIP, id.IP))
					}
				}
				db.Model(&models.ProxyProfile{}).Where("id = ?", p.ID).Updates(updates)
			}
		}
	}()
}

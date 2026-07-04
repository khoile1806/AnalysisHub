package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/config"
	"github.com/analysishub/backend/internal/egress"
	"github.com/analysishub/backend/internal/models"
)

// proxy.go — the "Proxy Manager" pool. CRUD over saved egress proxies plus the
// switch (Activate) that re-points the whole project-wide egress layer at a
// chosen proxy at runtime. Flow recording lives in proxy_flows.go.

type proxyProfilePayload struct {
	Name           string `json:"name"`
	URL            string `json:"url"`
	NoProxy        string `json:"no_proxy"`
	FallbackDirect bool   `json:"fallback_direct"`
	Lane           string `json:"lane"`            // default | osint | vulnscan
	QuotaBytes     int64  `json:"quota_bytes"`     // 0 = unlimited
	QuotaHardStop  bool   `json:"quota_hard_stop"` // auto-deactivate when quota reached
}

// validLanes are the egress lanes a profile may drive.
var validLanes = map[string]bool{"default": true, "osint": true, "vulnscan": true}

// laneOf normalises a profile's lane; empty means the default egress lane.
func laneOf(lane string) string {
	lane = strings.TrimSpace(strings.ToLower(lane))
	if lane == "" {
		return "default"
	}
	return lane
}

// normalizeProxyURL trims and validates a proxy URL (http/https/socks5).
func normalizeProxyURL(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", errors.New("proxy url is required")
	}
	u, err := url.Parse(p)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5") {
		return "", errors.New("proxy URL must be http(s) or socks5")
	}
	return p, nil
}

// withMask fills the display-only MaskedURL so credentials never leave the server.
func withMask(p *models.ProxyProfile) {
	p.MaskedURL = maskProxyURL(p.URL)
}

func requireAdmin(c *gin.Context) bool {
	if middleware.GetRole(c) != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "admin role required"})
		return false
	}
	return true
}

// ApplyActiveProxyProfile points the relevant egress lane at profile. The default
// lane re-points the whole project-wide egress; a named lane (osint / vulnscan)
// only re-routes that traffic class. Shared by Activate and by startup restore.
func ApplyActiveProxyProfile(p models.ProxyProfile) {
	switch laneOf(p.Lane) {
	case "osint", "vulnscan":
		egress.SetLaneProxy(laneOf(p.Lane), p.URL)
	default:
		egress.Set(p.URL, config.EffectiveNoProxy(p.NoProxy), p.FallbackDirect)
		egress.SetActiveLabel(p.Name)
	}
}

// clearProxyLane drops a lane's routing when its active profile is removed.
func clearProxyLane(lane string) {
	switch laneOf(lane) {
	case "osint", "vulnscan":
		egress.SetLaneProxy(laneOf(lane), "")
	default:
		egress.Set("", config.EffectiveNoProxy(""), false)
		egress.SetActiveLabel("direct")
	}
}

// ListProxyProfiles GET /api/v1/system/proxies
func ListProxyProfiles(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	var profiles []models.ProxyProfile
	if err := db.Order("is_active desc, created_at asc").Find(&profiles).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to list proxies"})
		return
	}
	// Quota usage: bytes attributed to each profile's label over the flow window.
	usage := map[string]int64{}
	type row struct {
		ProxyLabel string
		Bytes      int64
	}
	var rows []row
	db.Model(&models.ProxyFlow{}).
		Select("proxy_label, coalesce(sum(bytes_in + bytes_out),0) as bytes").
		Group("proxy_label").Scan(&rows)
	for _, r := range rows {
		usage[r.ProxyLabel] = r.Bytes
	}
	for i := range profiles {
		withMask(&profiles[i])
		profiles[i].QuotaUsedBytes = usage[profiles[i].Name]
		profiles[i].OverQuota = profiles[i].QuotaBytes > 0 && profiles[i].QuotaUsedBytes >= profiles[i].QuotaBytes
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": profiles})
}

// CreateProxyProfile POST /api/v1/system/proxies
func CreateProxyProfile(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	var payload proxyProfilePayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	if strings.TrimSpace(payload.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "name is required"})
		return
	}
	rawURL, err := normalizeProxyURL(payload.URL)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	lane := laneOf(payload.Lane)
	if !validLanes[lane] {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "lane must be default, osint, or vulnscan"})
		return
	}
	p := models.ProxyProfile{
		Name:           strings.TrimSpace(payload.Name),
		URL:            rawURL,
		NoProxy:        strings.TrimSpace(payload.NoProxy),
		FallbackDirect: payload.FallbackDirect,
		Lane:           lane,
		QuotaBytes:     payload.QuotaBytes,
		QuotaHardStop:  payload.QuotaHardStop,
	}
	if err := db.Create(&p).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to save proxy"})
		return
	}
	withMask(&p)
	c.JSON(http.StatusCreated, gin.H{"success": true, "data": p})
}

// UpdateProxyProfile PATCH /api/v1/system/proxies/:id
func UpdateProxyProfile(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	var p models.ProxyProfile
	if err := db.First(&p, "id = ?", c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "proxy not found"})
		return
	}
	var payload proxyProfilePayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	if strings.TrimSpace(payload.Name) != "" {
		p.Name = strings.TrimSpace(payload.Name)
	}
	if strings.TrimSpace(payload.URL) != "" {
		rawURL, err := normalizeProxyURL(payload.URL)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
			return
		}
		p.URL = rawURL
	}
	p.NoProxy = strings.TrimSpace(payload.NoProxy)
	p.FallbackDirect = payload.FallbackDirect
	if payload.Lane != "" {
		lane := laneOf(payload.Lane)
		if !validLanes[lane] {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "lane must be default, osint, or vulnscan"})
			return
		}
		p.Lane = lane
	}
	p.QuotaBytes = payload.QuotaBytes
	p.QuotaHardStop = payload.QuotaHardStop
	if err := db.Save(&p).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to update proxy"})
		return
	}
	// If we just edited the ACTIVE profile, push the change to the live egress.
	if p.IsActive {
		ApplyActiveProxyProfile(p)
		egress.CheckNow()
	}
	withMask(&p)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": p})
}

// DeleteProxyProfile DELETE /api/v1/system/proxies/:id
func DeleteProxyProfile(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	var p models.ProxyProfile
	if err := db.First(&p, "id = ?", c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "proxy not found"})
		return
	}
	if err := db.Delete(&models.ProxyProfile{}, "id = ?", p.ID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to delete proxy"})
		return
	}
	// Deleting the active proxy drops that lane back to direct so we never silently
	// keep routing through a profile the operator just removed.
	if p.IsActive {
		clearProxyLane(p.Lane)
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "proxy deleted"})
}

// ActivateProxyProfile POST /api/v1/system/proxies/:id/activate — the SWITCH.
func ActivateProxyProfile(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	var p models.ProxyProfile
	if err := db.First(&p, "id = ?", c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "proxy not found"})
		return
	}
	// Only one profile per LANE may be active, so activating an osint-lane exit
	// doesn't deactivate the default egress proxy (and vice-versa).
	err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&models.ProxyProfile{}).Where("lane = ? AND id <> ?", laneOf(p.Lane), p.ID).Update("is_active", false).Error; err != nil {
			return err
		}
		return tx.Model(&p).Update("is_active", true).Error
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to activate proxy"})
		return
	}
	p.IsActive = true
	ApplyActiveProxyProfile(p)
	egress.CheckNow()

	// Reflect the fresh health probe back onto the row.
	_, _, _, h := egress.Status()
	updateProfileHealth(db, &p, h)
	withMask(&p)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": p})
}

// DeactivateProxy POST /api/v1/system/proxies/deactivate — switch to direct.
func DeactivateProxy(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	db.Model(&models.ProxyProfile{}).Where("is_active = ?", true).Update("is_active", false)
	egress.Set("", config.EffectiveNoProxy(""), false)
	egress.SetActiveLabel("direct")
	egress.SetLaneProxy("osint", "")
	egress.SetLaneProxy("vulnscan", "")
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "egress set to direct"})
}

// CheckProxyProfile POST /api/v1/system/proxies/:id/check — probe one profile
// WITHOUT activating it, and persist the result.
func CheckProxyProfile(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	var p models.ProxyProfile
	if err := db.First(&p, "id = ?", c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "proxy not found"})
		return
	}
	h := egress.Probe(p.URL)
	updateProfileHealth(db, &p, h)
	withMask(&p)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": p})
}

// CheckProxyIdentity POST /api/v1/system/proxies/:id/identity — discovers the
// exit IP / geo / Tor status the world sees through this proxy, and persists it.
func CheckProxyIdentity(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	var p models.ProxyProfile
	if err := db.First(&p, "id = ?", c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "proxy not found"})
		return
	}
	id := egress.ProbeIdentity(p.URL)
	now := id.CheckedAt
	// Drift: a different exit IP than last seen can mean the proxy died and
	// traffic fell back, or the exit rotated unexpectedly.
	drift := p.ExitIP != "" && id.IP != "" && id.IP != p.ExitIP
	prev := p.ExitIPPrev
	if drift {
		prev = p.ExitIP
	}
	p.ExitIP = id.IP
	p.ExitCountry = id.Country
	p.ExitOrg = id.Org
	p.IsTor = id.IsTor
	p.ExitCheckedAt = &now
	p.ExitIPPrev = prev
	p.IdentityDrift = drift
	db.Model(&p).Updates(map[string]interface{}{
		"exit_ip": p.ExitIP, "exit_country": p.ExitCountry, "exit_org": p.ExitOrg,
		"is_tor": p.IsTor, "exit_checked_at": p.ExitCheckedAt,
		"exit_ip_prev": p.ExitIPPrev, "identity_drift": p.IdentityDrift,
	})
	withMask(&p)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": p, "identity": id, "drift": drift})
}

// updateProfileHealth persists the latest probe result onto a profile row.
func updateProfileHealth(db *gorm.DB, p *models.ProxyProfile, h egress.Health) {
	now := h.LastCheck
	if now.IsZero() {
		now = time.Now()
	}
	p.Healthy = h.Healthy
	p.LatencyMs = h.LatencyMs
	p.LastError = h.Err
	p.LastCheck = &now
	db.Model(p).Updates(map[string]interface{}{
		"healthy":    p.Healthy,
		"latency_ms": p.LatencyMs,
		"last_error": p.LastError,
		"last_check": p.LastCheck,
	})
	// Append a rolling health sample for the per-profile uptime/latency sparkline,
	// and trim anything older than the retention window.
	if p.ID != 0 {
		db.Create(&models.ProxyHealthSample{ProfileID: p.ID, Healthy: h.Healthy, LatencyMs: h.LatencyMs, CreatedAt: now})
		db.Where("profile_id = ? AND created_at < ?", p.ID, now.Add(-7*24*time.Hour)).Delete(&models.ProxyHealthSample{})
	}
}

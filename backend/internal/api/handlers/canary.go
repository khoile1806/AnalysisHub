package handlers

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/api/middleware"
	"github.com/forensichub/backend/internal/config"
	"github.com/forensichub/backend/internal/models"
	"github.com/forensichub/backend/internal/osint"
)

// CanaryHandler manages canary tokens (tracking / honeytoken links) and serves
// the public redirect endpoint that records visitor metadata.
type CanaryHandler struct {
	DB *gorm.DB
}

func NewCanaryHandler(db *gorm.DB) *CanaryHandler {
	return &CanaryHandler{DB: db}
}

// canaryTokenView wraps a token with its fully-qualified public link so the
// frontend can display / copy it without rebuilding the base URL.
type canaryTokenView struct {
	models.CanaryToken
	Link           string `json:"link"`
	UniqueVisitors int    `json:"unique_visitors"`
}

func (h *CanaryHandler) view(c *gin.Context, t models.CanaryToken) canaryTokenView {
	return canaryTokenView{CanaryToken: t, Link: h.canaryBase(c, t) + "/c/" + t.Slug}
}

// canaryBase resolves the public base URL for a token's link, in priority order:
//  1. the token's own BaseURL override,
//  2. the global CANARY_BASE_URL config (a shared front/disposable domain),
//  3. the request-derived server host (last resort — exposes the real host).
// This lets operators keep the real ForensicHub address off the generated link.
func (h *CanaryHandler) canaryBase(c *gin.Context, t models.CanaryToken) string {
	if b := strings.TrimRight(strings.TrimSpace(t.BaseURL), "/"); b != "" {
		return b
	}
	if v, ok := c.Get("config"); ok {
		if cfg, ok := v.(*config.Config); ok && cfg.CanaryBaseURL != "" {
			return strings.TrimRight(cfg.CanaryBaseURL, "/")
		}
	}
	return getServerURL(c)
}

// resolveCaseID validates an optional case_id input. Returns (nil,true) when the
// field is absent/empty, (ptr,true) when it names an existing case, and
// (nil,false) after writing a 400 when it's malformed or unknown.
func (h *CanaryHandler) resolveCaseID(c *gin.Context, raw *string) (*uuid.UUID, bool) {
	if raw == nil || strings.TrimSpace(*raw) == "" {
		return nil, true
	}
	cid, err := uuid.Parse(strings.TrimSpace(*raw))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case_id"})
		return nil, false
	}
	if err := h.DB.First(&models.Case{}, "id = ?", cid).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "case not found"})
		return nil, false
	}
	return &cid, true
}

// ListCanaryTokens returns all tokens, newest first.
// GET /api/v1/canary/tokens
func (h *CanaryHandler) ListCanaryTokens(c *gin.Context) {
	var tokens []models.CanaryToken
	h.DB.Order("created_at desc").Find(&tokens)

	// Unique human visitors per token in ONE grouped query (no N+1). Bots and
	// empty IPs are excluded so the number reflects distinct real people.
	uniq := map[uuid.UUID]int{}
	var rows []struct {
		TokenID uuid.UUID
		Cnt     int
	}
	h.DB.Model(&models.CanaryHit{}).
		Select("token_id, COUNT(DISTINCT ip) as cnt").
		Where("is_bot = ? AND ip <> ''", false).
		Group("token_id").
		Scan(&rows)
	for _, r := range rows {
		uniq[r.TokenID] = r.Cnt
	}

	out := make([]canaryTokenView, 0, len(tokens))
	for _, t := range tokens {
		v := h.view(c, t)
		v.UniqueVisitors = uniq[t.ID]
		out = append(out, v)
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": out})
}

// CreateCanaryToken mints a new tracking link.
// POST /api/v1/canary/tokens
func (h *CanaryHandler) CreateCanaryToken(c *gin.Context) {
	var input struct {
		Name            string `json:"name" binding:"required"`
		TargetURL       string `json:"target_url" binding:"required"`
		Description     string `json:"description"`
		Slug            string  `json:"slug"`     // optional custom slug
		BaseURL         string  `json:"base_url"` // optional per-token link domain
		CaseID          *string `json:"case_id"`  // optional Case to attach to
		CollectDetails  *bool   `json:"collect_details"`
		RequestLocation *bool   `json:"request_location"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	caseID, ok := h.resolveCaseID(c, input.CaseID)
	if !ok {
		return
	}

	// Collection is OPT-IN: default to a transparent 302 (stealth) unless the
	// operator explicitly enables it. RequestLocation implies CollectDetails (the
	// interstitial is what runs the geolocation call).
	collectDetails := input.CollectDetails != nil && *input.CollectDetails
	requestLocation := input.RequestLocation != nil && *input.RequestLocation
	if requestLocation {
		collectDetails = true
	}

	target := normalizeURL(input.TargetURL)
	if !validRedirectTarget(target) {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "target_url must be a valid http(s) URL"})
		return
	}

	baseURL := strings.TrimRight(normalizeURL(input.BaseURL), "/")
	if baseURL != "" && !validRedirectTarget(baseURL) {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "base_url must be a valid http(s) URL"})
		return
	}

	slug := canarySlugify(input.Slug)
	if slug == "" {
		slug = randomSlug()
	}
	// Guarantee uniqueness; regenerate on the (rare) collision for random slugs.
	for i := 0; i < 5; i++ {
		var count int64
		h.DB.Model(&models.CanaryToken{}).Where("slug = ?", slug).Count(&count)
		if count == 0 {
			break
		}
		if input.Slug != "" {
			c.JSON(http.StatusConflict, gin.H{"success": false, "error": "slug already in use"})
			return
		}
		slug = randomSlug()
	}

	var userUUID uuid.UUID
	if v, ok := c.Get("userID"); ok {
		if uid, err := uuid.Parse(v.(string)); err == nil {
			userUUID = uid
		}
	}

	tok := models.CanaryToken{
		Slug:            slug,
		Name:            strings.TrimSpace(input.Name),
		TargetURL:       target,
		BaseURL:         baseURL,
		CaseID:          caseID,
		Description:     strings.TrimSpace(input.Description),
		Active:          true,
		CollectDetails:  collectDetails,
		RequestLocation: requestLocation,
		CreatedBy:       userUUID,
	}
	if err := h.DB.Create(&tok).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to create token"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"success": true, "data": h.view(c, tok)})
}

// bulkCanaryMaxTargets caps how many links one bulk request may mint.
const bulkCanaryMaxTargets = 200

// BulkCreateCanaryTokens mints one token per target URL in a single request.
// Invalid targets are skipped and reported, not fatal — partial success is fine.
// POST /api/v1/canary/tokens/bulk
//
//	{ "targets": ["https://a", "b.com/x"], "name_prefix": "...", "base_url": "...",
//	  "collect_details": false, "request_location": false, "description": "..." }
func (h *CanaryHandler) BulkCreateCanaryTokens(c *gin.Context) {
	var input struct {
		Targets         []string `json:"targets" binding:"required"`
		NamePrefix      string   `json:"name_prefix"`
		BaseURL         string   `json:"base_url"`
		Description     string   `json:"description"`
		CollectDetails  *bool    `json:"collect_details"`
		RequestLocation *bool    `json:"request_location"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	if len(input.Targets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "targets is required"})
		return
	}
	if len(input.Targets) > bulkCanaryMaxTargets {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": fmt.Sprintf("too many targets (max %d)", bulkCanaryMaxTargets)})
		return
	}

	baseURL := strings.TrimRight(normalizeURL(input.BaseURL), "/")
	if baseURL != "" && !validRedirectTarget(baseURL) {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "base_url must be a valid http(s) URL"})
		return
	}

	collectDetails := input.CollectDetails != nil && *input.CollectDetails
	requestLocation := input.RequestLocation != nil && *input.RequestLocation
	if requestLocation {
		collectDetails = true
	}

	var userUUID uuid.UUID
	if v, ok := c.Get("userID"); ok {
		if uid, err := uuid.Parse(v.(string)); err == nil {
			userUUID = uid
		}
	}
	prefix := strings.TrimSpace(input.NamePrefix)

	created := make([]canaryTokenView, 0, len(input.Targets))
	type bulkErr struct {
		Target string `json:"target"`
		Error  string `json:"error"`
	}
	errs := make([]bulkErr, 0)

	for i, raw := range input.Targets {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		target := normalizeURL(line)
		if !validRedirectTarget(target) {
			errs = append(errs, bulkErr{Target: line, Error: "not a valid http(s) URL"})
			continue
		}

		// Unique random slug (retry on the astronomically rare collision).
		slug := randomSlug()
		for j := 0; j < 5; j++ {
			var count int64
			h.DB.Model(&models.CanaryToken{}).Where("slug = ?", slug).Count(&count)
			if count == 0 {
				break
			}
			slug = randomSlug()
		}

		name := prefix
		if name != "" {
			name = fmt.Sprintf("%s #%d", prefix, i+1)
		} else if u, err := url.Parse(target); err == nil && u.Host != "" {
			name = u.Host // default label = target host
		} else {
			name = fmt.Sprintf("canary #%d", i+1)
		}

		tok := models.CanaryToken{
			Slug:            slug,
			Name:            name,
			TargetURL:       target,
			BaseURL:         baseURL,
			Description:     strings.TrimSpace(input.Description),
			Active:          true,
			CollectDetails:  collectDetails,
			RequestLocation: requestLocation,
			CreatedBy:       userUUID,
		}
		if err := h.DB.Create(&tok).Error; err != nil {
			errs = append(errs, bulkErr{Target: line, Error: "failed to create"})
			continue
		}
		created = append(created, h.view(c, tok))
	}

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": gin.H{"created": created, "errors": errs}})
}

// GetCanaryToken returns a single token.
// GET /api/v1/canary/tokens/:id
func (h *CanaryHandler) GetCanaryToken(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid token id"})
		return
	}
	var tok models.CanaryToken
	if err := h.DB.First(&tok, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "token not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": h.view(c, tok)})
}

// UpdateCanaryToken edits a token's mutable fields.
// PATCH /api/v1/canary/tokens/:id
func (h *CanaryHandler) UpdateCanaryToken(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid token id"})
		return
	}
	var tok models.CanaryToken
	if err := h.DB.First(&tok, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "token not found"})
		return
	}
	var input struct {
		Name            *string `json:"name"`
		TargetURL       *string `json:"target_url"`
		BaseURL         *string `json:"base_url"`
		CaseID          *string `json:"case_id"` // "" detaches; a uuid attaches
		Description     *string `json:"description"`
		Active          *bool   `json:"active"`
		CollectDetails  *bool   `json:"collect_details"`
		RequestLocation *bool   `json:"request_location"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	updates := map[string]interface{}{}
	if input.CaseID != nil {
		if strings.TrimSpace(*input.CaseID) == "" {
			updates["case_id"] = nil // detach
		} else {
			cid, ok := h.resolveCaseID(c, input.CaseID)
			if !ok {
				return
			}
			updates["case_id"] = cid
		}
	}
	if input.Name != nil {
		updates["name"] = strings.TrimSpace(*input.Name)
	}
	if input.TargetURL != nil {
		target := normalizeURL(*input.TargetURL)
		if !validRedirectTarget(target) {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "target_url must be a valid http(s) URL"})
			return
		}
		updates["target_url"] = target
	}
	if input.BaseURL != nil {
		base := strings.TrimRight(normalizeURL(*input.BaseURL), "/")
		if base != "" && !validRedirectTarget(base) {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "base_url must be a valid http(s) URL"})
			return
		}
		updates["base_url"] = base
	}
	if input.Description != nil {
		updates["description"] = strings.TrimSpace(*input.Description)
	}
	if input.Active != nil {
		updates["active"] = *input.Active
	}
	if input.CollectDetails != nil {
		updates["collect_details"] = *input.CollectDetails
	}
	if input.RequestLocation != nil {
		updates["request_location"] = *input.RequestLocation
		if *input.RequestLocation {
			updates["collect_details"] = true // GPS prompt needs the interstitial
		}
	}
	if len(updates) > 0 {
		h.DB.Model(&tok).Updates(updates)
	}
	h.DB.First(&tok, "id = ?", id)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": h.view(c, tok)})
}

// DeleteCanaryToken removes a token and all of its recorded hits.
// DELETE /api/v1/canary/tokens/:id
func (h *CanaryHandler) DeleteCanaryToken(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid token id"})
		return
	}
	h.DB.Where("token_id = ?", id).Delete(&models.CanaryHit{})
	h.DB.Delete(&models.CanaryToken{}, "id = ?", id)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// ListCanaryHits returns recorded visits for a token, newest first.
// GET /api/v1/canary/tokens/:id/hits
func (h *CanaryHandler) ListCanaryHits(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid token id"})
		return
	}
	var hits []models.CanaryHit
	h.DB.Where("token_id = ?", id).Order("created_at desc").Limit(1000).Find(&hits)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": hits})
}

// DeleteCanaryHits clears the hit log for a token (keeps the token).
// DELETE /api/v1/canary/tokens/:id/hits
func (h *CanaryHandler) DeleteCanaryHits(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid token id"})
		return
	}
	h.DB.Where("token_id = ?", id).Delete(&models.CanaryHit{})
	h.DB.Model(&models.CanaryToken{}).Where("id = ?", id).Updates(map[string]interface{}{"hit_count": 0, "last_hit_at": nil})
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// ScanCanaryHit pivots a captured visitor IP into a full OSINT investigation
// using the existing engine, inheriting the token's Case when one is attached.
// POST /api/v1/canary/tokens/:id/hits/:hitId/scan
func (h *CanaryHandler) ScanCanaryHit(c *gin.Context) {
	engine, ok := mustGetOsintEngine(c)
	if !ok {
		return
	}
	tokenID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid token id"})
		return
	}
	hitID, err := uuid.Parse(c.Param("hitId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid hit id"})
		return
	}

	var hit models.CanaryHit
	if err := h.DB.First(&hit, "id = ? AND token_id = ?", hitID, tokenID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "hit not found"})
		return
	}

	ip := strings.TrimSpace(hit.IP)
	ttype, err := osint.DetectTargetType(ip)
	if err != nil || ttype != "ip" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "hit has no scannable IP"})
		return
	}
	if err := osint.ValidateTarget(ip, ttype); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	// Inherit the token's case so the pivot lands in the same investigation.
	var tok models.CanaryToken
	h.DB.First(&tok, "id = ?", tokenID)

	userID, _ := middleware.GetUserID(c)
	scan := models.OsintScan{
		Name:       "canary IP: " + ip,
		Target:     ip,
		TargetType: ttype,
		Status:     models.OsintPending,
		Depth:      0,
		CaseID:     tok.CaseID,
		CreatedBy:  userID,
	}
	if err := h.DB.Create(&scan).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to create scan"})
		return
	}
	rootSelf := scan.ID
	h.DB.Model(&scan).Update("root_scan_id", rootSelf)
	scan.RootScanID = &rootSelf

	names := osint.CollectorNamesFor(ttype)
	collectors := make([]models.OsintCollector, len(names))
	for i, n := range names {
		collectors[i] = models.OsintCollector{ScanID: scan.ID, Name: n, Status: models.OsintCollectorPending}
		h.DB.Create(&collectors[i])
	}
	if err := engine.StartScan(&scan, collectors); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": fmt.Sprintf("failed to start scan: %v", err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"success": true, "data": gin.H{"scan_id": scan.ID}})
}

// ServeCanary is the PUBLIC endpoint hit when someone opens the link. It records
// the visitor's request metadata, then either 302-redirects to the token's
// harmless target (transparent mode) or serves a brief JS interstitial that
// gathers rich client data (and optionally precise GPS) before redirecting.
// Mounted without auth so the link works for anyone who clicks it.
// GET /c/:slug
func (h *CanaryHandler) ServeCanary(c *gin.Context) {
	hardenCanaryResponse(c)
	slug := c.Param("slug")
	var tok models.CanaryToken
	if err := h.DB.First(&tok, "slug = ?", slug).Error; err != nil || !tok.Active {
		// Don't reveal whether the slug exists; behave like a normal 404.
		c.String(http.StatusNotFound, "404 page not found")
		return
	}

	ua := c.GetHeader("User-Agent")
	browser, os, device := parseUserAgent(ua)
	hit := models.CanaryHit{
		TokenID:        tok.ID,
		IP:             realClientIP(c),
		ForwardedFor:   c.GetHeader("X-Forwarded-For"),
		RemoteAddr:     c.Request.RemoteAddr,
		UserAgent:      ua,
		Browser:        browser,
		OS:             os,
		DeviceType:     device,
		IsBot:          device == "bot",
		Referer:        c.GetHeader("Referer"),
		AcceptLanguage: c.GetHeader("Accept-Language"),
		// Cloudflare adds CF-IPCountry — an accurate country with no extra lookup.
		CountryCode: cfCountry(c),
		CreatedAt:   time.Now(),
	}
	created := h.DB.Create(&hit).Error == nil
	// Bot/preview hits are stored (for forensics) but DON'T bump the headline
	// counter or trigger a GeoIP lookup — so hit_count reflects real human clicks.
	if created && !hit.IsBot {
		now := time.Now()
		h.DB.Model(&models.CanaryToken{}).Where("id = ?", tok.ID).
			Updates(map[string]interface{}{"hit_count": gorm.Expr("hit_count + 1"), "last_hit_at": now})
		// Enrich GeoIP off the request path so the response stays fast. Route the
		// lookup through the configured egress proxy (OSINT_TOR_PROXY) when set so
		// even this single outbound call doesn't reveal the server's real IP.
		proxyURL := ""
		if v, ok := c.Get("config"); ok {
			if cfg, ok := v.(*config.Config); ok {
				proxyURL = cfg.TorProxy
			}
		}
		go h.enrichGeo(hit.ID, hit.IP, proxyURL)
	}

	// Transparent mode (or if the hit row failed): plain 302, no JS, stealthiest.
	if !tok.CollectDetails || !created {
		c.Redirect(http.StatusFound, tok.TargetURL)
		return
	}

	// Rich mode: serve the interstitial. The page collects client data, POSTs it
	// back to this same URL (POST /c/:slug) keyed by the hit id, then redirects.
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.String(http.StatusOK, canaryInterstitial(tok.TargetURL, hit.ID.String(), tok.RequestLocation))
}

// canaryCollectMaxAge bounds how long after a hit its client data may be posted,
// so the public collect endpoint can't be replayed against old hits.
const canaryCollectMaxAge = 5 * time.Minute

// CollectCanary receives the interstitial's client-side report and merges it into
// the existing hit row. PUBLIC, one-shot: it only fills a hit that belongs to the
// slug's token, is recent, and hasn't been filled yet.
// POST /c/:slug   { "hid": "...", ...client fields... }
func (h *CanaryHandler) CollectCanary(c *gin.Context) {
	hardenCanaryResponse(c)
	slug := c.Param("slug")
	var tok models.CanaryToken
	if err := h.DB.First(&tok, "slug = ?", slug).Error; err != nil {
		c.Status(http.StatusNoContent)
		return
	}

	// Cap the body — the report is small; reject anything abusive.
	raw, err := io.ReadAll(io.LimitReader(c.Request.Body, 64<<10))
	if err != nil {
		c.Status(http.StatusNoContent)
		return
	}

	var p struct {
		HID          string   `json:"hid"`
		GeoLat       *float64 `json:"geo_lat"`
		GeoLon       *float64 `json:"geo_lon"`
		GeoAccuracy  *float64 `json:"geo_accuracy"`
		GeoError     string   `json:"geo_error"`
		Timezone     string   `json:"timezone"`
		Languages    string   `json:"languages"`
		ScreenW      int      `json:"screen_w"`
		ScreenH      int      `json:"screen_h"`
		ViewportW    int      `json:"viewport_w"`
		ViewportH    int      `json:"viewport_h"`
		PixelRatio   float64  `json:"pixel_ratio"`
		Platform     string   `json:"platform"`
		CPUCores     int      `json:"cpu_cores"`
		DeviceMemory float64  `json:"device_memory"`
		GPUVendor    string   `json:"gpu_vendor"`
		GPURenderer  string   `json:"gpu_renderer"`
		ConnType     string   `json:"conn_type"`
		BatteryLevel *float64 `json:"battery_level"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		c.Status(http.StatusNoContent)
		return
	}
	hid, err := uuid.Parse(p.HID)
	if err != nil {
		c.Status(http.StatusNoContent)
		return
	}

	var hit models.CanaryHit
	if err := h.DB.First(&hit, "id = ? AND token_id = ?", hid, tok.ID).Error; err != nil {
		c.Status(http.StatusNoContent)
		return
	}
	// One-shot + recency guard.
	if hit.ClientData != "" || time.Since(hit.CreatedAt) > canaryCollectMaxAge {
		c.Status(http.StatusNoContent)
		return
	}

	h.DB.Model(&models.CanaryHit{}).Where("id = ?", hid).Updates(map[string]interface{}{
		"geo_lat":       p.GeoLat,
		"geo_lon":       p.GeoLon,
		"geo_accuracy":  p.GeoAccuracy,
		"geo_error":     p.GeoError,
		"timezone":      p.Timezone,
		"languages":     p.Languages,
		"screen_w":      p.ScreenW,
		"screen_h":      p.ScreenH,
		"viewport_w":    p.ViewportW,
		"viewport_h":    p.ViewportH,
		"pixel_ratio":   p.PixelRatio,
		"platform":      p.Platform,
		"cpu_cores":     p.CPUCores,
		"device_memory": p.DeviceMemory,
		"gpu_vendor":    p.GPUVendor,
		"gpu_renderer":  p.GPURenderer,
		"conn_type":     p.ConnType,
		"battery_level": p.BatteryLevel,
		"client_data":   string(raw),
	})
	c.Status(http.StatusNoContent)
}

// canaryInterstitial builds the loading page served in rich-collection mode. It
// shows a spinner, runs canaryJS to gather client data (+ optional GPS), POSTs
// the report back to the same URL, then redirects to target. A <noscript>
// meta-refresh still redirects visitors with JS disabled (the hit's server-side
// fields were already recorded).
func canaryInterstitial(target, hid string, askGeo bool) string {
	cfg, _ := json.Marshal(map[string]interface{}{
		"hid":    hid,
		"target": target,
		"geo":    askGeo,
	})
	return `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<meta name="referrer" content="no-referrer">` +
		`<meta name="robots" content="noindex,nofollow">` +
		`<title>Loading…</title>` +
		`<noscript><meta http-equiv="refresh" content="0;url=` + html.EscapeString(target) + `"></noscript>` +
		`<style>html,body{height:100%;margin:0}body{display:flex;align-items:center;justify-content:center;` +
		`background:#0b0f17;color:#9aa4b2;font:14px system-ui,Segoe UI,sans-serif}` +
		`.s{width:28px;height:28px;border:3px solid rgba(255,255,255,.15);border-top-color:#10b981;` +
		`border-radius:50%;animation:r .8s linear infinite}@keyframes r{to{transform:rotate(360deg)}}</style>` +
		`</head><body><div class="s"></div>` +
		`<script>` + canaryJS + `</script>` +
		`<script>__canaryRun(` + string(cfg) + `);</script></body></html>`
}

// canaryJS is the client-side collector embedded in the interstitial. It avoids
// template literals (backticks) so it can live in a Go raw string. Everything is
// best-effort and wrapped in try/catch; the visitor is always redirected.
const canaryJS = `
function __canaryRun(CFG){
  var d = { hid: CFG.hid };
  function go(){ try{ location.replace(CFG.target); }catch(e){ location.href = CFG.target; } }
  function send(){ try{
    var body = JSON.stringify(d);
    if(navigator.sendBeacon){ navigator.sendBeacon(location.pathname, body); }
    else { fetch(location.pathname,{method:'POST',body:body,keepalive:true}); }
  }catch(e){} }
  function finish(){ send(); go(); }
  try{
    var n = navigator, s = screen;
    d.platform = n.platform || '';
    d.languages = (n.languages && n.languages.join) ? n.languages.join(',') : (n.language||'');
    d.cpu_cores = n.hardwareConcurrency || 0;
    d.device_memory = n.deviceMemory || 0;
    d.touch_points = n.maxTouchPoints || 0;
    d.cookies_enabled = !!n.cookieEnabled;
    d.dnt = n.doNotTrack || '';
    d.referrer = document.referrer || '';
    d.screen_w = s.width||0; d.screen_h = s.height||0;
    d.avail_w = s.availWidth||0; d.avail_h = s.availHeight||0;
    d.color_depth = s.colorDepth||0;
    d.viewport_w = window.innerWidth||0; d.viewport_h = window.innerHeight||0;
    d.pixel_ratio = window.devicePixelRatio||0;
    d.timezone = (window.Intl && Intl.DateTimeFormat) ? Intl.DateTimeFormat().resolvedOptions().timeZone : '';
    d.tz_offset = new Date().getTimezoneOffset();
    var c = n.connection || n.mozConnection || n.webkitConnection;
    if(c){ d.conn_type = c.effectiveType||c.type||''; d.downlink = c.downlink||0; d.rtt = c.rtt||0; d.save_data = !!c.saveData; }
    try{
      var cv = document.createElement('canvas');
      var gl = cv.getContext('webgl') || cv.getContext('experimental-webgl');
      if(gl){ var dbg = gl.getExtension('WEBGL_debug_renderer_info');
        if(dbg){ d.gpu_vendor = gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL); d.gpu_renderer = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL); } }
    }catch(e){}
  }catch(e){}
  var timer = setTimeout(finish, CFG.geo ? 12000 : 2000);
  function battery(next){
    try{ if(navigator.getBattery){ navigator.getBattery().then(function(b){ d.battery_level=b.level; d.battery_charging=b.charging; next(); }, next); return; } }catch(e){}
    next();
  }
  function geo(next){
    if(!CFG.geo || !navigator.geolocation){ next(); return; }
    var done=false; function once(){ if(done) return; done=true; next(); }
    try{
      navigator.geolocation.getCurrentPosition(function(p){
        d.geo_lat=p.coords.latitude; d.geo_lon=p.coords.longitude; d.geo_accuracy=p.coords.accuracy;
        d.geo_altitude=p.coords.altitude; d.geo_heading=p.coords.heading; d.geo_speed=p.coords.speed; once();
      }, function(err){ d.geo_error = (err && err.message) ? err.message : 'geolocation failed'; once(); },
      {enableHighAccuracy:true, timeout:10000, maximumAge:0});
    }catch(e){ d.geo_error='geolocation error'; once(); }
    setTimeout(once, 10500);
  }
  battery(function(){ geo(function(){ clearTimeout(timer); finish(); }); });
}
`

// enrichGeo resolves geolocation/network ownership for a recorded hit using
// ip-api.com (free, no key) and writes it back to the row. Best-effort: any
// failure is silently dropped. Private / loopback addresses are skipped. When
// proxyURL is set (OSINT_TOR_PROXY, e.g. socks5://tor:9050) the lookup egresses
// through it so the server's real IP isn't revealed to ip-api.com.
func (h *CanaryHandler) enrichGeo(hitID uuid.UUID, ip, proxyURL string) {
	if ip == "" || isPrivateOrLoopback(ip) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	u := "http://ip-api.com/json/" + url.PathEscape(ip) +
		"?fields=status,country,countryCode,city,isp,as,lat,lon,mobile,proxy,hosting"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return
	}

	// net/http supports socks5:// / http:// proxy URLs natively via Transport.Proxy.
	client := http.DefaultClient
	if proxyURL != "" {
		if pu, perr := url.Parse(proxyURL); perr == nil {
			client = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var r struct {
		Status      string  `json:"status"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		City        string  `json:"city"`
		ISP         string  `json:"isp"`
		AS          string  `json:"as"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		Mobile      bool    `json:"mobile"`
		Proxy       bool    `json:"proxy"`
		Hosting     bool    `json:"hosting"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil || r.Status != "success" {
		return
	}
	updates := map[string]interface{}{
		"country": r.Country,
		"city":    r.City,
		"isp":     r.ISP,
		"asn":     r.AS,
		"lat":     r.Lat,
		"lon":     r.Lon,
		"mobile":  r.Mobile,
		"proxy":   r.Proxy,
		"hosting": r.Hosting,
	}
	// Don't clobber an accurate CF-IPCountry already stored at hit time.
	if r.CountryCode != "" {
		updates["country_code"] = gorm.Expr("COALESCE(NULLIF(country_code, ''), ?)", r.CountryCode)
	}
	h.DB.Model(&models.CanaryHit{}).Where("id = ?", hitID).Updates(updates)
}

// --- helpers -----------------------------------------------------------------

// hardenCanaryResponse normalises response headers on the PUBLIC canary endpoints
// so a click leaks nothing about the operator's infrastructure (anti-reverse-
// tracking) and the link isn't obviously a tracker:
//   - Referrer-Policy: no-referrer  → the redirect destination never sees the
//     canary URL in its Referer logs (hides the operation from the target site).
//   - X-Robots-Tag: noindex,nofollow → crawlers won't index/expose the link.
//   - generic Server + no-store      → don't reveal the Go/gin origin stack or
//     allow shared-cache fingerprinting.
func hardenCanaryResponse(c *gin.Context) {
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("X-Robots-Tag", "noindex, nofollow")
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate")
	c.Header("Server", "nginx")
}

// realClientIP returns the visitor's true IP. Behind Cloudflare the authoritative
// value is CF-Connecting-IP (Cloudflare sets it from the real edge connection and
// strips any client-supplied copy); True-Client-IP is the enterprise equivalent.
// Falls back to gin's X-Forwarded-For-based ClientIP when not fronted by Cloudflare.
func realClientIP(c *gin.Context) string {
	if ip := strings.TrimSpace(c.GetHeader("CF-Connecting-IP")); ip != "" {
		return ip
	}
	if ip := strings.TrimSpace(c.GetHeader("True-Client-IP")); ip != "" {
		return ip
	}
	return c.ClientIP()
}

// cfCountry returns the ISO country code Cloudflare attaches via CF-IPCountry
// (empty / "XX" / "T1" when unknown or Tor). Free, no lookup.
func cfCountry(c *gin.Context) string {
	cc := strings.ToUpper(strings.TrimSpace(c.GetHeader("CF-IPCountry")))
	if cc == "" || cc == "XX" || cc == "T1" {
		return ""
	}
	return cc
}

// normalizeURL trims the input and prepends "https://" when no http(s) scheme is
// present, so operators can paste a bare host/path (e.g. "example.com/page")
// without a 400. Empty input stays empty.
func normalizeURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	low := strings.ToLower(s)
	if !strings.HasPrefix(low, "http://") && !strings.HasPrefix(low, "https://") {
		s = "https://" + s
	}
	return s
}

// validRedirectTarget requires an absolute http(s) URL with a host. The link is
// only a browser-side 302 (no server-side fetch), so this guards against broken
// / non-web schemes rather than SSRF.
func validRedirectTarget(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return u.Host != ""
}

const slugAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// randomSlug returns an unguessable 10-char URL-safe slug.
func randomSlug() string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is unexpected; fall back to a timestamp-derived id.
		return "c" + time.Now().Format("20060102150405")
	}
	for i := range b {
		b[i] = slugAlphabet[int(b[i])%len(slugAlphabet)]
	}
	return string(b)
}

// canarySlugify normalises an operator-supplied custom slug to [a-zA-Z0-9_-].
// Unlike the hunting-scenario slugify it preserves case and returns "" for
// empty input (the caller then generates a random slug).
func canarySlugify(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
	}
	out := b.String()
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

// isPrivateOrLoopback reports whether ip is a private, loopback, or otherwise
// non-routable address that ip-api can't enrich.
func isPrivateOrLoopback(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true
	}
	return parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() || parsed.IsUnspecified()
}

// botUASignatures are lower-case substrings that mark automated visits: link-
// preview unfurlers (chat/social apps that fetch a URL when it's pasted), search
// crawlers, security scanners / mail link-rewriters, and HTTP libraries. These
// generate hits WITHOUT a human clicking, so they must be flagged out.
var botUASignatures = []string{
	"bot", "crawler", "spider", "preview", "scanner", "fetch", "monitor",
	"curl", "wget", "python-requests", "go-http-client", "okhttp", "axios",
	"java/", "libwww", "headlesschrome", "phantomjs", "puppeteer", "playwright",
	// link-preview unfurlers (Slack/Telegram/Facebook/Discord/Twitter/…)
	"facebookexternalhit", "facebot", "slackbot", "slack-imgproxy", "telegrambot",
	"whatsapp", "discordbot", "twitterbot", "linkedinbot", "skypeuripreview",
	"pinterest", "redditbot", "embedly", "viber", "googlebot", "bingbot",
	"applebot", "yandexbot", "duckduckbot", "petalbot", "vkshare", "tumblr",
	// security scanners / mail link protection that pre-fetch links
	"safelinks", "proofpoint", "mimecast", "barracuda", "microsoft-cryptoapi",
	"google-safety", "urlpreview", "metainspector", "bitlybot",
}

// isBotUserAgent reports whether the UA looks like an automated / preview /
// scanner client rather than a human browser. An empty UA is treated as a bot.
func isBotUserAgent(ua string) bool {
	if strings.TrimSpace(ua) == "" {
		return true
	}
	l := strings.ToLower(ua)
	for _, s := range botUASignatures {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// parseUserAgent does a lightweight, dependency-free classification of a
// User-Agent string into (browser, os, deviceType). It is best-effort and only
// covers common clients; the raw UA is always stored alongside.
func parseUserAgent(ua string) (browser, os, device string) {
	l := strings.ToLower(ua)

	// Device / bot first.
	switch {
	case isBotUserAgent(ua):
		device = "bot"
	case strings.Contains(l, "ipad") || strings.Contains(l, "tablet"):
		device = "tablet"
	case strings.Contains(l, "mobile") || strings.Contains(l, "android") || strings.Contains(l, "iphone"):
		device = "mobile"
	default:
		device = "desktop"
	}

	switch {
	case strings.Contains(l, "windows"):
		os = "Windows"
	case strings.Contains(l, "android"):
		os = "Android"
	case strings.Contains(l, "iphone") || strings.Contains(l, "ipad") || strings.Contains(l, "ios"):
		os = "iOS"
	case strings.Contains(l, "mac os") || strings.Contains(l, "macintosh"):
		os = "macOS"
	case strings.Contains(l, "linux"):
		os = "Linux"
	}

	// Browser — order matters (Edge/Chrome both contain "chrome").
	switch {
	case strings.Contains(l, "edg/") || strings.Contains(l, "edge"):
		browser = "Edge"
	case strings.Contains(l, "opr/") || strings.Contains(l, "opera"):
		browser = "Opera"
	case strings.Contains(l, "firefox"):
		browser = "Firefox"
	case strings.Contains(l, "chrome") || strings.Contains(l, "crios"):
		browser = "Chrome"
	case strings.Contains(l, "safari"):
		browser = "Safari"
	}
	return browser, os, device
}

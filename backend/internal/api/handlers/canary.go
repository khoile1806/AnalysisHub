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

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/config"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/notify"
	"github.com/analysishub/backend/internal/osint"
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
	// DownloadURL is the authenticated path to fetch the served artefact for
	// non-link tokens (the real image, or the weaponised document). Empty for
	// "link" tokens and "image" tokens with no uploaded file (blank pixel).
	DownloadURL string `json:"download_url,omitempty"`
}

func (h *CanaryHandler) view(c *gin.Context, t models.CanaryToken) canaryTokenView {
	v := canaryTokenView{CanaryToken: t, Link: h.canaryBase(c, t) + "/c/" + t.Slug}
	if len(t.FileData) > 0 {
		v.DownloadURL = "/api/v1/canary/tokens/" + t.ID.String() + "/file"
	}
	return v
}

// canaryBase resolves the public base URL for a token's link, in priority order:
//  1. the token's own BaseURL override,
//  2. the global CANARY_BASE_URL config (a shared front/disposable domain),
//  3. the request-derived server host (last resort — exposes the real host).
//
// This lets operators keep the real AnalysisHub address off the generated link.
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
		Name            string  `json:"name" binding:"required"`
		Kind            string  `json:"kind"`       // link (default) | image (blank pixel)
		TargetURL       string  `json:"target_url"` // required for kind=link
		Description     string  `json:"description"`
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

	kind := canaryKind(input.Kind)
	if kind == "document" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "document tokens are created via file upload"})
		return
	}

	caseID, ok := h.resolveCaseID(c, input.CaseID)
	if !ok {
		return
	}

	// Collection is OPT-IN: default to a transparent 302 (stealth) unless the
	// operator explicitly enables it. RequestLocation implies CollectDetails (the
	// interstitial is what runs the geolocation call). Only "link" tokens use the
	// interstitial — an image is fetched without a JS context.
	collectDetails := input.CollectDetails != nil && *input.CollectDetails
	requestLocation := input.RequestLocation != nil && *input.RequestLocation
	if requestLocation {
		collectDetails = true
	}
	if kind != "link" {
		collectDetails, requestLocation = false, false
	}

	// A link token must redirect somewhere; an image token's redirect target is
	// optional (it serves a pixel, it doesn't redirect).
	target := normalizeURL(input.TargetURL)
	if kind == "link" {
		if !validRedirectTarget(target) {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "target_url must be a valid http(s) URL"})
			return
		}
	} else if target != "" && !validRedirectTarget(target) {
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
		Kind:            kind,
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

// canaryKind normalises a requested token kind, defaulting to "link".
func canaryKind(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "image":
		return "image"
	case "document", "doc", "docx":
		return "document"
	default:
		return "link"
	}
}

// canaryFileMaxBytes caps an uploaded image / document for a file-based token.
const canaryFileMaxBytes = 12 << 20 // 12 MB

// canaryImageTypes is the set of real-image media types accepted for an image
// token (served back verbatim so the bait displays correctly).
var canaryImageTypes = map[string]bool{
	"image/png": true, "image/jpeg": true, "image/gif": true, "image/webp": true,
	"image/bmp": true, "image/x-icon": true,
}

// CreateCanaryFileToken mints an image or document token from a REAL uploaded
// file. For kind=image the uploaded image is stored and served verbatim at the
// public link (so an embedded bait image renders correctly while every view is
// recorded). For kind=document the uploaded .docx is weaponised with a remote
// beacon image and returned for download; opening it in Word fetches the beacon.
// POST /api/v1/canary/tokens/upload  (multipart/form-data)
//
//	kind=image|document  name=<label>  file=<upload>
//	[slug] [base_url] [case_id] [description]
func (h *CanaryHandler) CreateCanaryFileToken(c *gin.Context) {
	kind := canaryKind(c.PostForm("kind"))
	if kind == "link" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "kind must be image or document for an upload"})
		return
	}
	name := strings.TrimSpace(c.PostForm("name"))
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "name is required"})
		return
	}

	caseIDRaw := c.PostForm("case_id")
	var caseIDPtr *string
	if strings.TrimSpace(caseIDRaw) != "" {
		caseIDPtr = &caseIDRaw
	}
	caseID, ok := h.resolveCaseID(c, caseIDPtr)
	if !ok {
		return
	}

	fileHdr, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "file is required"})
		return
	}
	if fileHdr.Size > canaryFileMaxBytes {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "file exceeds the 12 MB limit"})
		return
	}
	f, err := fileHdr.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "cannot read uploaded file"})
		return
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, canaryFileMaxBytes+1))
	if err != nil || len(raw) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "empty or unreadable file"})
		return
	}

	baseURL := strings.TrimRight(normalizeURL(c.PostForm("base_url")), "/")
	if baseURL != "" && !validRedirectTarget(baseURL) {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "base_url must be a valid http(s) URL"})
		return
	}

	// Mint a unique slug up-front; the document beacon URL needs it before we
	// weaponise the file.
	slug := canarySlugify(c.PostForm("slug"))
	customSlug := slug != ""
	if slug == "" {
		slug = randomSlug()
	}
	for i := 0; i < 5; i++ {
		var count int64
		h.DB.Model(&models.CanaryToken{}).Where("slug = ?", slug).Count(&count)
		if count == 0 {
			break
		}
		if customSlug {
			c.JSON(http.StatusConflict, gin.H{"success": false, "error": "slug already in use"})
			return
		}
		slug = randomSlug()
	}

	var fileData []byte
	var fileMime, fileName string

	switch kind {
	case "image":
		mime := http.DetectContentType(raw)
		if !canaryImageTypes[mime] {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "unsupported image type (use PNG, JPEG, GIF, WebP, BMP or ICO)"})
			return
		}
		fileData = raw
		fileMime = mime
		fileName = sanitizeFileName(fileHdr.Filename)
	case "document":
		if !strings.HasSuffix(strings.ToLower(fileHdr.Filename), ".docx") {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "document tokens currently support .docx (Word) files only"})
			return
		}
		// Build the beacon URL the document will fetch when opened.
		base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
		if base == "" {
			if v, ok := c.Get("config"); ok {
				if cfg, ok := v.(*config.Config); ok && cfg.CanaryBaseURL != "" {
					base = strings.TrimRight(cfg.CanaryBaseURL, "/")
				}
			}
		}
		if base == "" {
			base = getServerURL(c)
		}
		beaconURL := base + "/c/" + slug
		weaponised, werr := weaponizeDocx(raw, beaconURL)
		if werr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": werr.Error()})
			return
		}
		fileData = weaponised
		fileMime = docxContentType
		fileName = sanitizeFileName(fileHdr.Filename)
	}

	var userUUID uuid.UUID
	if v, ok := c.Get("userID"); ok {
		if uid, err := uuid.Parse(v.(string)); err == nil {
			userUUID = uid
		}
	}

	tok := models.CanaryToken{
		Slug:        slug,
		Name:        name,
		Kind:        kind,
		BaseURL:     baseURL,
		CaseID:      caseID,
		Description: strings.TrimSpace(c.PostForm("description")),
		Active:      true,
		FileName:    fileName,
		FileMime:    fileMime,
		FileData:    fileData,
		CreatedBy:   userUUID,
	}
	if err := h.DB.Create(&tok).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to create token"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"success": true, "data": h.view(c, tok)})
}

// DownloadCanaryFile returns the artefact served/distributed for a non-link
// token: the real image for an image token, or the weaponised .docx (as an
// attachment) for a document token.
// GET /api/v1/canary/tokens/:id/file
func (h *CanaryHandler) DownloadCanaryFile(c *gin.Context) {
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
	if len(tok.FileData) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "token has no downloadable file"})
		return
	}
	mime := tok.FileMime
	if mime == "" {
		mime = "application/octet-stream"
	}
	if tok.Kind == "document" {
		fn := tok.FileName
		if fn == "" {
			fn = "document.docx"
		}
		c.Header("Content-Disposition", `attachment; filename="`+fn+`"`)
	}
	c.Data(http.StatusOK, mime, tok.FileData)
}

// sanitizeFileName strips path separators and control characters from an
// uploaded filename so it is safe to echo back in a Content-Disposition header.
func sanitizeFileName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ReplaceAll(name, `\`, "/")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	var b strings.Builder
	for _, r := range name {
		if r < 0x20 || r == '"' {
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	if len(out) > 128 {
		out = out[len(out)-128:]
	}
	return out
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
	h.DB.Where("token_id = ?", id).Delete(&models.CanaryAlert{})
	h.DB.Delete(&models.CanaryToken{}, "id = ?", id)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// ListCanaryAlerts returns recent alerts (newest first) across all tokens, for
// the in-app alert feed/badge. ?unseen=1 limits to unacknowledged alerts.
// GET /api/v1/canary/alerts
func (h *CanaryHandler) ListCanaryAlerts(c *gin.Context) {
	q := h.DB.Order("created_at desc").Limit(200)
	if c.Query("unseen") == "1" {
		q = q.Where("seen = ?", false)
	}
	var alerts []models.CanaryAlert
	q.Find(&alerts)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": alerts})
}

// CountCanaryAlerts returns the number of unseen alerts, for the nav badge.
// GET /api/v1/canary/alerts/count
func (h *CanaryHandler) CountCanaryAlerts(c *gin.Context) {
	var n int64
	h.DB.Model(&models.CanaryAlert{}).Where("seen = ?", false).Count(&n)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"unseen": n}})
}

// MarkCanaryAlertsSeen acknowledges alerts. Body: {"all": true} marks every
// unseen alert; {"ids": ["..."]} marks the given ones. Marking seen also
// recomputes each affected token's denormalised AlertCount.
// POST /api/v1/canary/alerts/seen
func (h *CanaryHandler) MarkCanaryAlertsSeen(c *gin.Context) {
	var input struct {
		All bool        `json:"all"`
		IDs []uuid.UUID `json:"ids"`
	}
	_ = c.ShouldBindJSON(&input)

	q := h.DB.Model(&models.CanaryAlert{}).Where("seen = ?", false)
	if !input.All {
		if len(input.IDs) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "provide ids or all=true"})
			return
		}
		q = q.Where("id IN ?", input.IDs)
	}
	q.Update("seen", true)

	// Recompute AlertCount per token from the surviving unseen alerts so the
	// badge stays consistent (one grouped query, no N+1).
	h.DB.Exec(`UPDATE canary_tokens t SET alert_count = COALESCE(
		(SELECT COUNT(*) FROM canary_alerts a WHERE a.token_id = t.id AND a.seen = false), 0)`)
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
	// Slugs never contain a dot (randomSlug is alnum, canarySlugify drops them),
	// so a trailing ".png"/".docx"/etc. is just a cosmetic extension on an image
	// or document beacon URL — strip it before lookup so /c/<slug>.png resolves.
	slug := c.Param("slug")
	if i := strings.IndexByte(slug, '.'); i >= 0 {
		slug = slug[:i]
	}
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
	// counter, score, alert or trigger a GeoIP lookup — so hit_count reflects real
	// human clicks and alerts aren't noise.
	if created && !hit.IsBot {
		now := time.Now()
		h.DB.Model(&models.CanaryToken{}).Where("id = ?", tok.ID).
			Updates(map[string]interface{}{"hit_count": gorm.Expr("hit_count + 1"), "last_hit_at": now})
		// Enrich + score + alert off the request path so the response stays fast.
		// Route any outbound lookup through the configured egress proxy
		// (OSINT_TOR_PROXY) when set so it doesn't reveal the server's real IP.
		proxyURL := ""
		var notifier *notify.Notifier
		if v, ok := c.Get("config"); ok {
			if cfg, ok := v.(*config.Config); ok {
				proxyURL = cfg.TorProxy
				notifier = notify.New(cfg.NotifyWebhookURL, cfg.NotifyTelegramToken, cfg.NotifyTelegramChat)
			}
		}
		go h.processHit(tok, hit.ID, hit.IP, proxyURL, notifier)
	}

	// Serve the response according to the token kind.
	switch tok.Kind {
	case "image":
		// Real image when one was uploaded; otherwise a 1×1 transparent pixel.
		if len(tok.FileData) > 0 {
			mime := tok.FileMime
			if mime == "" {
				mime = "image/png"
			}
			c.Data(http.StatusOK, mime, tok.FileData)
			return
		}
		serveTransparentPixel(c)
		return
	case "document":
		// The GET is Word fetching the embedded beacon image → serve a pixel.
		serveTransparentPixel(c)
		return
	}

	// kind == "link": transparent mode (or if the hit row failed) → plain 302.
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

// pixelPNG is a 1×1 fully-transparent PNG (the classic invisible web bug),
// served for image tokens with no uploaded image and for document beacons.
var pixelPNG = []byte{
	0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
	0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00,
	0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x62, 0x00, 0x01, 0x00, 0x00,
	0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49,
	0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
}

// serveTransparentPixel writes the 1×1 transparent PNG with no-cache headers so
// every fetch re-hits the server (each open is recorded, none served from cache).
func serveTransparentPixel(c *gin.Context) {
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	c.Header("Pragma", "no-cache")
	c.Data(http.StatusOK, "image/png", pixelPNG)
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

// processHit runs the post-capture pipeline for a human hit, off the request
// path: GeoIP enrichment → risk scoring → alert creation → outbound notify. It
// is deliberately sequential so the alert summary reflects the enriched Geo /
// network-type data rather than racing it.
func (h *CanaryHandler) processHit(tok models.CanaryToken, hitID uuid.UUID, ip, proxyURL string, notifier *notify.Notifier) {
	// 1. Enrich GeoIP / network ownership (fills country/isp/proxy/hosting/…).
	h.enrichGeo(hitID, ip, proxyURL)

	// 2. Reload the enriched hit and score how suspicious the visitor's network is.
	var hit models.CanaryHit
	if err := h.DB.First(&hit, "id = ?", hitID).Error; err != nil {
		return
	}
	severity, flags := h.scoreHit(hit)
	h.DB.Model(&models.CanaryHit{}).Where("id = ?", hitID).Updates(map[string]interface{}{
		"severity":   severity,
		"risk_flags": strings.Join(flags, ", "),
	})

	// 3. Raise a durable, in-app alert (badge + feed) and bump the unseen counter.
	loc := strings.Join(filterEmpty([]string{hit.City, hit.Country}), ", ")
	netInfo := hit.ISP
	if len(flags) > 0 {
		if netInfo != "" {
			netInfo += " · "
		}
		netInfo += strings.Join(flags, ", ")
	}
	summary := strings.TrimSpace(ip)
	if loc != "" {
		summary += " (" + loc + ")"
	}
	if netInfo != "" {
		summary += " — " + netInfo
	}
	title := "Canary '" + tok.Name + "' triggered"

	alert := models.CanaryAlert{
		TokenID:   tok.ID,
		HitID:     hitID,
		TokenName: tok.Name,
		Title:     title,
		Summary:   summary,
		IP:        ip,
		Severity:  severity,
		CreatedAt: time.Now(),
	}
	if err := h.DB.Create(&alert).Error; err == nil {
		h.DB.Model(&models.CanaryToken{}).Where("id = ?", tok.ID).
			Update("alert_count", gorm.Expr("alert_count + 1"))
	}

	// 4. Fan out to external channels (webhook/Telegram), best-effort.
	if notifier != nil && notifier.Enabled() {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		notifier.Send(ctx, title, summary)
	}
}

// scoreHit grades how suspicious a visitor's network is from the data already
// captured/enriched on the hit, returning a severity band and the human-readable
// flags that drove it. It is intentionally cheap (no extra network calls beyond
// the local IOC lookup) so it runs inline on every human hit.
func (h *CanaryHandler) scoreHit(hit models.CanaryHit) (severity string, flags []string) {
	score := 0
	if hit.Proxy {
		score += 2
		flags = append(flags, "VPN/Proxy/Tor")
	}
	if hit.Hosting {
		score += 2
		flags = append(flags, "Datacenter/Hosting")
	}
	// A country disagreement between Cloudflare's edge and the GeoIP provider is a
	// weak tell of relayed / proxied traffic.
	if hit.CountryCode != "" && hit.Country != "" && !countryMatches(hit.CountryCode, hit.Country) {
		score++
		flags = append(flags, "Geo/CF country mismatch")
	}
	if knownLocalIOC(h.DB, hit.IP) {
		score += 3
		flags = append(flags, "KNOWN IOC (local intel)")
	}

	switch {
	case score >= 4:
		severity = "critical"
	case score >= 3:
		severity = "high"
	case score >= 1:
		severity = "medium"
	default:
		severity = "low"
	}
	return severity, flags
}

// knownLocalIOC reports whether ip is already present in AnalysisHub's local IOC
// store (OpenCTI sync + manual entries) — a strong "we already know this is bad"
// signal for a canary visitor.
func knownLocalIOC(db *gorm.DB, ip string) bool {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false
	}
	var n int64
	db.Model(&models.IOC{}).
		Where("type IN ? AND value = ?", []string{"IPv4-Addr", "IPv6-Addr"}, ip).
		Count(&n)
	return n > 0
}

// countryMatches reports whether an ISO country code and a country name plausibly
// refer to the same country. It is a best-effort check for the common cases; an
// unknown code is treated as a match (no false mismatch flag).
func countryMatches(code, name string) bool {
	known := map[string]string{
		"US": "united states", "GB": "united kingdom", "VN": "vietnam", "CN": "china",
		"RU": "russia", "DE": "germany", "FR": "france", "JP": "japan", "KR": "south korea",
		"IN": "india", "BR": "brazil", "CA": "canada", "AU": "australia", "NL": "netherlands",
		"SG": "singapore", "HK": "hong kong", "TW": "taiwan", "ID": "indonesia", "TH": "thailand",
	}
	want, ok := known[strings.ToUpper(strings.TrimSpace(code))]
	if !ok {
		return true // unknown code → don't raise a mismatch flag
	}
	return strings.Contains(strings.ToLower(name), want)
}

// filterEmpty returns the non-empty, trimmed elements of in.
func filterEmpty(in []string) []string {
	out := in[:0]
	for _, s := range in {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	return out
}

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

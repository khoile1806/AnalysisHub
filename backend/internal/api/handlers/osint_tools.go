package handlers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/osint"
)

// docMetaMaxBytes caps an uploaded document for metadata extraction.
const docMetaMaxBytes = 30 << 20 // 30 MB

// EmailPermute generates the standard corporate e-mail patterns for a person at
// a domain and validates each via MX + catch-all detection — the classic
// "find someone's work e-mail" task.
//
// POST /api/v1/osint/email-permute  { "name": "John Doe", "domain": "acme.com" }
func EmailPermute(c *gin.Context) {
	var body struct {
		Name     string `json:"name" binding:"required"`
		Domain   string `json:"domain" binding:"required"`
		Validate *bool  `json:"validate"` // default true
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	cands := osint.GenerateEmailCandidates(body.Name, body.Domain)
	if len(cands) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "could not generate candidates (need a name and a domain)"})
		return
	}
	if body.Validate == nil || *body.Validate {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
		defer cancel()
		cands = osint.ValidateEmailCandidates(ctx, cands)
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"domain":     strings.ToLower(strings.TrimSpace(body.Domain)),
		"candidates": cands,
	}})
}

// ExtractDocMeta recovers the author/tool metadata embedded in an uploaded
// document (DOCX/XLSX/PPTX/PDF) — often de-anonymising who authored an evidence
// file. Native parsing, no AI/provider required.
//
// POST /api/v1/osint/extract-doc-meta  (multipart/form-data: file=<doc>)
func ExtractDocMeta(c *gin.Context) {
	fileHdr, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "file is required"})
		return
	}
	if fileHdr.Size > docMetaMaxBytes {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "file exceeds the 30 MB limit"})
		return
	}
	f, err := fileHdr.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "cannot read uploaded file"})
		return
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, docMetaMaxBytes+1))
	if err != nil || len(raw) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "empty or unreadable file"})
		return
	}

	meta := osint.ParseDocumentMetadata(raw)

	// Offer the discovered author(s) as scannable name candidates.
	candidates := []gin.H{}
	for _, n := range dedupeNonEmpty(meta.Creator, meta.LastModBy) {
		if tt, derr := osint.DetectTargetType(n); derr == nil {
			candidates = append(candidates, gin.H{"value": n, "type": tt})
		}
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"metadata":   meta,
		"candidates": candidates,
	}})
}

// GetOsintIdentity scores how strongly the investigation graph corroborates a
// single identity, with a per-signal breakdown.
//
// GET /api/v1/osint/:id/identity
func GetOsintIdentity(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scan id"})
		return
	}
	var scan models.OsintScan
	if err := db.First(&scan, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "scan not found"})
		return
	}
	root := scan.ID
	if scan.RootScanID != nil {
		root = *scan.RootScanID
	}

	var scanIDs []uuid.UUID
	db.Model(&models.OsintScan{}).Where("root_scan_id = ? OR id = ?", root, root).Pluck("id", &scanIDs)

	var findings []models.OsintFinding
	if len(scanIDs) > 0 {
		db.Where("scan_id IN ?", scanIDs).Find(&findings)
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": osint.ComputeIdentityConfidence(findings)})
}

// ReverseImage returns reverse-image-search deep-links. Two modes:
//   - JSON { "image_url": "https://..." } → URL-prefill engines (Lens/Yandex/Bing/TinEye)
//   - multipart file=<image>             → the avatar's dHash fingerprint (for
//     correlation) + face-search engines to upload into (PimEyes/FaceCheck/Lenso)
//
// Face engines need an upload in their own UI, so for a local file we return the
// fingerprint + those landing pages rather than publicly re-hosting the image.
//
// POST /api/v1/osint/reverse-image
func ReverseImage(c *gin.Context) {
	// Upload mode.
	if fileHdr, err := c.FormFile("image"); err == nil {
		if fileHdr.Size > imageGeoMaxBytes {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "image too large"})
			return
		}
		f, ferr := fileHdr.Open()
		if ferr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "cannot read image"})
			return
		}
		defer f.Close()
		raw, rerr := io.ReadAll(io.LimitReader(f, imageGeoMaxBytes+1))
		if rerr != nil || len(raw) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "empty or unreadable image"})
			return
		}
		hash, ok := osint.DifferenceHash(raw)
		resp := gin.H{
			"face_engines": osint.FaceSearchEngines(),
			"note":         "URL engines (Lens/Yandex/TinEye) need a public URL; for a local file, open the face engines and upload it. The fingerprint links this image to scanned avatars.",
		}
		if ok {
			resp["fingerprint"] = hash
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
		return
	}

	// URL mode.
	var body struct {
		ImageURL string `json:"image_url"`
	}
	_ = c.ShouldBindJSON(&body)
	u := strings.TrimSpace(body.ImageURL)
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "provide an http(s) image_url or upload an image file"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"image_url":    u,
		"engines":      osint.ReverseImageLinks(u),
		"face_engines": osint.FaceSearchEngines(),
	}})
}

func dedupeNonEmpty(vals ...string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" || seen[strings.ToLower(v)] {
			continue
		}
		seen[strings.ToLower(v)] = true
		out = append(out, v)
	}
	return out
}

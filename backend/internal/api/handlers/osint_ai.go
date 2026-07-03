package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	ai "github.com/analysishub/backend/internal/ai"
	"github.com/analysishub/backend/internal/analysis"
	"github.com/analysishub/backend/internal/crypto"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/osint"
)

// TriageOsintScan summarizes an OSINT scan's findings with AI from a defensive
// angle (what the entity is, malicious or not, pivots, DFIR next steps). It
// reuses the shared inference seam (analysis.Chat) and the AI provider config.
//
// POST /api/v1/osint/:id/triage  { "provider_id": "<uuid>" }
func (h *AIHandler) TriageOsintScan(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scan id"})
		return
	}

	var input struct {
		ProviderID string `json:"provider_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	providerID, err := uuid.Parse(input.ProviderID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid provider_id"})
		return
	}
	var provider models.AIProvider
	if err := h.db.First(&provider, "id = ?", providerID).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "provider not found"})
		return
	}
	client, clientErr := h.newDecryptedClient(&provider)
	if clientErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": clientErr.Error()})
		return
	}

	var scan models.OsintScan
	if err := h.db.First(&scan, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "scan not found"})
		return
	}
	var findings []models.OsintFinding
	h.db.Where("scan_id = ?", id).Order("category, severity").Find(&findings)
	if len(findings) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "scan has no findings to triage"})
		return
	}

	text := formatOsintFindings(findings)
	prompt := analysis.BuildOsintTriagePrompt(scan.Target, scan.TargetType, text)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 180*time.Second)
	defer cancel()

	out, usage, aiErr := analysis.Chat(ctx, client, prompt, ai.Options{MaxTokens: provider.MaxTokens})
	if aiErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "AI error: " + aiErr.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"summary": stripThinkBlocks(out),
		"tokens":  usage.Total(),
	}})
}

// -- OCR → pivot (image IOC extraction) ---------------------------------------

// imageExtractMaxBytes caps the uploaded image size. Anthropic's vision API
// accepts images up to ~5 MB once base64-encoded.
const imageExtractMaxBytes = 5 << 20

// allowedImageTypes is the set of media types the vision model accepts.
var allowedImageTypes = map[string]bool{
	"image/png": true, "image/jpeg": true, "image/gif": true, "image/webp": true,
}

// ExtractOsintFromImage runs OCR + indicator extraction on an uploaded image
// (e.g. a ransom note, phishing email screenshot, or chat capture) using a
// Claude vision model, then validates every extracted identifier through the
// OSINT target detector so the UI can launch a footprinting scan for each one in
// a click. It is a pre-processing step: it returns candidates, it does NOT start
// scans itself. Requires an Anthropic (Claude) AI provider since the extraction
// is vision-based.
//
// POST /api/v1/osint/extract-image  (multipart/form-data: image=<file>, provider_id=<uuid>)
func (h *AIHandler) ExtractOsintFromImage(c *gin.Context) {
	providerID, err := uuid.Parse(strings.TrimSpace(c.PostForm("provider_id")))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid or missing provider_id"})
		return
	}
	var provider models.AIProvider
	if err := h.db.First(&provider, "id = ?", providerID).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "provider not found"})
		return
	}
	if provider.ProviderType != "anthropic" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "image extraction requires an Anthropic (Claude) vision provider"})
		return
	}

	fileHdr, err := c.FormFile("image")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "image file is required"})
		return
	}
	if fileHdr.Size > imageExtractMaxBytes {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "image exceeds the 5 MB limit"})
		return
	}
	f, err := fileHdr.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "cannot read uploaded image"})
		return
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, imageExtractMaxBytes+1))
	if err != nil || len(raw) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "empty or unreadable image"})
		return
	}
	mediaType := http.DetectContentType(raw)
	if !allowedImageTypes[mediaType] {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "unsupported image type (use PNG, JPEG, GIF or WebP)"})
		return
	}

	decKey, err := crypto.Decrypt(provider.APIKey, h.cfg.AESEncryptionKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "failed to decrypt provider API key"})
		return
	}
	model := provider.Model
	if strings.TrimSpace(model) == "" {
		model = "claude-opus-4-8"
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 120*time.Second)
	defer cancel()

	rawText, vErr := anthropicVisionExtract(ctx, decKey, model, mediaType, base64.StdEncoding.EncodeToString(raw))
	if vErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "vision extraction failed: " + vErr.Error()})
		return
	}

	ocrText, candidates := parseImageExtraction(rawText)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"ocr_text":   ocrText,
		"candidates": candidates,
	}})
}

// imageCandidate is one validated OSINT target found in an image.
type imageCandidate struct {
	Value string `json:"value"`
	Type  string `json:"type"`
}

// parseImageExtraction pulls the model's JSON ({ocr_text, indicators[]}) out of
// its reply and validates every indicator through the OSINT detector, so only
// real, scannable targets are returned (deduplicated, authoritative type).
func parseImageExtraction(modelReply string) (string, []imageCandidate) {
	var parsed struct {
		OCRText    string `json:"ocr_text"`
		Indicators []struct {
			Value string `json:"value"`
		} `json:"indicators"`
	}
	_ = json.Unmarshal([]byte(ai.ExtractJSON(modelReply)), &parsed)

	seen := map[string]bool{}
	candidates := make([]imageCandidate, 0, len(parsed.Indicators))
	for _, ind := range parsed.Indicators {
		v := strings.TrimSpace(ind.Value)
		if v == "" || seen[strings.ToLower(v)] {
			continue
		}
		ttype, derr := osint.DetectTargetType(v)
		if derr != nil {
			continue
		}
		if osint.ValidateTarget(v, ttype) != nil {
			continue
		}
		seen[strings.ToLower(v)] = true
		candidates = append(candidates, imageCandidate{Value: v, Type: ttype})
	}
	return parsed.OCRText, candidates
}

// anthropicVisionExtract sends a single image + instruction to Anthropic's
// Messages API (non-streaming) and returns the model's text reply. It is a
// contained call so the shared text-only ai.Client seam stays untouched.
func anthropicVisionExtract(ctx context.Context, apiKey, model, mediaType, imgB64 string) (string, error) {
	const instruction = "You are a DFIR OSINT assistant. Read ALL text in this image (OCR) and extract every digital identifier or indicator of compromise it contains: IP addresses, domains, emails, phone numbers, crypto wallet addresses (BTC/ETH), file hashes (MD5/SHA1/SHA256), usernames, and people's full names. " +
		"Respond with ONLY a JSON object, no prose, of the form: {\"ocr_text\": \"<full transcript>\", \"indicators\": [{\"type\": \"ip|domain|email|phone|wallet|hash|username|name\", \"value\": \"...\"}]}. If there are no indicators, return an empty array."

	reqBody := map[string]interface{}{
		"model":      model,
		"max_tokens": 1500,
		"messages": []map[string]interface{}{
			{
				"role": "user",
				"content": []map[string]interface{}{
					{
						"type": "image",
						"source": map[string]string{
							"type":       "base64",
							"media_type": mediaType,
							"data":       imgB64,
						},
					},
					{"type": "text", "text": instruction},
				},
			},
		},
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("anthropic returned %d: %s", resp.StatusCode, truncateStr(string(respBody), 300))
	}

	var parsed struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("decode anthropic response: %w", err)
	}
	var sb strings.Builder
	for _, blk := range parsed.Content {
		if blk.Type == "text" {
			sb.WriteString(blk.Text)
		}
	}
	return sb.String(), nil
}

// truncateStr shortens s to at most n runes for error messages.
func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// formatOsintFindings renders findings as compact lines for the AI prompt,
// bounded by the shared content budget.
func formatOsintFindings(findings []models.OsintFinding) string {
	budget := analysis.EnvIntKB("AI_CONTENT_CAP_KB", 128) * 1024
	var sb strings.Builder
	for _, f := range findings {
		if sb.Len() > budget {
			sb.WriteString("\n... [truncated]\n")
			break
		}
		sev := f.Severity
		if sev == "" {
			sev = "info"
		}
		fmt.Fprintf(&sb, "[%s] %s/%s - %s", strings.ToUpper(sev), f.Source, f.Category, f.Title)
		if f.Value != "" {
			fmt.Fprintf(&sb, ": %s", f.Value)
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

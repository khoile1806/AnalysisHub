package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	ai "github.com/analysishub/backend/internal/ai"
	"github.com/analysishub/backend/internal/analysis"
	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/config"
	"github.com/analysishub/backend/internal/crypto"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/storage"
	"github.com/analysishub/backend/internal/threatintel"
)

// AIHandler groups all AI analysis endpoints.
type AIHandler struct {
	db     *gorm.DB
	store  *storage.LocalStorage
	cfg    *config.Config
	enrich *threatintel.EnrichClient // nil when no threat-intel keys are configured
}

func NewAIHandler(db *gorm.DB, store *storage.LocalStorage, cfg *config.Config, enrich *threatintel.EnrichClient) *AIHandler {
	return &AIHandler{db: db, store: store, cfg: cfg, enrich: enrich}
}

// ──────────────────────────────────────────────────────────────
// Provider CRUD
// ──────────────────────────────────────────────────────────────

// ListProviders GET /api/v1/ai/providers
func (h *AIHandler) ListProviders(c *gin.Context) {
	var providers []models.AIProvider
	h.db.Order("created_at desc").Find(&providers)
	for i := range providers {
		providers[i].HasKey = providers[i].APIKey != ""
		providers[i].APIKey = ""
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": providers})
}

// CreateProvider POST /api/v1/ai/providers
func (h *AIHandler) CreateProvider(c *gin.Context) {
	userID, _ := middleware.GetUserID(c)

	var input struct {
		Name         string `json:"name" binding:"required"`
		ProviderType string `json:"provider_type"`
		BaseURL      string `json:"base_url"`
		APIKey       string `json:"api_key"`
		Model        string `json:"model"`
		MaxTokens    int    `json:"max_tokens"`
		IsActive     *bool  `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	provType := input.ProviderType
	if provType == "" {
		provType = "openai"
	}

	p := models.AIProvider{
		Name:         input.Name,
		ProviderType: provType,
		BaseURL:      input.BaseURL,
		Model:        input.Model,
		MaxTokens:    input.MaxTokens,
		IsActive:     true,
		CreatedBy:    userID,
	}
	if input.IsActive != nil {
		p.IsActive = *input.IsActive
	}
	if input.APIKey != "" {
		enc, err := crypto.Encrypt(input.APIKey, h.cfg.AESEncryptionKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "encryption failed"})
			return
		}
		p.APIKey = enc
	}

	if err := h.db.Create(&p).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to save provider"})
		return
	}

	p.HasKey = p.APIKey != ""
	p.APIKey = ""
	c.JSON(http.StatusCreated, gin.H{"success": true, "data": p})
}

// UpdateProvider PUT /api/v1/ai/providers/:id
func (h *AIHandler) UpdateProvider(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid provider ID"})
		return
	}

	var p models.AIProvider
	if err := h.db.First(&p, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "provider not found"})
		return
	}

	var input struct {
		Name         *string `json:"name"`
		ProviderType *string `json:"provider_type"`
		BaseURL      *string `json:"base_url"`
		APIKey       *string `json:"api_key"`
		Model        *string `json:"model"`
		MaxTokens    *int    `json:"max_tokens"`
		IsActive     *bool   `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	updates := map[string]interface{}{}
	if input.Name != nil {
		updates["name"] = *input.Name
	}
	if input.ProviderType != nil {
		updates["provider_type"] = *input.ProviderType
	}
	if input.BaseURL != nil {
		updates["base_url"] = *input.BaseURL
	}
	if input.Model != nil {
		updates["model"] = *input.Model
	}
	if input.MaxTokens != nil {
		updates["max_tokens"] = *input.MaxTokens
	}
	if input.IsActive != nil {
		updates["is_active"] = *input.IsActive
	}
	if input.APIKey != nil && *input.APIKey != "" {
		enc, err := crypto.Encrypt(*input.APIKey, h.cfg.AESEncryptionKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "encryption failed"})
			return
		}
		updates["api_key"] = enc
	}

	if len(updates) > 0 {
		h.db.Model(&p).Updates(updates)
	}

	h.db.First(&p, "id = ?", id)
	p.HasKey = p.APIKey != ""
	p.APIKey = ""
	c.JSON(http.StatusOK, gin.H{"success": true, "data": p})
}

// DeleteProvider DELETE /api/v1/ai/providers/:id
func (h *AIHandler) DeleteProvider(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid provider ID"})
		return
	}
	h.db.Delete(&models.AIProvider{}, "id = ?", id)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// TestProvider POST /api/v1/ai/providers/:id/test
func (h *AIHandler) TestProvider(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid provider ID"})
		return
	}

	var p models.AIProvider
	if err := h.db.First(&p, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "provider not found"})
		return
	}

	client, decErr := h.newDecryptedClient(&p)
	if decErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": decErr.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	if err := client.TestConnection(ctx); err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Connection successful"})
}

// ──────────────────────────────────────────────────────────────
// Analysis Sessions
// ──────────────────────────────────────────────────────────────

// ListSessions GET /api/v1/ai/sessions
func (h *AIHandler) ListSessions(c *gin.Context) {
	userID, _ := middleware.GetUserID(c)
	var sessions []models.AnalysisSession
	h.db.Preload("Provider").
		Where("created_by = ?", userID).
		Order("created_at desc").
		Find(&sessions)
	// Sanitize provider key from preloaded relation
	for i := range sessions {
		if sessions[i].Provider != nil {
			sessions[i].Provider.APIKey = ""
			sessions[i].Provider.HasKey = true
		}
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": sessions})
}

// GetSession GET /api/v1/ai/sessions/:id
func (h *AIHandler) GetSession(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid session ID"})
		return
	}
	var session models.AnalysisSession
	if err := h.db.Preload("Provider").First(&session, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "session not found"})
		return
	}
	if session.Provider != nil {
		session.Provider.APIKey = ""
		session.Provider.HasKey = true
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": session})
}

// DeleteSession DELETE /api/v1/ai/sessions/:id
func (h *AIHandler) DeleteSession(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid session ID"})
		return
	}
	h.db.Delete(&models.AnalysisSession{}, "id = ?", id)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// CreateSession POST /api/v1/ai/sessions
// Accepts multipart/form-data: provider_id, source_type, source_id, title, file (optional)
func (h *AIHandler) CreateSession(c *gin.Context) {
	userID, _ := middleware.GetUserID(c)

	providerIDStr := c.PostForm("provider_id")
	if providerIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "provider_id is required"})
		return
	}
	providerID, err := uuid.Parse(providerIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid provider_id"})
		return
	}

	sourceType := c.PostForm("source_type")
	if sourceType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "source_type is required"})
		return
	}

	sourceID := c.PostForm("source_id")
	title := c.PostForm("title")

	session := models.AnalysisSession{
		ProviderID: providerID,
		SourceType: sourceType,
		SourceID:   sourceID,
		Title:      title,
		Status:     "pending",
		CreatedBy:  userID,
	}

	// Handle optional file upload
	if fh, ferr := c.FormFile("file"); ferr == nil {
		f, openErr := fh.Open()
		if openErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to open upload"})
			return
		}
		defer f.Close()

		// Temporarily create session to get ID for storage path
		if createErr := h.db.Create(&session).Error; createErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to create session"})
			return
		}

		relPath, saveErr := h.store.SaveAnalysisUpload(session.ID.String(), fh.Filename, f)
		if saveErr != nil {
			log.Printf("[analysis] save upload: %v", saveErr)
		} else {
			session.UploadPath = relPath
			session.UploadName = fh.Filename
			if session.Title == "" {
				session.Title = fh.Filename
			}
			h.db.Model(&session).Updates(map[string]interface{}{
				"upload_path": relPath,
				"upload_name": fh.Filename,
				"title":       session.Title,
			})

			// For offline_report: parse bundle JSON to generate a descriptive title.
			if sourceType == "offline_report" {
				fullPath := h.store.GetAnalysisUploadPath(relPath)
				if rawJSON, rerr := os.ReadFile(fullPath); rerr == nil {
					var meta struct {
						BundleName string `json:"bundle_name"`
						CaseName   string `json:"case_name"`
						Hostname   string `json:"hostname"`
					}
					if json.Unmarshal(rawJSON, &meta) == nil && meta.BundleName != "" {
						// Only override if title is still the raw filename
						if session.Title == "" || session.Title == fh.Filename {
							autoTitle := meta.BundleName
							if meta.CaseName != "" {
								autoTitle = "[" + meta.CaseName + "] " + autoTitle
							}
							if meta.Hostname != "" {
								autoTitle += " @ " + meta.Hostname
							}
							session.Title = autoTitle
							h.db.Model(&session).Update("title", autoTitle)
						}
					}
				}
			}
		}
	} else {
		if createErr := h.db.Create(&session).Error; createErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to create session"})
			return
		}
	}

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": session})
}

// StreamSession GET /api/v1/ai/sessions/:id/stream
// Runs the analysis chain and streams progress + AI tokens as SSE events.
// Events:
//
//	event: step   data: {"id":"...","label":"...","status":"running|done|failed","detail":"..."}
//	event: token  data: {"content":"..."}
//	event: done   data: {}
//	event: error  data: {"message":"..."}
func (h *AIHandler) StreamSession(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid session ID"})
		return
	}

	var session models.AnalysisSession
	if err := h.db.First(&session, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "session not found"})
		return
	}

	// If already done, replay the stored result immediately.
	if session.Status == "done" {
		c.Header("Content-Type", "text/event-stream")
		c.Header("Cache-Control", "no-cache")
		c.Header("Connection", "keep-alive")
		c.Header("X-Accel-Buffering", "no")
		c.Writer.WriteHeader(http.StatusOK)
		// Replay stored steps
		if session.Steps != "" {
			var steps []models.ChainStep
			if jerr := json.Unmarshal([]byte(session.Steps), &steps); jerr == nil {
				for _, s := range steps {
					h.sendStepEvent(c, s)
				}
			}
		}
		// Replay result tokens
		for _, tok := range strings.Split(session.Result, "") {
			if tok != "" {
				h.sendSSE(c, "token", gin.H{"content": tok})
			}
		}
		h.sendSSE(c, "done", gin.H{})
		c.Writer.Flush()
		return
	}

	var provider models.AIProvider
	if err := h.db.First(&provider, "id = ?", session.ProviderID).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "provider not found"})
		return
	}
	aiClient, clientErr := h.newDecryptedClient(&provider)
	if clientErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": clientErr.Error()})
		return
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	c.Writer.WriteHeader(http.StatusOK)
	c.Writer.Flush()

	h.db.Model(&session).Update("status", "running")

	ctx := c.Request.Context()

	// Build chain steps and broadcast them immediately so the client renders
	// the full pipeline before any step starts running.
	steps := h.buildChainSteps(session.SourceType, session.UploadPath)
	h.saveSteps(session.ID, steps)
	h.sendSSE(c, "init", steps) // client renders full chain in pending state

	h.sendLog(c, "info", fmt.Sprintf("Starting analysis — source: %s", session.SourceType))

	// Helper to update and emit a step.
	setStep := func(idx int, status, detail string) {
		steps[idx].Status = status
		steps[idx].Detail = detail
		h.saveSteps(session.ID, steps)
		h.sendStepEvent(c, steps[idx])
	}

	// ── Step: collect ──────────────────────────────────────────
	collectIdx := h.stepIndex(steps, "collect")
	setStep(collectIdx, "running", "reading...")
	h.sendLog(c, "info", fmt.Sprintf("Reading data from source [%s]", session.SourceType))

	pipeline := analysis.NewPipeline(h.db, h.store)
	content, collectErr := pipeline.Collect(analysis.Source{
		Type:       session.SourceType,
		ID:         session.SourceID,
		UploadPath: session.UploadPath,
	})
	if collectErr != nil {
		setStep(collectIdx, "failed", collectErr.Error())
		h.sendLog(c, "warn", "Collection error: "+collectErr.Error())
		h.sendSSE(c, "error", gin.H{"message": collectErr.Error()})
		h.db.Model(&session).Update("status", "failed")
		return
	}
	sizeKB := float64(len(content)) / 1024
	setStep(collectIdx, "done", fmt.Sprintf("%.1f KB", sizeKB))
	h.sendLog(c, "success", fmt.Sprintf("Collected — %.1f KB of data", sizeKB))

	// ── Step: parse_tools (offline reports) ───────────────────
	if ptIdx := h.stepIndex(steps, "parse_tools"); ptIdx >= 0 {
		setStep(ptIdx, "running", "analyzing tool outputs...")
		h.sendLog(c, "info", "Analyzing each tool in the offline report...")
		toolCount := strings.Count(content, "\n--- [")
		setStep(ptIdx, "done", fmt.Sprintf("%d tools", toolCount))
		h.sendLog(c, "success", fmt.Sprintf("Analyzed %d tools", toolCount))
	}

	// ── Step: aggregate (checklist batches) ────────────────────
	if aggIdx := h.stepIndex(steps, "aggregate"); aggIdx >= 0 {
		setStep(aggIdx, "running", "")
		h.sendLog(c, "info", "Aggregating output from checklist batches...")
		setStep(aggIdx, "done", fmt.Sprintf("%.1f KB after aggregation", float64(len(content))/1024))
	}

	// ── Step: extract strings (binary uploads) ─────────────────
	if parseIdx := h.stepIndex(steps, "extract_strings"); parseIdx >= 0 {
		setStep(parseIdx, "running", "")
		h.sendLog(c, "info", "Extracting printable strings from the binary file...")
		extracted := analysis.ExtractStrings(content, 512*1024)
		content = extracted
		setStep(parseIdx, "done", fmt.Sprintf("%.1f KB strings", float64(len(content))/1024))
		h.sendLog(c, "success", fmt.Sprintf("Extracted — %.1f KB of strings", float64(len(content))/1024))
	}

	// ── Step: extract_iocs + enrich (threat intel) ────────────
	var enrichSummary string
	if h.enrich != nil && h.enrich.Configured() {
		iocIdx := h.stepIndex(steps, "extract_iocs")
		setStep(iocIdx, "running", "")
		h.sendLog(c, "info", "Extracting IOCs from data (IP, hash, domain)...")
		iocs := threatintel.ExtractIOCs(content)
		total := iocs.Total()
		if total == 0 {
			setStep(iocIdx, "done", "No suspicious IOCs found")
			h.sendLog(c, "info", "No IOCs extracted — skipping enrichment")
			enrichIdx := h.stepIndex(steps, "enrich")
			setStep(enrichIdx, "done", "Skipped (no IOC)")
		} else {
			detail := fmt.Sprintf("Found %d IOC(s) (%d IP, %d hash, %d domain)",
				total, len(iocs.IPs), len(iocs.Hashes), len(iocs.Domains))
			setStep(iocIdx, "done", detail)
			h.sendLog(c, "success", detail)

			enrichIdx := h.stepIndex(steps, "enrich")
			setStep(enrichIdx, "running", fmt.Sprintf("enriching %d IOC(s)...", total))
			h.sendLog(c, "info", fmt.Sprintf("Enriching threat intel for %d IOC(s) (VT, AbuseIPDB, OTX, Shodan)...", total))

			results := h.enrich.Enrich(ctx, iocs)
			enrichSummary = threatintel.FormatSummary(results)

			threats := 0
			for _, r := range results {
				if r.Threat {
					threats++
				}
			}
			enrichDetail := fmt.Sprintf("%d/%d IOC(s) flagged malicious", threats, len(results))
			setStep(enrichIdx, "done", enrichDetail)
			h.sendLog(c, "success", "Enrichment complete — "+enrichDetail)
		}
	}

	// ── Step: context ──────────────────────────────────────────
	contextIdx := h.stepIndex(steps, "context")
	setStep(contextIdx, "running", "")
	h.sendLog(c, "info", "Building the DFIR forensic prompt...")
	budget := analysis.EnvIntKB("AI_CONTENT_CAP_KB", 128) * 1024
	truncated := false
	if len(content) > budget {
		content = content[:budget]
		truncated = true
	}
	prompt := analysis.BuildDFIRPrompt(session.SourceType, content, enrichSummary, truncated)
	promptKB := float64(len(prompt)) / 1024
	setStep(contextIdx, "done", fmt.Sprintf("%.1f KB prompt", promptKB))
	h.sendLog(c, "success", fmt.Sprintf("Prompt ready — %.1f KB (~%d tokens)", promptKB, int(promptKB*250)))

	// ── Step: analyze ──────────────────────────────────────────
	analyzeIdx := h.stepIndex(steps, "analyze")
	setStep(analyzeIdx, "running", "connecting to AI...")
	h.sendLog(c, "info", fmt.Sprintf("Connecting to %s — model: %s", provider.Name, provider.Model))
	h.sendLog(c, "ai", "Starting to receive tokens from AI...")

	tokenCh := make(chan string, 256)
	var resultBuilder strings.Builder
	aiErrCh := make(chan error, 1)
	usageCh := make(chan ai.Usage, 1)
	var usage ai.Usage
	tokenCount := 0

	go func() {
		msgs := []ai.Message{
			{Role: "user", Content: prompt},
		}
		opts := ai.Options{MaxTokens: provider.MaxTokens}
		u, err := aiClient.StreamChat(ctx, msgs, opts, tokenCh)
		close(tokenCh)
		usageCh <- u
		aiErrCh <- err
	}()

	for tok := range tokenCh {
		resultBuilder.WriteString(tok)
		tokenCount++
		h.sendSSE(c, "token", gin.H{"content": tok})
		// Emit a progress log every ~200 tokens
		if tokenCount == 50 {
			setStep(analyzeIdx, "running", "streaming…")
			h.sendLog(c, "ai", "AI is processing the forensic data...")
		} else if tokenCount%300 == 0 {
			h.sendLog(c, "ai", fmt.Sprintf("Received %d tokens...", tokenCount))
		}
		select {
		case <-ctx.Done():
			goto clientGone
		default:
		}
	}

	if aiErr := <-aiErrCh; aiErr != nil {
		setStep(analyzeIdx, "failed", aiErr.Error())
		h.sendLog(c, "warn", "AI error: "+aiErr.Error())
		h.sendSSE(c, "error", gin.H{"message": aiErr.Error()})
		h.db.Model(&session).Update("status", "failed")
		return
	}
	usage = <-usageCh
	setStep(analyzeIdx, "done", fmt.Sprintf("%d tokens", tokenCount))
	h.sendLog(c, "success", fmt.Sprintf("AI complete — %d tokens received", tokenCount))
	if usage.Total() > 0 {
		h.sendLog(c, "info", fmt.Sprintf("Token usage — input: %d, output: %d", usage.InputTokens, usage.OutputTokens))
	}

	// ── Step: save ─────────────────────────────────────────────
	{
		saveIdx := h.stepIndex(steps, "save")
		setStep(saveIdx, "running", "")
		h.sendLog(c, "info", "Saving the report to the database...")
		// Strip <think>/<thinking> blocks before persisting — reasoning models
		// (DeepSeek-R1, Qwen-thinking, etc.) interleave internal chain-of-thought
		// inside the token stream using these tags. We keep them in liveTokens for
		// the Live Activity panel, but the stored report should contain only the
		// final formatted output.
		cleanResult := stripThinkBlocks(resultBuilder.String())
		wordCount := len(strings.Fields(cleanResult))
		now := time.Now()
		h.db.Model(&session).Updates(map[string]interface{}{
			"status":      "done",
			"result":      cleanResult,
			"finished_at": now,
			"tokens_used": usage.Total(),
		})
		setStep(saveIdx, "done", fmt.Sprintf("%d words", wordCount))
		h.sendLog(c, "success", fmt.Sprintf("Report saved — %d words", wordCount))
	}

	h.sendSSE(c, "done", gin.H{})
	return

clientGone:
	h.db.Model(&session).Update("status", "failed")
}

// ──────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────

// thinkBlockRe matches <think>…</think> and <thinking>…</thinking> blocks
// produced by reasoning models such as DeepSeek-R1 and Qwen-thinking.
var thinkBlockRe = regexp.MustCompile(`(?si)<think(?:ing)?>[\s\S]*?</think(?:ing)?>`)

// stripThinkBlocks removes reasoning-model chain-of-thought sections so that
// only the final formatted answer is stored and displayed to the user.
func stripThinkBlocks(s string) string {
	return strings.TrimSpace(thinkBlockRe.ReplaceAllString(s, ""))
}

func (h *AIHandler) sendSSE(c *gin.Context, event string, data interface{}) {
	payload, _ := json.Marshal(data)
	fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", event, string(payload))
	c.Writer.Flush()
}

func (h *AIHandler) sendStepEvent(c *gin.Context, step models.ChainStep) {
	h.sendSSE(c, "step", step)
}

// sendLog emits a timestamped log entry to the client for the live activity feed.
func (h *AIHandler) sendLog(c *gin.Context, level, message string) {
	h.sendSSE(c, "log", gin.H{
		"ts":      time.Now().Format("15:04:05"),
		"level":   level, // "info" | "success" | "warn" | "ai"
		"message": message,
	})
}

func (h *AIHandler) saveSteps(sessionID uuid.UUID, steps []models.ChainStep) {
	if b, err := json.Marshal(steps); err == nil {
		h.db.Model(&models.AnalysisSession{}).Where("id = ?", sessionID).Update("steps", string(b))
	}
}

func (h *AIHandler) stepIndex(steps []models.ChainStep, id string) int {
	for i, s := range steps {
		if s.ID == id {
			return i
		}
	}
	return -1
}

func (h *AIHandler) buildChainSteps(sourceType, uploadPath string) []models.ChainStep {
	collectLabel := map[string]string{
		"job":            "Read output & artifact",
		"checklist_run":  "Load batches from DB",
		"elk_result":     "Load IOC hit results",
		"upload":         "Receive uploaded file",
		"offline_report": "Read offline agent report",
	}[sourceType]
	if collectLabel == "" {
		collectLabel = "Collect data"
	}

	steps := []models.ChainStep{
		{ID: "collect", Label: collectLabel, Status: "pending"},
	}

	// Offline report: parse tool-by-tool breakdown
	if sourceType == "offline_report" {
		steps = append(steps, models.ChainStep{ID: "parse_tools", Label: "Analyze each tool", Status: "pending"})
	}

	// Binary upload needs strings extraction
	if sourceType == "upload" && uploadPath != "" {
		ext := strings.ToLower(filepath.Ext(uploadPath))
		isBinary := ext == ".raw" || ext == ".dmp" || ext == ".vmem" || ext == ".mem" || ext == ".bin"
		if isBinary {
			steps = append(steps, models.ChainStep{ID: "extract_strings", Label: "Extract strings from binary", Status: "pending"})
		}
	}

	// Aggregate step for checklist runs (many batches)
	if sourceType == "checklist_run" {
		steps = append(steps, models.ChainStep{ID: "aggregate", Label: "Aggregate batch results", Status: "pending"})
	}

	// Threat intel enrichment steps — only shown when keys are configured
	if h.enrich != nil && h.enrich.Configured() {
		steps = append(steps,
			models.ChainStep{ID: "extract_iocs", Label: "Extract IOCs", Status: "pending"},
			models.ChainStep{ID: "enrich", Label: "Enrich Threat Intel", Status: "pending"},
		)
	}

	steps = append(steps,
		models.ChainStep{ID: "context", Label: "Build DFIR prompt", Status: "pending"},
		models.ChainStep{ID: "analyze", Label: "AI analysis", Status: "pending"},
		models.ChainStep{ID: "save", Label: "Save report", Status: "pending"},
	)
	return steps
}

// newDecryptedClient decrypts the provider API key and returns an ai.Client.
func (h *AIHandler) newDecryptedClient(p *models.AIProvider) (ai.Client, error) {
	if p.APIKey == "" {
		return nil, fmt.Errorf("provider %q has no API key configured", p.Name)
	}
	decKey, err := crypto.Decrypt(p.APIKey, h.cfg.AESEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt API key: %w", err)
	}
	client, err := ai.NewClient(p, decKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AI client: %w", err)
	}
	return client, nil
}

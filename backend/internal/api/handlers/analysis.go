package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	ai "github.com/forensichub/backend/internal/ai"
	"github.com/forensichub/backend/internal/api/middleware"
	"github.com/forensichub/backend/internal/config"
	"github.com/forensichub/backend/internal/crypto"
	"github.com/forensichub/backend/internal/models"
	"github.com/forensichub/backend/internal/storage"
	"github.com/forensichub/backend/internal/threatintel"
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

	h.sendLog(c, "info", fmt.Sprintf("Bắt đầu phân tích — nguồn: %s", session.SourceType))

	// Helper to update and emit a step.
	setStep := func(idx int, status, detail string) {
		steps[idx].Status = status
		steps[idx].Detail = detail
		h.saveSteps(session.ID, steps)
		h.sendStepEvent(c, steps[idx])
	}

	// ── Step: collect ──────────────────────────────────────────
	collectIdx := h.stepIndex(steps, "collect")
	setStep(collectIdx, "running", "đang đọc...")
	h.sendLog(c, "info", fmt.Sprintf("Đọc dữ liệu từ nguồn [%s]", session.SourceType))

	content, collectErr := h.collectData(ctx, &session)
	if collectErr != nil {
		setStep(collectIdx, "failed", collectErr.Error())
		h.sendLog(c, "warn", "Lỗi thu thập: "+collectErr.Error())
		h.sendSSE(c, "error", gin.H{"message": collectErr.Error()})
		h.db.Model(&session).Update("status", "failed")
		return
	}
	sizeKB := float64(len(content)) / 1024
	setStep(collectIdx, "done", fmt.Sprintf("%.1f KB", sizeKB))
	h.sendLog(c, "success", fmt.Sprintf("Thu thập xong — %.1f KB dữ liệu", sizeKB))

	// ── Step: parse_tools (offline reports) ───────────────────
	if ptIdx := h.stepIndex(steps, "parse_tools"); ptIdx >= 0 {
		setStep(ptIdx, "running", "đang phân tích tool outputs...")
		h.sendLog(c, "info", "Phân tích từng tool trong báo cáo offline...")
		toolCount := strings.Count(content, "\n--- [")
		setStep(ptIdx, "done", fmt.Sprintf("%d tools", toolCount))
		h.sendLog(c, "success", fmt.Sprintf("Phân tích xong %d tools", toolCount))
	}

	// ── Step: aggregate (checklist batches) ────────────────────
	if aggIdx := h.stepIndex(steps, "aggregate"); aggIdx >= 0 {
		setStep(aggIdx, "running", "")
		h.sendLog(c, "info", "Gộp output từ các checklist batches...")
		setStep(aggIdx, "done", fmt.Sprintf("%.1f KB sau gộp", float64(len(content))/1024))
	}

	// ── Step: extract strings (binary uploads) ─────────────────
	if parseIdx := h.stepIndex(steps, "extract_strings"); parseIdx >= 0 {
		setStep(parseIdx, "running", "")
		h.sendLog(c, "info", "Trích xuất printable strings từ binary file...")
		extracted := extractStrings(content, 512*1024)
		content = extracted
		setStep(parseIdx, "done", fmt.Sprintf("%.1f KB strings", float64(len(content))/1024))
		h.sendLog(c, "success", fmt.Sprintf("Trích xuất xong — %.1f KB strings", float64(len(content))/1024))
	}

	// ── Step: extract_iocs + enrich (threat intel) ────────────
	var enrichSummary string
	if h.enrich != nil && h.enrich.Configured() {
		iocIdx := h.stepIndex(steps, "extract_iocs")
		setStep(iocIdx, "running", "")
		h.sendLog(c, "info", "Trích xuất IOC từ dữ liệu (IP, hash, domain)...")
		iocs := threatintel.ExtractIOCs(content)
		total := iocs.Total()
		if total == 0 {
			setStep(iocIdx, "done", "Không phát hiện IOC đáng ngờ")
			h.sendLog(c, "info", "Không có IOC nào được trích xuất — bỏ qua bước tra cứu")
			enrichIdx := h.stepIndex(steps, "enrich")
			setStep(enrichIdx, "done", "Bỏ qua (không có IOC)")
		} else {
			detail := fmt.Sprintf("Tìm thấy %d IOC (%d IP, %d hash, %d domain)",
				total, len(iocs.IPs), len(iocs.Hashes), len(iocs.Domains))
			setStep(iocIdx, "done", detail)
			h.sendLog(c, "success", detail)

			enrichIdx := h.stepIndex(steps, "enrich")
			setStep(enrichIdx, "running", fmt.Sprintf("đang tra cứu %d IOC...", total))
			h.sendLog(c, "info", fmt.Sprintf("Tra cứu threat intel cho %d IOC (VT, AbuseIPDB, OTX, Shodan)...", total))

			results := h.enrich.Enrich(ctx, iocs)
			enrichSummary = threatintel.FormatSummary(results)

			threats := 0
			for _, r := range results {
				if r.Threat {
					threats++
				}
			}
			enrichDetail := fmt.Sprintf("%d/%d IOC có dấu hiệu độc hại", threats, len(results))
			setStep(enrichIdx, "done", enrichDetail)
			h.sendLog(c, "success", "Tra cứu hoàn tất — "+enrichDetail)
		}
	}

	// ── Step: context ──────────────────────────────────────────
	contextIdx := h.stepIndex(steps, "context")
	setStep(contextIdx, "running", "")
	h.sendLog(c, "info", "Xây dựng DFIR forensic prompt...")
	prompt := h.buildPrompt(&session, content, enrichSummary)
	promptKB := float64(len(prompt)) / 1024
	setStep(contextIdx, "done", fmt.Sprintf("%.1f KB prompt", promptKB))
	h.sendLog(c, "success", fmt.Sprintf("Prompt sẵn sàng — %.1f KB (~%d tokens)", promptKB, int(promptKB*250)))

	// ── Step: analyze ──────────────────────────────────────────
	analyzeIdx := h.stepIndex(steps, "analyze")
	setStep(analyzeIdx, "running", "kết nối AI...")
	h.sendLog(c, "info", fmt.Sprintf("Kết nối tới %s — model: %s", provider.Name, provider.Model))
	h.sendLog(c, "ai", "Bắt đầu nhận tokens từ AI...")

	tokenCh := make(chan string, 256)
	var resultBuilder strings.Builder
	aiErrCh := make(chan error, 1)
	tokenCount := 0

	go func() {
		msgs := []ai.Message{
			{Role: "user", Content: prompt},
		}
		opts := ai.Options{MaxTokens: provider.MaxTokens}
		aiErrCh <- aiClient.StreamChat(ctx, msgs, opts, tokenCh)
		close(tokenCh)
	}()

	for tok := range tokenCh {
		resultBuilder.WriteString(tok)
		tokenCount++
		h.sendSSE(c, "token", gin.H{"content": tok})
		// Emit a progress log every ~200 tokens
		if tokenCount == 50 {
			setStep(analyzeIdx, "running", "streaming…")
			h.sendLog(c, "ai", "AI đang xử lý dữ liệu forensic...")
		} else if tokenCount%300 == 0 {
			h.sendLog(c, "ai", fmt.Sprintf("Đã nhận %d tokens...", tokenCount))
		}
		select {
		case <-ctx.Done():
			goto clientGone
		default:
		}
	}

	if aiErr := <-aiErrCh; aiErr != nil {
		setStep(analyzeIdx, "failed", aiErr.Error())
		h.sendLog(c, "warn", "Lỗi AI: "+aiErr.Error())
		h.sendSSE(c, "error", gin.H{"message": aiErr.Error()})
		h.db.Model(&session).Update("status", "failed")
		return
	}
	setStep(analyzeIdx, "done", fmt.Sprintf("%d tokens", tokenCount))
	h.sendLog(c, "success", fmt.Sprintf("AI hoàn thành — %d tokens nhận được", tokenCount))

	// ── Step: save ─────────────────────────────────────────────
	{
		saveIdx := h.stepIndex(steps, "save")
		setStep(saveIdx, "running", "")
		h.sendLog(c, "info", "Lưu báo cáo vào database...")
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
		})
		setStep(saveIdx, "done", fmt.Sprintf("%d words", wordCount))
		h.sendLog(c, "success", fmt.Sprintf("Báo cáo đã lưu — %d words", wordCount))
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
		"job":            "Đọc output & artifact",
		"checklist_run":  "Tải batches từ DB",
		"elk_result":     "Tải IOC hit results",
		"upload":         "Nhận file upload",
		"offline_report": "Đọc báo cáo offline agent",
	}[sourceType]
	if collectLabel == "" {
		collectLabel = "Thu thập dữ liệu"
	}

	steps := []models.ChainStep{
		{ID: "collect", Label: collectLabel, Status: "pending"},
	}

	// Offline report: parse tool-by-tool breakdown
	if sourceType == "offline_report" {
		steps = append(steps, models.ChainStep{ID: "parse_tools", Label: "Phân tích từng tool", Status: "pending"})
	}

	// Binary upload needs strings extraction
	if sourceType == "upload" && uploadPath != "" {
		ext := strings.ToLower(filepath.Ext(uploadPath))
		isBinary := ext == ".raw" || ext == ".dmp" || ext == ".vmem" || ext == ".mem" || ext == ".bin"
		if isBinary {
			steps = append(steps, models.ChainStep{ID: "extract_strings", Label: "Trích xuất strings từ binary", Status: "pending"})
		}
	}

	// Aggregate step for checklist runs (many batches)
	if sourceType == "checklist_run" {
		steps = append(steps, models.ChainStep{ID: "aggregate", Label: "Gộp kết quả batches", Status: "pending"})
	}

	// Threat intel enrichment steps — only shown when keys are configured
	if h.enrich != nil && h.enrich.Configured() {
		steps = append(steps,
			models.ChainStep{ID: "extract_iocs", Label: "Trích xuất IOC",       Status: "pending"},
			models.ChainStep{ID: "enrich",        Label: "Tra cứu Threat Intel", Status: "pending"},
		)
	}

	steps = append(steps,
		models.ChainStep{ID: "context",  Label: "Xây dựng DFIR prompt",   Status: "pending"},
		models.ChainStep{ID: "analyze",  Label: "AI phân tích",            Status: "pending"},
		models.ChainStep{ID: "save",     Label: "Lưu báo cáo",             Status: "pending"},
	)
	return steps
}

// collectData gathers text content from the session source.
func (h *AIHandler) collectData(ctx context.Context, session *models.AnalysisSession) (string, error) {
	switch session.SourceType {
	case "job":
		return h.collectJob(session.SourceID)
	case "checklist_run":
		return h.collectChecklistRun(session.SourceID)
	case "elk_result":
		return h.collectELKResult(session.SourceID)
	case "upload":
		return h.collectUpload(session.UploadPath)
	case "offline_report":
		return h.collectOfflineReport(session.UploadPath)
	default:
		return "", fmt.Errorf("unknown source type: %q", session.SourceType)
	}
}

func (h *AIHandler) collectJob(jobIDStr string) (string, error) {
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		return "", fmt.Errorf("invalid job ID: %w", err)
	}
	var job models.Job
	if err := h.db.Preload("Tool").Preload("Agent").First(&job, "id = ?", jobID).Error; err != nil {
		return "", fmt.Errorf("job not found: %w", err)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "=== JOB EXECUTION RESULT ===\n")
	fmt.Fprintf(&sb, "Tool: %s\n", job.Tool.Name)
	fmt.Fprintf(&sb, "Agent: %s (OS: %s, IP: %s)\n", job.Agent.Name, job.Agent.OS, job.Agent.IPAddress)
	fmt.Fprintf(&sb, "Args: %s\n", job.Args)
	fmt.Fprintf(&sb, "Status: %s\n", job.Status)
	if job.StartedAt != nil {
		fmt.Fprintf(&sb, "Started: %s\n", job.StartedAt.Format(time.RFC3339))
	}
	if job.FinishedAt != nil {
		fmt.Fprintf(&sb, "Finished: %s\n", job.FinishedAt.Format(time.RFC3339))
	}
	sb.WriteString("\n=== OUTPUT ===\n")
	sb.WriteString(job.Output)

	// If there's a JSON artifact, include it (capped at 200KB).
	if job.ArtifactPath != "" {
		fullPath := h.store.GetArtifactByRelPath(job.ArtifactPath)
		ext := strings.ToLower(filepath.Ext(fullPath))
		if ext == ".json" || ext == ".txt" || ext == ".csv" || ext == ".log" || ext == ".xml" {
			data, readErr := os.ReadFile(fullPath)
			if readErr == nil {
				sb.WriteString("\n=== ARTIFACT (" + filepath.Base(job.ArtifactPath) + ") ===\n")
				artifact := string(data)
				if len(artifact) > 16*1024 {
					artifact = artifact[:16*1024] + "\n... [truncated]"
				}
				sb.WriteString(artifact)
			}
		}
	}
	return sb.String(), nil
}

func (h *AIHandler) collectChecklistRun(runIDStr string) (string, error) {
	runID, err := uuid.Parse(runIDStr)
	if err != nil {
		return "", fmt.Errorf("invalid run ID: %w", err)
	}
	var run models.ChecklistRun
	if err := h.db.Preload("Batches").First(&run, "id = ?", runID).Error; err != nil {
		return "", fmt.Errorf("checklist run not found: %w", err)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "=== EVIDENCE COLLECTION CHECKLIST RESULTS ===\n")
	fmt.Fprintf(&sb, "Platform: %s | Analyst: %s | Label: %s\n", run.Platform, run.Analyst, run.Label)
	fmt.Fprintf(&sb, "Status: %s | Created: %s\n\n", run.Status, run.CreatedAt.Format(time.RFC3339))

	// Per-batch cap: keep first 2KB of each batch output.
	// Checklist runs often have many batches; the first part of each is most
	// representative (command header + immediate output). Total per-run budget
	// is further capped by buildPrompt (24KB), so even 20 batches × 2KB = 40KB
	// will be trimmed before sending to the AI.
	const batchCap = 2 * 1024
	for _, batch := range run.Batches {
		if batch.Output == "" {
			continue
		}
		out := batch.Output
		if len(out) > batchCap {
			out = out[:batchCap] + "\n... [truncated]"
		}
		fmt.Fprintf(&sb, "--- [%s] %s ---\n", batch.BatchKey, batch.BatchLabel)
		sb.WriteString(out)
		sb.WriteString("\n")
	}
	return sb.String(), nil
}

func (h *AIHandler) collectELKResult(resultIDStr string) (string, error) {
	resultID, err := uuid.Parse(resultIDStr)
	if err != nil {
		return "", fmt.Errorf("invalid ELK result ID: %w", err)
	}
	var result models.ELKHuntResult
	if err := h.db.First(&result, "id = ?", resultID).Error; err != nil {
		return "", fmt.Errorf("ELK result not found: %w", err)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "=== ELK THREAT HUNT RESULTS ===\n")
	fmt.Fprintf(&sb, "Title: %s\n", result.Title)
	fmt.Fprintf(&sb, "IOCs used: %d | Total hits: %d | Status: %s\n\n", result.IOCsUsed, result.TotalHits, result.Status)

	if result.Results != "" {
		// Cap hits to 16KB — beyond that the AI can't usefully process anyway
		data := result.Results
		if len(data) > 16*1024 {
			data = data[:16*1024] + "\n... [truncated]"
		}
		sb.WriteString("=== HITS ===\n")
		sb.WriteString(data)
	}
	return sb.String(), nil
}

// offlineReport mirrors the JSON structure emitted by the offline agent reporter.
type offlineReport struct {
	BundleName  string `json:"bundle_name"`
	CaseID      string `json:"case_id"`
	CaseName    string `json:"case_name"`
	Hostname    string `json:"hostname"`
	IP          string `json:"ip"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	GeneratedAt string `json:"generated_at"`
	Jobs        []struct {
		ToolName    string    `json:"tool_name"`
		ToolID      string    `json:"tool_id"`
		Args        string    `json:"args"`
		Status      string    `json:"status"`
		StartedAt   time.Time `json:"started_at"`
		FinishedAt  time.Time `json:"finished_at"`
		DurationSec float64   `json:"duration_seconds"`
		OutputLines int       `json:"output_lines"`
		Output      string    `json:"output"`
		Error       string    `json:"error"`
	} `json:"jobs"`
	Summary struct {
		TotalTools int `json:"total_tools"`
		Done       int `json:"done"`
		Failed     int `json:"failed"`
		Stopped    int `json:"stopped"`
	} `json:"summary"`
}

// collectOfflineReport reads and formats an offline-agent JSON report for AI analysis.
// Each tool's output is included up to 4 KB; total is further capped by buildPrompt.
func (h *AIHandler) collectOfflineReport(uploadPath string) (string, error) {
	if uploadPath == "" {
		return "", fmt.Errorf("no upload file associated with this session")
	}
	fullPath := h.store.GetAnalysisUploadPath(uploadPath)
	raw, err := os.ReadFile(fullPath)
	if err != nil {
		return "", fmt.Errorf("read offline report: %w", err)
	}

	var rep offlineReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		// Not a valid bundle JSON — treat as plain text
		return string(raw), nil
	}

	var sb strings.Builder
	sb.WriteString("=== FORENSICHUB OFFLINE HUNTING REPORT ===\n")
	fmt.Fprintf(&sb, "Bundle   : %s\n", rep.BundleName)
	if rep.CaseName != "" {
		fmt.Fprintf(&sb, "Case     : %s\n", rep.CaseName)
	}
	fmt.Fprintf(&sb, "Host     : %s\n", rep.Hostname)
	fmt.Fprintf(&sb, "IP       : %s\n", rep.IP)
	fmt.Fprintf(&sb, "OS/Arch  : %s / %s\n", rep.OS, rep.Arch)
	if rep.GeneratedAt != "" {
		fmt.Fprintf(&sb, "Generated: %s\n", rep.GeneratedAt)
	}
	fmt.Fprintf(&sb, "Summary  : %d tools — %d done, %d failed, %d stopped\n\n",
		rep.Summary.TotalTools, rep.Summary.Done, rep.Summary.Failed, rep.Summary.Stopped)

	const perToolCap = 4 * 1024
	for i, job := range rep.Jobs {
		dur := ""
		if job.DurationSec > 0 {
			dur = fmt.Sprintf(" (%.1fs)", job.DurationSec)
		}
		fmt.Fprintf(&sb, "--- [%d/%d] %s | %s%s | args: %s ---\n",
			i+1, len(rep.Jobs), job.ToolName, job.Status, dur, job.Args)
		if job.Error != "" {
			fmt.Fprintf(&sb, "ERROR: %s\n", job.Error)
		}
		output := job.Output
		if len(output) > perToolCap {
			output = output[:perToolCap] + "\n... [truncated]"
		}
		sb.WriteString(output)
		sb.WriteString("\n\n")
	}
	return sb.String(), nil
}

// collectUpload reads a sampled portion of the uploaded file without loading
// the whole thing into memory.  Memory dumps and disk images can be multiple
// gigabytes; os.ReadFile on such a file OOMs the server.  Instead we read:
//   - up to 1 MB from the beginning (process lists, PE headers, registry hives)
//   - up to 512 KB from the middle (heap allocations, stack frames)
//   - up to 512 KB from the end (recent activity, logs)
//
// Total in-memory footprint: ≤ 2 MB regardless of file size.
// The extractStrings step that follows will reduce this to ≤ 512 KB of
// printable ASCII, and buildPrompt caps to 24 KB before sending to the AI.
func (h *AIHandler) collectUpload(uploadPath string) (string, error) {
	if uploadPath == "" {
		return "", fmt.Errorf("no upload file associated with this session")
	}
	fullPath := h.store.GetAnalysisUploadPath(uploadPath)

	f, err := os.Open(fullPath)
	if err != nil {
		return "", fmt.Errorf("open upload file: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat upload file: %w", err)
	}
	size := info.Size()

	const (
		headBytes   = 1 * 1024 * 1024 // 1 MB from start
		middleBytes = 512 * 1024       // 512 KB from middle
		tailBytes   = 512 * 1024       // 512 KB from end
	)

	// Small file: read entirely
	if size <= int64(headBytes+middleBytes+tailBytes) {
		data, rerr := io.ReadAll(io.LimitReader(f, int64(headBytes+middleBytes+tailBytes)))
		if rerr != nil {
			return "", fmt.Errorf("read upload file: %w", rerr)
		}
		return string(data), nil
	}

	var sb strings.Builder
	sb.Grow(headBytes + middleBytes + tailBytes + 64)

	// Head
	head := make([]byte, headBytes)
	n, _ := io.ReadFull(f, head)
	sb.Write(head[:n])

	// Middle
	midOffset := (size / 2) - int64(middleBytes/2)
	if _, seekErr := f.Seek(midOffset, io.SeekStart); seekErr == nil {
		mid := make([]byte, middleBytes)
		n, _ = io.ReadFull(f, mid)
		sb.WriteString("\n\n[... middle sample ...]\n\n")
		sb.Write(mid[:n])
	}

	// Tail
	tailOffset := size - int64(tailBytes)
	if tailOffset < 0 {
		tailOffset = 0
	}
	if _, seekErr := f.Seek(tailOffset, io.SeekStart); seekErr == nil {
		tail := make([]byte, tailBytes)
		n, _ = io.ReadFull(f, tail)
		sb.WriteString("\n\n[... tail sample ...]\n\n")
		sb.Write(tail[:n])
	}

	return sb.String(), nil
}

// buildPrompt constructs the forensic analysis prompt.
// enrichSummary is the optional threat-intel block injected between the raw
// content and the analysis instructions; pass "" to omit it.
func (h *AIHandler) buildPrompt(session *models.AnalysisSession, content, enrichSummary string) string {
	sourceLabel := map[string]string{
		"job":            "kết quả chạy tool",
		"checklist_run":  "kết quả thu thập bằng chứng (Evidence Checklist)",
		"elk_result":     "kết quả ELK Threat Hunt",
		"upload":         "file upload từ bên ngoài",
		"offline_report": "báo cáo forensic hunting offline (chạy trên endpoint không có mạng)",
	}[session.SourceType]
	if sourceLabel == "" {
		sourceLabel = "dữ liệu forensic"
	}

	// Adaptive cap based on content size.
	// Free-tier APIs (Groq on_demand: 12K TPM, Gemini free: 1M TPM) have very
	// different limits. We use a conservative 24KB cap (~6000 tokens) which fits
	// safely within Groq free tier while still covering most forensic outputs.
	// For large outputs, the most useful data is at the start (headers, errors,
	// findings) so front-truncation is intentional.
	const contentCap = 24 * 1024
	truncated := false
	if len(content) > contentCap {
		content = content[:contentCap]
		truncated = true
	}
	truncateNote := ""
	if truncated {
		truncateNote = "\n\n⚠️ *Nội dung đã được cắt bớt do giới hạn token của API. Chỉ phần đầu được phân tích.*"
	}

	// Build the enrichment block and tailor analysis instructions accordingly.
	enrichSection := ""
	iocInstruction := "Liệt kê các IOC được phát hiện (IP, domain, hash, path, v.v.) nếu có."
	enrichInstruction := ""
	if enrichSummary != "" {
		enrichSection = "\n\n---\n\n" + enrichSummary
		iocInstruction = `Dựa trên kết quả Threat Intelligence ở trên, liệt kê từng IOC kèm đánh giá:
- Với mỗi IOC: ghi rõ giá trị, loại (IP/hash/domain), điểm reputation và verdict (MALICIOUS / SUSPICIOUS / CLEAN)
- Tham chiếu nguồn cụ thể: VirusTotal score, AbuseIPDB confidence, OTX pulses
- Nếu IOC là CLEAN, ghi rõ để loại bỏ khỏi danh sách nghi vấn`
		enrichInstruction = `
⚠️ **Lưu ý quan trọng**: Kết quả Threat Intelligence thực tế đã được tra cứu tự động và đính kèm bên trên.
Hãy:
- Dựa HOÀN TOÀN vào dữ liệu reputation thực tế (VT score, AbuseIPDB score, OTX pulses) — không được phỏng đoán
- Phân loại mức độ nguy hiểm dựa trên số liệu cụ thể, không phải nhận xét chung chung
- Nêu rõ tên malware family / threat label khi VT cung cấp (ví dụ: "Emotet", "Cobalt Strike", "Mirai")
- Phân biệt rõ IOC đã được xác nhận độc hại vs. chưa tìm thấy trong database

`
	}

	return fmt.Sprintf(`Bạn là chuyên gia DFIR (Digital Forensics & Incident Response) với nhiều năm kinh nghiệm.

Dưới đây là %s cần được phân tích:%s

%s
%s
---

%sHãy thực hiện phân tích toàn diện theo cấu trúc sau (dùng Markdown):

## Tóm tắt tổng quan
Mô tả ngắn gọn về dữ liệu và những điểm đáng chú ý nhất. Nêu số lượng IOC phát hiện được và mức độ nguy hiểm tổng thể dựa trên dữ liệu thực tế.

## Phát hiện chính
Liệt kê các phát hiện quan trọng, phân loại theo mức độ nghiêm trọng (dựa trên dữ liệu threat intel thực tế nếu có):
- 🔴 **Critical** — xác nhận là malicious, cần xử lý ngay
- 🟠 **High** — suspicious hoặc có dấu hiệu rõ ràng
- 🟡 **Medium** — cần điều tra thêm
- 🟢 **Low/Info** — clean hoặc không đủ bằng chứng

## Phân tích chi tiết
Giải thích từng phát hiện: nguyên nhân, tác động, threat family (nếu có từ VT labels), bằng chứng cụ thể với số liệu reputation.

## Indicators of Compromise (IOC)
%s

## Đề xuất hành động
Các bước điều tra và khắc phục cụ thể, theo thứ tự ưu tiên. Bao gồm cách block/quarantine IOC đã được xác nhận độc hại.

## Kết luận
Đánh giá tổng thể mức độ rủi ro dựa trên kết quả threat intel. Nêu rõ: bao nhiêu IOC được xác nhận malicious, loại mối đe dọa, và mức độ khẩn cấp cần phản hồi.`, sourceLabel, truncateNote, content, enrichSection, enrichInstruction, iocInstruction)
}

// extractStrings extracts printable ASCII sequences (≥4 chars) from binary data.
// Returns at most maxBytes of extracted strings.
func extractStrings(data string, maxBytes int) string {
	bytes := []byte(data)
	var sb strings.Builder
	var current strings.Builder

	for _, b := range bytes {
		if b >= 0x20 && b < 0x7f && unicode.IsPrint(rune(b)) {
			current.WriteByte(b)
		} else {
			if current.Len() >= 4 {
				sb.WriteString(current.String())
				sb.WriteByte('\n')
				if sb.Len() >= maxBytes {
					sb.WriteString("\n... [truncated]")
					return sb.String()
				}
			}
			current.Reset()
		}
	}
	if current.Len() >= 4 {
		sb.WriteString(current.String())
	}
	return sb.String()
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


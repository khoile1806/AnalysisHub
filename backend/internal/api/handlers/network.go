package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	ai "github.com/analysishub/backend/internal/ai"
	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/config"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/netscan"
	"github.com/analysishub/backend/internal/storage"
	"github.com/analysishub/backend/internal/threatintel"
)

// network.go — PCAP network-traffic analysis handler. Mirrors the malware
// feature: upload a .pcap → async Suricata pipeline → findings + flow graph. The
// raw capture is registered in the Evidence Store (admin download only).

type NetworkHandler struct {
	DB      *gorm.DB
	Store   *storage.LocalStorage
	Cfg     *config.Config
	AI      *AIHandler      // provider resolution (resolveProvider)
	Malware *MalwareHandler // pivot a carved file into full malware analysis
	engine  *netscan.Engine
}

func NewNetworkHandler(db *gorm.DB, store *storage.LocalStorage, cfg *config.Config, enrich *threatintel.EnrichClient, aiHandler *AIHandler, malwareHandler *MalwareHandler) *NetworkHandler {
	h := &NetworkHandler{
		DB: db, Store: store, Cfg: cfg, AI: aiHandler, Malware: malwareHandler,
		engine: netscan.NewEngine(db, store, cfg.NetAnalyzerURL, enrich, cfg.MalwareLocalOnly),
	}
	// Close the loop between the two features. Carved files already flow from a
	// pcap INTO malware analysis; this sends a detonation's captured traffic back
	// the other way, so live malware traffic finally reaches the Suricata/Zeek
	// pipeline instead of existing only as the sinkhole's JSON records.
	if malwareHandler != nil {
		malwareHandler.SetPcapAnalyzer(h.AnalyzeDetonationPcap)
	}
	return h
}

func (h *NetworkHandler) maxUpload() int64 {
	mb := 512
	if h.Cfg != nil && h.Cfg.NetworkMaxUploadMB > 0 {
		mb = h.Cfg.NetworkMaxUploadMB
	}
	return int64(mb) << 20
}

// Config reports whether the pcap analyzer is available.
// GET /api/v1/network/config
func (h *NetworkHandler) Config(c *gin.Context) {
	available := h.engine.Available()
	rules := 0
	ctx, cancel := context.WithTimeout(c.Request.Context(), 4*time.Second)
	defer cancel()
	if hz := h.engine.Health(ctx); hz != nil {
		if !toBool(hz["suricata"]) {
			available = false
		}
		if r, ok := hz["rules"].(float64); ok {
			rules = int(r)
		}
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"available": available, "rules": rules,
	}})
}

func toBool(v interface{}) bool { b, _ := v.(bool); return b }

// Analyze uploads a pcap and starts the async analysis.
// POST /api/v1/network/analyze  (multipart: file, optional case_id)
func (h *NetworkHandler) Analyze(c *gin.Context) {
	if middleware.GetRole(c) != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "admin role required"})
		return
	}
	if !h.engine.Available() {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "network analyzer (Suricata sidecar) is not configured"})
		return
	}
	fileHdr, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "file is required"})
		return
	}
	maxBytes := h.maxUpload()
	if fileHdr.Size > maxBytes {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": fmt.Sprintf("pcap exceeds the %d MB limit (raise NETWORK_MAX_UPLOAD_MB)", maxBytes>>20)})
		return
	}
	f, err := fileHdr.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "cannot read uploaded file"})
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil || len(data) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "empty or unreadable file"})
		return
	}
	if int64(len(data)) > maxBytes {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "pcap exceeds the upload limit"})
		return
	}
	// Basic sanity: pcap/pcapng magic (0xa1b2c3d4 / 0x0a0d0d0a) — best-effort.
	name := sanitizeSampleName(fileHdr.Filename)
	if !looksLikePcap(data) && !strings.HasSuffix(strings.ToLower(name), ".pcap") && !strings.HasSuffix(strings.ToLower(name), ".pcapng") && !strings.HasSuffix(strings.ToLower(name), ".cap") {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "not a pcap/pcapng capture"})
		return
	}

	// Optional SSLKEYLOG for decrypting TLS (bounded — it is only key lines).
	var keylog []byte
	if kf, kerr := c.FormFile("keylog"); kerr == nil && kf.Size > 0 && kf.Size < 4<<20 {
		if kfh, oerr := kf.Open(); oerr == nil {
			keylog, _ = io.ReadAll(io.LimitReader(kfh, 4<<20))
			kfh.Close()
		}
	}

	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])

	var userID uuid.UUID
	if uid, ok := middleware.GetUserID(c); ok {
		userID = uid
	}
	var caseID *uuid.UUID
	if cid, perr := uuid.Parse(c.PostForm("case_id")); perr == nil {
		caseID = &cid
	}

	scan := models.NetworkScan{FileName: name, Size: int64(len(data)), Sha256: sha,
		Status: "pending", Verdict: "unknown", CaseID: caseID, CreatedBy: userID}
	if err := h.DB.Create(&scan).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "could not create analysis: " + err.Error()})
		return
	}
	// Persist the raw pcap AND register it in the Evidence Store (admin download).
	if path, serr := h.Store.SaveAnalysisUpload(scan.ID.String(), name, bytes.NewReader(data)); serr == nil {
		h.DB.Model(&scan).Update("stored_path", path)
		registerExistingEvidence(h.DB, caseID, nil, "", "pcap", "network-analysis", name, path, int64(len(data)), sha)
	}
	writeAudit(c, h.DB, &userID, nil, "network.analyze", name, "pcap network-traffic analysis")

	// Resolve the default AI provider (if any) so the pipeline can auto-write the
	// analyst summary. A missing provider is fine — the engine falls back to a
	// deterministic narrative.
	var client ai.Client
	maxTokens := 0
	if h.AI != nil {
		if prov, cl, perr := h.AI.resolveProvider(""); perr == nil {
			client, maxTokens = cl, prov.MaxTokens
		}
	}

	go h.engine.Analyze(context.Background(), scan.ID.String(), data, name, keylog, client, maxTokens)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"scan_id": scan.ID, "decrypt": len(keylog) > 0}})
}

// List returns recent pcap analyses.
// GET /api/v1/network
func (h *NetworkHandler) List(c *gin.Context) {
	var scans []models.NetworkScan
	h.DB.Order("created_at desc").Limit(200).Find(&scans)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": scans})
}

// Get returns one analysis with its full result.
// GET /api/v1/network/:id
func (h *NetworkHandler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	var scan models.NetworkScan
	if h.DB.First(&scan, "id = ?", id).Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": scan})
}

// AIAnalyze runs a SEPARATE AI pass over a completed capture — its own verdict,
// kill-chain narrative, ATT&CK mapping and transparent score card — alongside
// (not replacing) the deterministic Suricata verdict. Async: it flips
// network_ai_status to "running" and a goroutine fills in network_ai. Mirrors
// the malware feature's per-stage AI opinion.
//
// POST /api/v1/network/:id/ai-analyze  { "provider_id": "<uuid>" (optional) }
func (h *NetworkHandler) AIAnalyze(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	var scan models.NetworkScan
	if h.DB.First(&scan, "id = ?", id).Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "not found"})
		return
	}
	if scan.Status != "done" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "analysis is not finished yet"})
		return
	}
	if scan.NetworkAIStatus == "running" {
		c.JSON(http.StatusConflict, gin.H{"success": false, "error": "AI analysis already in progress"})
		return
	}

	var input struct {
		ProviderID string `json:"provider_id"`
	}
	_ = c.ShouldBindJSON(&input)
	provider, client, perr := h.AI.resolveProvider(input.ProviderID)
	if perr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": perr.Error()})
		return
	}

	h.DB.Model(&scan).Update("network_ai_status", "running")
	var userID uuid.UUID
	if uid, ok := middleware.GetUserID(c); ok {
		userID = uid
	}
	writeAudit(c, h.DB, &userID, nil, "network.ai_analyze", scan.FileName, "AI network-traffic analysis")

	go h.engine.AIAnalyze(context.Background(), scan.ID.String(), client, provider.MaxTokens)

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"status": "running"}})
}

// Delete removes an analysis (the pcap stays in the Evidence Store).
// DELETE /api/v1/network/:id
func (h *NetworkHandler) Delete(c *gin.Context) {
	if middleware.GetRole(c) != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "admin role required"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	h.DB.Delete(&models.NetworkScan{}, "id = ?", id)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// looksLikePcap checks the classic pcap/pcapng magic numbers.
func looksLikePcap(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	m := string(b[:4])
	return m == "\xd4\xc3\xb2\xa1" || m == "\xa1\xb2\xc3\xd4" || // pcap (LE/BE)
		m == "\x0a\x0d\x0d\x0a" || // pcapng
		m == "\x4d\x3c\xb2\xa1" || m == "\xa1\xb2\x3c\x4d" // nanosecond pcap
}

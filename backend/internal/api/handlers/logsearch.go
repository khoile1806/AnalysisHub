package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/logsearch"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/storage"
	"github.com/analysishub/backend/internal/threatintel"
	"github.com/analysishub/backend/internal/ws"
)

// hashFile returns the hex sha256 of a file's contents (for upload dedup).
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// maxLogUploadBytes bounds a single uploaded log file.
const maxLogUploadBytes = 16 << 30 // 16 GB

// logIngestConcurrency caps how many files parse/index at once so a folder drop
// of hundreds of files can't exhaust CPU or sockets to Elasticsearch.
const logIngestConcurrency = 3

// LogSearchHandler ingests uploaded log files into the built-in Elasticsearch
// store. Search itself is done from the SIEM Threat Hunting page against the
// auto-registered "Local Log Store" ELK profile.
type LogSearchHandler struct {
	DB           *gorm.DB
	Store        *storage.LocalStorage
	ES           *logsearch.ESClient
	Enricher     *threatintel.EnrichClient // threat-intel lookups over ingested IPs
	KibanaURL    string                    // internal Kibana URL (with /kbn) for data view provisioning
	DockerAPIURL string                    // scoped docker-socket-proxy base URL; empty = toggle off
	Hub          *ws.Hub                   // agent WS hub — used to trigger agent log collection
	sem          chan struct{}

	// Idle auto-shutdown policy for the ELK + Sandbox containers.
	IdlePowerEnabled      bool
	ELKIdleTimeoutMin     int
	SandboxIdleTimeoutMin int
}

// LogSearchConfig carries the wiring the handler needs.
type LogSearchConfig struct {
	ESURL         string
	KibanaURL     string
	DockerAPIURL  string
	RetentionDays int
	Enricher      *threatintel.EnrichClient
	Hub           *ws.Hub

	IdlePowerEnabled      bool
	ELKIdleTimeoutMin     int
	SandboxIdleTimeoutMin int
}

func NewLogSearchHandler(db *gorm.DB, store *storage.LocalStorage, cfg LogSearchConfig) *LogSearchHandler {
	return &LogSearchHandler{
		DB:                    db,
		Store:                 store,
		ES:                    logsearch.NewESClient(cfg.ESURL, cfg.RetentionDays),
		Enricher:              cfg.Enricher,
		KibanaURL:             cfg.KibanaURL,
		DockerAPIURL:          cfg.DockerAPIURL,
		Hub:                   cfg.Hub,
		sem:                   make(chan struct{}, logIngestConcurrency),
		IdlePowerEnabled:      cfg.IdlePowerEnabled,
		ELKIdleTimeoutMin:     cfg.ELKIdleTimeoutMin,
		SandboxIdleTimeoutMin: cfg.SandboxIdleTimeoutMin,
	}
}

// Meta GET /api/v1/logsearch/meta — capabilities + store health for the UI.
func (h *LogSearchHandler) Meta(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"log_types":    logsearch.LogTypes,
		"index_prefix": logsearch.IndexPrefix,
		"es_up":        h.ES.Ping(),
	})
}

// kibanaUp reports whether Kibana answers its status endpoint.
func (h *LogSearchHandler) kibanaUp() bool {
	if strings.TrimSpace(h.KibanaURL) == "" {
		return false
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(strings.TrimRight(h.KibanaURL, "/") + "/api/status")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// Health GET /api/v1/logsearch/health — end-to-end health of the whole feature.
func (h *LogSearchHandler) Health(c *gin.Context) {
	esStatus, esUp := h.ES.ClusterStatus()
	indices, _ := h.ES.CatIndices()
	docs := 0
	for _, ix := range indices {
		docs += atoiSafe(ix.Docs)
	}
	c.JSON(http.StatusOK, gin.H{
		"elasticsearch": gin.H{"up": esUp, "status": esStatus},
		"kibana":        gin.H{"up": h.kibanaUp()},
		"indices":       len(indices),
		"documents":     docs,
		"elk_control":   h.controlEnabled(),
	})
}

// Enrich POST /api/v1/logsearch/enrich?case= — threat-intel lookup of the top
// source IPs in the ingested logs (VirusTotal/AbuseIPDB/AlienVault/Shodan).
func (h *LogSearchHandler) Enrich(c *gin.Context) {
	if h.Enricher == nil || !h.Enricher.Configured() {
		c.JSON(http.StatusOK, gin.H{"configured": false, "results": []interface{}{}})
		return
	}
	summ, err := h.ES.Summarize(strings.TrimSpace(c.Query("case")))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	var ips []string
	for _, b := range summ.TopSourceIP {
		if b.Key != "" {
			ips = append(ips, b.Key)
		}
	}
	if len(ips) == 0 {
		c.JSON(http.StatusOK, gin.H{"configured": true, "results": []interface{}{}})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 90*time.Second)
	defer cancel()
	results := h.Enricher.Enrich(ctx, threatintel.IOCSet{IPs: ips})
	c.JSON(http.StatusOK, gin.H{"configured": true, "results": results})
}

// Summary GET /api/v1/logsearch/summary?case= — fast triage aggregations.
func (h *LogSearchHandler) Summary(c *gin.Context) {
	s, err := h.ES.Summarize(strings.TrimSpace(c.Query("case")))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, s)
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// Upload POST /api/v1/logsearch/upload — multipart: case, log_type, case_id?, files[]
func (h *LogSearchHandler) Upload(c *gin.Context) {
	markELKActivity() // ingesting logs keeps ELK alive
	caseName := strings.TrimSpace(c.PostForm("case"))
	if caseName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "case is required"})
		return
	}
	logType := strings.TrimSpace(c.PostForm("log_type"))
	if logType == "" {
		logType = logsearch.TypeAuto
	}
	if !validLogType(logType) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid log_type"})
		return
	}

	tz := strings.TrimSpace(c.PostForm("timezone"))

	var caseID *uuid.UUID
	if v := strings.TrimSpace(c.PostForm("case_id")); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			caseID = &id
		}
	}

	var createdBy uuid.UUID
	if v, ok := c.Get("userID"); ok {
		if uid, err := uuid.Parse(v.(string)); err == nil {
			createdBy = uid
		}
	}

	form, err := c.MultipartForm()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid multipart form"})
		return
	}
	files := form.File["files"]
	if len(files) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no files uploaded"})
		return
	}

	meta := ingestMeta{Case: caseName, CaseID: caseID, LogType: logType, Timezone: tz, Source: "upload", CreatedBy: createdBy}
	jobs := make([]models.LogIngestJob, 0, len(files))
	for _, fh := range files {
		if fh.Size > maxLogUploadBytes {
			continue
		}
		if job, ok := h.enqueueFromMultipart(fh, meta); ok {
			jobs = append(jobs, job)
		}
	}

	c.JSON(http.StatusAccepted, gin.H{"jobs": jobs})
}

// ingestMeta carries the per-file metadata shared by the manual upload path and
// the agent auto-collect path.
type ingestMeta struct {
	Case      string
	CaseID    *uuid.UUID
	Host      string // source host; "" for manual uploads
	Source    string // upload|agent
	LogType   string
	Timezone  string
	CreatedBy uuid.UUID
}

// enqueueFromMultipart persists one uploaded file, creates its LogIngestJob,
// runs sha256 dedup (scoped to case+host), and kicks off ingestion. Returns the
// job row and whether it was enqueued. Used by both Upload and AgentIngest.
func (h *LogSearchHandler) enqueueFromMultipart(fh *multipart.FileHeader, meta ingestMeta) (models.LogIngestJob, bool) {
	logType := meta.LogType
	if logType == "" {
		logType = logsearch.TypeAuto
	}
	source := meta.Source
	if source == "" {
		source = "upload"
	}
	job := models.LogIngestJob{
		Case:      meta.Case,
		CaseID:    meta.CaseID,
		Host:      meta.Host,
		Source:    source,
		Filename:  fh.Filename,
		LogType:   logType,
		Timezone:  meta.Timezone,
		Status:    "queued",
		CreatedBy: meta.CreatedBy,
	}
	if err := h.DB.Create(&job).Error; err != nil {
		return job, false
	}
	f, openErr := fh.Open()
	if openErr != nil {
		h.markError(&job, "failed to open upload")
		return job, true
	}
	relPath, saveErr := h.Store.SaveLogUpload(job.ID.String(), fh.Filename, f)
	f.Close()
	if saveErr != nil {
		h.markError(&job, "failed to store file: "+saveErr.Error())
		return job, true
	}
	h.DB.Model(&job).Update("stored_path", relPath)
	job.StoredPath = relPath

	// Dedup: skip a file already ingested (same sha256) for this case+host.
	if hash, herr := hashFile(h.Store.GetLogUploadPath(relPath)); herr == nil {
		job.FileHash = hash
		h.DB.Model(&job).Update("file_hash", hash)
		var dup models.LogIngestJob
		if err := h.DB.Where("file_hash = ? AND status = ? AND \"case\" = ? AND host = ? AND id <> ?", hash, "done", meta.Case, meta.Host, job.ID).First(&dup).Error; err == nil {
			now := time.Now()
			h.DB.Model(&job).Updates(map[string]interface{}{
				"status": "skipped", "finished_at": &now,
				"message": "duplicate of an already-ingested file (same content)",
			})
			return job, true
		}
	}

	go h.runIngest(job)
	return job, true
}

// runIngest parses and indexes one file, updating its job row as it goes.
func (h *LogSearchHandler) runIngest(job models.LogIngestJob) {
	h.sem <- struct{}{}
	defer func() { <-h.sem }()

	h.DB.Model(&models.LogIngestJob{}).Where("id = ?", job.ID).Update("status", "running")

	absPath := h.Store.GetLogUploadPath(job.StoredPath)
	onProgress := func(indexed, failed int) {
		h.DB.Model(&models.LogIngestJob{}).Where("id = ?", job.ID).
			Updates(map[string]interface{}{"docs_indexed": indexed, "docs_failed": failed})
	}

	indices, indexed, failed, sampleErr, err := h.ES.IngestPath(absPath, job.Filename, job.Case, job.Host, job.LogType, job.Timezone, onProgress)
	now := time.Now()
	updates := map[string]interface{}{
		"index":        strings.Join(indices, ","),
		"docs_indexed": indexed,
		"docs_failed":  failed,
		"finished_at":  &now,
	}
	// detected_type: the single index's last segment, or "archive" for a bundle.
	if len(indices) == 1 {
		if parts := strings.Split(indices[0], "-"); len(parts) > 0 {
			updates["detected_type"] = parts[len(parts)-1]
		}
	} else if len(indices) > 1 {
		updates["detected_type"] = "archive"
	}
	if err != nil {
		updates["status"] = "error"
		updates["message"] = err.Error()
		log.Printf("logsearch: job %s failed: %v", job.ID, err)
	} else {
		updates["status"] = "done"
		msg := "indexed " + strconv.Itoa(indexed) + " docs into " + strconv.Itoa(len(indices)) + " index(es)"
		if failed > 0 {
			msg += ", " + strconv.Itoa(failed) + " failed"
			if sampleErr != "" {
				msg += " — e.g. " + sampleErr
			}
		}
		updates["message"] = msg
		// Ensure the Kibana data view for each category exists so the logs are
		// immediately browsable, even if startup provisioning missed it.
		if indexed > 0 && h.KibanaURL != "" {
			cats := map[string]bool{}
			for _, idx := range indices {
				if parts := strings.Split(idx, "-"); len(parts) >= 2 {
					cats[parts[1]] = true
				}
			}
			for cat := range cats {
				go logsearch.EnsureCategoryDataView(h.KibanaURL, cat)
			}
		}
	}
	h.DB.Model(&models.LogIngestJob{}).Where("id = ?", job.ID).Updates(updates)
}

// ListJobs GET /api/v1/logsearch/jobs?case=
func (h *LogSearchHandler) ListJobs(c *gin.Context) {
	// Limit is generous: the Log Ingest repository groups these rows by host, and
	// one agent collection alone yields ~15 files, so a small cap would silently
	// hide hosts once a few endpoints have been collected.
	q := h.DB.Order("created_at desc").Limit(2000)
	if cs := strings.TrimSpace(c.Query("case")); cs != "" {
		q = q.Where("\"case\" = ?", cs)
	}
	if cid := strings.TrimSpace(c.Query("case_id")); cid != "" {
		q = q.Where("case_id = ?", cid)
	}
	var jobs []models.LogIngestJob
	if err := q.Find(&jobs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list jobs"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"jobs": jobs})
}

// ListIndices GET /api/v1/logsearch/indices — hunt-* indices with doc counts.
func (h *LogSearchHandler) ListIndices(c *gin.Context) {
	indices, err := h.ES.CatIndices()
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"indices": indices})
}

// DeleteIndex DELETE /api/v1/logsearch/indices/:index — admin only.
func (h *LogSearchHandler) DeleteIndex(c *gin.Context) {
	index := c.Param("index")
	if err := h.ES.DeleteIndex(index); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": index})
}

func (h *LogSearchHandler) markError(job *models.LogIngestJob, msg string) {
	now := time.Now()
	h.DB.Model(job).Updates(map[string]interface{}{"status": "error", "message": msg, "finished_at": &now})
}

func validLogType(t string) bool {
	for _, v := range logsearch.LogTypes {
		if v == t {
			return true
		}
	}
	return false
}

// ReconcileStalledJobs marks jobs left in queued/running by a previous process
// (e.g. the backend restarted mid-ingest) as errored, so they don't hang forever
// in the UI. Called once at startup.
func ReconcileStalledJobs(db *gorm.DB) {
	now := time.Now()
	db.Model(&models.LogIngestJob{}).
		Where("status IN ?", []string{"queued", "running"}).
		Updates(map[string]interface{}{
			"status":      "error",
			"finished_at": &now,
			"message":     "interrupted — backend restarted before completion",
		})
}

// SeedLocalLogStore registers the built-in Elasticsearch as an ELK hunting
// profile on first boot so ingested logs are immediately searchable from the
// SIEM Threat Hunting page. No-op if a profile with the same URL already exists.
func SeedLocalLogStore(db *gorm.DB, esURL string) {
	esURL = strings.TrimSpace(esURL)
	if esURL == "" {
		return
	}
	var existing models.ELKConfig
	if err := db.Where("url = ?", esURL).First(&existing).Error; err == nil {
		return // already seeded
	}
	var activeCount int64
	db.Model(&models.ELKConfig{}).Where("is_active = ?", true).Count(&activeCount)
	cfg := models.ELKConfig{
		Name:        "Local Log Store (built-in)",
		Description: "Elasticsearch bundled with AnalysisHub — target of the Log Ingest tab.",
		URL:         esURL,
		IsActive:    activeCount == 0, // become active only if nothing else is
	}
	if err := db.Create(&cfg).Error; err != nil {
		log.Printf("logsearch: seed local ELK profile failed: %v", err)
	}
}

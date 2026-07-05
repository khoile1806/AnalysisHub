package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/logsearch"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/storage"
)

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
	KibanaURL    string // internal Kibana URL (with /kbn) for data view provisioning
	DockerAPIURL string // scoped docker-socket-proxy base URL; empty = toggle off
	sem          chan struct{}
}

func NewLogSearchHandler(db *gorm.DB, store *storage.LocalStorage, esURL, kibanaURL, dockerAPIURL string) *LogSearchHandler {
	return &LogSearchHandler{
		DB:           db,
		Store:        store,
		ES:           logsearch.NewESClient(esURL),
		KibanaURL:    kibanaURL,
		DockerAPIURL: dockerAPIURL,
		sem:          make(chan struct{}, logIngestConcurrency),
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

// Upload POST /api/v1/logsearch/upload — multipart: case, log_type, case_id?, files[]
func (h *LogSearchHandler) Upload(c *gin.Context) {
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

	jobs := make([]models.LogIngestJob, 0, len(files))
	for _, fh := range files {
		if fh.Size > maxLogUploadBytes {
			continue
		}
		job := models.LogIngestJob{
			Case:      caseName,
			CaseID:    caseID,
			Filename:  fh.Filename,
			LogType:   logType,
			Status:    "queued",
			CreatedBy: createdBy,
		}
		if err := h.DB.Create(&job).Error; err != nil {
			continue
		}
		f, openErr := fh.Open()
		if openErr != nil {
			h.markError(&job, "failed to open upload")
			continue
		}
		relPath, saveErr := h.Store.SaveLogUpload(job.ID.String(), fh.Filename, f)
		f.Close()
		if saveErr != nil {
			h.markError(&job, "failed to store file: "+saveErr.Error())
			continue
		}
		h.DB.Model(&job).Update("stored_path", relPath)
		job.StoredPath = relPath

		go h.runIngest(job)
		jobs = append(jobs, job)
	}

	c.JSON(http.StatusAccepted, gin.H{"jobs": jobs})
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

	index, indexed, failed, err := h.ES.IngestFile(absPath, job.Filename, job.Case, job.LogType, onProgress)
	now := time.Now()
	updates := map[string]interface{}{
		"index":        index,
		"docs_indexed": indexed,
		"docs_failed":  failed,
		"finished_at":  &now,
	}
	// detected type is what the index name's last segment encodes
	if parts := strings.Split(index, "-"); len(parts) > 0 {
		updates["detected_type"] = parts[len(parts)-1]
	}
	if err != nil {
		updates["status"] = "error"
		updates["message"] = err.Error()
		log.Printf("logsearch: job %s failed: %v", job.ID, err)
	} else {
		updates["status"] = "done"
		msg := "indexed " + strconv.Itoa(indexed) + " docs"
		if failed > 0 {
			msg += ", " + strconv.Itoa(failed) + " failed"
		}
		updates["message"] = msg
		// Make sure the Kibana data view for this category exists so the logs are
		// immediately browsable, even if startup provisioning missed it.
		if indexed > 0 && h.KibanaURL != "" {
			if parts := strings.Split(index, "-"); len(parts) >= 2 {
				go logsearch.EnsureCategoryDataView(h.KibanaURL, parts[1])
			}
		}
	}
	h.DB.Model(&models.LogIngestJob{}).Where("id = ?", job.ID).Updates(updates)
}

// ListJobs GET /api/v1/logsearch/jobs?case=
func (h *LogSearchHandler) ListJobs(c *gin.Context) {
	q := h.DB.Order("created_at desc").Limit(300)
	if cs := strings.TrimSpace(c.Query("case")); cs != "" {
		q = q.Where("\"case\" = ?", cs)
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

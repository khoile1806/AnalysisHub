package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/toolproc"
)

// UploadToolResult receives one collected result file from an agent, stores it,
// runs the server-side processing step (classify + normalize + summarize), and
// records a ToolResult row. Unlike UploadArtifact this does NOT finalize the job
// — a job may emit several result files, and completion is still driven by the
// job's output stream.
//
// POST /api/v1/jobs/:id/result   (agent-token auth)
// Form: file (required), filename (optional original name), processor (optional).
func UploadToolResult(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	store, ok := mustGetStorage(c)
	if !ok {
		return
	}

	agentIDStr := middleware.GetAgentID(c)

	jobID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid job ID"})
		return
	}

	var job models.Job
	if err := db.First(&job, "id = ?", jobID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "job not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	// The uploading agent must own the job.
	if job.AgentID.String() != agentIDStr {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "forbidden"})
		return
	}

	fileHeader, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "file is required"})
		return
	}
	origName := c.DefaultPostForm("filename", fileHeader.Filename)
	processor := c.PostForm("processor")

	f, err := fileHeader.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to read result file"})
		return
	}
	defer f.Close()

	resultID := uuid.New()
	rawRel, err := store.SaveToolResult(jobID.String(), resultID.String(), fileHeader.Filename, f)
	if err != nil {
		log.Printf("[tool-result] save: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to store result file"})
		return
	}

	// Optional client-supplied integrity hash; verify when present so a truncated
	// or corrupted transfer is rejected rather than silently processed.
	claimedHash := strings.ToLower(strings.TrimSpace(c.PostForm("sha256")))
	if claimedHash != "" {
		if got := sha256OfFile(store.AbsPath(rawRel)); got != "" && got != claimedHash {
			_ = os.Remove(store.AbsPath(rawRel))
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "integrity check failed (sha256 mismatch)"})
			return
		}
	}

	// Async: record the result as queued and return immediately. The raw-data
	// processing step (parse/normalize/summarize) runs off-request in the
	// tool-result worker so a multi-GB Redline/KAPE parse never blocks the upload.
	agentUUID, _ := uuid.Parse(agentIDStr)
	tr := models.ToolResult{
		ID:            resultID,
		JobID:         jobID,
		AgentID:       agentUUID,
		ToolID:        job.ToolID,
		FileName:      origName,
		Kind:          toolproc.QuickKind(origName),
		Processor:     strings.ToLower(strings.TrimSpace(processor)),
		SizeBytes:     fileHeader.Size,
		Sha256:        claimedHash,
		RawStoredPath: rawRel,
		ProcessStatus: "queued",
		AIStatus:      "pending",
	}
	if err := db.Create(&tr).Error; err != nil {
		log.Printf("[tool-result] db create: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to record result"})
		return
	}

	writeAudit(c, db, nil, &agentUUID, "job.result", jobID.String(),
		fmt.Sprintf("result %q collected (%s, queued for processing)", origName, tr.Kind))

	c.JSON(http.StatusAccepted, gin.H{"success": true, "data": tr})
}

// sha256OfFile returns the lowercase hex SHA-256 of a file, or "" on error.
func sha256OfFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ListToolResults returns the collected result files for a job.
//
// GET /api/v1/jobs/:id/results
func ListToolResults(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	jobID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid job ID"})
		return
	}
	var results []models.ToolResult
	if err := db.Where("job_id = ?", jobID).Order("created_at asc").Find(&results).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to list results"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": results})
}

// DownloadToolResult serves a stored result file. ?parsed=true serves the
// normalized output when available.
//
// GET /api/v1/tool-results/:id/download
func DownloadToolResult(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	store, ok := mustGetStorage(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	var tr models.ToolResult
	if err := db.First(&tr, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "result not found"})
		return
	}
	path := store.AbsPath(tr.RawStoredPath)
	name := tr.FileName
	if c.Query("parsed") == "true" && tr.ParsedStoredPath != "" {
		path = store.AbsPath(tr.ParsedStoredPath)
		name = filepath.Base(tr.ParsedStoredPath)
	}
	c.FileAttachment(path, name)
}

// SetToolResultAI toggles whether a result file is included in AI analysis.
//
// PATCH /api/v1/tool-results/:id   { "for_ai": true|false }
func SetToolResultAI(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	var body struct {
		ForAI *bool `json:"for_ai"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.ForAI == nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "for_ai is required"})
		return
	}
	var tr models.ToolResult
	if err := db.First(&tr, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "result not found"})
		return
	}
	if err := db.Model(&tr).Update("for_ai", *body.ForAI).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to update"})
		return
	}
	tr.ForAI = *body.ForAI
	c.JSON(http.StatusOK, gin.H{"success": true, "data": tr})
}

// SetJobResultsAI bulk-toggles the for-AI flag for every result of a job, so an
// analyst can include/exclude a whole job's collected output in one click.
//
// PATCH /api/v1/jobs/:id/results/for-ai   { "for_ai": true|false }
func SetJobResultsAI(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	jobID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid job ID"})
		return
	}
	var body struct {
		ForAI *bool `json:"for_ai"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.ForAI == nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "for_ai is required"})
		return
	}
	res := db.Model(&models.ToolResult{}).Where("job_id = ?", jobID).Update("for_ai", *body.ForAI)
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to update"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"updated": res.RowsAffected, "for_ai": *body.ForAI}})
}

package handlers

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
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

	// The agent gzip-compresses the transfer; decompress on the way to disk so the
	// stored file is the original (and its SHA-256 matches the agent's raw hash).
	var src io.Reader = f
	if strings.EqualFold(c.PostForm("content_encoding"), "gzip") {
		gr, gzErr := gzip.NewReader(f)
		if gzErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid gzip result upload"})
			return
		}
		defer gr.Close()
		src = gr
	}

	resultID := uuid.New()
	rawRel, err := store.SaveToolResult(jobID.String(), resultID.String(), fileHeader.Filename, src)
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

	// Real (decompressed) size from the stored file — fileHeader.Size is the
	// gzip-compressed transfer size, not the original.
	storedSize := fileHeader.Size
	if fi, statErr := os.Stat(store.AbsPath(rawRel)); statErr == nil {
		storedSize = fi.Size()
	}

	// Provenance: what produced this file (chain-of-custody).
	cmdline := c.PostForm("cmdline")
	exitCode, _ := strconv.Atoi(c.PostForm("exit_code"))
	toolVersion := ""
	if job.ToolID != uuid.Nil {
		var tool models.Tool
		if db.Select("version").First(&tool, "id = ?", job.ToolID).Error == nil {
			toolVersion = tool.Version
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
		SizeBytes:     storedSize,
		Sha256:        claimedHash,
		RawStoredPath: rawRel,
		Cmdline:       cmdline,
		ExitCode:      exitCode,
		ToolVersion:   toolVersion,
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

// LinkToolResult lets the agent avoid re-transferring a result file whose exact
// content the server already stores: if any prior result has the same SHA-256 and
// a readable raw file, the server clones that file locally for this job and
// records a queued ToolResult (the worker then dedups the parse). Returns
// linked=false when there is no match, so the agent uploads normally.
//
// POST /api/v1/jobs/:id/result/link   (agent-token)
func LinkToolResult(c *gin.Context) {
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
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "job not found"})
		return
	}
	if job.AgentID.String() != agentIDStr {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "forbidden"})
		return
	}

	var body struct {
		Sha256    string `json:"sha256"`
		Filename  string `json:"filename"`
		Processor string `json:"processor"`
		Cmdline   string `json:"cmdline"`
		ExitCode  int    `json:"exit_code"`
	}
	_ = c.ShouldBindJSON(&body)
	sum := strings.ToLower(strings.TrimSpace(body.Sha256))
	if sum == "" {
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"linked": false}})
		return
	}

	// Find any prior result with the same content that still has a readable raw file.
	var srcRow models.ToolResult
	if db.Where("sha256 = ? AND raw_stored_path <> ''", sum).Order("created_at asc").First(&srcRow).Error != nil {
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"linked": false}})
		return
	}
	rf, oerr := os.Open(store.AbsPath(srcRow.RawStoredPath))
	if oerr != nil {
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"linked": false}})
		return
	}
	defer rf.Close()

	filename := body.Filename
	if filename == "" {
		filename = srcRow.FileName
	}
	resultID := uuid.New()
	rawRel, serr := store.SaveToolResult(jobID.String(), resultID.String(), filename, rf)
	if serr != nil {
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"linked": false}})
		return
	}

	toolVersion := ""
	if job.ToolID != uuid.Nil {
		var tool models.Tool
		if db.Select("version").First(&tool, "id = ?", job.ToolID).Error == nil {
			toolVersion = tool.Version
		}
	}
	agentUUID, _ := uuid.Parse(agentIDStr)
	tr := models.ToolResult{
		ID:            resultID,
		JobID:         jobID,
		AgentID:       agentUUID,
		ToolID:        job.ToolID,
		FileName:      filename,
		Kind:          toolproc.QuickKind(filename),
		Processor:     strings.ToLower(strings.TrimSpace(body.Processor)),
		SizeBytes:     srcRow.SizeBytes,
		Sha256:        sum,
		RawStoredPath: rawRel,
		Cmdline:       body.Cmdline,
		ExitCode:      body.ExitCode,
		ToolVersion:   toolVersion,
		ProcessStatus: "queued",
		AIStatus:      "pending",
	}
	if err := db.Create(&tr).Error; err != nil {
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"linked": false}})
		return
	}
	writeAudit(c, db, nil, &agentUUID, "job.result.link", jobID.String(),
		fmt.Sprintf("result %q linked by content (sha256 dedup)", filename))
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"linked": true, "id": tr.ID}})
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
	variant := "raw"
	if c.Query("parsed") == "true" && tr.ParsedStoredPath != "" {
		path = store.AbsPath(tr.ParsedStoredPath)
		name = filepath.Base(tr.ParsedStoredPath)
		variant = "parsed"
	}

	// A tool result is collected output from an endpoint; downloading it takes
	// that data off the platform, so record who took which result (by hash) from
	// which agent.
	if uid, ok := middleware.GetUserID(c); ok {
		agentID := tr.AgentID
		writeAudit(c, db, &uid, &agentID, "tool_result.download", tr.ID.String(),
			fmt.Sprintf("file=%s sha256=%s variant=%s", tr.FileName, tr.Sha256, variant))
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

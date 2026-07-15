package handlers

import (
	"archive/zip"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/ws"
)

// createJobRequest is the JSON body for dispatching a new job.
type createJobRequest struct {
	AgentID  string `json:"agent_id" binding:"required"`
	ToolID   string `json:"tool_id"  binding:"required"`
	Args     string `json:"args"`
	CPULimit int    `json:"cpu_limit,omitempty"`
	RAMLimit int    `json:"ram_limit,omitempty"`
	Priority string `json:"priority,omitempty"`
}

// ListJobs returns all jobs, optionally filtered by agent_id and/or status.
//
// GET /api/v1/jobs?agent_id=<uuid>&status=<status>
func ListJobs(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}

	agentID := c.Query("agent_id")
	if agentID != "" {
		if _, err := uuid.Parse(agentID); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid agent_id"})
			return
		}
	}
	status := c.Query("status")

	// filter applies the (identical) WHERE conditions to a fresh query chain so
	// the count and the data fetch never share GORM statement state.
	filter := func(q *gorm.DB) *gorm.DB {
		if agentID != "" {
			q = q.Where("agent_id = ?", agentID)
		}
		if status != "" {
			q = q.Where("status = ?", status)
		}
		return q
	}

	writeTotalCount(c, filter(db.Model(&models.Job{})))

	query := filter(db.Model(&models.Job{})).Preload("Agent").Preload("Tool").Order("created_at desc")
	query = applyLimitOffset(c, query)

	var jobs []models.Job
	if err := query.Find(&jobs).Error; err != nil {
		log.Printf("[jobs] list error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to list jobs"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": jobs})
}

// CreateJob creates a new job and immediately dispatches it to the target agent
// via the WebSocket hub.
//
// POST /api/v1/jobs
// Body: {"agent_id":"...","tool_id":"...","args":"..."}
func CreateJob(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	hub, ok := mustGetHub(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetUserID(c)

	var req createJobRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	agentID, err := uuid.Parse(req.AgentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid agent_id"})
		return
	}
	toolID, err := uuid.Parse(req.ToolID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid tool_id"})
		return
	}

	// Verify agent exists.
	var agent models.Agent
	if err := db.First(&agent, "id = ?", agentID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "agent not found"})
			return
		}
		log.Printf("[jobs] agent lookup: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	// Verify tool exists.
	var tool models.Tool
	if err := db.First(&tool, "id = ?", toolID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "tool not found"})
			return
		}
		log.Printf("[jobs] tool lookup: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	job := models.Job{
		AgentID:   agentID,
		ToolID:    toolID,
		Args:      req.Args,
		Status:    models.JobPending,
		CPULimit:  req.CPULimit,
		RAMLimit:  req.RAMLimit,
		Priority:  firstNonEmpty(req.Priority, "normal"),
		CreatedBy: userID,
	}

	if err := db.Create(&job).Error; err != nil {
		log.Printf("[jobs] db create: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to create job"})
		return
	}

	// Build download URL for the tool binary — use the agent-authenticated route
	// so agents can fetch with their X-Agent-Token instead of a JWT.
	serverURL := getServerURL(c)
	downloadURL := fmt.Sprintf("%s/api/v1/agent/tools/%s/download", serverURL, tool.ID)

	// Dispatch to agent — best-effort (agent may reconnect and poll).
	cmd := ws.AgentCommand{
		Type:           "job_start",
		JobID:          job.ID.String(),
		ToolID:         tool.ID.String(),
		ToolName:       tool.Name,
		FileName:       tool.FileName,
		DownloadURL:    downloadURL,
		Args:           mergeArgs(tool.Args, req.Args),
		ExecutablePath: tool.ExecutablePath,
		CollectResult:   tool.CollectResult,
		OutputGlobs:     tool.OutputGlobs,
		OutputScope:     tool.OutputScope,
		ResultProcessor: tool.ResultProcessor,
		MaxResultMB:     tool.MaxResultMB,
	}
	if dispatchErr := hub.SendJobToAgent(agentID.String(), cmd); dispatchErr != nil {
		log.Printf("[jobs] dispatch to agent %s: %v", agentID, dispatchErr)
		// Update status to reflect the agent is not connected.
		db.Model(&job).Update("status", models.JobFailed)
		db.Model(&job).Update("output", fmt.Sprintf("agent not connected: %v", dispatchErr))
		job.Status = models.JobFailed
	}
	// Otherwise leave status as "pending". The agent will report "ready" via
	// job_status after download + extract completes; hub.OnJobStatus will
	// transition pending → ready.

	// Reload with associations.
	db.Preload("Agent").Preload("Tool").First(&job, "id = ?", job.ID)

	writeAudit(c, db, &userID, &agentID, "job.create", job.ID.String(),
		fmt.Sprintf("dispatched tool %q to agent %q (download-only)", tool.Name, agent.Name))

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": job})
}

// RunJob dispatches a "job_run" command to the agent, instructing it to
// execute a previously-downloaded tool. Only jobs in status "ready" or
// "stopped" may be (re)started.
//
// POST /api/v1/jobs/:id/run
func RunJob(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	hub, ok := mustGetHub(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetUserID(c)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid job ID"})
		return
	}

	var job models.Job
	if err := db.Preload("Tool").First(&job, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "job not found"})
			return
		}
		log.Printf("[jobs] run fetch error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	if job.Status != models.JobReady && job.Status != models.JobStopped {
		c.JSON(http.StatusConflict, gin.H{"success": false, "error": fmt.Sprintf("job must be in status 'ready' or 'stopped' to run (current: %s)", job.Status)})
		return
	}

	cmd := ws.AgentCommand{
		Type:           "job_run",
		JobID:          job.ID.String(),
		ToolID:         job.Tool.ID.String(),
		ToolName:       job.Tool.Name,
		FileName:       job.Tool.FileName,
		Args:           mergeArgs(job.Tool.Args, job.Args),
		ExecutablePath: job.Tool.ExecutablePath,
		CPULimit:       job.CPULimit,
		RAMLimit:       job.RAMLimit,
		Priority:       job.Priority,
		CollectResult:   job.Tool.CollectResult,
		OutputGlobs:     job.Tool.OutputGlobs,
		OutputScope:     job.Tool.OutputScope,
		ResultProcessor: job.Tool.ResultProcessor,
		MaxResultMB:     job.Tool.MaxResultMB,
	}
	if err := hub.SendJobToAgent(job.AgentID.String(), cmd); err != nil {
		log.Printf("[jobs] run dispatch error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": fmt.Sprintf("failed to dispatch run: %v", err)})
		return
	}

	now := time.Now()
	updates := map[string]interface{}{
		"status":     models.JobRunning,
		"started_at": now,
	}
	if job.Status == models.JobStopped {
		// Re-running a stopped job — reset output and clear finished_at.
		updates["output"] = ""
		updates["finished_at"] = nil
	}
	db.Model(&job).Updates(updates)

	agentID := job.AgentID
	writeAudit(c, db, &userID, &agentID, "job.run", job.ID.String(),
		"started job on agent")

	db.Preload("Agent").Preload("Tool").First(&job, "id = ?", job.ID)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": job})
}

// StopJob dispatches a "job_stop" command to the agent to kill a running job.
//
// POST /api/v1/jobs/:id/stop
func StopJob(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	hub, ok := mustGetHub(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetUserID(c)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid job ID"})
		return
	}

	var job models.Job
	if err := db.First(&job, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "job not found"})
			return
		}
		log.Printf("[jobs] stop fetch error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	if job.Status != models.JobRunning {
		c.JSON(http.StatusConflict, gin.H{"success": false, "error": fmt.Sprintf("job must be running to stop (current: %s)", job.Status)})
		return
	}

	cmd := ws.AgentCommand{
		Type:  "job_stop",
		JobID: job.ID.String(),
	}
	if err := hub.SendJobToAgent(job.AgentID.String(), cmd); err != nil {
		log.Printf("[jobs] stop dispatch error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": fmt.Sprintf("failed to dispatch stop: %v", err)})
		return
	}

	// Mark as stopped immediately; the agent will confirm via job_status
	// but the user expects instant feedback.
	now := time.Now()
	db.Model(&job).Updates(map[string]interface{}{
		"status":      models.JobStopped,
		"finished_at": now,
	})

	agentID := job.AgentID
	writeAudit(c, db, &userID, &agentID, "job.stop", job.ID.String(), "stopped job")

	db.Preload("Agent").Preload("Tool").First(&job, "id = ?", job.ID)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": job})
}

// GetJob returns a single job by UUID, preloading Agent and Tool.
//
// GET /api/v1/jobs/:id
func GetJob(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid job ID"})
		return
	}

	var job models.Job
	if err := db.Preload("Agent").Preload("Tool").First(&job, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "job not found"})
			return
		}
		log.Printf("[jobs] get error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": job})
}

// StreamJobOutput streams real-time job output to the client using Server-Sent Events.
// Each output line from the agent is sent as `data: <line>\n\n`.
// A special `data: __DONE__\n\n` event signals completion.
//
// GET /api/v1/jobs/:id/output
func StreamJobOutput(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	hub, ok := mustGetHub(c)
	if !ok {
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid job ID"})
		return
	}

	// Verify the job exists.
	var job models.Job
	if err := db.First(&job, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "job not found"})
			return
		}
		log.Printf("[jobs] stream fetch error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	// If the job is already terminal, stream the buffered output and close.
	if job.Status == models.JobDone || job.Status == models.JobFailed || job.Status == models.JobStopped {
		c.Header("Content-Type", "text/event-stream")
		c.Header("Cache-Control", "no-cache")
		c.Header("Connection", "keep-alive")
		c.Header("X-Accel-Buffering", "no")

		lines := strings.Split(job.Output, "\n")
		for _, line := range lines {
			if line != "" {
				fmt.Fprintf(c.Writer, "data: %s\n\n", line)
			}
		}
		fmt.Fprintf(c.Writer, "data: __DONE__\n\n")
		c.Writer.Flush()
		return
	}

	// Subscribe to live output.
	ch := hub.SubscribeJobOutput(id.String())
	defer hub.UnsubscribeJobOutput(id.String(), ch)

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	c.Writer.WriteHeader(http.StatusOK)
	c.Writer.Flush()

	clientGone := c.Request.Context().Done()

	for {
		select {
		case <-clientGone:
			return
		case line, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(c.Writer, "data: %s\n\n", line)
			c.Writer.Flush()
			if line == "__DONE__" {
				return
			}
		}
	}
}

// DeleteJob removes a job record. Only terminal jobs (done or failed) may be deleted;
// running or pending jobs must be cancelled first.
//
// DELETE /api/v1/jobs/:id
func DeleteJob(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetUserID(c)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid job ID"})
		return
	}

	var job models.Job
	if err := db.First(&job, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "job not found"})
			return
		}
		log.Printf("[jobs] delete fetch error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	if job.Status != models.JobDone && job.Status != models.JobFailed && job.Status != models.JobStopped {
		c.JSON(http.StatusConflict, gin.H{"success": false, "error": fmt.Sprintf("cannot delete a job in status %q — stop it first", job.Status)})
		return
	}

	if err := db.Delete(&job).Error; err != nil {
		log.Printf("[jobs] db delete error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to delete job"})
		return
	}

	agentID := job.AgentID
	writeAudit(c, db, &userID, &agentID, "job.delete", id.String(), "deleted job")

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"id": id}})
}

// UploadArtifact accepts a multipart file upload from an agent after job completion.
// Authentication is via X-Agent-Token header.
//
// POST /api/v1/jobs/:id/artifact
func UploadArtifact(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	store, ok := mustGetStorage(c)
	if !ok {
		return
	}

	agentIDStr := middleware.GetAgentID(c)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid job ID"})
		return
	}

	var job models.Job
	if err := db.First(&job, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "job not found"})
			return
		}
		log.Printf("[jobs] artifact fetch error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	// Ensure the uploading agent owns the job.
	if job.AgentID.String() != agentIDStr {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "forbidden"})
		return
	}

	fileHeader, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "file is required"})
		return
	}

	f, err := fileHeader.Open()
	if err != nil {
		log.Printf("[jobs] open artifact: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to read artifact"})
		return
	}
	defer f.Close()

	artifactPath, err := store.SaveArtifact(id.String(), fileHeader.Filename, f)
	if err != nil {
		log.Printf("[jobs] save artifact: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to store artifact"})
		return
	}

	now := time.Now()
	updates := map[string]interface{}{
		"artifact_path": artifactPath,
		"status":        models.JobDone,
		"finished_at":   now,
	}
	if err := db.Model(&job).Updates(updates).Error; err != nil {
		log.Printf("[jobs] update after artifact: %v", err)
	}

	agentUUID, _ := uuid.Parse(agentIDStr)

	// Register the artifact into the Evidence Store so report-style outputs (e.g.
	// a YARA/HTML report) appear alongside collected tool results — viewable,
	// downloadable and AI-analyzable. Deduped by stored path.
	var agent models.Agent
	host := ""
	var caseID *uuid.UUID
	if db.First(&agent, "id = ?", agentUUID).Error == nil {
		host = agent.Hostname
		if host == "" {
			host = agent.Name
		}
		caseID = agent.CaseID
	}
	toolName := ""
	if job.ToolID != uuid.Nil {
		var tool models.Tool
		if db.Select("name").First(&tool, "id = ?", job.ToolID).Error == nil {
			toolName = tool.Name
		}
	}
	registerExistingEvidence(db, caseID, &agentUUID, host, "artifact", toolName, fileHeader.Filename, artifactPath, fileHeader.Size, "")

	writeAudit(c, db, nil, &agentUUID, "job.artifact", id.String(),
		fmt.Sprintf("artifact uploaded: %s", fileHeader.Filename))

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"job_id":        id,
			"artifact_path": artifactPath,
		},
	})
}

// mergeArgs combines default tool args with per-job override args.
func mergeArgs(defaultArgs, overrideArgs string) string {
	if overrideArgs != "" {
		return overrideArgs
	}
	return defaultArgs
}

// DownloadArtifact serves the job artifact file with a custom filename.
// GET /api/v1/jobs/:id/artifact/download
func DownloadArtifact(c *gin.Context) {
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
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid job ID"})
		return
	}

	var job models.Job
	if err := db.Preload("Agent").First(&job, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "job not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	if job.ArtifactPath == "" {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "artifact not found for this job"})
		return
	}

	fullPath := filepath.Join(store.BasePath, job.ArtifactPath)

	// Custom filename: <agent_name>_<timestamp>.html (or original ext)
	ext := filepath.Ext(fullPath)
	customName := fmt.Sprintf("%s_%s%s", job.Agent.Name, job.CreatedAt.Format("20060102_150405"), ext)

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Transfer-Encoding", "binary")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", customName))
	c.Header("Content-Type", "application/octet-stream")
	c.File(fullPath)
}

// GetArtifactContent returns the raw content of the artifact (primarily for HTML viewing).
// GET /api/v1/jobs/:id/artifact/content
func GetArtifactContent(c *gin.Context) {
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
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid job ID"})
		return
	}

	var job models.Job
	if err := db.First(&job, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "job not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	if job.ArtifactPath == "" {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "artifact not found"})
		return
	}

	fullPath := filepath.Join(store.BasePath, job.ArtifactPath)

	if strings.EqualFold(filepath.Ext(fullPath), ".zip") {
		z, err := zip.OpenReader(fullPath)
		if err == nil {
			defer z.Close()
			for _, f := range z.File {
				if strings.EqualFold(filepath.Ext(f.Name), ".html") {
					rc, err := f.Open()
					if err == nil {
						defer rc.Close()
						// Agent-produced HTML is untrusted — sandbox it so it renders
						// but cannot run script in the app origin.
						setInlineSafeHeaders(c)
						c.Header("Content-Type", "text/html")
						io.Copy(c.Writer, rc)
						return
					}
				}
			}
		}
	}

	setInlineSafeHeaders(c)
	c.File(fullPath)
}

// GetJobReport generates a self-contained HTML report from the job's accumulated
// output and serves it as an inline or downloadable file. Works for any job with
// output — no artifact upload required.
//
// GET /api/v1/jobs/:id/report?download=true
func GetJobReport(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid job ID"})
		return
	}

	var job models.Job
	if err := db.Preload("Agent").Preload("Tool").First(&job, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "job not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	agentName := "unknown"
	if job.Agent.Name != "" {
		agentName = job.Agent.Name
	}
	toolName := "unknown"
	if job.Tool.Name != "" {
		toolName = job.Tool.Name
	}

	started := ""
	finished := ""
	duration := ""
	if job.StartedAt != nil {
		started = job.StartedAt.UTC().Format(time.RFC3339)
	}
	if job.FinishedAt != nil {
		finished = job.FinishedAt.UTC().Format(time.RFC3339)
		if job.StartedAt != nil {
			d := job.FinishedAt.Sub(*job.StartedAt)
			if d.Seconds() < 60 {
				duration = fmt.Sprintf("%.1fs", d.Seconds())
			} else {
				duration = fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
			}
		}
	}

	lines := strings.Split(job.Output, "\n")

	html := buildJobReportHTML(jobReportData{
		JobID:      id.String(),
		ToolName:   toolName,
		AgentName:  agentName,
		Args:       job.Args,
		Status:     string(job.Status),
		StartedAt:  started,
		FinishedAt: finished,
		Duration:   duration,
		Lines:      lines,
	})

	download := c.Query("download") == "true"
	fname := fmt.Sprintf("job-report-%s-%s.html", safeFileSlug(agentName), id.String()[:8])
	if download {
		c.Header("Content-Disposition", `attachment; filename="`+fname+`"`)
	} else {
		c.Header("Content-Disposition", `inline; filename="`+fname+`"`)
	}
	setInlineSafeHeaders(c)
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}

type jobReportData struct {
	JobID      string
	ToolName   string
	AgentName  string
	Args       string
	Status     string
	StartedAt  string
	FinishedAt string
	Duration   string
	Lines      []string
}

func buildJobReportHTML(d jobReportData) string {
	statusColor := map[string]string{
		"done": "#22c55e", "failed": "#ef4444",
		"stopped": "#f59e0b", "running": "#3b82f6",
	}
	col, ok := statusColor[d.Status]
	if !ok {
		col = "#6b7280"
	}

	// Escape every interpolated field: tool name, agent name/hostname and args are
	// attacker-influenced (an agent registers its own hostname), so raw
	// concatenation into this inline-rendered HTML is a stored-XSS sink.
	tool := html.EscapeString(d.ToolName)
	agentName := html.EscapeString(d.AgentName)
	args := html.EscapeString(d.Args)
	status := html.EscapeString(strings.ToUpper(d.Status))
	started := html.EscapeString(d.StartedAt)
	finished := html.EscapeString(d.FinishedAt)
	duration := html.EscapeString(d.Duration)

	var outputHTML strings.Builder
	for _, line := range d.Lines {
		escaped := strings.ReplaceAll(line, "&", "&amp;")
		escaped = strings.ReplaceAll(escaped, "<", "&lt;")
		escaped = strings.ReplaceAll(escaped, ">", "&gt;")
		lower := strings.ToLower(line)
		cls := ""
		if strings.Contains(lower, "error") || strings.Contains(lower, "[!]") {
			cls = ` class="err"`
		} else if strings.Contains(lower, "found") || strings.Contains(lower, "[+]") {
			cls = ` class="ok"`
		} else if strings.Contains(lower, "warn") || strings.Contains(lower, "[?]") {
			cls = ` class="warn"`
		}
		outputHTML.WriteString(`<div` + cls + `>` + escaped + `</div>`)
	}

	return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Job Report — ` + tool + `</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;font-size:14px}
header{background:#1e293b;border-bottom:1px solid #334155;padding:14px 24px}
h1{font-size:17px;font-weight:700;color:#f8fafc}
.meta{display:flex;gap:20px;flex-wrap:wrap;padding:12px 24px;background:#1e293b;border-bottom:1px solid #334155}
.m{display:flex;flex-direction:column;gap:2px}
.ml{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.08em}
.mv{font-size:13px;color:#cbd5e1;font-weight:500}
.badge{display:inline-block;font-size:11px;font-weight:700;padding:2px 10px;border-radius:9999px;color:#fff;background:` + col + `}
.out{background:#020617;padding:16px 20px;font-family:'Cascadia Code','Fira Code',monospace;font-size:12px;line-height:1.7;white-space:pre-wrap;word-break:break-all;min-height:400px;margin:16px}
.out .err{color:#fca5a5}.out .ok{color:#86efac}.out .warn{color:#fde68a}
</style></head><body>
<header><h1>` + tool + ` — Job Report</h1></header>
<div class="meta">
<div class="m"><span class="ml">Status</span><span class="mv"><span class="badge">` + status + `</span></span></div>
<div class="m"><span class="ml">Agent</span><span class="mv">` + agentName + `</span></div>
<div class="m"><span class="ml">Args</span><span class="mv" style="font-family:monospace;font-size:12px">` + args + `</span></div>
<div class="m"><span class="ml">Started</span><span class="mv">` + started + `</span></div>
<div class="m"><span class="ml">Finished</span><span class="mv">` + finished + `</span></div>
<div class="m"><span class="ml">Duration</span><span class="mv">` + duration + `</span></div>
<div class="m"><span class="ml">Lines</span><span class="mv">` + fmt.Sprintf("%d", len(d.Lines)) + `</span></div>
</div>
<div class="out">` + outputHTML.String() + `</div>
</body></html>`
}

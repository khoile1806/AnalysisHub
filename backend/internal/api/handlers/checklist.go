package handlers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
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

type checklistBatchInput struct {
	BatchKey   string   `json:"batch_key"`
	BatchLabel string   `json:"batch_label"`
	ItemIDs    []string `json:"item_ids"`
	Command    string   `json:"command" binding:"required"`
}

type runChecklistRequest struct {
	AgentID  string                `json:"agent_id"  binding:"required"`
	Platform string                `json:"platform"  binding:"required"`
	Label    string                `json:"label"`
	CaseID   string                `json:"case_id"`
	Analyst  string                `json:"analyst"`
	Batches  []checklistBatchInput `json:"batches"   binding:"required,min=1"`
}

// RunChecklist creates a ChecklistRun, builds ChecklistBatch records, subscribes
// output persistence goroutines, then dispatches all batches simultaneously via
// the new cmd_exec WebSocket command.
//
// POST /api/v1/checklist/run
func RunChecklist(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	hub, ok := mustGetHub(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetUserID(c)

	var req runChecklistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	agentID, err := uuid.Parse(req.AgentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid agent_id"})
		return
	}

	var agent models.Agent
	if err := db.First(&agent, "id = ?", agentID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "agent not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "db error"})
		return
	}

	if !hub.IsAgentOnline(agentID.String()) {
		c.JSON(http.StatusConflict, gin.H{"success": false, "error": "agent is not online"})
		return
	}

	caseID := req.CaseID
	if caseID == "" && agent.CaseID != nil {
		caseID = agent.CaseID.String()
	}

	run := models.ChecklistRun{
		AgentID:   agentID,
		Label:     req.Label,
		Platform:  req.Platform,
		CaseID:    caseID,
		Analyst:   req.Analyst,
		Status:    "running",
		CreatedBy: userID,
	}
	if err := db.Create(&run).Error; err != nil {
		log.Printf("[checklist] create run: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to create run"})
		return
	}

	var batches []models.ChecklistBatch
	for _, b := range req.Batches {
		if strings.TrimSpace(b.Command) == "" {
			continue
		}
		itemIDsJSON, _ := json.Marshal(b.ItemIDs)
		batch := models.ChecklistBatch{
			RunID:      run.ID,
			AgentID:    agentID,
			BatchKey:   b.BatchKey,
			BatchLabel: b.BatchLabel,
			ItemIDs:    string(itemIDsJSON),
			Command:    b.Command,
			Platform:   req.Platform,
			Status:     "pending",
		}
		if err := db.Create(&batch).Error; err != nil {
			log.Printf("[checklist] create batch %s: %v", b.BatchKey, err)
			continue
		}
		batches = append(batches, batch)
	}

	if len(batches) == 0 {
		db.Delete(&run)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "no valid batches to dispatch"})
		return
	}

	// Subscribe output persistence goroutines BEFORE dispatching so no output is lost.
	for i := range batches {
		batch := batches[i]
		batchIDStr := batch.ID.String()
		ch := hub.SubscribeJobOutput(batchIDStr)

		go func(b models.ChecklistBatch, ch chan string) {
			defer hub.UnsubscribeJobOutput(b.ID.String(), ch)

			now := time.Now()
			db.Model(&b).Updates(map[string]interface{}{
				"status":     "running",
				"started_at": now,
			})

			storagePath := os.Getenv("STORAGE_PATH")
			if storagePath == "" {
				storagePath = "/app/storage"
			}
			outDir := filepath.Join(storagePath, "checklists")
			os.MkdirAll(outDir, 0755)

			outFilePath := filepath.Join(outDir, b.ID.String()+".txt")
			file, err := os.OpenFile(outFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				log.Printf("[checklist] failed to open output file: %v", err)
			} else {
				defer file.Close()
			}

			// Accumulate output in memory so it can be saved to the DB column
			// even when the file is unavailable (e.g. path issues on Windows dev).
			var outputBuf strings.Builder

			for line := range ch {
				if line == "__DONE__" {
					break
				}
				outputBuf.WriteString(line)
				outputBuf.WriteString("\n")
				if file != nil {
					file.WriteString(line + "\n")
				}
			}

			finishedAt := time.Now()
			db.Model(&b).Updates(map[string]interface{}{
				"status":      "done",
				"output":      outputBuf.String(), // always persist real output to DB
				"finished_at": finishedAt,
			})

			// Mark run as done when all batches finish.
			var pendingCount int64
			db.Model(&models.ChecklistBatch{}).
				Where("run_id = ? AND status NOT IN ('done','failed','stopped')", b.RunID).
				Count(&pendingCount)
			if pendingCount == 0 {
				db.Model(&models.ChecklistRun{}).Where("id = ?", b.RunID).Update("status", "done")
			}
		}(batch, ch)
	}

	// Dispatch all batches simultaneously.
	for _, batch := range batches {
		cmd := ws.AgentCommand{
			Type:  "cmd_exec",
			JobID: batch.ID.String(),
			Args:  batch.Command,
		}
		if dispatchErr := hub.SendJobToAgent(agentID.String(), cmd); dispatchErr != nil {
			log.Printf("[checklist] dispatch batch %s: %v", batch.BatchKey, dispatchErr)
			db.Model(&batch).Updates(map[string]interface{}{
				"status": "failed",
				"output": fmt.Sprintf("dispatch error: %v", dispatchErr),
			})
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data": gin.H{
			"run_id":  run.ID,
			"batches": batches,
		},
	})
}

// ListChecklistRuns returns all runs optionally filtered by agent_id.
//
// GET /api/v1/checklist/runs
func ListChecklistRuns(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}

	query := db.Model(&models.ChecklistRun{})
	if agentID := c.Query("agent_id"); agentID != "" {
		query = query.Where("agent_id = ?", agentID)
	}

	var runs []models.ChecklistRun
	if err := query.Preload("Batches").Order("created_at desc").Find(&runs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "db error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": runs})
}

// GetChecklistRun returns a single run with all its batches.
//
// GET /api/v1/checklist/runs/:id
func GetChecklistRun(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid run ID"})
		return
	}

	var run models.ChecklistRun
	if err := db.Preload("Batches").First(&run, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "run not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "db error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": run})
}

// StreamBatchOutput streams real-time output for one batch via Server-Sent Events.
// If the batch is already complete, buffered output is replayed from the DB.
//
// GET /api/v1/checklist/batches/:id/output
func StreamBatchOutput(c *gin.Context) {
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
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid batch ID"})
		return
	}

	var batch models.ChecklistBatch
	if err := db.First(&batch, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "batch not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "db error"})
		return
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	if batch.Status == "done" || batch.Status == "failed" || batch.Status == "stopped" {
		storagePath := os.Getenv("STORAGE_PATH")
		if storagePath == "" {
			storagePath = "/app/storage"
		}
		filePath := filepath.Join(storagePath, "checklists", batch.ID.String()+".txt")
		file, err := os.Open(filePath)
		if err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				fmt.Fprintf(c.Writer, "data: %s\n\n", scanner.Text())
			}
		} else {
			for _, line := range strings.Split(batch.Output, "\n") {
				if line != "" {
					fmt.Fprintf(c.Writer, "data: %s\n\n", line)
				}
			}
		}
		fmt.Fprintf(c.Writer, "data: __DONE__\n\n")
		c.Writer.Flush()
		return
	}

	ch := hub.SubscribeJobOutput(id.String())
	defer hub.UnsubscribeJobOutput(id.String(), ch)

	c.Writer.WriteHeader(http.StatusOK)
	c.Writer.Flush()

	clientGone := c.Request.Context().Done()

	// Poll fallback: if the batch finished before our subscription was registered
	// (race: fast command completes before the browser opens the SSE connection),
	// __DONE__ was broadcast to no subscribers and the channel will never receive
	// it. We detect this by polling the DB every second while no live output has
	// arrived; once we see status=done we replay from DB and send __DONE__.
	pollTicker := time.NewTicker(1 * time.Second)
	defer pollTicker.Stop()
	receivedAny := false

	for {
		select {
		case <-clientGone:
			return
		case line, ok := <-ch:
			receivedAny = true
			if !ok {
				return
			}
			fmt.Fprintf(c.Writer, "data: %s\n\n", line)
			c.Writer.Flush()
			if line == "__DONE__" {
				return
			}
		case <-pollTicker.C:
			if receivedAny {
				// Live stream is active — no need to poll DB.
				continue
			}
			if err := db.First(&batch, "id = ?", id).Error; err != nil {
				continue
			}
			if batch.Status == "done" || batch.Status == "failed" || batch.Status == "stopped" {
				storagePath := os.Getenv("STORAGE_PATH")
				if storagePath == "" {
					storagePath = "/app/storage"
				}
				filePath := filepath.Join(storagePath, "checklists", batch.ID.String()+".txt")
				file, err := os.Open(filePath)
				if err == nil {
					defer file.Close()
					scanner := bufio.NewScanner(file)
					for scanner.Scan() {
						fmt.Fprintf(c.Writer, "data: %s\n\n", scanner.Text())
					}
				} else {
					for _, line := range strings.Split(batch.Output, "\n") {
						if line != "" {
							fmt.Fprintf(c.Writer, "data: %s\n\n", line)
						}
					}
				}
				fmt.Fprintf(c.Writer, "data: __DONE__\n\n")
				c.Writer.Flush()
				return
			}
		}
	}
}

// DownloadBatchOutput returns the raw text output of a batch.
// GET /api/v1/checklist/batches/:id/download
func DownloadBatchOutput(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var batch models.ChecklistBatch
	if err := db.First(&batch, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	storagePath := os.Getenv("STORAGE_PATH")
	if storagePath == "" {
		storagePath = "/app/storage"
	}
	filePath := filepath.Join(storagePath, "checklists", batch.ID.String()+".txt")

	if _, err := os.Stat(filePath); err == nil {
		c.File(filePath)
		return
	}

	// Fallback to database output
	c.String(http.StatusOK, batch.Output)
}

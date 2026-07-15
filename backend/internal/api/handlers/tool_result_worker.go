package handlers

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/config"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/storage"
	"github.com/analysishub/backend/internal/toolproc"
)

// toolResultTick is how often the queue of unprocessed results is drained.
const toolResultTick = 3 * time.Second

// Auto-analyze concurrency guard: bound background AI runs and never analyze the
// same job twice at once (a re-run is idempotent via the timeline dedupe key, but
// this avoids wasted AI calls).
var (
	autoAnalyzeSem = make(chan struct{}, 2)
	analyzingMu    sync.Mutex
	analyzingJobs  = map[uuid.UUID]bool{}
)

// StartToolResultWorker runs the async raw-data processing step for collected
// tool results, off the upload request path so a multi-GB Redline/KAPE parse
// never blocks the agent's upload. Results are picked up in FIFO order; each is
// classified, normalized and summarized by the toolproc registry. When a tool
// opts into AutoAnalyze, findings extraction is triggered once its job finishes.
func StartToolResultWorker(db *gorm.DB, store *storage.LocalStorage, cfg *config.Config) {
	db.Model(&models.ToolResult{}).
		Where("process_status = ?", "processing").
		Update("process_status", "queued")

	log.Println("[tool-result-processor] starting...")
	go runWorker("tool-result-processor", toolResultTick, func() { processQueuedResults(db, store, cfg) })
}

func processQueuedResults(db *gorm.DB, store *storage.LocalStorage, cfg *config.Config) {
	var batch []models.ToolResult
	if err := db.Where("process_status = ?", "queued").
		Order("created_at asc").Limit(8).Find(&batch).Error; err != nil {
		return
	}
	for i := range batch {
		tr := &batch[i]
		claim := db.Model(&models.ToolResult{}).
			Where("id = ? AND process_status = ?", tr.ID, "queued").
			Update("process_status", "processing")
		if claim.RowsAffected == 0 {
			continue
		}
		processOneResult(db, store, cfg, tr)
	}
}

func processOneResult(db *gorm.DB, store *storage.LocalStorage, cfg *config.Config, tr *models.ToolResult) {
	defer func() {
		if r := recover(); r != nil {
			db.Model(&models.ToolResult{}).Where("id = ?", tr.ID).Updates(map[string]interface{}{
				"process_status": "error",
				"process_error":  fmt.Sprintf("panic: %v", r),
			})
			log.Printf("[tool-result-processor] PANIC on %s: %v", tr.ID, r)
		}
	}()

	// Load the tool (name + AI default) once.
	var tool models.Tool
	toolName := tr.ToolName
	haveTool := tr.ToolID != uuid.Nil && db.First(&tool, "id = ?", tr.ToolID).Error == nil
	if haveTool {
		toolName = tool.Name
	}

	var kind, processor, parsedRel, summary string
	var rowCount int
	var forAI bool

	// #1 dedup: if the SAME tool already produced an identical file (same sha256),
	// reuse its parsed outcome instead of re-parsing — identical content from the
	// same tool yields an identical result, so this is safe and saves the work.
	deduped := false
	if tr.Sha256 != "" && tr.ToolID != uuid.Nil {
		var twin models.ToolResult
		if db.Where("sha256 = ? AND tool_id = ? AND process_status = ? AND id <> ?",
			tr.Sha256, tr.ToolID, "done", tr.ID).Order("created_at asc").First(&twin).Error == nil {
			kind, processor, parsedRel = twin.Kind, twin.Processor, twin.ParsedStoredPath
			rowCount, summary, forAI = twin.RowCount, twin.Summary, twin.ForAI
			deduped = true
		}
	}

	if !deduped {
		outcome := toolproc.Process(tr.Processor, store.AbsPath(tr.RawStoredPath), store.ToolResultDir(tr.JobID.String()))
		if outcome.ParsedAbs != "" {
			if rel, err := filepath.Rel(store.BasePath, outcome.ParsedAbs); err == nil {
				parsedRel = rel
			}
		}
		kind, processor, rowCount, summary = outcome.Kind, outcome.Processor, outcome.RowCount, outcome.Summary
		forAI = outcome.AIWorthy
		if haveTool {
			forAI = tool.AIDefault && outcome.AIWorthy
		}
	}

	db.Model(&models.ToolResult{}).Where("id = ?", tr.ID).Updates(map[string]interface{}{
		"tool_name":          toolName,
		"kind":               kind,
		"processor":          processor,
		"parsed_stored_path": parsedRel,
		"row_count":          rowCount,
		"summary":            summary,
		"for_ai":             forAI,
		"process_status":     "done",
		"process_error":      "",
	})

	// Register the collected result into the central Evidence Store (references
	// the already-stored raw file; deduped by path).
	var agent models.Agent
	if db.First(&agent, "id = ?", tr.AgentID).Error == nil {
		host := agent.Hostname
		if host == "" {
			host = agent.Name
		}
		registerExistingEvidence(db, agent.CaseID, &tr.AgentID, host, "tool-result", toolName, tr.FileName, tr.RawStoredPath, tr.SizeBytes, tr.Sha256)
	}

	// Close the loop: if this result is for AI and the tool opted into
	// auto-analysis, kick off findings extraction in the background (once the
	// whole job is finished and all its results are processed).
	if forAI && cfg != nil && tool.AutoAnalyze {
		go func(jid uuid.UUID) {
			autoAnalyzeSem <- struct{}{}
			defer func() { <-autoAnalyzeSem }()
			maybeAutoAnalyze(db, store, cfg, jid)
		}(tr.JobID)
	}
}

// maybeAutoAnalyze runs findings extraction for a job exactly once, after the
// agent has finished the job AND every collected result has been processed.
func maybeAutoAnalyze(db *gorm.DB, store *storage.LocalStorage, cfg *config.Config, jobID uuid.UUID) {
	// Fire once per job.
	analyzingMu.Lock()
	if analyzingJobs[jobID] {
		analyzingMu.Unlock()
		return
	}
	analyzingJobs[jobID] = true
	analyzingMu.Unlock()
	defer func() {
		analyzingMu.Lock()
		delete(analyzingJobs, jobID)
		analyzingMu.Unlock()
	}()

	// Wait until no result for this job is still queued/processing.
	var pending int64
	db.Model(&models.ToolResult{}).
		Where("job_id = ? AND process_status IN ?", jobID, []string{"queued", "processing"}).
		Count(&pending)
	if pending > 0 {
		return
	}

	var job models.Job
	if db.Preload("Agent").Preload("Tool").First(&job, "id = ?", jobID).Error != nil {
		return
	}
	if !job.Tool.AutoAnalyze {
		return
	}
	// Only after the agent finished the job, so all results are in.
	if job.Status != models.JobDone && job.Status != models.JobFailed && job.Status != models.JobStopped {
		return
	}
	if job.Agent.CaseID == nil {
		return // findings need a case to land on the timeline
	}

	h := NewAIHandler(db, store, cfg, nil)
	provider, client, err := h.resolveProvider("")
	if err != nil {
		return // no AI provider configured → skip silently (manual analyze still works)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	f, cr, ic, aerr := h.analyzeOneJob(ctx, &job, *job.Agent.CaseID, client, provider.MaxTokens, uuid.UUID{})
	if aerr != nil {
		log.Printf("[tool-result-processor] auto-analyze job %s failed: %v", jobID, aerr)
		return
	}
	if f > 0 {
		log.Printf("[tool-result-processor] auto-analyzed job %s: %d finding(s) -> %d event(s), %d IOC(s)", jobID, f, cr, ic)
	}
}

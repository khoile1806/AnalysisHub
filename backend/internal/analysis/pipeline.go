package analysis

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/storage"
)

// Source describes where an analysis pulls its evidence from.
type Source struct {
	Type       string // job | checklist_run | elk_result | upload | offline_report
	ID         string // UUID of the source (empty for uploads)
	UploadPath string // relative upload path (upload / offline_report)
}

// Pipeline turns a Source into bounded text ready for an AI prompt. It owns the
// per-source collectors and the (future) pre-filter/budget stages so that every
// AI feature collects evidence the same way instead of duplicating the logic.
type Pipeline struct {
	db    *gorm.DB
	store *storage.LocalStorage
}

// NewPipeline builds a Pipeline bound to the given DB and storage.
func NewPipeline(db *gorm.DB, store *storage.LocalStorage) *Pipeline {
	return &Pipeline{db: db, store: store}
}

// Collect gathers text content from the source.
func (p *Pipeline) Collect(source Source) (string, error) {
	switch source.Type {
	case "job":
		return p.collectJob(source.ID)
	case "checklist_run":
		return p.collectChecklistRun(source.ID)
	case "elk_result":
		return p.collectELKResult(source.ID)
	case "upload":
		return p.collectUpload(source.UploadPath)
	case "offline_report":
		return p.collectOfflineReport(source.UploadPath)
	default:
		return "", fmt.Errorf("unknown source type: %q", source.Type)
	}
}

func (p *Pipeline) collectJob(jobIDStr string) (string, error) {
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		return "", fmt.Errorf("invalid job ID: %w", err)
	}
	var job models.Job
	if err := p.db.Preload("Tool").Preload("Agent").First(&job, "id = ?", jobID).Error; err != nil {
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

	// If there's a JSON artifact, include it (capped at 16KB).
	if job.ArtifactPath != "" {
		fullPath := p.store.GetArtifactByRelPath(job.ArtifactPath)
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

func (p *Pipeline) collectChecklistRun(runIDStr string) (string, error) {
	runID, err := uuid.Parse(runIDStr)
	if err != nil {
		return "", fmt.Errorf("invalid run ID: %w", err)
	}
	var run models.ChecklistRun
	if err := p.db.Preload("Batches").First(&run, "id = ?", runID).Error; err != nil {
		return "", fmt.Errorf("checklist run not found: %w", err)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "=== EVIDENCE COLLECTION CHECKLIST RESULTS ===\n")
	fmt.Fprintf(&sb, "Platform: %s | Analyst: %s | Label: %s\n", run.Platform, run.Analyst, run.Label)
	fmt.Fprintf(&sb, "Status: %s | Created: %s\n\n", run.Status, run.CreatedAt.Format(time.RFC3339))

	// Per-batch cap: keep first 2KB of each batch output. The total is further
	// capped by the caller's content budget.
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

func (p *Pipeline) collectELKResult(resultIDStr string) (string, error) {
	resultID, err := uuid.Parse(resultIDStr)
	if err != nil {
		return "", fmt.Errorf("invalid ELK result ID: %w", err)
	}
	var result models.ELKHuntResult
	if err := p.db.First(&result, "id = ?", resultID).Error; err != nil {
		return "", fmt.Errorf("ELK result not found: %w", err)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "=== ELK THREAT HUNT RESULTS ===\n")
	fmt.Fprintf(&sb, "Title: %s\n", result.Title)
	fmt.Fprintf(&sb, "IOCs used: %d | Total hits: %d | Status: %s\n\n", result.IOCsUsed, result.TotalHits, result.Status)

	if result.Results != "" {
		data := result.Results
		if len(data) > 16*1024 {
			data = data[:16*1024] + "\n... [truncated]"
		}
		sb.WriteString("=== HITS ===\n")
		sb.WriteString(data)
	}
	return sb.String(), nil
}

// collectOfflineReport reads and formats an offline-agent JSON report for AI
// analysis. Each tool's output is included up to 4 KB; total is further capped
// by the caller's content budget.
func (p *Pipeline) collectOfflineReport(uploadPath string) (string, error) {
	if uploadPath == "" {
		return "", fmt.Errorf("no upload file associated with this session")
	}
	fullPath := p.store.GetAnalysisUploadPath(uploadPath)
	raw, err := os.ReadFile(fullPath)
	if err != nil {
		return "", fmt.Errorf("read offline report: %w", err)
	}

	var rep models.OfflineReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		// Not a valid bundle JSON — treat as plain text
		return string(raw), nil
	}

	var sb strings.Builder
	sb.WriteString("=== ANALYSISHUB OFFLINE HUNTING REPORT ===\n")
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

// collectUpload reads a sampled portion of the uploaded file without loading the
// whole thing into memory. Memory dumps and disk images can be multiple
// gigabytes; reading them whole OOMs the server. Instead we sample head/middle/
// tail (≤ 2 MB total). For binary uploads the caller runs ExtractStrings next.
func (p *Pipeline) collectUpload(uploadPath string) (string, error) {
	if uploadPath == "" {
		return "", fmt.Errorf("no upload file associated with this session")
	}
	fullPath := p.store.GetAnalysisUploadPath(uploadPath)

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
		middleBytes = 512 * 1024      // 512 KB from middle
		tailBytes   = 512 * 1024      // 512 KB from end
	)

	if size <= int64(headBytes+middleBytes+tailBytes) {
		data, rerr := io.ReadAll(io.LimitReader(f, int64(headBytes+middleBytes+tailBytes)))
		if rerr != nil {
			return "", fmt.Errorf("read upload file: %w", rerr)
		}
		return string(data), nil
	}

	var sb strings.Builder
	sb.Grow(headBytes + middleBytes + tailBytes + 64)

	head := make([]byte, headBytes)
	n, _ := io.ReadFull(f, head)
	sb.Write(head[:n])

	midOffset := (size / 2) - int64(middleBytes/2)
	if _, seekErr := f.Seek(midOffset, io.SeekStart); seekErr == nil {
		mid := make([]byte, middleBytes)
		n, _ = io.ReadFull(f, mid)
		sb.WriteString("\n\n[... middle sample ...]\n\n")
		sb.Write(mid[:n])
	}

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

// ExtractStrings extracts printable ASCII sequences (≥4 chars) from binary data,
// returning at most maxBytes of extracted strings.
func ExtractStrings(data string, maxBytes int) string {
	raw := []byte(data)
	var sb strings.Builder
	var current strings.Builder

	for _, b := range raw {
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

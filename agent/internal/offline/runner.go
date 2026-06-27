package offline

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/forensichub/agent/internal/executor"
)

// JobStatus mirrors the online-agent job lifecycle but lives entirely in
// memory — no server, no WebSocket.
type JobStatus string

const (
	StatusPending JobStatus = "pending"
	StatusRunning JobStatus = "running"
	StatusDone    JobStatus = "done"
	StatusFailed  JobStatus = "failed"
	StatusStopped JobStatus = "stopped"
)

// Job is an in-memory record of one tool execution.
type Job struct {
	ID         string
	ToolID     string
	ToolName   string
	Args       string
	Status     JobStatus
	StartedAt  *time.Time
	FinishedAt *time.Time
	Output     []string // accumulated output lines
	Error      string   // non-empty on failure

	cancel context.CancelFunc
}

// Runner manages all offline jobs. It is safe for concurrent use.
type Runner struct {
	mu   sync.RWMutex
	jobs []*Job
	seq  int

	// subscribers: jobID → list of channels receiving output lines.
	subsMu      sync.Mutex
	subscribers map[string][]chan string
}

// NewRunner creates an empty offline runner.
func NewRunner() *Runner {
	return &Runner{
		subscribers: make(map[string][]chan string),
	}
}

// StartJob resolves the tool from the manifest and begins execution in a
// goroutine. Returns the new job immediately; callers should subscribe via
// Subscribe() before calling StartJob if they need every line.
func (r *Runner) StartJob(tool BundleTool, customArgs string) (*Job, error) {
	// bundleRoot is the directory containing the agent binary, bundle.json and
	// the tools/ subdirectory. The executor's prepareToolDir appends
	// "tools/<toolID>" itself, so we must pass the bundle root here — passing
	// the tools dir would produce a doubled "tools/tools/<toolID>" path.
	bundleRoot, err := bundleDir()
	if err != nil {
		return nil, fmt.Errorf("resolve bundle dir: %w", err)
	}
	toolDir, err := ToolDir(tool.ID)
	if err != nil {
		return nil, fmt.Errorf("resolve tool dir: %w", err)
	}

	args := tool.DefaultArgs
	if strings.TrimSpace(customArgs) != "" {
		args = customArgs
	}

	// Validate executable path exists before starting the job.
	if _, err := resolveExecutable(tool, toolDir); err != nil {
		return nil, fmt.Errorf("resolve executable: %w", err)
	}

	r.mu.Lock()
	r.seq++
	job := &Job{
		ID:       fmt.Sprintf("job-%d", r.seq),
		ToolID:   tool.ID,
		ToolName: tool.Name,
		Args:     args,
		Status:   StatusRunning,
	}
	now := time.Now()
	job.StartedAt = &now
	r.jobs = append(r.jobs, job)
	r.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	job.cancel = cancel

	req := executor.JobRequest{
		JobID:          job.ID,
		ToolID:         tool.ID,
		ToolName:       tool.Name,
		FileName:       tool.FileName,
		ExecutablePath: tool.ExecutablePath,
		Args:           args,
		// No DownloadURL / AgentToken / ServerURL — fully offline.
	}

	outputCh := make(chan string, 256)

	// Single consumer: forward every line in order until ExecuteJob closes the
	// channel. Using one consumer (not two) guarantees output ordering — two
	// concurrent `range` loops would split buffered lines arbitrarily on close.
	consumerDone := make(chan struct{})
	go func() {
		for line := range outputCh {
			r.appendLine(job, line)
			r.broadcast(job.ID, line, false)
		}
		close(consumerDone)
	}()

	go func() {
		err := executor.ExecuteJob(ctx, req, bundleRoot, outputCh)
		fin := time.Now()

		r.mu.Lock()
		job.FinishedAt = &fin
		if err != nil {
			if ctx.Err() != nil {
				job.Status = StatusStopped
			} else {
				job.Status = StatusFailed
				job.Error = err.Error()
			}
		} else {
			job.Status = StatusDone
		}
		r.mu.Unlock()

		<-consumerDone                // wait until all lines are flushed in order
		r.broadcast(job.ID, "", true) // signal done to all SSE subscribers
		cancel()
	}()

	return job, nil
}

// StopJob cancels a running job.
func (r *Runner) StopJob(jobID string) {
	r.mu.RLock()
	job := r.findLocked(jobID)
	r.mu.RUnlock()
	if job != nil && job.cancel != nil {
		job.cancel()
	}
}

// ListJobs returns a snapshot of all jobs (copy, safe to read without lock).
func (r *Runner) ListJobs() []Job {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Job, len(r.jobs))
	for i, j := range r.jobs {
		out[i] = *j
	}
	return out
}

// GetJob returns a copy of the job, or nil if not found.
func (r *Runner) GetJob(jobID string) *Job {
	r.mu.RLock()
	j := r.findLocked(jobID)
	r.mu.RUnlock()
	if j == nil {
		return nil
	}
	cp := *j
	return &cp
}

// Subscribe registers a channel that will receive output lines for jobID.
// Callers must drain the channel; it is closed when the job finishes.
// Returns a snapshot of output lines already accumulated so callers can
// replay history before the live stream begins.
func (r *Runner) Subscribe(jobID string) (history []string, ch chan string) {
	ch = make(chan string, 256)

	r.mu.RLock()
	job := r.findLocked(jobID)
	if job != nil {
		history = make([]string, len(job.Output))
		copy(history, job.Output)
	}
	r.mu.RUnlock()

	r.subsMu.Lock()
	r.subscribers[jobID] = append(r.subscribers[jobID], ch)
	r.subsMu.Unlock()

	return history, ch
}

// Unsubscribe removes a channel from the subscriber list.
func (r *Runner) Unsubscribe(jobID string, ch chan string) {
	r.subsMu.Lock()
	defer r.subsMu.Unlock()
	list := r.subscribers[jobID]
	for i, c := range list {
		if c == ch {
			r.subscribers[jobID] = append(list[:i], list[i+1:]...)
			break
		}
	}
}

// --- internal helpers ---

func (r *Runner) appendLine(job *Job, line string) {
	r.mu.Lock()
	job.Output = append(job.Output, line)
	r.mu.Unlock()
}

func (r *Runner) broadcast(jobID, line string, done bool) {
	r.subsMu.Lock()
	subs := make([]chan string, len(r.subscribers[jobID]))
	copy(subs, r.subscribers[jobID])
	if done {
		delete(r.subscribers, jobID)
	}
	r.subsMu.Unlock()

	for _, ch := range subs {
		if done {
			close(ch)
		} else {
			select {
			case ch <- line:
			default:
			}
		}
	}
}

func (r *Runner) findLocked(jobID string) *Job {
	for _, j := range r.jobs {
		if j.ID == jobID {
			return j
		}
	}
	return nil
}

// resolveExecutable resolves the executable path from template placeholders
// and returns the full absolute path.
func resolveExecutable(tool BundleTool, toolDir string) (string, error) {
	ep := tool.ExecutablePath
	if ep == "" {
		// Single-file tool: use FileName directly.
		ep = tool.FileName
	}
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	ep = strings.ReplaceAll(ep, "{{OS}}", runtime.GOOS)
	ep = strings.ReplaceAll(ep, "{{EXT}}", ext)
	full := filepath.Join(toolDir, filepath.FromSlash(ep))
	return full, nil
}

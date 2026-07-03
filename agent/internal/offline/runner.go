package offline

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/analysishub/agent/internal/executor"
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
	Output     []string  // accumulated output lines
	Error      string    // non-empty on failure
	Findings   []Finding // triage findings parsed from output on completion

	cancel context.CancelFunc
}

// Runner manages all offline jobs. It is safe for concurrent use.
type Runner struct {
	mu   sync.RWMutex
	jobs []*Job
	seq  int

	// Operator-set resource throttle applied to every job (single + batch) so a
	// heavy tool can't peg the responder's machine during live hunting. Zero
	// limits = unthrottled (full speed). Guarded by limMu.
	limMu    sync.RWMutex
	cpuLimit int    // hard CPU cap, percent of total system (0 = none)
	ramLimit int    // hard RAM cap, MB (0 = none)
	priority string // "normal" or "idle" (lowest scheduling priority)

	// subscribers: jobID → list of channels receiving output lines.
	subsMu      sync.Mutex
	subscribers map[string][]chan string
}

// SetLimits updates the global resource throttle applied to subsequent jobs.
// cpuPercent/ramMB of 0 disable the respective cap; priority is "normal"|"idle".
func (r *Runner) SetLimits(cpuPercent, ramMB int, priority string) {
	if priority != "idle" {
		priority = "normal"
	}
	if cpuPercent < 0 {
		cpuPercent = 0
	}
	if ramMB < 0 {
		ramMB = 0
	}
	r.limMu.Lock()
	r.cpuLimit, r.ramLimit, r.priority = cpuPercent, ramMB, priority
	r.limMu.Unlock()
}

// Limits returns the current global throttle (cpuPercent, ramMB, priority).
func (r *Runner) Limits() (int, int, string) {
	r.limMu.RLock()
	defer r.limMu.RUnlock()
	prio := r.priority
	if prio == "" {
		prio = "normal"
	}
	return r.cpuLimit, r.ramLimit, prio
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

	cpuLimit, ramLimit, priority := r.Limits()
	req := executor.JobRequest{
		JobID:          job.ID,
		ToolID:         tool.ID,
		ToolName:       tool.Name,
		FileName:       tool.FileName,
		ExecutablePath: tool.ExecutablePath,
		Args:           args,
		CPULimit:       cpuLimit,
		RAMLimit:       ramLimit,
		Priority:       priority,
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

		<-consumerDone // wait until all lines are flushed in order BEFORE parsing findings

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
		job.Findings = extractFindings(job.ToolName, job.Status, job.Output)
		r.mu.Unlock()

		r.broadcast(job.ID, "", true) // signal done to all SSE subscribers
		cancel()
	}()

	return job, nil
}

// RunBatch runs an ordered set of steps sequentially in the background (one
// tool finishes before the next starts), so a "Collect Everything" doesn't
// storm a live machine with parallel heavy collectors. Returns the number of
// steps that resolved to a runnable tool.
func (r *Runner) RunBatch(steps []PlaybookStep, manifest *BundleManifest) int {
	type resolved struct {
		tool BundleTool
		args string
	}
	var queue []resolved
	for _, st := range steps {
		for i := range manifest.Tools {
			if manifest.Tools[i].ID == st.ToolID {
				queue = append(queue, resolved{tool: manifest.Tools[i], args: st.Args})
				break
			}
		}
	}
	go func() {
		for _, q := range queue {
			job, err := r.StartJob(q.tool, q.args)
			if err != nil {
				continue
			}
			r.waitJob(job.ID)
		}
	}()
	return len(queue)
}

// waitJob blocks until the job leaves the running/pending state.
func (r *Runner) waitJob(jobID string) {
	_, ch := r.Subscribe(jobID)
	defer r.Unsubscribe(jobID, ch)
	// Guard the race where the job finished between StartJob and Subscribe (the
	// done-broadcast already deleted subscribers, so ch would never close).
	if j := r.GetJob(jobID); j != nil && j.Status != StatusRunning && j.Status != StatusPending {
		return
	}
	for range ch { // drain until the channel is closed on completion
	}
}

// AllFindings returns every job's findings, most-severe first.
func (r *Runner) AllFindings() []Finding {
	r.mu.RLock()
	var all []Finding
	for _, j := range r.jobs {
		all = append(all, j.Findings...)
	}
	r.mu.RUnlock()
	sort.SliceStable(all, func(i, k int) bool {
		return sevRank(all[i].Severity) > sevRank(all[k].Severity)
	})
	return all
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

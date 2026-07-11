package handlers

import (
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
)

// JobOutputBuffer coalesces streamed job output so the DB sees one batched
// append per job every flush interval instead of one UPDATE per line. Buffering
// under a single mutex also keeps a job's lines in arrival order, fixing the
// out-of-order transcript that per-line concurrent UPDATEs could produce.
type JobOutputBuffer struct {
	db       *gorm.DB
	interval time.Duration
	mu       sync.Mutex
	pending  map[string]*strings.Builder
	stop     chan struct{}
	stopped  bool
}

// NewJobOutputBuffer starts a batched output writer flushing every interval
// (defaults to 500ms). Call Stop() on shutdown to flush and end the goroutine.
func NewJobOutputBuffer(db *gorm.DB, interval time.Duration) *JobOutputBuffer {
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	b := &JobOutputBuffer{
		db:       db,
		interval: interval,
		pending:  make(map[string]*strings.Builder),
		stop:     make(chan struct{}),
	}
	go b.loop()
	return b
}

// Append queues one output line (a trailing newline is added) for a job.
func (b *JobOutputBuffer) Append(jobID, line string) {
	b.mu.Lock()
	sb := b.pending[jobID]
	if sb == nil {
		sb = &strings.Builder{}
		b.pending[jobID] = sb
	}
	sb.WriteString(line)
	sb.WriteString("\n")
	b.mu.Unlock()
}

// Flush writes and clears the buffered output for one job. Deleting the entry
// under the lock guarantees the buffered text is appended by exactly one Exec.
func (b *JobOutputBuffer) Flush(jobID string) {
	b.mu.Lock()
	sb := b.pending[jobID]
	if sb == nil || sb.Len() == 0 {
		b.mu.Unlock()
		return
	}
	data := sb.String()
	delete(b.pending, jobID)
	b.mu.Unlock()

	b.db.Exec("UPDATE jobs SET output = COALESCE(output, '') || ? WHERE id = ?", data, jobID)
}

func (b *JobOutputBuffer) flushAll() {
	b.mu.Lock()
	ids := make([]string, 0, len(b.pending))
	for id := range b.pending {
		ids = append(ids, id)
	}
	b.mu.Unlock()
	for _, id := range ids {
		b.Flush(id)
	}
}

func (b *JobOutputBuffer) loop() {
	t := time.NewTicker(b.interval)
	defer t.Stop()
	for {
		select {
		case <-b.stop:
			b.flushAll()
			return
		case <-t.C:
			b.flushAll()
		}
	}
}

// Stop flushes any remaining buffered output and stops the writer goroutine.
func (b *JobOutputBuffer) Stop() {
	b.mu.Lock()
	if b.stopped {
		b.mu.Unlock()
		return
	}
	b.stopped = true
	b.mu.Unlock()
	close(b.stop)
}

// Package vulnscan runs active vulnerability scans (httpx + nuclei) against
// assets discovered by the OSINT module. It mirrors the OSINT engine's shape —
// bounded concurrent scans, per-scan SSE fan-out, context cancellation — but
// drives external scanner binaries instead of in-process collectors, so it is
// admin-gated, scope-checked and routed through the configured egress proxy.
package vulnscan

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/config"
	"github.com/forensichub/backend/internal/models"
)

// histCap bounds the in-memory SSE replay buffer per scan.
const histCap = 4000

// historyTTL retains a finished scan's output buffer for late SSE subscribers
// (page refresh) before it is freed; the durable record is in the database.
const historyTTL = 15 * time.Minute

// CVEIntel is the exploit-likelihood intel for a CVE id.
type CVEIntel struct {
	EPSS float64 // 0..1 exploit probability (EPSS)
	KEV  bool    // listed in CISA Known-Exploited Vulnerabilities
}

// Enricher resolves EPSS + KEV intel for CVE ids. Implemented in the handlers
// package (which owns the EPSS/KEV lookups) and injected at construction so the
// engine stays decoupled from the CVE data source. May be nil (no enrichment).
type Enricher interface {
	EnrichCVEs(ctx context.Context, cveIDs []string) map[string]CVEIntel
}

// Engine owns scan lifecycle, concurrency limiting and live output streaming.
type Engine struct {
	db       *gorm.DB
	cfg      *config.Config
	enricher Enricher

	mu      sync.Mutex
	running map[string]context.CancelFunc
	scanSem chan struct{}

	subMu sync.Mutex
	subs  map[string][]chan string

	histMu  sync.Mutex
	history map[string][]string
}

func maxConcurrentScans(cfg *config.Config) int {
	if cfg != nil && cfg.VulnScanMaxConcurrent > 0 {
		return cfg.VulnScanMaxConcurrent
	}
	return 2
}

// NewEngine builds the engine and marks any scan left "running" by a crash as
// failed (external tool state cannot be resumed safely). enricher may be nil.
func NewEngine(db *gorm.DB, cfg *config.Config, enricher Enricher) *Engine {
	e := &Engine{
		db:       db,
		cfg:      cfg,
		enricher: enricher,
		running:  make(map[string]context.CancelFunc),
		scanSem:  make(chan struct{}, maxConcurrentScans(cfg)),
		subs:     make(map[string][]chan string),
		history:  make(map[string][]string),
	}
	e.recoverStuckScans()
	return e
}

// recoverStuckScans fails scans that were mid-run when the process died. Unlike
// OSINT collectors, an external scanner's progress can't be resumed.
func (e *Engine) recoverStuckScans() {
	if e.db == nil {
		return
	}
	now := time.Now()
	e.db.Model(&models.VulnScan{}).
		Where("status IN ?", []models.VulnScanStatus{models.VulnRunning, models.VulnPending}).
		Updates(map[string]interface{}{"status": models.VulnFailed, "finished_at": now})
	e.db.Model(&models.VulnTool{}).
		Where("status IN ?", []models.VulnToolStatus{models.VulnToolRunning, models.VulnToolPending}).
		Updates(map[string]interface{}{"status": models.VulnToolFailed, "error": "interrupted by server restart", "finished_at": now})
}

// ── SSE fan-out ───────────────────────────────────────────────────────────────

// Subscribe returns a channel pre-loaded with the scan's output history; live
// lines follow while the scan runs. A finished scan with no buffered history
// gets a single "__DONE__" sentinel so the client closes cleanly.
func (e *Engine) Subscribe(scanID string) chan string {
	e.histMu.Lock()
	hist := e.history[scanID]
	bufSize := len(hist) + 256
	if bufSize < 512 {
		bufSize = 512
	}
	ch := make(chan string, bufSize)
	for _, line := range hist {
		ch <- line
	}
	histLen := len(hist)
	e.histMu.Unlock()

	e.mu.Lock()
	_, isRunning := e.running[scanID]
	e.mu.Unlock()

	if isRunning {
		e.subMu.Lock()
		e.subs[scanID] = append(e.subs[scanID], ch)
		e.subMu.Unlock()
	} else if histLen == 0 {
		ch <- "__DONE__"
	}
	return ch
}

// Unsubscribe removes ch and closes it.
func (e *Engine) Unsubscribe(scanID string, ch chan string) {
	e.subMu.Lock()
	defer e.subMu.Unlock()
	list := e.subs[scanID]
	for i, s := range list {
		if s == ch {
			e.subs[scanID] = append(list[:i], list[i+1:]...)
			break
		}
	}
	close(ch)
}

func (e *Engine) broadcast(scanID, line string) {
	e.histMu.Lock()
	h := append(e.history[scanID], line)
	if len(h) > histCap {
		h = h[len(h)-histCap:]
	}
	e.history[scanID] = h
	e.histMu.Unlock()

	e.subMu.Lock()
	defer e.subMu.Unlock()
	for _, ch := range e.subs[scanID] {
		select {
		case ch <- line:
		default:
		}
	}
}

func (e *Engine) emit(scanID, line string) {
	e.broadcast(scanID, line)
	log.Printf("[vulnscan] %s", line)
}

// DeleteHistory frees a deleted scan's output buffer.
func (e *Engine) DeleteHistory(scanID string) {
	e.histMu.Lock()
	delete(e.history, scanID)
	e.histMu.Unlock()
}

func (e *Engine) scheduleHistoryCleanup(scanID string) {
	time.AfterFunc(historyTTL, func() {
		if !e.IsRunning(scanID) {
			e.DeleteHistory(scanID)
		}
	})
}

// IsRunning reports whether a scan is currently executing.
func (e *Engine) IsRunning(scanID string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.running[scanID]
	return ok
}

// StopScan cancels a running scan.
func (e *Engine) StopScan(scanID string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	cancel, ok := e.running[scanID]
	if ok {
		cancel()
	}
	return ok
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

// StartScan launches the httpx→nuclei pipeline for scan against targets in a
// goroutine, bounded by the engine-wide concurrency semaphore.
func (e *Engine) StartScan(scan *models.VulnScan, targets []string) error {
	e.mu.Lock()
	if _, exists := e.running[scan.ID.String()]; exists {
		e.mu.Unlock()
		return fmt.Errorf("scan already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.running[scan.ID.String()] = cancel
	e.mu.Unlock()

	go func() {
		defer func() {
			e.mu.Lock()
			delete(e.running, scan.ID.String())
			e.mu.Unlock()
		}()
		// Last line of defence: a panic anywhere in the pipeline (a tool stage, a
		// bad tool line, a DB hiccup) must never leave the scan stuck "running"
		// with subscribers hanging. Finalize it as failed and close the stream.
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[vulnscan] PANIC in scan %s: %v", scan.ID.String(), r)
				e.finalize(scan, models.VulnFailed)
				e.failOpenTools(scan.ID, fmt.Sprintf("scan crashed: %v", r))
				e.emit(scan.ID.String(), fmt.Sprintf("[!] Scan crashed (%v) — finalized as failed", r))
				e.emit(scan.ID.String(), "__DONE__")
				e.scheduleHistoryCleanup(scan.ID.String())
			}
		}()
		select {
		case e.scanSem <- struct{}{}:
			defer func() { <-e.scanSem }()
		default:
			e.emit(scan.ID.String(), "[*] Queued — waiting for a free scan slot...")
			select {
			case e.scanSem <- struct{}{}:
				defer func() { <-e.scanSem }()
			case <-ctx.Done():
				e.finalize(scan, models.VulnStopped)
				e.emit(scan.ID.String(), "[!] Scan stopped before it started (was queued)")
				e.emit(scan.ID.String(), "__DONE__")
				e.scheduleHistoryCleanup(scan.ID.String())
				return
			}
		}
		e.runPipeline(ctx, scan, targets)
	}()
	return nil
}

// failOpenTools marks any still-pending/running tool rows of a scan as failed —
// used by the panic handler so a crashed scan doesn't leave dangling tool runs.
func (e *Engine) failOpenTools(scanID uuid.UUID, msg string) {
	now := time.Now()
	e.db.Model(&models.VulnTool{}).
		Where("scan_id = ? AND status IN ?", scanID,
			[]models.VulnToolStatus{models.VulnToolRunning, models.VulnToolPending}).
		Updates(map[string]interface{}{"status": models.VulnToolFailed, "error": msg, "finished_at": now})
}

// ClassifyForPreview classifies assets for the pre-scan review UI using the
// platform's DEFAULT egress posture (Tor-preferred). When a proxy is configured
// the preview defers hostname resolution to scan time, so merely opening the
// review modal never leaks target names to the local/ISP resolver.
func (e *Engine) ClassifyForPreview(targets []string) []ScopeVerdict {
	proxyURL, _ := e.resolveProxy("tor")
	return classifyScope(targets, proxyURL != "")
}

// finalize writes the terminal status, finish time and severity summary.
func (e *Engine) finalize(scan *models.VulnScan, status models.VulnScanStatus) {
	updates := map[string]interface{}{"status": status, "finished_at": time.Now()}
	if summary := e.severitySummary(scan.ID); summary != "" {
		updates["summary"] = summary
	}
	e.db.Model(scan).Updates(updates)
}

// severitySummary returns a JSON object of severity → count for the scan.
func (e *Engine) severitySummary(scanID interface{ String() string }) string {
	type row struct {
		Severity string
		N        int
	}
	var rows []row
	e.db.Model(&models.VulnFinding{}).
		Select("severity, count(*) as n").
		Where("scan_id = ?", scanID).
		Group("severity").Scan(&rows)
	if len(rows) == 0 {
		return ""
	}
	m := make(map[string]int, len(rows))
	for _, r := range rows {
		m[r.Severity] = r.N
	}
	b, _ := json.Marshal(m)
	return string(b)
}

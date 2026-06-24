package osint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/config"
	"github.com/forensichub/backend/internal/models"
	"github.com/forensichub/backend/internal/threatintel"
)

// histCap is the number of output lines kept in memory per scan for SSE
// history replay (page refresh / late subscribers).
const histCap = 2000

// Engine runs OSINT investigations concurrently and fans live progress out to
// SSE subscribers. It owns its own per-scan subscription map - the ws.Hub is
// not involved (the hub's broadcast pairs are global, not per-scan).
type Engine struct {
	db     *gorm.DB
	keys   Keys
	cfg    *config.Config
	enrich *threatintel.EnrichClient
	cache  *osintCache // optional Redis read-through cache for idempotent lookups

	mu      sync.Mutex
	running map[string]context.CancelFunc

	// scanSem bounds how many scans execute concurrently across the whole engine
	// (root + auto-pivot children alike). A scan is accepted immediately but waits
	// here for a slot before its collectors run, so a wide/deep pivot graph can't
	// exhaust sockets, goroutines or third-party rate limits.
	scanSem chan struct{}

	subMu sync.Mutex
	subs  map[string][]chan string

	histMu  sync.Mutex
	history map[string][]string
}

// maxConcurrentScans resolves the engine-wide concurrent-scan limit from config,
// defaulting to 6 when unset.
func maxConcurrentScans(cfg *config.Config) int {
	if cfg != nil && cfg.OsintMaxConcurrentScans > 0 {
		return cfg.OsintMaxConcurrentScans
	}
	return 6
}

// NewEngine builds the engine and recovers any scans left "running" by a crash.
func NewEngine(db *gorm.DB, keys Keys, cfg *config.Config, enrich *threatintel.EnrichClient, rdb *redis.Client) *Engine {
	e := &Engine{
		db:      db,
		keys:    keys,
		cfg:     cfg,
		enrich:  enrich,
		cache:   newOsintCache(rdb),
		running: make(map[string]context.CancelFunc),
		scanSem: make(chan struct{}, maxConcurrentScans(cfg)),
		subs:    make(map[string][]chan string),
		history: make(map[string][]string),
	}
	e.recoverStuckScans()
	e.startWatchScheduler()
	return e
}

// recoverStuckScans marks scans/collectors left running after a restart as
// failed so they can be re-run or deleted.
func (e *Engine) recoverStuckScans() {
	now := time.Now()
	var ids []string
	e.db.Model(&models.OsintScan{}).
		Where("status = ?", models.OsintRunning).
		Pluck("id", &ids)
	if len(ids) == 0 {
		return
	}
	e.db.Model(&models.OsintCollector{}).
		Where("scan_id IN ? AND status IN ?", ids,
			[]string{string(models.OsintCollectorRunning), string(models.OsintCollectorPending)}).
		Updates(map[string]interface{}{"status": models.OsintCollectorFailed, "finished_at": now})
	res := e.db.Model(&models.OsintScan{}).
		Where("status = ?", models.OsintRunning).
		Updates(map[string]interface{}{"status": models.OsintFailed, "finished_at": now})
	log.Printf("[osint] recovered %d stuck scan(s) on startup", res.RowsAffected)
}

// -- SSE subscription ----------------------------------------------------------

// Subscribe returns a channel pre-loaded with the scan's output history so a
// late subscriber (refresh / navigation) sees all prior output immediately.
func (e *Engine) Subscribe(scanID string) chan string {
	ch := make(chan string, 512)

	e.histMu.Lock()
	hist := e.history[scanID]
	for _, line := range hist {
		select {
		case ch <- line:
		default:
		}
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
		// Not running, no history (server restarted after scan finished).
		ch <- "__DONE__"
	}
	return ch
}

// Unsubscribe removes ch from the subscriber list and closes it.
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
	log.Printf("[osint] %s", line)
}

// DeleteHistory frees the in-memory output buffer for a deleted scan.
func (e *Engine) DeleteHistory(scanID string) {
	e.histMu.Lock()
	delete(e.history, scanID)
	e.histMu.Unlock()
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

// StartScan launches the collector pipeline for a scan in a goroutine.
func (e *Engine) StartScan(scan *models.OsintScan, collectors []models.OsintCollector) error {
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
		// Wait for an engine-wide execution slot. The scan stays "pending" while
		// queued; if it is stopped or the engine shuts down before a slot frees,
		// abort cleanly instead of running.
		if e.scanSem != nil {
			// Fast path: a slot is free right now.
			select {
			case e.scanSem <- struct{}{}:
				defer func() { <-e.scanSem }()
			default:
				// All slots busy - tell subscribers the scan is queued, then wait.
				e.emit(scan.ID.String(), "[*] Queued - waiting for a free scan slot...")
				select {
				case e.scanSem <- struct{}{}:
					defer func() { <-e.scanSem }()
				case <-ctx.Done():
					e.finalizeScan(scan, models.OsintStopped)
					e.emit(scan.ID.String(), "[!] Scan stopped before it started (was queued)")
					e.emit(scan.ID.String(), "__DONE__")
					return
				}
			}
		}
		e.runPipeline(ctx, scan, collectors)
	}()
	return nil
}

// -- Pipeline ------------------------------------------------------------------

// collectorTimeout is the per-collector wall-time budget.
func collectorTimeout(name string) time.Duration {
	switch name {
	case "maigret":
		// Maigret scans hundreds of sites; give it a generous budget.
		return 150 * time.Second
	case "portscan":
		// Full 65535-port active sweep + banner grabs + rate-limited NVD lookups.
		// A heavily-filtered host can make every probe wait the connect timeout,
		// so the budget is generous; partial results are still saved on timeout.
		return 600 * time.Second
	case "webtech":
		// Active fetch + banner grab, then rate-limited NVD CVE lookups per product.
		return 120 * time.Second
	case "typosquat":
		// Resolves up to ~48 candidate domains.
		return 60 * time.Second
	case "subbrute":
		// Resolves a ~250-name wordlist concurrently.
		return 60 * time.Second
	case "cloud":
		// Probes up to ~120 bucket candidates across S3/GCS/Azure, bounded
		// concurrency; a generous budget covers slow cloud edge responses.
		return 120 * time.Second
	case "crtsh", "wayback", "social_search":
		return 60 * time.Second
	default:
		return 45 * time.Second
	}
}

// runPipeline runs every collector for the scan concurrently, then finalises.
func (e *Engine) runPipeline(ctx context.Context, scan *models.OsintScan, rows []models.OsintCollector) {
	scanID := scan.ID.String()
	db := e.db

	db.Model(scan).Update("status", models.OsintRunning)
	e.emit(scanID, fmt.Sprintf("[*] Starting OSINT scan - %s: %s", scan.TargetType, scan.Target))
	e.emit(scanID, fmt.Sprintf("[*] %d collector(s) running in parallel", len(rows)))

	impls := buildCollectors(scan.TargetType)
	implByName := make(map[string]collector, len(impls))
	for _, c := range impls {
		implByName[c.name] = c
	}

	env := &collectorEnv{
		target: scan.Target,
		ttype:  scan.TargetType,
		keys:   e.keys,
		cfg:    e.cfg,
		db:     db,
		enrich: e.enrich,
		cache:  e.cache,
		emit:   func(l string) { e.emit(scanID, l) },
	}

	var wg sync.WaitGroup
	for i := range rows {
		row := &rows[i]
		impl, ok := implByName[row.Name]
		if !ok {
			db.Model(row).Updates(map[string]interface{}{
				"status": models.OsintCollectorSkipped,
				"error":  "unknown collector",
			})
			continue
		}
		wg.Add(1)
		go func(r *models.OsintCollector, c collector) {
			defer wg.Done()
			e.runCollector(ctx, scan, r, c, env)
		}(row, impl)
	}
	wg.Wait()

	if ctx.Err() != nil {
		e.finalizeScan(scan, models.OsintStopped)
		e.emit(scanID, "[!] Scan stopped by user")
	} else {
		e.corroborateFindings(scan)
		e.finalizeScan(scan, models.OsintDone)
		e.emit(scanID, "[*] Scan complete")
		e.autoPivot(scan)
		// Continuous-monitoring diff: only the watch's root scan raises alerts.
		if scan.WatchID != nil && scan.ParentScanID == nil {
			e.diffWatch(scan)
		}
	}
	e.emit(scanID, "__DONE__")
}

// autoPivot expands the investigation graph: it reads the related entities this
// scan discovered and launches a child scan for each new one, up to MaxDepth.
// This turns a single-target snapshot into a recursive trace investigation.
func (e *Engine) autoPivot(parent *models.OsintScan) {
	if !parent.AutoPivot || parent.Depth >= parent.MaxDepth {
		return
	}
	rootID := parent.ID
	if parent.RootScanID != nil {
		rootID = *parent.RootScanID
	}

	// Resolve the investigation's root subject so pivots can be scope-checked
	// against it (keeps a domain investigation within its own namespace).
	rootTarget, rootType := parent.Target, parent.TargetType
	if rootID != parent.ID {
		var root models.OsintScan
		if e.db.Select("target", "target_type").First(&root, "id = ?", rootID).Error == nil {
			rootTarget, rootType = root.Target, root.TargetType
		}
	}

	var findings []models.OsintFinding
	e.db.Where("scan_id = ? AND related_entities <> ''", parent.ID).Find(&findings)

	seen := make(map[string]bool)
	type pivot struct{ value, ttype string }
	var pivots []pivot
	for _, f := range findings {
		var rels []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		}
		if json.Unmarshal([]byte(f.RelatedEntities), &rels) != nil {
			continue
		}
		for _, r := range rels {
			v := strings.TrimSpace(r.Value)
			if v == "" || seen[v] {
				continue
			}
			seen[v] = true
			pivots = append(pivots, pivot{value: v, ttype: r.Type})
		}
	}
	if len(pivots) == 0 {
		return
	}

	// Cap children per scan so a noisy collector can't explode the graph.
	const maxChildren = 8
	if len(pivots) > maxChildren {
		pivots = pivots[:maxChildren]
	}
	parentID := parent.ID

	for _, p := range pivots {
		ttype := p.ttype
		if ttype == "" {
			t, derr := DetectTargetType(p.value)
			if derr != nil {
				continue
			}
			ttype = t
		}
		if ValidateTarget(p.value, ttype) != nil {
			continue
		}
		// Keep the investigation in scope - a domain hunt must not pivot into
		// registrar contacts, provider domains or co-hosted tenants.
		if ok, reason := inPivotScope(rootTarget, rootType, p.value, ttype); !ok {
			e.emit(parentID.String(), fmt.Sprintf("[*] auto-pivot skip %s (%s) - %s", p.value, ttype, reason))
			continue
		}
		// Only pivot into meaningful, investigable entities - skip placeholder
		// domains and gibberish handles so the graph doesn't fill with noise.
		if ok, reason := pivotWorthy(p.value, ttype); !ok {
			e.emit(parentID.String(), fmt.Sprintf("[*] auto-pivot skip %s (%s) - %s", p.value, ttype, reason))
			continue
		}

		// Skip if this target was already investigated in this graph.
		var count int64
		e.db.Model(&models.OsintScan{}).
			Where("(root_scan_id = ? OR id = ?) AND target = ?", rootID, rootID, p.value).
			Count(&count)
		if count > 0 {
			continue
		}

		child := models.OsintScan{
			Name:         fmt.Sprintf("%s: %s", ttype, p.value),
			Target:       p.value,
			TargetType:   ttype,
			Status:       models.OsintPending,
			RootScanID:   &rootID,
			ParentScanID: &parentID,
			Depth:        parent.Depth + 1,
			PivotFrom:    parent.Target,
			AutoPivot:    parent.AutoPivot,
			MaxDepth:     parent.MaxDepth,
			CaseID:       parent.CaseID, // child inherits the case → whole graph stays grouped
			CreatedBy:    parent.CreatedBy,
		}
		if err := e.db.Create(&child).Error; err != nil {
			continue
		}

		names := CollectorNamesFor(ttype)
		collectors := make([]models.OsintCollector, len(names))
		for i, n := range names {
			collectors[i] = models.OsintCollector{ScanID: child.ID, Name: n, Status: models.OsintCollectorPending}
			e.db.Create(&collectors[i])
		}
		e.emit(parentID.String(), fmt.Sprintf("[*] auto-pivot -> %s (%s) - depth %d", p.value, ttype, child.Depth))
		_ = e.StartScan(&child, collectors)
	}
}

// runCollector executes one collector, persists its findings, and updates the
// collector row's status.
func (e *Engine) runCollector(ctx context.Context, scan *models.OsintScan, row *models.OsintCollector, c collector, env *collectorEnv) {
	scanID := scan.ID.String()
	db := e.db

	db.Model(row).Updates(map[string]interface{}{
		"status":     models.OsintCollectorRunning,
		"started_at": time.Now(),
	})
	env.emit(fmt.Sprintf("[*] %s - collecting...", c.name))

	timeout := collectorTimeout(c.name)
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	findings, err := c.run(cctx, env)
	finishedAt := time.Now()

	// Whole scan cancelled - record the collector as skipped, not failed.
	if ctx.Err() != nil {
		db.Model(row).Updates(map[string]interface{}{
			"status":      models.OsintCollectorSkipped,
			"finished_at": finishedAt,
			"error":       "scan stopped",
		})
		return
	}

	if errors.Is(err, errNoAPIKey) {
		db.Model(row).Updates(map[string]interface{}{
			"status":      models.OsintCollectorSkipped,
			"finished_at": finishedAt,
			"error":       "optional API key not configured",
		})
		e.emit(scanID, fmt.Sprintf("[*] %s skipped - optional API key not configured", c.name))
		return
	}

	if err != nil {
		msg := err.Error()
		if cctx.Err() == context.DeadlineExceeded {
			msg = fmt.Sprintf("timed out after %s", timeout)
		}
		db.Model(row).Updates(map[string]interface{}{
			"status":      models.OsintCollectorFailed,
			"finished_at": finishedAt,
			"error":       msg,
		})
		e.emit(scanID, fmt.Sprintf("[!] %s failed: %s", c.name, msg))
		return
	}

	for i := range findings {
		findings[i].ScanID = scan.ID
		findings[i].CollectorID = row.ID
	}
	inserted := persistFindings(db, findings)
	db.Model(row).Updates(map[string]interface{}{
		"status":         models.OsintCollectorDone,
		"finished_at":    finishedAt,
		"findings_count": inserted,
	})
	e.emit(scanID, fmt.Sprintf("[+] %s done - %d finding(s)", c.name, inserted))
}

// finalizeScan writes the scan's terminal status and finish time.
func (e *Engine) finalizeScan(scan *models.OsintScan, status models.OsintStatus) {
	e.db.Model(scan).Updates(map[string]interface{}{
		"status":      status,
		"finished_at": time.Now(),
	})
}

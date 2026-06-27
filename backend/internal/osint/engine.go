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

// cohostPivotMax resolves the shared-hosting co-host pivot threshold, defaulting
// to 5 when unset.
func cohostPivotMax(cfg *config.Config) int {
	if cfg != nil && cfg.OsintCohostPivotMax > 0 {
		return cfg.OsintCohostPivotMax
	}
	return 5
}

// maxPivotChildren resolves the per-scan auto-pivot child budget, defaulting to
// 12 when unset.
func maxPivotChildren(cfg *config.Config) int {
	if cfg != nil && cfg.OsintMaxPivotChildren > 0 {
		return cfg.OsintMaxPivotChildren
	}
	return 12
}

// roundRobinSelect picks up to budget items from category buckets, cycling
// through cats in order so every category is represented before any single one
// is exhausted (fair sharing of the pivot child budget across IP/domain/account).
func roundRobinSelect[T any](buckets map[string][]T, cats []string, budget int) []T {
	var out []T
	for len(out) < budget {
		progressed := false
		for _, cat := range cats {
			if len(out) >= budget {
				break
			}
			if len(buckets[cat]) > 0 {
				out = append(out, buckets[cat][0])
				buckets[cat] = buckets[cat][1:]
				progressed = true
			}
		}
		if !progressed {
			break // every bucket drained
		}
	}
	return out
}

// pivotCategory buckets a related-entity type into one of the broad classes the
// auto-pivot budget is balanced across, so IP infrastructure, domains, and
// accounts (e-mail/username/person) are each investigated rather than one class
// crowding out the others.
func pivotCategory(ttype string) string {
	switch ttype {
	case TargetIP:
		return "ip"
	case TargetDomain:
		return "domain"
	case TargetEmail, TargetUsername, TargetName:
		return "account"
	default:
		return "other" // phone / wallet / hash
	}
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
	e.resumePendingScans()
	e.startWatchScheduler()
	return e
}

// recoverStuckScans marks scans/collectors left running after a restart as
// pending so they can be re-run by the persistent queue.
func (e *Engine) recoverStuckScans() {
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
		Updates(map[string]interface{}{
			"status":      models.OsintCollectorPending,
			"started_at":  nil,
			"finished_at": nil,
			"error":       "",
		})
	res := e.db.Model(&models.OsintScan{}).
		Where("status = ?", models.OsintRunning).
		Updates(map[string]interface{}{
			"status":      models.OsintPending,
			"finished_at": nil,
		})
	log.Printf("[osint] recovered and requeued %d stuck scan(s) on startup", res.RowsAffected)
}

// resumePendingScans fetches all pending scans from the database and starts them.
// This acts as a persistent queue that resumes scans after a server restart.
func (e *Engine) resumePendingScans() {
	var scans []models.OsintScan
	e.db.Preload("Collectors").Where("status = ?", models.OsintPending).Find(&scans)

	count := 0
	for i := range scans {
		s := &scans[i]
		if !e.IsRunning(s.ID.String()) {
			count++
			if err := e.StartScan(s, s.Collectors); err != nil {
				log.Printf("[osint] failed to resume scan %s: %v", s.ID, err)
			}
		}
	}
	if count > 0 {
		log.Printf("[osint] resumed %d pending scan(s) from persistent queue", count)
	}
}

// -- SSE subscription ----------------------------------------------------------

// Subscribe returns a channel pre-loaded with the scan's output history so a
// late subscriber (refresh / navigation) sees all prior output immediately.
func (e *Engine) Subscribe(scanID string) chan string {
	e.histMu.Lock()
	hist := e.history[scanID]
	histLen := len(hist)
	// Size the buffer to fit the entire replayed history plus live-line headroom,
	// so a late subscriber to a chatty scan (e.g. a long portscan) never silently
	// loses the start of its log to a full channel.
	bufSize := histLen + 256
	if bufSize < 512 {
		bufSize = 512
	}
	ch := make(chan string, bufSize)
	for _, line := range hist {
		ch <- line // guaranteed to fit: bufSize >= histLen
	}
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

// historyTTL is how long a finished scan's output buffer is retained in memory
// for SSE replay (page refresh) before it is freed. Without this, the history
// map grows unbounded across every scan and auto-pivot child for the life of the
// process; the durable record lives in the database, not this buffer.
const historyTTL = 15 * time.Minute

// scheduleHistoryCleanup frees a finished scan's in-memory output buffer after a
// grace period, unless the scan has been started again in the meantime.
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
					e.scheduleHistoryCleanup(scan.ID.String())
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
		e.autoPromoteIOCs(scan)
		e.emit(scanID, "[*] Scan complete")
		e.autoPivot(scan)
		// Continuous-monitoring diff: only the watch's root scan raises alerts.
		if scan.WatchID != nil && scan.ParentScanID == nil {
			e.diffWatch(scan)
		}
	}
	e.emit(scanID, "__DONE__")
	e.scheduleHistoryCleanup(scanID)
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
			// Resolve the type eagerly so prioritisation below classifies untyped
			// related entities (e.g. a bare resolved IP) correctly.
			tt := r.Type
			if tt == "" {
				if d, derr := DetectTargetType(v); derr == nil {
					tt = d
				}
			}
			pivots = append(pivots, pivot{value: v, ttype: tt})
		}
	}
	if len(pivots) == 0 {
		return
	}

	parentID := parent.ID

	// Shared-hosting guard: an IP that hosts many domains is shared infrastructure,
	// so its co-hosted domains are other tenants - keep them as findings but don't
	// pivot into them (otherwise an IP root explodes into unrelated sites).
	suppressedCohost := map[string]bool{}
	if parent.TargetType == TargetIP {
		var cohosts []string
		for i := range findings {
			if findings[i].Source == "reverse_ip" {
				cohosts = append(cohosts, strings.ToLower(strings.TrimSpace(findings[i].Value)))
			}
		}
		if len(cohosts) > cohostPivotMax(e.cfg) {
			for _, c := range cohosts {
				suppressedCohost[c] = true
			}
			e.emit(parentID.String(), fmt.Sprintf(
				"[*] auto-pivot: %d co-hosted domains on %s - treating as shared hosting, not pivoting tenants",
				len(cohosts), parent.Target))
		}
	}

	// Resolve, in one query, which candidate targets are already in this graph,
	// so the filter pass doesn't run an N+1 of COUNT queries.
	candVals := make([]string, 0, len(pivots))
	for _, p := range pivots {
		candVals = append(candVals, p.value)
	}
	alreadyInGraph := map[string]bool{}
	if len(candVals) > 0 {
		var existing []string
		e.db.Model(&models.OsintScan{}).
			Where("(root_scan_id = ? OR id = ?) AND target IN ?", rootID, rootID, candVals).
			Pluck("target", &existing)
		for _, t := range existing {
			alreadyInGraph[t] = true
		}
	}

	// Pass 1 — FILTER, then cap. Apply every out-of-scope / noise / duplicate
	// check across the WHOLE candidate set first, so that rejected entities never
	// consume a child-budget slot (the previous order capped first, so a handful
	// of out-of-scope hits at the front could starve the real pivots behind them).
	type pivotC struct {
		value, ttype, category string
	}
	var valid []pivotC
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
		if ok, reason := inPivotScope(e.cfg, rootTarget, rootType, p.value, ttype); !ok {
			e.emit(parentID.String(), fmt.Sprintf("[*] auto-pivot skip %s (%s) - %s", p.value, ttype, reason))
			continue
		}
		// Only pivot into meaningful, investigable entities - skip placeholder
		// domains and gibberish handles so the graph doesn't fill with noise.
		if ok, reason := pivotWorthy(p.value, ttype); !ok {
			e.emit(parentID.String(), fmt.Sprintf("[*] auto-pivot skip %s (%s) - %s", p.value, ttype, reason))
			continue
		}
		// Skip co-hosted tenants of a shared IP (recorded as findings, not scanned).
		if suppressedCohost[strings.ToLower(p.value)] {
			e.emit(parentID.String(), fmt.Sprintf("[*] auto-pivot skip %s (%s) - co-hosted on shared IP", p.value, ttype))
			continue
		}
		// Skip if this target was already investigated in this graph.
		if alreadyInGraph[p.value] {
			continue
		}
		valid = append(valid, pivotC{value: p.value, ttype: ttype, category: pivotCategory(ttype)})
	}
	if len(valid) == 0 {
		return
	}

	// Pass 2 — allocate the child budget round-robin across categories (IP /
	// domain / account / other) so the user's requirement holds: a target's
	// related IPs, domains AND accounts are each investigated, instead of one
	// long class (e.g. many resolved IPs) crowding the others out of the cap.
	budget := maxPivotChildren(e.cfg)
	buckets := map[string][]pivotC{}
	for _, v := range valid {
		buckets[v.category] = append(buckets[v.category], v)
	}
	selected := roundRobinSelect(buckets, []string{"ip", "domain", "account", "other"}, budget)
	if dropped := len(valid) - len(selected); dropped > 0 {
		e.emit(parentID.String(), fmt.Sprintf(
			"[*] auto-pivot: %d in-scope pivot(s) deferred - child budget %d reached (raise OSINT_MAX_PIVOT_CHILDREN)",
			dropped, budget))
	}

	// Pass 3 — spawn a child scan for each selected pivot.
	for _, p := range selected {
		ttype := p.ttype

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
		}
		if len(collectors) > 0 {
			e.db.Create(&collectors) // single batch insert
		}
		alreadyInGraph[p.value] = true
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

// iocTypeFor maps an OSINT target type to the IOC-store Type used by the ELK
// auto-hunt / OpenCTI sync. Returns "" for non-promotable types.
func iocTypeFor(ttype, value string) string {
	switch ttype {
	case TargetIP:
		if strings.Contains(value, ":") {
			return "IPv6-Addr"
		}
		return "IPv4-Addr"
	case TargetDomain:
		return "Domain-Name"
	case TargetEmail:
		return "Email-Addr"
	case TargetHash:
		return "File-Hash"
	}
	return ""
}

// autoPromoteIOCs closes the OSINT → defence loop: when a finished scan carries
// a high-confidence malicious verdict about its target (reputation / ransomware
// / dark-web finding, severity high|critical, self-verified), the target is
// added to the IOC store so the ELK auto-hunt searches the logs for it. Gated by
// OSINT_AUTO_PROMOTE (default on); only ip/domain/email/hash targets qualify.
func (e *Engine) autoPromoteIOCs(scan *models.OsintScan) {
	if e.cfg == nil || !e.cfg.OsintAutoPromote {
		return
	}
	iocType := iocTypeFor(scan.TargetType, scan.Target)
	if iocType == "" {
		return
	}
	var f models.OsintFinding
	err := e.db.Where(
		"scan_id = ? AND category IN ? AND severity IN ? AND confidence = ?",
		scan.ID, []string{"reputation", "ransomware", "darkweb"}, []string{"high", "critical"}, "verified",
	).Order("severity DESC").First(&f).Error
	if err != nil {
		return // no verified malicious verdict — nothing to promote
	}
	ioc := models.IOC{
		Value:       strings.TrimSpace(scan.Target),
		Type:        iocType,
		Source:      "OSINT auto",
		Description: "Auto-promoted (verified malicious): " + f.Title,
	}
	res := e.db.Where("value = ? AND type = ?", ioc.Value, ioc.Type).FirstOrCreate(&ioc)
	if res.Error == nil && res.RowsAffected > 0 {
		e.emit(scan.ID.String(), fmt.Sprintf(
			"[+] Auto-promoted %s to the IOC store (verified malicious) — ELK auto-hunt will pick it up", scan.Target))
	}
}

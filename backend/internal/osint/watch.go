package osint

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/models"
)

// watchTick is how often the scheduler checks for watches that are due.
const watchTick = 60 * time.Second

// startWatchScheduler launches the continuous-monitoring loop (A4). It runs in
// the background and fires any OsintWatch whose NextRunAt has passed.
func (e *Engine) startWatchScheduler() {
	go func() {
		// Small initial delay so startup recovery settles first.
		select {
		case <-time.After(15 * time.Second):
		case <-e.baseCtx.Done():
			return
		}
		t := time.NewTicker(watchTick)
		defer t.Stop()
		for {
			select {
			case <-e.baseCtx.Done():
				return
			case <-t.C:
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("[osint] PANIC recovered in watch scheduler: %v", r)
					}
				}()
				e.runDueWatches()
			}()
		}
	}()
	log.Printf("[osint] watch scheduler started (tick %s)", watchTick)
}

// runDueWatches fires every enabled watch whose schedule has elapsed.
func (e *Engine) runDueWatches() {
	now := time.Now()
	var watches []models.OsintWatch
	e.db.Where("enabled = ? AND (next_run_at IS NULL OR next_run_at <= ?)", true, now).
		Find(&watches)
	for i := range watches {
		e.fireWatch(&watches[i])
	}
}

// fireWatch launches a fresh investigation for a watch and reschedules it. The
// diff against the previous run (and any alerts) happens when the scan finishes,
// in runPipeline → diffWatch.
func (e *Engine) fireWatch(w *models.OsintWatch) {
	interval := w.IntervalMinutes
	if interval < 5 {
		interval = 5 // floor so a misconfigured watch can't hammer sources
	}
	next := time.Now().Add(time.Duration(interval) * time.Minute)
	now := time.Now()
	// Reschedule immediately so a slow scan doesn't double-fire on the next tick.
	e.db.Model(&models.OsintWatch{}).Where("id = ?", w.ID).
		Updates(map[string]interface{}{"last_run_at": now, "next_run_at": next})

	maxDepth := w.MaxDepth
	if w.AutoPivot && maxDepth <= 0 {
		maxDepth = 2
	}
	if maxDepth > 4 {
		maxDepth = 4
	}
	wid := w.ID
	scan := models.OsintScan{
		Name:       fmt.Sprintf("[watch] %s", w.Name),
		Target:     w.Target,
		TargetType: w.TargetType,
		Status:     models.OsintPending,
		AutoPivot:  w.AutoPivot,
		MaxDepth:   maxDepth,
		CaseID:     w.CaseID,
		WatchID:    &wid,
		CreatedBy:  w.CreatedBy,
	}
	if err := e.db.Create(&scan).Error; err != nil {
		log.Printf("[osint] watch %s: create scan failed: %v", w.ID, err)
		return
	}
	rootSelf := scan.ID
	e.db.Model(&scan).Update("root_scan_id", rootSelf)
	scan.RootScanID = &rootSelf

	// A scheduled watch re-run obeys the same admin scope policy as a manual scan,
	// so recurring monitoring can never quietly run active/target-touching
	// collectors the policy would block (e.g. probing an external target while
	// egress is direct).
	decision := DecideScope(e.db, scan.Target, w.TargetType)
	e.db.Model(&scan).Updates(map[string]interface{}{
		"scope_mode": string(decision.Mode),
		"scope_rule": decision.MatchedRule,
	})
	if decision.Mode == ModeBlock {
		e.db.Model(&scan).Update("status", models.OsintDone)
		log.Printf("[osint] watch %s: scan blocked by scope policy (%s)", w.ID, decision.MatchedRule)
		return
	}

	names := decision.Allowed
	collectors := make([]models.OsintCollector, len(names))
	for i, n := range names {
		collectors[i] = models.OsintCollector{ScanID: scan.ID, Name: n, Status: models.OsintCollectorPending}
		e.db.Create(&collectors[i])
	}
	if err := e.StartScan(&scan, collectors); err != nil {
		log.Printf("[osint] watch %s: start scan failed: %v", w.ID, err)
	}
}

// TriggerWatch fires a watch immediately (used by the "run now" endpoint).
func (e *Engine) TriggerWatch(watchID uuid.UUID) error {
	var w models.OsintWatch
	if err := e.db.First(&w, "id = ?", watchID).Error; err != nil {
		return err
	}
	e.fireWatch(&w)
	return nil
}

// diffWatch compares a finished watch scan against the watch's previous scan and
// raises an alert for every NEW significant trace. The first run only sets a
// baseline (no alerts), so the analyst is notified about change, not the initial
// state.
func (e *Engine) diffWatch(scan *models.OsintScan) {
	if scan.WatchID == nil {
		return
	}
	watchID := *scan.WatchID

	// Previous scan = the most recent scan for this watch other than the current.
	var prev models.OsintScan
	hasPrev := e.db.Where("watch_id = ? AND id <> ?", watchID, scan.ID).
		Order("created_at desc").First(&prev).Error == nil

	// Always advance the watch's pointer to the latest scan.
	defer e.db.Model(&models.OsintWatch{}).Where("id = ?", watchID).
		Update("last_scan_id", scan.ID)

	if !hasPrev {
		log.Printf("[osint] watch %s: baseline established (scan %s)", watchID, scan.ID)
		return
	}

	// Build the set of previously-seen traces across the whole prior graph.
	prevRoot := prev.ID
	if prev.RootScanID != nil {
		prevRoot = *prev.RootScanID
	}
	var prevFindings []models.OsintFinding
	e.db.Where("scan_id IN (?)",
		e.db.Model(&models.OsintScan{}).Select("id").
			Where("root_scan_id = ? OR id = ?", prevRoot, prevRoot)).
		Find(&prevFindings)
	seen := make(map[string]bool, len(prevFindings))
	for i := range prevFindings {
		seen[traceKey(&prevFindings[i])] = true
	}

	// Walk the current graph's findings; alert on new significant ones.
	curRoot := scan.ID
	var curFindings []models.OsintFinding
	e.db.Where("scan_id IN (?)",
		e.db.Model(&models.OsintScan{}).Select("id").
			Where("root_scan_id = ? OR id = ?", curRoot, curRoot)).
		Find(&curFindings)

	alerts := 0
	for i := range curFindings {
		f := &curFindings[i]
		if !significantSeverity(f.Severity) {
			continue
		}
		if seen[traceKey(f)] {
			continue
		}
		alert := models.OsintWatchAlert{
			WatchID:    watchID,
			ScanID:     scan.ID,
			Category:   f.Category,
			Source:     f.Source,
			Title:      f.Title,
			Value:      f.Value,
			Severity:   f.Severity,
			Confidence: f.Confidence,
		}
		if e.db.Create(&alert).Error == nil {
			alerts++
		}
		if alerts >= 200 {
			break // safety cap
		}
	}

	if alerts > 0 {
		e.db.Model(&models.OsintWatch{}).Where("id = ?", watchID).
			UpdateColumn("alert_count", gorm.Expr("alert_count + ?", alerts))
		e.emit(scan.ID.String(), fmt.Sprintf("[!] watch: %d NEW trace(s) since last run", alerts))
		log.Printf("[osint] watch %s: %d new alert(s)", watchID, alerts)
	}
}

// traceKey identifies a finding for change detection across runs (ignores the
// scan it came from, so the same trace in two runs collapses).
func traceKey(f *models.OsintFinding) string {
	return strings.ToLower(strings.TrimSpace(f.Category)) + "|" +
		strings.ToLower(strings.TrimSpace(f.Title)) + "|" +
		strings.ToLower(strings.TrimSpace(f.Value))
}

// significantSeverity reports whether a finding is worth alerting on.
func significantSeverity(sev string) bool {
	switch sev {
	case "medium", "high", "critical":
		return true
	}
	return false
}

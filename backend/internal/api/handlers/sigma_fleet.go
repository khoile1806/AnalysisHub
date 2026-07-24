package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/hunting/sigma"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/ws"
)

// fleetSweepCollection is the Collection value written on every per-agent result
// row. Reusing FleetCollectionResult means the existing fleet result endpoints
// and the Fleet UI can read a sweep without knowing anything new about it.
const fleetSweepCollection = "sigma-sweep"

// fleetSweepConcurrency bounds how many agents are swept at once. A sweep is far
// heavier than a plain collection — several EVTX queries per host plus a
// full-ruleset evaluation of everything they return — so the server holds
// roughly concurrency × sources × max_per_source events in memory at peak. Three
// keeps that bounded (and keeps the websocket hub from being flooded) while
// still clearing a fleet in waves rather than one host at a time.
const fleetSweepConcurrency = 3

// fleetSweepAgentBudget bounds one agent's slot in the pool. A single-machine
// sweep already caps its own collection at sweepTotalBudget; the extra headroom
// covers the final rule evaluation. A host that stops answering must give the
// slot back rather than starve every agent queued behind it.
const fleetSweepAgentBudget = sweepTotalBudget + 2*time.Minute

// fleetSweepRunSlack pads the derived run deadline so the last wave is not cut
// off by rounding.
const fleetSweepRunSlack = 2 * time.Minute

// fleetSweepRunBudgetMax is the hard ceiling on a single fleet sweep, however
// large the selection. Past this the run is almost certainly wedged rather than
// slow, and a detached goroutine set must not outlive that.
const fleetSweepRunBudgetMax = 3 * time.Hour

// fleetSummaryMaxRows bounds how many result rows one summary aggregates. Each
// row carries a full alert payload, so an unbounded scan of the history would be
// a memory hazard on a busy server.
const fleetSummaryMaxRows = 500

// fleetSummaryDefaultWindow is the lookback used when the caller gives neither
// scheduled_id nor since — a summary of the whole history is never what the
// analyst meant.
const fleetSummaryDefaultWindow = 24 * time.Hour

// fleetSweepData is the per-agent payload persisted in FleetCollectionResult.Data.
// It is deliberately the same shape the single-agent sweep returns so one viewer
// renders both.
type fleetSweepData struct {
	Alerts        []sigma.Alert       `json:"alerts"`
	EventsScanned int                 `json:"events_scanned"`
	Sources       []sweepSourceResult `json:"sources"`
	RulesCount    int                 `json:"rules_count"`
	Hours         int                 `json:"hours"`
}

// FleetSigmaSweep runs the whole Sigma ruleset across many agents at once, so a
// technique can be hunted across the estate instead of one machine at a time.
//
// It returns as soon as the work is dispatched: the sweeps themselves run under
// a bounded worker pool and land in FleetCollectionResult rows, readable through
// the existing /agents/fleet/results endpoints and rolled up by
// /agents/fleet/sigma-sweep/summary.
//
// POST /api/v1/agents/fleet/sigma-sweep
// Body: {"agent_ids": [...], "group": "...", "tag": "...", "hours": 24, "max_per_source": 2000}
func (h *FleetHandler) FleetSigmaSweep(c *gin.Context) {
	hub, ok := mustGetHub(c)
	if !ok {
		return
	}

	var body struct {
		AgentIDs     []string `json:"agent_ids"`
		Group        string   `json:"group"`
		Tag          string   `json:"tag"`
		Hours        int      `json:"hours"`
		MaxPerSource int      `json:"max_per_source"`
	}
	_ = c.ShouldBindJSON(&body) // all fields optional; an empty selector is rejected below

	if body.Hours <= 0 {
		body.Hours = 24
	}
	if body.MaxPerSource <= 0 {
		body.MaxPerSource = defaultSweepMax
	}
	if body.MaxPerSource > agentMaxEventsPerQuery {
		body.MaxPerSource = agentMaxEventsPerQuery
	}

	engine := sigma.DefaultEngine
	if engine == nil || engine.RuleCount() == 0 {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error":   "no Sigma rules are loaded on the server - rebuild the backend image or run a rule sync",
		})
		return
	}

	agents := selectFleetAgents(h.DB, body.AgentIDs, body.Group, body.Tag)
	if len(agents) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "selector matched no agents"})
		return
	}

	sources := engine.RequiredSources()
	if len(sources) == 0 {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error":   "the loaded ruleset declares no queryable log sources - nothing could be collected",
		})
		return
	}

	// Every row of one run shares a run id so the summary can aggregate exactly
	// the agents that were dispatched together. ScheduledID carries it: the
	// column is already indexed and already filterable via ListFleetResults.
	runID := uuid.New()

	type dispatch struct {
		AgentID  string `json:"agent_id"`
		Name     string `json:"name"`
		Status   string `json:"status"` // dispatched | offline
		ResultID string `json:"result_id,omitempty"`
	}
	out := make([]dispatch, 0, len(agents))
	pending := make([]fleetSweepJob, 0, len(agents))

	for i := range agents {
		agent := agents[i]
		res := models.FleetCollectionResult{
			ScheduledID: &runID,
			AgentID:     agent.ID,
			AgentName:   agent.Name,
			Collection:  fleetSweepCollection,
			Status:      "pending",
			StartedAt:   time.Now().UTC(),
		}

		// An offline agent is recorded, never skipped: "we did not look there" and
		// "we looked and found nothing" are different answers to a hunt.
		if !hub.IsAgentOnline(agent.ID.String()) {
			now := time.Now().UTC()
			res.Status = "offline"
			res.Error = "agent offline at dispatch time"
			res.FinishedAt = &now
			h.DB.Create(&res)
			out = append(out, dispatch{AgentID: agent.ID.String(), Name: agent.Name, Status: "offline", ResultID: res.ID.String()})
			continue
		}
		if err := h.DB.Create(&res).Error; err != nil {
			out = append(out, dispatch{AgentID: agent.ID.String(), Name: agent.Name, Status: "error"})
			continue
		}

		out = append(out, dispatch{AgentID: agent.ID.String(), Name: agent.Name, Status: "dispatched", ResultID: res.ID.String()})
		pending = append(pending, fleetSweepJob{ResultID: res.ID, AgentID: agent.ID.String(), AgentName: agent.Name})
	}

	if len(pending) > 0 {
		// context.Background(), NOT the request context: this HTTP handler returns
		// long before the sweeps do, and a request-scoped context would cancel
		// every one of them the moment the response is written.
		go runFleetSigmaSweep(h.DB, hub, pending, sources, body.Hours, body.MaxPerSource)
	}

	c.JSON(http.StatusAccepted, gin.H{"success": true, "data": gin.H{
		"run_id":         runID.String(),
		"collection":     fleetSweepCollection,
		"hours":          body.Hours,
		"max_per_source": body.MaxPerSource,
		"rules_count":    engine.RuleCount(),
		"sources":        len(sources),
		"concurrency":    fleetSweepConcurrency,
		"dispatched":     out,
	}})
}

// fleetSweepJob is one queued agent sweep.
type fleetSweepJob struct {
	ResultID  uuid.UUID
	AgentID   string
	AgentName string
}

// fleetSweepRunBudget derives the whole-run deadline from the fleet size. The
// pool only runs fleetSweepConcurrency agents at a time, so a 200-host sweep
// legitimately takes far longer than a 5-host one; a flat deadline would either
// strangle large fleets or leave small ones hanging for hours.
func fleetSweepRunBudget(agents int) time.Duration {
	if agents <= 0 {
		return fleetSweepRunSlack
	}
	waves := (agents + fleetSweepConcurrency - 1) / fleetSweepConcurrency
	d := time.Duration(waves)*fleetSweepAgentBudget + fleetSweepRunSlack
	if d > fleetSweepRunBudgetMax {
		return fleetSweepRunBudgetMax
	}
	return d
}

// runFleetSigmaSweep executes the queued sweeps under a bounded pool. It owns its
// own context so the run survives the HTTP response that started it.
func runFleetSigmaSweep(db *gorm.DB, hub *ws.Hub, jobs []fleetSweepJob, sources []sigma.Source, hours, max int) {
	runCtx, cancelRun := context.WithTimeout(context.Background(), fleetSweepRunBudget(len(jobs)))
	defer cancelRun()

	sem := make(chan struct{}, fleetSweepConcurrency)
	var wg sync.WaitGroup

	for _, job := range jobs {
		wg.Add(1)
		go func(job fleetSweepJob) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// One agent must never take the run down with it: a panic in a
			// detached goroutine kills the process, and a failed host is just a
			// failed row.
			defer func() {
				if r := recover(); r != nil {
					log.Printf("fleet sigma sweep: agent %s panicked: %v", job.AgentID, r)
					finishResult(db, job.ResultID, "error", "", "sweep panicked on the server")
				}
			}()

			if runCtx.Err() != nil {
				finishResult(db, job.ResultID, "timeout", "", "run time budget exhausted before this agent was reached")
				return
			}
			sweepAgent(runCtx, db, hub, job, sources, hours, max)
		}(job)
	}
	wg.Wait()
}

// sweepAgent collects every source the ruleset needs from one agent, evaluates
// the lot, and writes the outcome onto the agent's result row.
func sweepAgent(runCtx context.Context, db *gorm.DB, hub *ws.Hub, job fleetSweepJob, sources []sigma.Source, hours, max int) {
	ctx, cancel := context.WithTimeout(runCtx, fleetSweepAgentBudget)
	defer cancel()

	engine := sigma.DefaultEngine
	if engine == nil || engine.RuleCount() == 0 {
		finishResult(db, job.ResultID, "error", "", "sigma ruleset was unloaded while the sweep was running")
		return
	}

	var allEvents []map[string]interface{}
	results := make([]sweepSourceResult, 0, len(sources))

	for _, src := range sources {
		res := sweepSourceResult{LogName: src.LogName, EventIDs: src.EventIDs, Rules: src.Rules}
		// collectEvtxForSweep blocks up to sweepSourceTimeout on its own, so the
		// budget is enforced between sources: a hung host costs one extra source
		// timeout at worst, never the whole slot.
		if err := ctx.Err(); err != nil {
			res.Error = "skipped: sweep time budget exhausted"
			results = append(results, res)
			continue
		}
		events, err := collectEvtxForSweep(hub, job.AgentID, src, hours, max)
		if err != nil {
			res.Error = err.Error()
			results = append(results, res)
			continue
		}
		res.Events = len(events)
		allEvents = append(allEvents, events...)
		results = append(results, res)
	}

	data := fleetSweepData{
		Alerts:        []sigma.Alert{},
		EventsScanned: len(allEvents),
		Sources:       results,
		RulesCount:    engine.RuleCount(),
		Hours:         hours,
	}

	if len(allEvents) > 0 {
		alerts, scanErr := engine.ScanEvents(ctx, allEvents)
		if scanErr != nil {
			// ScanEvents returns the partial alert set alongside a cancellation,
			// so a host cut off by the budget still reports what it found.
			if ctx.Err() != nil {
				data.Alerts = append(data.Alerts, alerts...)
				blob, _ := json.Marshal(data)
				finishResult(db, job.ResultID, "timeout", string(blob), "sweep exceeded its time budget mid-scan")
				return
			}
			finishResult(db, job.ResultID, "error", "", "sigma scan failed: "+scanErr.Error())
			return
		}
		data.Alerts = append(data.Alerts, alerts...)
	}

	blob, err := json.Marshal(data)
	if err != nil {
		finishResult(db, job.ResultID, "error", "", "failed to encode sweep result")
		return
	}

	// Every source failing is a failed sweep, not a clean host — say so rather
	// than reporting "0 alerts" from a machine nothing was read from.
	if allFailed := countSourceErrors(results); allFailed == len(results) && len(results) > 0 {
		finishResult(db, job.ResultID, "error", string(blob), "every log source failed: "+results[0].Error)
		return
	}
	finishResult(db, job.ResultID, "done", string(blob), "")
}

func countSourceErrors(results []sweepSourceResult) int {
	n := 0
	for _, r := range results {
		if r.Error != "" {
			n++
		}
	}
	return n
}

// ── Cross-host rollup ─────────────────────────────────────────────────────────

// fleetSweepEntry is one agent's contribution to a rollup: the row status plus
// its decoded payload (nil unless the sweep produced one). Keeping the rollup on
// this type instead of on the GORM model is what makes it testable without a DB.
type fleetSweepEntry struct {
	AgentID   string
	AgentName string
	Status    string
	Data      *fleetSweepData
}

// fleetRuleHit is one machine's contribution to a fleet-wide rule rollup.
type fleetRuleHit struct {
	AgentID    string `json:"agent_id"`
	AgentName  string `json:"agent_name"`
	EventCount int    `json:"event_count"`
}

// fleetRuleRollup answers the question a fleet sweep exists to answer: which
// machines show this technique, and how loudly.
type fleetRuleRollup struct {
	RuleID     string         `json:"rule_id,omitempty"`
	RuleTitle  string         `json:"rule_title"`
	RuleLevel  string         `json:"rule_level"`
	Techniques []string       `json:"mitre_techniques,omitempty"`
	Tactics    []string       `json:"mitre_tactics,omitempty"`
	AgentCount int            `json:"agent_count"`
	Hosts      []string       `json:"hosts"`
	EventCount int            `json:"event_count"`
	Agents     []fleetRuleHit `json:"agents"`
}

// fleetSweepSummary is the aggregate view over one run (or one time window).
type fleetSweepSummary struct {
	TotalAgents      int               `json:"total_agents"`
	Done             int               `json:"done"`
	Errors           int               `json:"error"`
	Offline          int               `json:"offline"`
	Pending          int               `json:"pending"`
	Timeout          int               `json:"timeout"`
	EventsScanned    int               `json:"events_scanned"`
	AgentsWithAlerts int               `json:"agents_with_alerts"`
	RulesTriggered   int               `json:"rules_triggered"`
	TotalAlerts      int               `json:"total_alerts"`
	Rules            []fleetRuleRollup `json:"rules"`
}

// ruleLevelRank orders severities so the rollup leads with what matters. Unknown
// levels sort last rather than being dropped.
var ruleLevelRank = map[string]int{
	"critical":      5,
	"high":          4,
	"medium":        3,
	"low":           2,
	"informational": 1,
	"info":          1,
}

// rollupFleetSweep aggregates per-agent sweep results into fleet-wide, per-rule
// findings. It is a pure function of its input — no DB, no clock.
//
// The engine rolls repeated matches of one rule into the FIRST alert it emitted
// for that rule (EventCount carries the total; the extra sample alerts carry 0),
// so per agent the event total is the sum over that rule's alerts, with the
// number of alert rows as a floor for payloads that lost their counts.
func rollupFleetSweep(entries []fleetSweepEntry) fleetSweepSummary {
	sum := fleetSweepSummary{TotalAgents: len(entries), Rules: []fleetRuleRollup{}}

	// order preserves first-seen rule order so the sort below is stable across
	// runs regardless of map iteration.
	byRule := map[string]*fleetRuleRollup{}
	order := []string{}

	for _, e := range entries {
		switch strings.ToLower(strings.TrimSpace(e.Status)) {
		case "done":
			sum.Done++
		case "offline":
			sum.Offline++
		case "timeout":
			sum.Timeout++
		case "pending", "":
			sum.Pending++
		default:
			sum.Errors++
		}
		if e.Data == nil {
			continue
		}
		sum.EventsScanned += e.Data.EventsScanned
		if len(e.Data.Alerts) == 0 {
			continue
		}
		sum.AgentsWithAlerts++

		host := strings.TrimSpace(e.AgentName)
		if host == "" {
			host = e.AgentID
		}

		// Fold this agent's alerts per rule first, so one agent contributes
		// exactly one hit per rule no matter how many sample alerts it carries.
		type agentRule struct {
			events int
			rows   int
			alert  sigma.Alert
		}
		perRule := map[string]*agentRule{}
		localOrder := []string{}
		for _, a := range e.Data.Alerts {
			key := fleetRuleKey(a)
			ar, seen := perRule[key]
			if !seen {
				ar = &agentRule{alert: a}
				perRule[key] = ar
				localOrder = append(localOrder, key)
			}
			ar.rows++
			ar.events += a.EventCount
		}

		for _, key := range localOrder {
			ar := perRule[key]
			events := ar.events
			if events < ar.rows {
				events = ar.rows
			}

			roll, seen := byRule[key]
			if !seen {
				roll = &fleetRuleRollup{
					RuleID:     ar.alert.RuleID,
					RuleTitle:  ar.alert.RuleTitle,
					RuleLevel:  strings.ToLower(strings.TrimSpace(ar.alert.RuleLevel)),
					Techniques: ar.alert.Techniques,
					Tactics:    ar.alert.Tactics,
					Hosts:      []string{},
					Agents:     []fleetRuleHit{},
				}
				byRule[key] = roll
				order = append(order, key)
			}
			if roll.RuleLevel == "" {
				roll.RuleLevel = strings.ToLower(strings.TrimSpace(ar.alert.RuleLevel))
			}
			if len(roll.Techniques) == 0 {
				roll.Techniques = ar.alert.Techniques
			}
			if len(roll.Tactics) == 0 {
				roll.Tactics = ar.alert.Tactics
			}
			roll.AgentCount++
			roll.EventCount += events
			roll.Hosts = append(roll.Hosts, host)
			roll.Agents = append(roll.Agents, fleetRuleHit{AgentID: e.AgentID, AgentName: e.AgentName, EventCount: events})
			sum.TotalAlerts++
		}
	}

	for _, key := range order {
		roll := byRule[key]
		sort.Strings(roll.Hosts)
		sum.Rules = append(sum.Rules, *roll)
	}
	sum.RulesTriggered = len(sum.Rules)

	// Severity first, then spread across the fleet, then volume: a critical on
	// one box outranks a medium on forty, but a technique on forty boxes must
	// still surface above the same technique on one.
	sort.SliceStable(sum.Rules, func(i, j int) bool {
		a, b := sum.Rules[i], sum.Rules[j]
		if ra, rb := ruleLevelRank[a.RuleLevel], ruleLevelRank[b.RuleLevel]; ra != rb {
			return ra > rb
		}
		if a.AgentCount != b.AgentCount {
			return a.AgentCount > b.AgentCount
		}
		if a.EventCount != b.EventCount {
			return a.EventCount > b.EventCount
		}
		return a.RuleTitle < b.RuleTitle
	})
	return sum
}

// fleetRuleKey identifies a rule across hosts. Rule IDs are the reliable
// identity; a ruleset entry without one falls back to its title, which is what
// the fleet has in common (the engine's own fallback includes a file path that
// is meaningless across machines).
func fleetRuleKey(a sigma.Alert) string {
	if id := strings.TrimSpace(a.RuleID); id != "" {
		return "id:" + id
	}
	return "title:" + strings.TrimSpace(a.RuleTitle)
}

// FleetSigmaSweepSummary rolls the per-agent sweep results up across the fleet:
// coverage (how many hosts answered) plus, per rule, which machines show it.
//
// GET /api/v1/agents/fleet/sigma-sweep/summary?scheduled_id=&since=
// since accepts a duration ("24h") or a timestamp (RFC3339 / 2006-01-02).
func (h *FleetHandler) FleetSigmaSweepSummary(c *gin.Context) {
	q := h.DB.Model(&models.FleetCollectionResult{}).
		Where("collection = ?", fleetSweepCollection).
		Order("started_at desc").
		Limit(fleetSummaryMaxRows)

	runID := strings.TrimSpace(c.Query("scheduled_id"))
	if runID != "" {
		if _, err := uuid.Parse(runID); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scheduled_id"})
			return
		}
		q = q.Where("scheduled_id = ?", runID)
	}

	sinceRaw := c.Query("since")
	since, ok := parseFleetSince(sinceRaw)
	if sinceRaw != "" && !ok {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid since: use a duration (24h) or a timestamp (RFC3339)"})
		return
	}
	// Without a run id the summary would otherwise span the entire history, which
	// blends unrelated hunts together.
	if !ok && runID == "" {
		since = time.Now().UTC().Add(-fleetSummaryDefaultWindow)
		ok = true
	}
	if ok {
		q = q.Where("started_at >= ?", since)
	}

	var rows []models.FleetCollectionResult
	if err := q.Find(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to read sweep results"})
		return
	}

	entries := make([]fleetSweepEntry, 0, len(rows))
	for i := range rows {
		e := fleetSweepEntry{
			AgentID:   rows[i].AgentID.String(),
			AgentName: rows[i].AgentName,
			Status:    rows[i].Status,
		}
		if rows[i].Data != "" {
			var d fleetSweepData
			if err := json.Unmarshal([]byte(rows[i].Data), &d); err == nil {
				e.Data = &d
			}
		}
		entries = append(entries, e)
	}

	summary := rollupFleetSweep(entries)
	out := gin.H{
		"scheduled_id": runID,
		"truncated":    len(rows) >= fleetSummaryMaxRows,
		"summary":      summary,
	}
	if ok {
		out["since"] = since.UTC().Format(time.RFC3339)
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": out})
}

// parseFleetSince accepts a lookback duration ("24h", "90m") or an absolute
// timestamp, because both are natural for "since" and guessing wrong is worse
// than accepting both.
func parseFleetSince(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return time.Now().UTC().Add(-d), true
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

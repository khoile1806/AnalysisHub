package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/analysishub/backend/internal/hunting/sigma"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/ws"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// sweepSourceTimeout bounds a single channel query. A channel that is missing on
// the host (no Sysmon, for example) simply never answers, so the sweep must move
// on rather than stall.
const sweepSourceTimeout = 90 * time.Second

// sweepTotalBudget bounds the whole sweep. Sources are queried in rule-count
// order, so an early cut-off still covers the most productive channels.
const sweepTotalBudget = 8 * time.Minute

// defaultSweepMax is the per-source event cap. Sigma matching is
// O(events × rules); a few thousand per channel is a meaningful sample without
// turning one button into a multi-minute stall on a busy server.
const defaultSweepMax = 2000

// agentMaxEventsPerQuery mirrors the agent's own ceiling: it silently falls back
// to 500 for anything larger, so asking for more returns fewer events.
const agentMaxEventsPerQuery = 5000

// sweepSourceResult reports what one channel contributed, including why it
// produced nothing — "no Sysmon on this host" and "query failed" must not look
// the same as "clean".
type sweepSourceResult struct {
	LogName  string `json:"log_name"`
	EventIDs []int  `json:"event_ids,omitempty"`
	Events   int    `json:"events"`
	Rules    int    `json:"rules"`
	Error    string `json:"error,omitempty"`
}

// SigmaSweep runs the entire loaded Sigma ruleset against a whole machine.
//
// Rather than scanning only the events an analyst happened to pull, it asks the
// engine which channels and event IDs the ruleset actually needs, queries each
// of them on the agent, and evaluates everything in one pass.
//
// POST /api/v1/agents/:id/sigma/sweep
// Body: {"hours": 24, "max_per_source": 2000}
func SigmaSweep(c *gin.Context) {
	hub, ok := mustGetHub(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid agent ID"})
		return
	}
	if !hub.IsAgentOnline(id.String()) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": "agent is offline"})
		return
	}

	var req struct {
		// Pointer so an explicit 0 ("all time", which the agent understands as
		// "no time filter") is distinguishable from the field being omitted.
		// Coercing 0 to 24h made the UI's "All time" option quietly mean
		// "last 24 hours" — the tool answering a different question than the
		// one that was asked.
		Hours        *int `json:"hours"`
		MaxPerSource int  `json:"max_per_source"`
	}
	_ = c.ShouldBindJSON(&req) // all fields optional
	hours := 24
	if req.Hours != nil {
		hours = *req.Hours
	}
	if hours < 0 {
		hours = 0
	}
	// The agent rejects anything above 5000 by falling back to 500, so clamp
	// rather than pass a value through that would silently shrink the pull.
	if req.MaxPerSource <= 0 {
		req.MaxPerSource = defaultSweepMax
	}
	if req.MaxPerSource > agentMaxEventsPerQuery {
		req.MaxPerSource = agentMaxEventsPerQuery
	}

	engine := sigma.DefaultEngine
	if engine == nil || engine.RuleCount() == 0 {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"error":   "no Sigma rules are loaded on the server - rebuild the backend image or run a rule sync",
		})
		return
	}

	deadline := time.Now().Add(sweepTotalBudget)
	var allEvents []map[string]interface{}

	// A Linux endpoint has no EVTX channels at all. Sweeping it with the Windows
	// source plan would time out on every channel and report "nothing found",
	// which reads as a clean machine rather than the wrong question.
	if agentIsLinux(c, id.String()) {
		res := sweepSourceResult{LogName: linuxEventSource, Rules: engine.RuleCount()}
		events, err := collectLinuxEventsForSweep(hub, id.String(), hours, req.MaxPerSource)
		if err != nil {
			res.Error = err.Error()
		} else {
			res.Events = len(events)
			allEvents = events
		}
		finishSweep(c, engine, allEvents, []sweepSourceResult{res}, hours, id.String())
		return
	}

	sources := engine.RequiredSources()
	results := make([]sweepSourceResult, 0, len(sources))

	for _, src := range sources {
		res := sweepSourceResult{LogName: src.LogName, EventIDs: src.EventIDs, Rules: src.Rules}
		if time.Now().After(deadline) {
			res.Error = "skipped: sweep time budget exhausted"
			results = append(results, res)
			continue
		}
		events, err := collectEvtxForSweep(hub, id.String(), src, hours, req.MaxPerSource)
		if err != nil {
			res.Error = err.Error()
			results = append(results, res)
			continue
		}
		res.Events = len(events)
		allEvents = append(allEvents, events...)
		results = append(results, res)
	}

	finishSweep(c, engine, allEvents, results, hours, id.String())
}

// finishSweep evaluates the collected events and writes the response. Shared by
// the Windows channel sweep and the Linux event sweep so both report the same
// shape and both leave the same evidence trail.
func finishSweep(c *gin.Context, engine *sigma.Engine, allEvents []map[string]interface{},
	results []sweepSourceResult, hours int, agentID string) {

	if len(allEvents) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": gin.H{
				"alerts": []interface{}{}, "events_scanned": 0,
				"sources": results, "rules_count": engine.RuleCount(), "load_stats": engine.Stats(),
				"hours": hours,
			},
		})
		return
	}

	alerts, err := engine.ScanEvents(c.Request.Context(), allEvents)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "sigma scan failed: " + err.Error()})
		return
	}

	out := gin.H{
		"alerts":         alerts,
		"events_scanned": len(allEvents),
		"sources":        results,
		"rules_count":    engine.RuleCount(),
		"load_stats":     engine.Stats(),
		"hours":          hours,
	}

	// Snapshot into the Evidence Store so a full-machine sweep leaves the same
	// marked trail every other scan does.
	if snapshot, mErr := json.Marshal(out); mErr == nil {
		recordEdgeScanEvidence(c, agentID, "sigma-sweep", snapshot)
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": out})
}

// linuxEventSource is the pseudo-channel name reported for a Linux sweep, so the
// UI's per-source table reads sensibly on both platforms.
const linuxEventSource = "auditd / journald (Linux events)"

// agentIsLinux reports whether the agent runs Linux. Unknown agents fall back to
// the Windows path, which is what every existing deployment expects.
func agentIsLinux(c *gin.Context, agentID string) bool {
	dbAny, ok := c.Get("db")
	if !ok {
		return false
	}
	db, ok := dbAny.(*gorm.DB)
	if !ok {
		return false
	}
	var agent models.Agent
	if err := db.Select("os").First(&agent, "id = ?", agentID).Error; err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(agent.OS), "linux")
}

// collectLinuxEventsForSweep pulls the agent's structured Linux event feed and
// flattens it into the shape the rules match on.
func collectLinuxEventsForSweep(hub *ws.Hub, agentID string, hours, max int) ([]map[string]interface{}, error) {
	argsJSON, _ := json.Marshal(map[string]interface{}{"hours": hours, "max": max})

	reqID := uuid.New().String()
	outCh := hub.SubscribeJobOutput(reqID)
	defer hub.UnsubscribeJobOutput(reqID, outCh)

	if err := hub.SendJobToAgent(agentID, ws.AgentCommand{
		Type:  "edge_parse_linux_events",
		JobID: reqID,
		Args:  string(argsJSON),
	}); err != nil {
		return nil, fmt.Errorf("failed to send query")
	}

	select {
	case result := <-outCh:
		if strings.HasPrefix(result, "[agent error]") {
			return nil, fmt.Errorf("%s", strings.TrimSpace(strings.TrimPrefix(result, "[agent error]")))
		}
		return flattenLinuxEvents([]byte(result))
	case <-time.After(sweepSourceTimeout):
		return nil, fmt.Errorf("no response within %s", sweepSourceTimeout)
	}
}

// linuxEvent mirrors the agent's normalised Linux record.
type linuxEvent struct {
	Time        string `json:"time"`
	Source      string `json:"source"`
	RecordType  string `json:"record_type"`
	EventID     string `json:"event_id"`
	Executable  string `json:"executable"`
	CommandLine string `json:"command_line"`
	ParentExe   string `json:"parent_exe"`
	Comm        string `json:"comm"`
	PID         int    `json:"pid"`
	PPID        int    `json:"ppid"`
	User        string `json:"user"`
	UID         string `json:"uid"`
	AUID        string `json:"auid"`
	TTY         string `json:"tty"`
	CWD         string `json:"cwd"`
	Path        string `json:"path"`
	Key         string `json:"key"`
	Success     string `json:"success"`
	Host        string `json:"host"`
	Raw         string `json:"raw"`
}

func flattenLinuxEvents(raw []byte) ([]map[string]interface{}, error) {
	var events []linuxEvent
	if err := json.Unmarshal(raw, &events); err != nil {
		var one linuxEvent
		if err2 := json.Unmarshal(raw, &one); err2 != nil {
			return nil, fmt.Errorf("unreadable event data from agent")
		}
		events = []linuxEvent{one}
	}

	out := make([]map[string]interface{}, 0, len(events))
	for _, e := range events {
		// Platform is what stops a Windows rule being judged against Linux
		// telemetry (and vice versa); EventID carries the category name, which is
		// how logsource gating classifies a Linux event.
		m := map[string]interface{}{
			"Platform":         "linux",
			"Source":           e.Source,
			"EventID":          e.EventID,
			"RecordType":       e.RecordType,
			"Executable":       e.Executable,
			"CommandLine":      e.CommandLine,
			"ParentExe":        e.ParentExe,
			"Comm":             e.Comm,
			"ProcessId":        e.PID,
			"ParentPid":        e.PPID,
			"User":             e.User,
			"Uid":              e.UID,
			"Auid":             e.AUID,
			"TTY":              e.TTY,
			"CurrentDirectory": e.CWD,
			"TargetFilename":   e.Path,
			"AuditKey":         e.Key,
			"Success":          e.Success,
			"Computer":         e.Host,
			"TimeCreated":      e.Time,
			"Message":          e.Raw,
		}
		out = append(out, m)
	}
	return out, nil
}

// collectEvtxForSweep runs one edge_parse_evtx query and returns the events
// flattened into the shape the rules match on: EventData keys at the top level
// with the identity fields layered on top.
func collectEvtxForSweep(hub *ws.Hub, agentID string, src sigma.Source, hours, max int) ([]map[string]interface{}, error) {
	argsJSON, _ := json.Marshal(map[string]interface{}{
		"log":   src.LogName,
		"ids":   src.EventIDs,
		"hours": hours,
		"max":   max,
	})

	reqID := uuid.New().String()
	outCh := hub.SubscribeJobOutput(reqID)
	defer hub.UnsubscribeJobOutput(reqID, outCh)

	if err := hub.SendJobToAgent(agentID, ws.AgentCommand{
		Type:  "edge_parse_evtx",
		JobID: reqID,
		Args:  string(argsJSON),
	}); err != nil {
		return nil, fmt.Errorf("failed to send query")
	}

	select {
	case result := <-outCh:
		if strings.HasPrefix(result, "[agent error]") {
			return nil, fmt.Errorf("%s", strings.TrimSpace(strings.TrimPrefix(result, "[agent error]")))
		}
		return flattenEvtxEvents([]byte(result))
	case <-time.After(sweepSourceTimeout):
		// Most often this channel does not exist on the host (no Sysmon, no
		// PowerShell operational logging). Say so rather than failing the sweep.
		return nil, fmt.Errorf("no response within %s (channel may not exist on this host)", sweepSourceTimeout)
	}
}

// evtxEvent mirrors the agent's EVTX record.
type evtxEvent struct {
	Time     string            `json:"time"`
	ID       int               `json:"id"`
	Level    string            `json:"level"`
	Provider string            `json:"provider"`
	Computer string            `json:"computer"`
	RecordID int64             `json:"record_id"`
	Message  string            `json:"message"`
	Data     map[string]string `json:"data"`
}

func flattenEvtxEvents(raw []byte) ([]map[string]interface{}, error) {
	var events []evtxEvent
	if err := json.Unmarshal(raw, &events); err != nil {
		// A single object is valid too.
		var one evtxEvent
		if err2 := json.Unmarshal(raw, &one); err2 != nil {
			return nil, fmt.Errorf("unreadable event data from agent")
		}
		events = []evtxEvent{one}
	}

	out := make([]map[string]interface{}, 0, len(events))
	for _, e := range events {
		m := make(map[string]interface{}, len(e.Data)+6)
		for k, v := range e.Data {
			m[k] = v
		}
		// Identity fields go last: an EventData element named EventID or Provider
		// must not shadow the values logsource gating relies on.
		m["EventID"] = e.ID
		m["Provider"] = e.Provider
		m["Message"] = e.Message
		m["Computer"] = e.Computer
		m["TimeCreated"] = e.Time
		m["Level"] = e.Level
		out = append(out, m)
	}
	return out, nil
}

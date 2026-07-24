package handlers

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/hunting/sigma"
	"github.com/analysishub/backend/internal/models"
)

// Detection coverage answers the question a rule count hides: how much of the
// loaded ruleset can actually fire on the estate. "3000 rules loaded" means
// nothing when most of them need Sysmon and no host runs Sysmon — those rules
// have never evaluated a single event. The evidence is the per-channel outcome
// already recorded by every fleet sigma sweep: a channel that errored on a host
// is a channel that host cannot supply.

// coverageDefaultDays is the lookback when the caller gives none. A week is long
// enough to include the last scheduled sweep on most fleets without dragging in
// a ruleset that has since been replaced.
const coverageDefaultDays = 7

// coverageMaxDays caps the lookback. Past this the sweeps predate the current
// ruleset badly enough that the verdicts would describe a machine that no longer
// exists.
const coverageMaxDays = 90

// coverageMaxRows bounds how many sweep rows one report decodes. Each row
// carries a full alert payload, so an unbounded scan is a memory hazard; only
// the newest row per agent is used, so the cap costs nothing until the window
// holds more sweeps than that.
const coverageMaxRows = 1000

// Channel verdicts. A channel no host can supply is `missing`; one that no sweep
// has ever touched is `unknown` and must never be reported as covered.
const (
	coverageCovered = "covered"
	coveragePartial = "partial"
	coverageMissing = "missing"
	coverageUnknown = "unknown"
	coverageBlind   = "blind"
)

// DetectionCoverageHandler reports which of the loaded detection rules the
// telemetry on the endpoints can actually exercise.
type DetectionCoverageHandler struct {
	DB *gorm.DB
}

func NewDetectionCoverageHandler(db *gorm.DB) *DetectionCoverageHandler {
	return &DetectionCoverageHandler{DB: db}
}

// ── Inputs to the aggregation (kept free of GORM and of the clock) ───────────

// coverageSweepRow is one decoded sigma-sweep result row.
type coverageSweepRow struct {
	AgentID   string
	AgentName string
	Status    string
	StartedAt time.Time
	Data      *fleetSweepData
}

// hasSources reports whether the row carries per-channel evidence. A row without
// it (offline agent, encode failure) says nothing about what the host can log.
func (r coverageSweepRow) hasSources() bool {
	return r.Data != nil && len(r.Data.Sources) > 0
}

// coverageAgent is the fleet inventory — the denominator. Without it a report
// built purely from sweep rows would silently omit every host nobody has swept.
type coverageAgent struct {
	ID       string
	Name     string
	Hostname string
	OS       string
	Status   string
}

// coverageInput is everything buildDetectionCoverage needs. WindowDesc carries
// the evidence basis in words so the aggregation never has to read a clock.
type coverageInput struct {
	Sources    []sigma.Source
	Stats      sigma.LoadStats
	RuleCount  int
	Rows       []coverageSweepRow
	Agents     []coverageAgent
	WindowDesc string
	Truncated  bool
}

// ── Response shape ───────────────────────────────────────────────────────────

// coverageRuleset surfaces the load outcome honestly: rules that parsed but can
// never fire, and files that could not be read at all, are part of the answer.
type coverageRuleset struct {
	Loaded           bool `json:"loaded"`
	RulesLoaded      int  `json:"rules_loaded"`
	RulesUnsupported int  `json:"rules_unsupported"`
	FilesScanned     int  `json:"files_scanned"`
	FilesUnreadable  int  `json:"files_unreadable"`
	ChannelsRequired int  `json:"channels_required"`
}

// coverageHeadline is the top-of-page summary. RulesAtRisk is the number the
// page exists to show.
type coverageHeadline struct {
	RulesAtRisk      int     `json:"rules_at_risk"`
	RulesUnmeasured  int     `json:"rules_unmeasured"`
	RulesReachable   int     `json:"rules_reachable"`
	ChannelRuleTotal int     `json:"channel_rule_total"`
	ChannelsCovered  int     `json:"channels_covered"`
	ChannelsPartial  int     `json:"channels_partial"`
	ChannelsMissing  int     `json:"channels_missing"`
	ChannelsUnknown  int     `json:"channels_unknown"`
	HostsTotal       int     `json:"hosts_total"`
	HostsSwept       int     `json:"hosts_swept"`
	HostsNeverSwept  int     `json:"hosts_never_swept"`
	HostsBlind       int     `json:"hosts_blind"`
	CoveragePercent  float64 `json:"coverage_percent"`
}

// coverageChannel is one log channel the ruleset needs, with what the fleet
// actually managed to read from it.
type coverageChannel struct {
	LogName         string `json:"log_name"`
	Rules           int    `json:"rules"`
	EventIDs        []int  `json:"event_ids,omitempty"`
	InRuleset       bool   `json:"in_ruleset"`
	HostsReporting  int    `json:"hosts_reporting"`
	HostsWithEvents int    `json:"hosts_with_events"`
	HostsSilent     int    `json:"hosts_silent"`
	HostsFailed     int    `json:"hosts_failed"`
	Events          int    `json:"events"`
	Verdict         string `json:"verdict"`
	SampleError     string `json:"sample_error,omitempty"`
	Note            string `json:"note,omitempty"`
}

// coverageHost is one endpoint's share of the ruleset. CoveragePercent is
// rule-weighted, not channel-counted: losing Sysmon costs far more than losing
// the BITS-Client log, and a plain channel ratio would hide that.
type coverageHost struct {
	AgentID        string   `json:"agent_id"`
	AgentName      string   `json:"agent_name"`
	Hostname       string   `json:"hostname,omitempty"`
	OS             string   `json:"os,omitempty"`
	AgentStatus    string   `json:"agent_status,omitempty"`
	Status         string   `json:"status"`
	Measured       bool     `json:"measured"`
	SweepStatus    string   `json:"sweep_status,omitempty"`
	LastSwept      string   `json:"last_swept,omitempty"`
	CoveragePct    float64  `json:"coverage_percent"`
	RulesReachable int      `json:"rules_reachable"`
	RulesBlocked   int      `json:"rules_blocked"`
	ChannelsOK     []string `json:"channels_ok"`
	ChannelsSilent []string `json:"channels_silent"`
	ChannelsFailed []string `json:"channels_failed"`
	Note           string   `json:"note,omitempty"`
}

// coverageTechnique is one ATT&CK technique observed firing in the sweeps.
type coverageTechnique struct {
	Technique string `json:"technique"`
	Hosts     int    `json:"hosts"`
	Rules     int    `json:"rules"`
}

// coverageAttack reports what is measurable about ATT&CK coverage — and says
// plainly what is not, rather than presenting an observed-technique list as if
// it were the ruleset's coverage.
type coverageAttack struct {
	RulesetMeasurable  bool                `json:"ruleset_measurable"`
	Note               string              `json:"note"`
	TechniquesObserved []coverageTechnique `json:"techniques_observed"`
	TacticsObserved    []string            `json:"tactics_observed"`
}

// detectionCoverage is the whole report.
type detectionCoverage struct {
	MeasuredFrom string            `json:"measured_from"`
	NoData       bool              `json:"no_data"`
	Truncated    bool              `json:"truncated"`
	Ruleset      coverageRuleset   `json:"ruleset"`
	Headline     coverageHeadline  `json:"headline"`
	Channels     []coverageChannel `json:"channels"`
	Hosts        []coverageHost    `json:"hosts"`
	Attack       coverageAttack    `json:"attack"`
	Notes        []string          `json:"notes"`
}

// attackNotMeasurable explains the one thing this report cannot compute. The
// engine exposes rule counts and required sources but not the rules themselves,
// so the ruleset's own technique list is out of reach from here.
const attackNotMeasurable = "the loaded ruleset's own ATT&CK technique list is not measurable: the Sigma engine exposes rule counts and required log sources, not the rules. Only techniques that actually fired during the sweeps below are counted here, so this is a floor on coverage, never the ruleset's full mapping."

// ── Aggregation (pure) ───────────────────────────────────────────────────────

// buildDetectionCoverage turns the ruleset's requirements plus the fleet's sweep
// evidence into a coverage report. It is a pure function of its input — no DB,
// no clock — so the verdicts are testable directly.
func buildDetectionCoverage(in coverageInput) detectionCoverage {
	out := detectionCoverage{
		Channels: []coverageChannel{},
		Hosts:    []coverageHost{},
		Notes:    []string{},
		Ruleset: coverageRuleset{
			Loaded:           in.RuleCount > 0,
			RulesLoaded:      in.RuleCount,
			RulesUnsupported: in.Stats.Unsupported,
			FilesScanned:     in.Stats.Files,
			FilesUnreadable:  in.Stats.Errors,
			ChannelsRequired: len(in.Sources),
		},
		Truncated: in.Truncated,
		Attack:    coverageAttack{Note: attackNotMeasurable, TechniquesObserved: []coverageTechnique{}, TacticsObserved: []string{}},
	}

	latest := latestSweepPerAgent(in.Rows)
	channels := aggregateChannels(in.Sources, latest)
	out.Channels = channels
	out.Hosts = aggregateHosts(in.Agents, latest)
	out.Attack.TechniquesObserved, out.Attack.TacticsObserved = aggregateAttack(latest)

	// Headline. Rule totals are summed per channel, so ChannelRuleTotal is the
	// denominator the percentages use — not RulesLoaded, which counts each rule
	// once however many channels it targets.
	head := coverageHeadline{HostsTotal: len(in.Agents)}
	for _, ch := range channels {
		switch ch.Verdict {
		case coverageCovered:
			head.ChannelsCovered++
		case coveragePartial:
			head.ChannelsPartial++
		case coverageMissing:
			head.ChannelsMissing++
		default:
			head.ChannelsUnknown++
		}
		if !ch.InRuleset {
			continue
		}
		head.ChannelRuleTotal += ch.Rules
		switch ch.Verdict {
		case coverageMissing:
			head.RulesAtRisk += ch.Rules
		case coverageUnknown:
			head.RulesUnmeasured += ch.Rules
		default:
			head.RulesReachable += ch.Rules
		}
	}
	head.CoveragePercent = coveragePct(head.RulesReachable, head.ChannelRuleTotal)

	for _, h := range out.Hosts {
		if h.Measured {
			head.HostsSwept++
			if h.Status == coverageBlind {
				head.HostsBlind++
			}
			continue
		}
		head.HostsNeverSwept++
	}

	out.Headline = head
	out.NoData = head.HostsSwept == 0
	out.MeasuredFrom = describeCoverageEvidence(in.WindowDesc, head)
	out.Notes = coverageNotes(in, head, out.NoData)
	return out
}

// latestSweepPerAgent reduces the rows to one per agent. A row carrying channel
// evidence beats one that does not, whatever their ages: "the agent was offline
// last night" says nothing about which channels exist on it, while last week's
// successful sweep does.
func latestSweepPerAgent(rows []coverageSweepRow) []coverageSweepRow {
	best := map[string]coverageSweepRow{}
	order := []string{}
	for _, r := range rows {
		id := strings.TrimSpace(r.AgentID)
		if id == "" {
			continue
		}
		r.AgentID = id
		cur, seen := best[id]
		if !seen {
			best[id] = r
			order = append(order, id)
			continue
		}
		if preferSweepRow(r, cur) {
			best[id] = r
		}
	}
	out := make([]coverageSweepRow, 0, len(order))
	for _, id := range order {
		out = append(out, best[id])
	}
	return out
}

func preferSweepRow(candidate, current coverageSweepRow) bool {
	if c, cur := candidate.hasSources(), current.hasSources(); c != cur {
		return c
	}
	return candidate.StartedAt.After(current.StartedAt)
}

// channelAgg accumulates one channel across hosts.
type channelAgg struct {
	ch    coverageChannel
	order int
}

// aggregateChannels joins what the ruleset needs with what the fleet could read.
// Channels the sweeps touched but the current ruleset no longer needs are kept
// (dropping them would hide evidence) but excluded from the rule arithmetic.
func aggregateChannels(sources []sigma.Source, rows []coverageSweepRow) []coverageChannel {
	byName := map[string]*channelAgg{}
	next := 0
	get := func(name string) *channelAgg {
		agg, ok := byName[name]
		if !ok {
			agg = &channelAgg{ch: coverageChannel{LogName: name, Verdict: coverageUnknown}, order: next}
			next++
			byName[name] = agg
		}
		return agg
	}

	for _, s := range sources {
		agg := get(s.LogName)
		agg.ch.Rules = s.Rules
		agg.ch.EventIDs = s.EventIDs
		agg.ch.InRuleset = true
	}

	for _, row := range rows {
		if !row.hasSources() {
			continue
		}
		for _, sr := range row.Data.Sources {
			agg := get(sr.LogName)
			if !agg.ch.InRuleset && agg.ch.Rules == 0 {
				// Rule count from the sweep itself: the ruleset that ran it knew
				// how many rules depended on the channel at the time.
				agg.ch.Rules = sr.Rules
				agg.ch.Note = "not required by the currently loaded ruleset - excluded from the rule totals"
			}
			agg.ch.HostsReporting++
			agg.ch.Events += sr.Events
			switch {
			case strings.TrimSpace(sr.Error) != "":
				agg.ch.HostsFailed++
				if agg.ch.SampleError == "" {
					agg.ch.SampleError = strings.TrimSpace(sr.Error)
				}
			case sr.Events > 0:
				agg.ch.HostsWithEvents++
			default:
				agg.ch.HostsSilent++
			}
		}
	}

	out := make([]coverageChannel, 0, len(byName))
	for _, agg := range byName {
		agg.ch.Verdict = channelVerdict(agg.ch)
		out = append(out, agg.ch)
	}
	// Worst first among the channels that matter: a missing channel carrying
	// thousands of rules is the whole point of the page.
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.InRuleset != b.InRuleset {
			return a.InRuleset
		}
		if ra, rb := channelVerdictRank(a.Verdict), channelVerdictRank(b.Verdict); ra != rb {
			return ra < rb
		}
		if a.Rules != b.Rules {
			return a.Rules > b.Rules
		}
		return a.LogName < b.LogName
	})
	return out
}

// channelVerdict is deliberately blunt. A channel every reporting host answered
// with events is covered; one that produced no event anywhere — whether it
// errored or stayed silent — cannot be relied on to fire anything.
func channelVerdict(ch coverageChannel) string {
	if ch.HostsReporting == 0 {
		return coverageUnknown
	}
	if ch.HostsWithEvents == 0 {
		return coverageMissing
	}
	if ch.HostsWithEvents == ch.HostsReporting {
		return coverageCovered
	}
	return coveragePartial
}

func channelVerdictRank(v string) int {
	switch v {
	case coverageMissing:
		return 0
	case coveragePartial:
		return 1
	case coverageUnknown:
		return 2
	default:
		return 3
	}
}

// aggregateHosts reports every enrolled agent, swept or not. An agent nobody has
// ever swept is `unknown`, never 0% and never omitted: both would be read as a
// measurement that was never taken.
func aggregateHosts(agents []coverageAgent, rows []coverageSweepRow) []coverageHost {
	byAgent := map[string]coverageSweepRow{}
	for _, r := range rows {
		byAgent[r.AgentID] = r
	}

	out := make([]coverageHost, 0, len(agents)+len(rows))
	seen := map[string]bool{}
	for _, a := range agents {
		seen[a.ID] = true
		row, ok := byAgent[a.ID]
		h := hostCoverage(row, ok)
		h.AgentID = a.ID
		h.AgentName = firstNonBlank(a.Name, row.AgentName, a.Hostname, a.ID)
		h.Hostname = a.Hostname
		h.OS = a.OS
		h.AgentStatus = a.Status
		out = append(out, h)
	}
	// A result whose agent has since been deleted still describes telemetry that
	// existed; keep it rather than pretending the sweep never happened.
	for _, r := range rows {
		if seen[r.AgentID] {
			continue
		}
		h := hostCoverage(r, true)
		h.AgentID = r.AgentID
		h.AgentName = firstNonBlank(r.AgentName, r.AgentID)
		h.Note = strings.TrimSpace(h.Note + " agent is no longer enrolled.")
		out = append(out, h)
	}

	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ra, rb := hostStatusRank(a.Status), hostStatusRank(b.Status); ra != rb {
			return ra < rb
		}
		if a.CoveragePct != b.CoveragePct {
			return a.CoveragePct < b.CoveragePct
		}
		return a.AgentName < b.AgentName
	})
	return out
}

// hostCoverage scores one agent from its most useful sweep row.
func hostCoverage(row coverageSweepRow, found bool) coverageHost {
	h := coverageHost{
		Status:         coverageUnknown,
		ChannelsOK:     []string{},
		ChannelsSilent: []string{},
		ChannelsFailed: []string{},
	}
	if !found {
		h.Note = "never swept - coverage on this host is unmeasured, not zero."
		return h
	}

	h.SweepStatus = row.Status
	if !row.StartedAt.IsZero() {
		h.LastSwept = row.StartedAt.UTC().Format(time.RFC3339)
	}
	if !row.hasSources() {
		h.Note = "the last sweep returned no channel results"
		if e := strings.TrimSpace(row.Status); e != "" {
			h.Note += " (status: " + e + ")"
		}
		h.Note += " - coverage on this host is unmeasured, not zero."
		return h
	}

	h.Measured = true
	total := 0
	for _, sr := range row.Data.Sources {
		total += sr.Rules
		switch {
		case strings.TrimSpace(sr.Error) != "":
			h.ChannelsFailed = append(h.ChannelsFailed, sr.LogName)
			h.RulesBlocked += sr.Rules
		case sr.Events > 0:
			h.ChannelsOK = append(h.ChannelsOK, sr.LogName)
			h.RulesReachable += sr.Rules
		default:
			h.ChannelsSilent = append(h.ChannelsSilent, sr.LogName)
		}
	}
	h.CoveragePct = coveragePct(h.RulesReachable, total)

	switch {
	case len(h.ChannelsOK) == 0:
		// Nothing was read, so nothing can be shown to fire — the same rule the
		// per-channel verdict applies. Whether that is a missing channel or a
		// quiet one changes the fix, so say which.
		h.Status = coverageBlind
		if len(h.ChannelsFailed) == 0 {
			h.Note = "every channel answered but returned no events in the window - the host may simply be quiet rather than unlogged."
		}
	case len(h.ChannelsFailed) == 0 && len(h.ChannelsSilent) == 0:
		h.Status = coverageCovered
	default:
		h.Status = coveragePartial
	}
	return h
}

func hostStatusRank(s string) int {
	switch s {
	case coverageBlind:
		return 0
	case coveragePartial:
		return 1
	case coverageUnknown:
		return 2
	default:
		return 3
	}
}

// aggregateAttack counts the techniques that actually fired across the fleet.
// This is evidence of coverage, not a map of it — see attackNotMeasurable.
func aggregateAttack(rows []coverageSweepRow) ([]coverageTechnique, []string) {
	hosts := map[string]map[string]bool{}
	rules := map[string]map[string]bool{}
	tactics := map[string]bool{}

	for _, row := range rows {
		if row.Data == nil {
			continue
		}
		for _, a := range row.Data.Alerts {
			for _, tech := range a.Techniques {
				tech = strings.ToUpper(strings.TrimSpace(tech))
				if tech == "" {
					continue
				}
				if hosts[tech] == nil {
					hosts[tech] = map[string]bool{}
					rules[tech] = map[string]bool{}
				}
				hosts[tech][row.AgentID] = true
				rules[tech][fleetRuleKey(a)] = true
			}
			for _, tac := range a.Tactics {
				if tac = strings.TrimSpace(tac); tac != "" {
					tactics[tac] = true
				}
			}
		}
	}

	techs := make([]coverageTechnique, 0, len(hosts))
	for tech, h := range hosts {
		techs = append(techs, coverageTechnique{Technique: tech, Hosts: len(h), Rules: len(rules[tech])})
	}
	sort.Slice(techs, func(i, j int) bool {
		if techs[i].Hosts != techs[j].Hosts {
			return techs[i].Hosts > techs[j].Hosts
		}
		return techs[i].Technique < techs[j].Technique
	})

	tacs := make([]string, 0, len(tactics))
	for t := range tactics {
		tacs = append(tacs, t)
	}
	sort.Strings(tacs)
	return techs, tacs
}

// describeCoverageEvidence states what the numbers rest on, so a 0% page cannot
// be mistaken for a measured blackout.
func describeCoverageEvidence(window string, head coverageHeadline) string {
	if head.HostsSwept == 0 {
		return fmt.Sprintf("no evidence: %s returned no sweep results (%d agent(s) enrolled)", window, head.HostsTotal)
	}
	return fmt.Sprintf("%s, %d of %d enrolled host(s) swept", window, head.HostsSwept, head.HostsTotal)
}

func coverageNotes(in coverageInput, head coverageHeadline, noData bool) []string {
	notes := []string{}
	if in.RuleCount == 0 {
		notes = append(notes, "No Sigma rules are loaded on the server, so there is nothing to cover - run a rule sync before reading these numbers.")
	}
	if in.Stats.Errors > 0 {
		notes = append(notes, fmt.Sprintf("%d rule file(s) could not be parsed and were never loaded.", in.Stats.Errors))
	}
	if in.Stats.Unsupported > 0 {
		notes = append(notes, fmt.Sprintf("%d rule(s) parsed but are unsupported by the engine (aggregation/correlation) and can never fire, whatever telemetry exists.", in.Stats.Unsupported))
	}
	if noData {
		notes = append(notes, "No fleet sigma sweep has produced results in this window, so every channel is `unknown`. This is missing evidence, not missing telemetry.")
	}
	if head.RulesAtRisk > 0 {
		notes = append(notes, "A rule that targets several channels (process_creation is 4688 on Security and 1 on Sysmon) is counted once per channel, so rules_at_risk can exceed the number of rules with no working alternative channel.")
	}
	if head.HostsNeverSwept > 0 {
		notes = append(notes, fmt.Sprintf("%d enrolled agent(s) have never been swept in this window and are reported as `unknown` rather than counted as covered.", head.HostsNeverSwept))
	}
	if head.RulesUnmeasured > 0 {
		notes = append(notes, fmt.Sprintf("%d rule(s) depend on channels no sweep has touched - their coverage is unknown, not confirmed.", head.RulesUnmeasured))
	}
	if in.Truncated {
		notes = append(notes, fmt.Sprintf("Only the %d most recent sweep rows were read; older sweeps in this window were ignored.", coverageMaxRows))
	}
	return notes
}

func coveragePct(part, total int) float64 {
	if total <= 0 {
		return 0
	}
	return math.Round(float64(part)/float64(total)*1000) / 10
}

// ── Handler ──────────────────────────────────────────────────────────────────

// GetDetectionCoverage reports which loaded detection rules the estate's actual
// telemetry can exercise: ruleset health, per-channel verdicts with the rule
// count stranded on channels no host can supply, per-host coverage (including
// hosts nobody has swept), and the ATT&CK techniques observed firing.
//
// GET /api/v1/detection/coverage?days=7
func (h *DetectionCoverageHandler) GetDetectionCoverage(c *gin.Context) {
	days := coverageDefaultDays
	if raw := strings.TrimSpace(c.Query("days")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 || n > coverageMaxDays {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": fmt.Sprintf("invalid days: use 1-%d", coverageMaxDays)})
			return
		}
		days = n
	}
	since := time.Now().UTC().AddDate(0, 0, -days)

	var results []models.FleetCollectionResult
	if err := h.DB.Model(&models.FleetCollectionResult{}).
		Where("collection = ? AND started_at >= ?", fleetSweepCollection, since).
		Order("started_at desc").
		Limit(coverageMaxRows).
		Find(&results).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to read sweep results"})
		return
	}

	var agents []models.Agent
	if err := h.DB.Model(&models.Agent{}).Find(&agents).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to read the agent inventory"})
		return
	}

	rows := make([]coverageSweepRow, 0, len(results))
	for i := range results {
		row := coverageSweepRow{
			AgentID:   results[i].AgentID.String(),
			AgentName: results[i].AgentName,
			Status:    results[i].Status,
			StartedAt: results[i].StartedAt,
		}
		if results[i].Data != "" {
			var d fleetSweepData
			if err := json.Unmarshal([]byte(results[i].Data), &d); err == nil {
				row.Data = &d
			}
		}
		rows = append(rows, row)
	}

	inv := make([]coverageAgent, 0, len(agents))
	for i := range agents {
		inv = append(inv, coverageAgent{
			ID:       agents[i].ID.String(),
			Name:     agents[i].Name,
			Hostname: agents[i].Hostname,
			OS:       agents[i].OS,
			Status:   agents[i].Status,
		})
	}

	in := coverageInput{
		Rows:       rows,
		Agents:     inv,
		WindowDesc: fmt.Sprintf("last %d day(s) of fleet sigma sweeps", days),
		Truncated:  len(results) >= coverageMaxRows,
	}
	// A server with no engine at all is reported as an unloaded ruleset rather
	// than an error: "no rules are loaded" is exactly the coverage answer.
	if engine := sigma.DefaultEngine; engine != nil {
		in.Sources = engine.RequiredSources()
		in.Stats = engine.Stats()
		in.RuleCount = engine.RuleCount()
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": buildDetectionCoverage(in)})
}

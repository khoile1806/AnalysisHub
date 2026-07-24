package handlers

import (
	"testing"
	"time"

	"github.com/analysishub/backend/internal/hunting/sigma"
)

const (
	sysmonCh = "Microsoft-Windows-Sysmon/Operational"
	secCh    = "Security"
	psCh     = "Microsoft-Windows-PowerShell/Operational"
)

var sweepBase = time.Date(2026, 7, 1, 8, 0, 0, 0, time.UTC)

// src builds one channel outcome as a sweep recorded it.
func src(logName string, rules, events int, err string) sweepSourceResult {
	return sweepSourceResult{LogName: logName, Rules: rules, Events: events, Error: err}
}

// sweptRow builds a completed sweep row for an agent.
func sweptRow(agentID, name string, at time.Time, sources ...sweepSourceResult) coverageSweepRow {
	return coverageSweepRow{
		AgentID:   agentID,
		AgentName: name,
		Status:    "done",
		StartedAt: at,
		Data:      &fleetSweepData{Sources: sources, Alerts: []sigma.Alert{}},
	}
}

func agent(id, name string) coverageAgent {
	return coverageAgent{ID: id, Name: name, OS: "windows", Status: "online"}
}

func findChannel(t *testing.T, rep detectionCoverage, logName string) coverageChannel {
	t.Helper()
	for _, ch := range rep.Channels {
		if ch.LogName == logName {
			return ch
		}
	}
	t.Fatalf("channel %q missing from report", logName)
	return coverageChannel{}
}

func findHost(t *testing.T, rep detectionCoverage, agentID string) coverageHost {
	t.Helper()
	for _, h := range rep.Hosts {
		if h.AgentID == agentID {
			return h
		}
	}
	t.Fatalf("host %q missing from report", agentID)
	return coverageHost{}
}

// noSysmonSources is the case the whole page exists for: Sysmon is absent, so
// every rule that depends on it is dead on that host.
func noSysmonSources() []sweepSourceResult {
	return []sweepSourceResult{
		src(sysmonCh, 2000, 0, "no response within 1m30s (channel may not exist on this host)"),
		src(secCh, 800, 1200, ""),
	}
}

func TestBuildDetectionCoverage(t *testing.T) {
	sources := []sigma.Source{
		{LogName: sysmonCh, Rules: 2000, EventIDs: []int{1, 3, 11}},
		{LogName: secCh, Rules: 800, EventIDs: []int{4688, 4624}},
		{LogName: psCh, Rules: 200, EventIDs: []int{4104}},
	}
	stats := sigma.LoadStats{Files: 3100, Loaded: 3000, Unsupported: 90, Errors: 10}

	cases := []struct {
		name  string
		in    coverageInput
		check func(t *testing.T, rep detectionCoverage)
	}{
		{
			name: "no sweep has ever run",
			in: coverageInput{
				Sources: sources, Stats: stats, RuleCount: 3000,
				Agents:     []coverageAgent{agent("a1", "WS-01"), agent("a2", "WS-02")},
				WindowDesc: "last 7 day(s) of fleet sigma sweeps",
			},
			check: func(t *testing.T, rep detectionCoverage) {
				if !rep.NoData {
					t.Fatalf("no_data must be true when nothing was swept")
				}
				if rep.Headline.RulesAtRisk != 0 {
					t.Errorf("rules_at_risk=%d want 0 - unmeasured is not at-risk", rep.Headline.RulesAtRisk)
				}
				if rep.Headline.RulesUnmeasured != 3000 {
					t.Errorf("rules_unmeasured=%d want 3000", rep.Headline.RulesUnmeasured)
				}
				if rep.Headline.ChannelsUnknown != 3 || rep.Headline.ChannelsMissing != 0 {
					t.Errorf("verdict counts wrong: %+v", rep.Headline)
				}
				if rep.Headline.HostsNeverSwept != 2 || rep.Headline.HostsSwept != 0 {
					t.Errorf("host counts wrong: %+v", rep.Headline)
				}
				for _, ch := range rep.Channels {
					if ch.Verdict != coverageUnknown {
						t.Errorf("channel %s verdict=%s want unknown", ch.LogName, ch.Verdict)
					}
				}
			},
		},
		{
			name: "sysmon missing everywhere strands its rules",
			in: coverageInput{
				Sources: sources, Stats: stats, RuleCount: 3000,
				Agents: []coverageAgent{agent("a1", "WS-01"), agent("a2", "WS-02")},
				Rows: []coverageSweepRow{
					sweptRow("a1", "WS-01", sweepBase, noSysmonSources()...),
					sweptRow("a2", "WS-02", sweepBase, noSysmonSources()...),
				},
				WindowDesc: "last 7 day(s) of fleet sigma sweeps",
			},
			check: func(t *testing.T, rep detectionCoverage) {
				if rep.NoData {
					t.Fatalf("no_data must be false once hosts were swept")
				}
				sys := findChannel(t, rep, sysmonCh)
				if sys.Verdict != coverageMissing {
					t.Errorf("sysmon verdict=%s want missing", sys.Verdict)
				}
				if sys.HostsFailed != 2 || sys.HostsWithEvents != 0 || sys.HostsReporting != 2 {
					t.Errorf("sysmon host counts wrong: %+v", sys)
				}
				if sys.SampleError == "" {
					t.Error("sysmon sample_error must carry why the channel failed")
				}
				if sec := findChannel(t, rep, secCh); sec.Verdict != coverageCovered {
					t.Errorf("security verdict=%s want covered", sec.Verdict)
				}
				// PowerShell was never queried by these sweeps: unknown, and its
				// rules must not be counted as at-risk.
				if ps := findChannel(t, rep, psCh); ps.Verdict != coverageUnknown {
					t.Errorf("powershell verdict=%s want unknown", ps.Verdict)
				}
				if rep.Headline.RulesAtRisk != 2000 {
					t.Errorf("rules_at_risk=%d want 2000", rep.Headline.RulesAtRisk)
				}
				if rep.Headline.RulesUnmeasured != 200 {
					t.Errorf("rules_unmeasured=%d want 200", rep.Headline.RulesUnmeasured)
				}
				if rep.Headline.RulesReachable != 800 {
					t.Errorf("rules_reachable=%d want 800", rep.Headline.RulesReachable)
				}
				// The missing channel must lead the table.
				if rep.Channels[0].LogName != sysmonCh {
					t.Errorf("channels[0]=%s want the missing sysmon channel first", rep.Channels[0].LogName)
				}
			},
		},
		{
			name: "partial verdict when only some hosts supply the channel",
			in: coverageInput{
				Sources: sources, Stats: stats, RuleCount: 3000,
				Agents: []coverageAgent{agent("a1", "WS-01"), agent("a2", "WS-02")},
				Rows: []coverageSweepRow{
					sweptRow("a1", "WS-01", sweepBase, src(sysmonCh, 2000, 500, ""), src(secCh, 800, 900, "")),
					sweptRow("a2", "WS-02", sweepBase, noSysmonSources()...),
				},
				WindowDesc: "last 7 day(s) of fleet sigma sweeps",
			},
			check: func(t *testing.T, rep detectionCoverage) {
				sys := findChannel(t, rep, sysmonCh)
				if sys.Verdict != coveragePartial {
					t.Errorf("sysmon verdict=%s want partial", sys.Verdict)
				}
				if sys.HostsWithEvents != 1 || sys.HostsFailed != 1 {
					t.Errorf("sysmon host split wrong: %+v", sys)
				}
				if rep.Headline.RulesAtRisk != 0 {
					t.Errorf("rules_at_risk=%d want 0 - one host can still supply sysmon", rep.Headline.RulesAtRisk)
				}
				h1 := findHost(t, rep, "a1")
				if h1.Status != coverageCovered || h1.CoveragePct != 100 {
					t.Errorf("WS-01 should be fully covered, got %s / %.1f%%", h1.Status, h1.CoveragePct)
				}
				h2 := findHost(t, rep, "a2")
				if h2.Status != coveragePartial {
					t.Errorf("WS-02 status=%s want partial", h2.Status)
				}
				// 800 of 2800 rule-weights reachable.
				if h2.CoveragePct != 28.6 {
					t.Errorf("WS-02 coverage=%.1f want 28.6", h2.CoveragePct)
				}
				if h2.RulesBlocked != 2000 {
					t.Errorf("WS-02 rules_blocked=%d want 2000", h2.RulesBlocked)
				}
				// Worst host first.
				if rep.Hosts[0].AgentID != "a2" {
					t.Errorf("hosts[0]=%s want the partial host first", rep.Hosts[0].AgentID)
				}
			},
		},
		{
			name: "never-swept host is unknown, not zero, and is never omitted",
			in: coverageInput{
				Sources: sources, Stats: stats, RuleCount: 3000,
				Agents: []coverageAgent{agent("a1", "WS-01"), agent("a2", "WS-02"), agent("a3", "WS-03")},
				Rows: []coverageSweepRow{
					sweptRow("a1", "WS-01", sweepBase, src(sysmonCh, 2000, 10, ""), src(secCh, 800, 20, "")),
				},
				WindowDesc: "last 7 day(s) of fleet sigma sweeps",
			},
			check: func(t *testing.T, rep detectionCoverage) {
				if len(rep.Hosts) != 3 {
					t.Fatalf("got %d host rows, want all 3 enrolled agents", len(rep.Hosts))
				}
				for _, id := range []string{"a2", "a3"} {
					h := findHost(t, rep, id)
					if h.Status != coverageUnknown || h.Measured {
						t.Errorf("%s status=%s measured=%v want unknown/false", id, h.Status, h.Measured)
					}
					if h.Note == "" {
						t.Errorf("%s must explain that it was never swept", id)
					}
				}
				if rep.Headline.HostsNeverSwept != 2 || rep.Headline.HostsSwept != 1 {
					t.Errorf("host counts wrong: %+v", rep.Headline)
				}
				if rep.MeasuredFrom != "last 7 day(s) of fleet sigma sweeps, 1 of 3 enrolled host(s) swept" {
					t.Errorf("measured_from=%q does not describe the evidence basis", rep.MeasuredFrom)
				}
			},
		},
		{
			name: "host whose every channel failed is blind",
			in: coverageInput{
				Sources: sources, Stats: stats, RuleCount: 3000,
				Agents: []coverageAgent{agent("a1", "WS-01")},
				Rows: []coverageSweepRow{
					sweptRow("a1", "WS-01", sweepBase,
						src(sysmonCh, 2000, 0, "no response"), src(secCh, 800, 0, "access denied")),
				},
				WindowDesc: "last 7 day(s) of fleet sigma sweeps",
			},
			check: func(t *testing.T, rep detectionCoverage) {
				h := findHost(t, rep, "a1")
				if h.Status != coverageBlind {
					t.Errorf("status=%s want blind", h.Status)
				}
				if h.CoveragePct != 0 || h.RulesReachable != 0 {
					t.Errorf("a blind host must reach nothing: %+v", h)
				}
				if rep.Headline.HostsBlind != 1 {
					t.Errorf("hosts_blind=%d want 1", rep.Headline.HostsBlind)
				}
				if rep.Headline.RulesAtRisk != 2800 {
					t.Errorf("rules_at_risk=%d want 2800", rep.Headline.RulesAtRisk)
				}
			},
		},
		{
			name: "silent channel counts as missing but is distinguished from a failure",
			in: coverageInput{
				Sources: []sigma.Source{{LogName: psCh, Rules: 200}}, RuleCount: 200,
				Agents: []coverageAgent{agent("a1", "WS-01")},
				Rows: []coverageSweepRow{
					sweptRow("a1", "WS-01", sweepBase, src(psCh, 200, 0, "")),
				},
				WindowDesc: "last 7 day(s) of fleet sigma sweeps",
			},
			check: func(t *testing.T, rep detectionCoverage) {
				ch := findChannel(t, rep, psCh)
				if ch.Verdict != coverageMissing {
					t.Errorf("verdict=%s want missing", ch.Verdict)
				}
				if ch.HostsSilent != 1 || ch.HostsFailed != 0 {
					t.Errorf("a silent channel must not be reported as a failure: %+v", ch)
				}
				h := findHost(t, rep, "a1")
				if h.Status != coverageBlind {
					t.Errorf("status=%s want blind - nothing was read, so nothing can fire", h.Status)
				}
				if len(h.ChannelsSilent) != 1 || len(h.ChannelsFailed) != 0 {
					t.Errorf("a silent channel must not be listed as failed: %+v", h)
				}
				if h.Note == "" {
					t.Error("a host that is quiet rather than unlogged must say so")
				}
			},
		},
		{
			name: "channel outside the current ruleset is kept but excluded from the totals",
			in: coverageInput{
				Sources: []sigma.Source{{LogName: secCh, Rules: 800}}, RuleCount: 800,
				Agents: []coverageAgent{agent("a1", "WS-01")},
				Rows: []coverageSweepRow{
					sweptRow("a1", "WS-01", sweepBase, src(secCh, 800, 50, ""), src("Microsoft-Windows-Bits-Client/Operational", 40, 0, "gone")),
				},
				WindowDesc: "last 7 day(s) of fleet sigma sweeps",
			},
			check: func(t *testing.T, rep detectionCoverage) {
				stale := findChannel(t, rep, "Microsoft-Windows-Bits-Client/Operational")
				if stale.InRuleset {
					t.Error("in_ruleset must be false for a channel the ruleset no longer needs")
				}
				if stale.Note == "" {
					t.Error("a stale channel must say why it is excluded")
				}
				if rep.Headline.RulesAtRisk != 0 {
					t.Errorf("rules_at_risk=%d want 0 - the failing channel is not required anymore", rep.Headline.RulesAtRisk)
				}
				if rep.Headline.ChannelRuleTotal != 800 {
					t.Errorf("channel_rule_total=%d want 800", rep.Headline.ChannelRuleTotal)
				}
			},
		},
		{
			name: "ruleset health is surfaced even with no telemetry evidence",
			in: coverageInput{
				Sources: sources, Stats: stats, RuleCount: 3000,
				WindowDesc: "last 7 day(s) of fleet sigma sweeps",
			},
			check: func(t *testing.T, rep detectionCoverage) {
				r := rep.Ruleset
				if !r.Loaded || r.RulesLoaded != 3000 || r.RulesUnsupported != 90 || r.FilesUnreadable != 10 || r.FilesScanned != 3100 {
					t.Errorf("ruleset health not surfaced honestly: %+v", r)
				}
				if r.ChannelsRequired != 3 {
					t.Errorf("channels_required=%d want 3", r.ChannelsRequired)
				}
				if len(rep.Notes) == 0 {
					t.Error("unsupported/unreadable rules and the empty window must produce notes")
				}
			},
		},
		{
			name: "engine unloaded reports a ruleset that covers nothing",
			in:   coverageInput{WindowDesc: "last 7 day(s) of fleet sigma sweeps"},
			check: func(t *testing.T, rep detectionCoverage) {
				if rep.Ruleset.Loaded {
					t.Error("loaded must be false with no rules")
				}
				if !rep.NoData {
					t.Error("no_data must be true with no sweeps")
				}
				if len(rep.Channels) != 0 || len(rep.Hosts) != 0 {
					t.Errorf("expected empty tables, got %d channels / %d hosts", len(rep.Channels), len(rep.Hosts))
				}
				if len(rep.Notes) == 0 {
					t.Error("an unloaded ruleset must be called out in the notes")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.check(t, buildDetectionCoverage(tc.in))
		})
	}
}

func TestBuildDetectionCoverageRowSelection(t *testing.T) {
	sources := []sigma.Source{{LogName: sysmonCh, Rules: 2000}, {LogName: secCh, Rules: 800}}

	cases := []struct {
		name  string
		rows  []coverageSweepRow
		check func(t *testing.T, h coverageHost)
	}{
		{
			name: "newest sweep wins",
			rows: []coverageSweepRow{
				sweptRow("a1", "WS-01", sweepBase.Add(-48*time.Hour), src(sysmonCh, 2000, 10, ""), src(secCh, 800, 10, "")),
				sweptRow("a1", "WS-01", sweepBase, src(sysmonCh, 2000, 0, "no response"), src(secCh, 800, 10, "")),
			},
			check: func(t *testing.T, h coverageHost) {
				if h.Status != coveragePartial {
					t.Errorf("status=%s want partial from the newest sweep", h.Status)
				}
				if h.LastSwept == "" || h.RulesBlocked != 2000 {
					t.Errorf("newest sweep not used: %+v", h)
				}
			},
		},
		{
			name: "a newer row without channel evidence never overwrites an older measurement",
			rows: []coverageSweepRow{
				{AgentID: "a1", AgentName: "WS-01", Status: "offline", StartedAt: sweepBase},
				sweptRow("a1", "WS-01", sweepBase.Add(-24*time.Hour), src(sysmonCh, 2000, 5, ""), src(secCh, 800, 5, "")),
			},
			check: func(t *testing.T, h coverageHost) {
				if !h.Measured || h.Status != coverageCovered {
					t.Errorf("older measured sweep should stand: %+v", h)
				}
			},
		},
		{
			name: "only rows without evidence leave the host unmeasured",
			rows: []coverageSweepRow{
				{AgentID: "a1", AgentName: "WS-01", Status: "offline", StartedAt: sweepBase},
			},
			check: func(t *testing.T, h coverageHost) {
				if h.Measured || h.Status != coverageUnknown {
					t.Errorf("status=%s measured=%v want unknown/false", h.Status, h.Measured)
				}
				if h.SweepStatus != "offline" || h.Note == "" {
					t.Errorf("the reason must be carried through: %+v", h)
				}
				if h.CoveragePct != 0 {
					t.Errorf("coverage=%.1f - an unmeasured host must not imply a measured 0", h.CoveragePct)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := buildDetectionCoverage(coverageInput{
				Sources: sources, RuleCount: 2800,
				Agents: []coverageAgent{agent("a1", "WS-01")},
				Rows:   tc.rows, WindowDesc: "last 7 day(s) of fleet sigma sweeps",
			})
			tc.check(t, findHost(t, rep, "a1"))
		})
	}
}

func TestBuildDetectionCoverageAttack(t *testing.T) {
	rowA := sweptRow("a1", "WS-01", sweepBase, src(secCh, 800, 100, ""))
	rowA.Data.Alerts = []sigma.Alert{
		alert("r-1", "Suspicious PowerShell", "high", 3, "T1059.001"),
		alert("r-2", "Rundll32 abuse", "medium", 1, "T1218.011"),
	}
	rowA.Data.Alerts[0].Tactics = []string{"Execution"}

	rowB := sweptRow("a2", "WS-02", sweepBase, src(secCh, 800, 100, ""))
	rowB.Data.Alerts = []sigma.Alert{
		alert("r-3", "Encoded command", "high", 2, "T1059.001"),
	}
	rowB.Data.Alerts[0].Tactics = []string{"Defense Evasion"}

	rep := buildDetectionCoverage(coverageInput{
		Sources: []sigma.Source{{LogName: secCh, Rules: 800}}, RuleCount: 800,
		Agents:     []coverageAgent{agent("a1", "WS-01"), agent("a2", "WS-02")},
		Rows:       []coverageSweepRow{rowA, rowB},
		WindowDesc: "last 7 day(s) of fleet sigma sweeps",
	})

	if rep.Attack.RulesetMeasurable {
		t.Error("ruleset_measurable must be false - the engine does not expose its rules")
	}
	if rep.Attack.Note == "" {
		t.Error("the ATT&CK section must say what it cannot measure")
	}
	if len(rep.Attack.TechniquesObserved) != 2 {
		t.Fatalf("got %d techniques, want 2", len(rep.Attack.TechniquesObserved))
	}
	top := rep.Attack.TechniquesObserved[0]
	if top.Technique != "T1059.001" || top.Hosts != 2 || top.Rules != 2 {
		t.Errorf("top technique wrong: %+v", top)
	}
	if len(rep.Attack.TacticsObserved) != 2 || rep.Attack.TacticsObserved[0] != "Defense Evasion" {
		t.Errorf("tactics_observed=%v want both, sorted", rep.Attack.TacticsObserved)
	}
}

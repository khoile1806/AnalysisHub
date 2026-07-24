package handlers

import (
	"testing"
	"time"

	"github.com/analysishub/backend/internal/hunting/sigma"
)

// alert builds a minimal alert; count mirrors the engine's convention where only
// the first alert for a rule carries the total match count.
func alert(id, title, level string, count int, techniques ...string) sigma.Alert {
	return sigma.Alert{
		RuleID:     id,
		RuleTitle:  title,
		RuleLevel:  level,
		Techniques: techniques,
		EventCount: count,
	}
}

func doneEntry(agentID, name string, scanned int, alerts ...sigma.Alert) fleetSweepEntry {
	return fleetSweepEntry{
		AgentID:   agentID,
		AgentName: name,
		Status:    "done",
		Data:      &fleetSweepData{Alerts: alerts, EventsScanned: scanned},
	}
}

func TestRollupFleetSweep(t *testing.T) {
	cases := []struct {
		name    string
		entries []fleetSweepEntry
		check   func(t *testing.T, s fleetSweepSummary)
	}{
		{
			name:    "empty input",
			entries: nil,
			check: func(t *testing.T, s fleetSweepSummary) {
				if s.TotalAgents != 0 || s.RulesTriggered != 0 || len(s.Rules) != 0 {
					t.Fatalf("expected an empty summary, got %+v", s)
				}
			},
		},
		{
			name: "status counts cover every outcome",
			entries: []fleetSweepEntry{
				doneEntry("a1", "WS-01", 100),
				{AgentID: "a2", AgentName: "WS-02", Status: "offline"},
				{AgentID: "a3", AgentName: "WS-03", Status: "error"},
				{AgentID: "a4", AgentName: "WS-04", Status: "timeout"},
				{AgentID: "a5", AgentName: "WS-05", Status: "pending"},
			},
			check: func(t *testing.T, s fleetSweepSummary) {
				if s.TotalAgents != 5 || s.Done != 1 || s.Offline != 1 || s.Errors != 1 || s.Timeout != 1 || s.Pending != 1 {
					t.Fatalf("bad status counts: %+v", s)
				}
				if s.EventsScanned != 100 {
					t.Fatalf("events_scanned=%d want 100", s.EventsScanned)
				}
				if s.AgentsWithAlerts != 0 {
					t.Fatalf("agents_with_alerts=%d want 0", s.AgentsWithAlerts)
				}
			},
		},
		{
			name: "same rule across hosts collapses into one row",
			entries: []fleetSweepEntry{
				doneEntry("a1", "WS-01", 500, alert("r-1", "Suspicious PowerShell", "high", 3, "T1059.001")),
				doneEntry("a2", "WS-02", 300, alert("r-1", "Suspicious PowerShell", "high", 2, "T1059.001")),
				doneEntry("a3", "WS-03", 200),
			},
			check: func(t *testing.T, s fleetSweepSummary) {
				if len(s.Rules) != 1 {
					t.Fatalf("want 1 rolled-up rule, got %d", len(s.Rules))
				}
				r := s.Rules[0]
				if r.AgentCount != 2 {
					t.Errorf("agent_count=%d want 2", r.AgentCount)
				}
				if r.EventCount != 5 {
					t.Errorf("event_count=%d want 5", r.EventCount)
				}
				if len(r.Hosts) != 2 || r.Hosts[0] != "WS-01" || r.Hosts[1] != "WS-02" {
					t.Errorf("hosts=%v want [WS-01 WS-02] sorted", r.Hosts)
				}
				if len(r.Techniques) != 1 || r.Techniques[0] != "T1059.001" {
					t.Errorf("techniques=%v want [T1059.001]", r.Techniques)
				}
				if s.EventsScanned != 1000 {
					t.Errorf("events_scanned=%d want 1000", s.EventsScanned)
				}
				if s.AgentsWithAlerts != 2 {
					t.Errorf("agents_with_alerts=%d want 2", s.AgentsWithAlerts)
				}
				if s.TotalAlerts != 2 {
					t.Errorf("total_alerts=%d want 2 (one per rule per agent)", s.TotalAlerts)
				}
			},
		},
		{
			name: "sample alerts of one rule count the agent once",
			// The engine emits up to 25 sample alerts per rule; only the first
			// carries EventCount. A host must still count as one affected host.
			entries: []fleetSweepEntry{
				doneEntry("a1", "WS-01", 900,
					alert("r-1", "Mimikatz", "critical", 7, "T1003"),
					alert("r-1", "Mimikatz", "critical", 0, "T1003"),
					alert("r-1", "Mimikatz", "critical", 0, "T1003"),
				),
			},
			check: func(t *testing.T, s fleetSweepSummary) {
				if len(s.Rules) != 1 {
					t.Fatalf("want 1 rule, got %d", len(s.Rules))
				}
				r := s.Rules[0]
				if r.AgentCount != 1 || len(r.Hosts) != 1 {
					t.Errorf("agent_count=%d hosts=%v want a single host", r.AgentCount, r.Hosts)
				}
				if r.EventCount != 7 {
					t.Errorf("event_count=%d want 7 (only the first alert carries the total)", r.EventCount)
				}
				if len(r.Agents) != 1 || r.Agents[0].EventCount != 7 {
					t.Errorf("per-agent hits=%+v want one hit with 7 events", r.Agents)
				}
			},
		},
		{
			name: "alert rows floor the count when EventCount is missing",
			entries: []fleetSweepEntry{
				doneEntry("a1", "WS-01", 10,
					alert("r-9", "No counts", "low", 0),
					alert("r-9", "No counts", "low", 0),
				),
			},
			check: func(t *testing.T, s fleetSweepSummary) {
				if s.Rules[0].EventCount != 2 {
					t.Errorf("event_count=%d want 2 (row count as floor)", s.Rules[0].EventCount)
				}
			},
		},
		{
			name: "rules without an id fall back to title identity",
			entries: []fleetSweepEntry{
				doneEntry("a1", "WS-01", 10, alert("", "Untitled Detection", "medium", 1)),
				doneEntry("a2", "WS-02", 10, alert("", "Untitled Detection", "medium", 1)),
				doneEntry("a3", "WS-03", 10, alert("", "Other Detection", "medium", 1)),
			},
			check: func(t *testing.T, s fleetSweepSummary) {
				if len(s.Rules) != 2 {
					t.Fatalf("want 2 distinct rules by title, got %d", len(s.Rules))
				}
				if s.Rules[0].RuleTitle != "Untitled Detection" || s.Rules[0].AgentCount != 2 {
					t.Errorf("expected the 2-host rule first, got %+v", s.Rules[0])
				}
			},
		},
		{
			name: "ordering: severity, then fleet spread, then volume",
			entries: []fleetSweepEntry{
				doneEntry("a1", "WS-01", 10,
					alert("low-wide", "Low Everywhere", "low", 1),
					alert("crit-one", "Critical Single", "critical", 1),
					alert("med-loud", "Medium Loud", "medium", 50),
				),
				doneEntry("a2", "WS-02", 10,
					alert("low-wide", "Low Everywhere", "low", 1),
					alert("med-quiet", "Medium Quiet", "medium", 1),
				),
				doneEntry("a3", "WS-03", 10, alert("low-wide", "Low Everywhere", "low", 1)),
			},
			check: func(t *testing.T, s fleetSweepSummary) {
				want := []string{"Critical Single", "Medium Loud", "Medium Quiet", "Low Everywhere"}
				if len(s.Rules) != len(want) {
					t.Fatalf("want %d rules, got %d", len(want), len(s.Rules))
				}
				for i, w := range want {
					if s.Rules[i].RuleTitle != w {
						t.Errorf("rules[%d]=%q want %q (full order: %v)", i, s.Rules[i].RuleTitle, w, titles(s.Rules))
					}
				}
				if s.Rules[3].AgentCount != 3 {
					t.Errorf("Low Everywhere agent_count=%d want 3", s.Rules[3].AgentCount)
				}
			},
		},
		{
			name: "unknown severity sorts last but is never dropped",
			entries: []fleetSweepEntry{
				doneEntry("a1", "WS-01", 10,
					alert("weird", "Weird Level", "banana", 1),
					alert("info", "Informational", "informational", 1),
				),
			},
			check: func(t *testing.T, s fleetSweepSummary) {
				if len(s.Rules) != 2 {
					t.Fatalf("want 2 rules, got %d", len(s.Rules))
				}
				if s.Rules[1].RuleTitle != "Weird Level" {
					t.Errorf("order=%v want the unknown level last", titles(s.Rules))
				}
			},
		},
		{
			name: "agent id stands in for a missing name",
			entries: []fleetSweepEntry{
				{AgentID: "a1", Status: "done", Data: &fleetSweepData{Alerts: []sigma.Alert{alert("r-1", "R", "high", 1)}}},
			},
			check: func(t *testing.T, s fleetSweepSummary) {
				if len(s.Rules[0].Hosts) != 1 || s.Rules[0].Hosts[0] != "a1" {
					t.Errorf("hosts=%v want [a1]", s.Rules[0].Hosts)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.check(t, rollupFleetSweep(tc.entries))
		})
	}
}

func titles(rules []fleetRuleRollup) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.RuleTitle)
	}
	return out
}

func TestFleetSweepRunBudget(t *testing.T) {
	cases := []struct {
		agents int
		want   time.Duration
	}{
		{0, fleetSweepRunSlack},
		{1, fleetSweepAgentBudget + fleetSweepRunSlack},
		{fleetSweepConcurrency, fleetSweepAgentBudget + fleetSweepRunSlack},
		{fleetSweepConcurrency + 1, 2*fleetSweepAgentBudget + fleetSweepRunSlack},
		{100000, fleetSweepRunBudgetMax},
	}
	for _, c := range cases {
		if got := fleetSweepRunBudget(c.agents); got != c.want {
			t.Errorf("fleetSweepRunBudget(%d)=%v want %v", c.agents, got, c.want)
		}
	}
}

func TestParseFleetSince(t *testing.T) {
	if _, ok := parseFleetSince(""); ok {
		t.Error("empty since should not parse")
	}
	if _, ok := parseFleetSince("nonsense"); ok {
		t.Error("garbage since should not parse")
	}
	if _, ok := parseFleetSince("-2h"); ok {
		t.Error("negative duration should not parse")
	}
	if got, ok := parseFleetSince("24h"); !ok || time.Since(got) < 23*time.Hour {
		t.Errorf("24h -> %v ok=%v", got, ok)
	}
	if got, ok := parseFleetSince("2026-07-24T00:00:00Z"); !ok || got.Year() != 2026 || got.Month() != time.July {
		t.Errorf("RFC3339 -> %v ok=%v", got, ok)
	}
	if got, ok := parseFleetSince("2026-07-24"); !ok || got.Day() != 24 {
		t.Errorf("date -> %v ok=%v", got, ok)
	}
}

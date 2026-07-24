package sigma

import (
	"context"
	"fmt"
	"testing"
)

// buildTestEngine mirrors what LoadDirectory does so the index is populated.
func buildTestEngine(rules []*Rule) *Engine {
	e := &Engine{rules: rules}
	e.buildIndex()
	return e
}

func sampleRules() []*Rule {
	return []*Rule{
		{
			ID: "proc", Title: "Process rule", Level: "high",
			Logsource: map[string]string{"product": "windows", "category": "process_creation"},
			Condition: "selection",
			Detection: map[string]interface{}{
				"selection": map[string]interface{}{"CommandLine|contains": "whoami"},
			},
		},
		{
			ID: "logon", Title: "Logon rule", Level: "medium",
			Logsource: map[string]string{"product": "windows", "service": "security"},
			Condition: "selection",
			Detection: map[string]interface{}{
				"selection": map[string]interface{}{"EventID": "4625"},
			},
		},
		{
			ID: "svc", Title: "Service rule", Level: "high",
			Logsource: map[string]string{"product": "windows", "service": "system"},
			Condition: "selection",
			Detection: map[string]interface{}{
				"selection": map[string]interface{}{"EventID": "7045", "ImagePath|contains": "powershell"},
			},
		},
	}
}

func sampleEvents() []map[string]interface{} {
	return []map[string]interface{}{
		{"EventID": 4688, "Provider": "Microsoft-Windows-Security-Auditing", "CommandLine": "cmd.exe /c whoami"},
		{"EventID": "4625", "Provider": "Microsoft-Windows-Security-Auditing", "TargetUserName": "admin"},
		{"EventID": 7045, "Provider": "Service Control Manager", "ImagePath": `powershell -enc AAA`},
		{"EventID": 4624, "Provider": "Microsoft-Windows-Security-Auditing", "TargetUserName": "alice"},
		{"Provider": "Weird", "CommandLine": "cmd.exe /c whoami"}, // no EventID at all
	}
}

// The index must be a pure speedup: an indexed engine and an unindexed one have
// to produce identical verdicts. If they ever diverge the index is hiding rules
// that could legitimately match, which is a silent loss of detection.
func TestIndex_ProducesSameAlertsAsUnindexedScan(t *testing.T) {
	rules := sampleRules()
	indexed := buildTestEngine(rules)
	// An Engine with no index falls back to scanning every rule.
	unindexed := &Engine{rules: rules}

	events := sampleEvents()
	a1, err := indexed.ScanEvents(context.Background(), events)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := unindexed.ScanEvents(context.Background(), events)
	if err != nil {
		t.Fatal(err)
	}

	if len(a1) != len(a2) {
		t.Fatalf("indexed produced %d alerts, unindexed %d", len(a1), len(a2))
	}
	for i := range a1 {
		if a1[i].RuleID != a2[i].RuleID || a1[i].EventCount != a2[i].EventCount {
			t.Errorf("alert %d differs: indexed=%s/%d unindexed=%s/%d",
				i, a1[i].RuleID, a1[i].EventCount, a2[i].RuleID, a2[i].EventCount)
		}
	}
	if len(a1) == 0 {
		t.Fatal("expected the sample rules to fire on the sample events")
	}
}

// A rule whose category pins it to specific IDs must not be considered for an
// unrelated event, and a rule with no ID gate must always be considered.
func TestIndex_BucketsMatchLogsourceGate(t *testing.T) {
	e := buildTestEngine(sampleRules())

	// process_creation → 1 / 4688
	if got := len(e.byEventID["4688"]); got != 1 {
		t.Errorf("expected the process rule bucketed under 4688, got %d", got)
	}
	if got := len(e.byEventID["4625"]); got != 0 {
		t.Errorf("the process rule must not be bucketed under 4625, got %d", got)
	}
	// service-only rules carry no category gate and stay always-considered
	if len(e.unbound) != 2 {
		t.Errorf("expected 2 unbound rules (the two service-scoped ones), got %d", len(e.unbound))
	}
}

// An event with no EventID cannot be narrowed and must still see every rule.
func TestIndex_UnclassifiableEventSeesAllRules(t *testing.T) {
	rules := sampleRules()
	e := buildTestEngine(rules)
	got := candidateRules(e.rules, e.byEventID, e.unbound, map[string]interface{}{"CommandLine": "x"})
	if len(got) != len(rules) {
		t.Errorf("expected all %d rules for an event with no EventID, got %d", len(rules), len(got))
	}
}

// The index only pays off at SigmaHQ scale; this documents the shape of the win.
func BenchmarkScanEvents(b *testing.B) {
	var rules []*Rule
	for i := 0; i < 1500; i++ {
		rules = append(rules, &Rule{
			ID:        fmt.Sprintf("r%d", i),
			Title:     fmt.Sprintf("Rule %d", i),
			Logsource: map[string]string{"product": "windows", "category": "process_creation"},
			Condition: "selection",
			Detection: map[string]interface{}{
				"selection": map[string]interface{}{"CommandLine|contains": fmt.Sprintf("needle%d", i)},
			},
		})
	}
	events := make([]map[string]interface{}, 0, 500)
	for i := 0; i < 500; i++ {
		// Logon events: none of the process_creation rules can apply to them.
		events = append(events, map[string]interface{}{
			"EventID": 4624, "TargetUserName": "alice", "Provider": "Microsoft-Windows-Security-Auditing",
		})
	}

	b.Run("indexed", func(b *testing.B) {
		e := buildTestEngine(rules)
		for i := 0; i < b.N; i++ {
			_, _ = e.ScanEvents(context.Background(), events)
		}
	})
	b.Run("unindexed", func(b *testing.B) {
		e := &Engine{rules: rules}
		for i := 0; i < b.N; i++ {
			_, _ = e.ScanEvents(context.Background(), events)
		}
	})
}

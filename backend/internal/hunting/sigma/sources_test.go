package sigma

import "testing"

func TestRequiredSources_DerivedFromRules(t *testing.T) {
	e := &Engine{rules: []*Rule{
		{ // process_creation → Security + Sysmon, IDs pulled from the detection
			Title:     "proc",
			Logsource: map[string]string{"product": "windows", "category": "process_creation"},
			Condition: "selection",
			Detection: map[string]interface{}{
				"selection": map[string]interface{}{"EventID": "4688", "Image|endswith": `\cmd.exe`},
			},
		},
		{ // service install on the System channel
			Title:     "svc",
			Logsource: map[string]string{"product": "windows", "service": "system"},
			Condition: "selection",
			Detection: map[string]interface{}{
				"selection": map[string]interface{}{"EventID": "7045"},
			},
		},
		{ // a linux rule must contribute no windows source at all
			Title:     "linux",
			Logsource: map[string]string{"product": "linux", "category": "process_creation"},
			Condition: "selection",
			Detection: map[string]interface{}{"selection": map[string]interface{}{"a": "b"}},
		},
	}}

	byLog := map[string]Source{}
	for _, s := range e.RequiredSources() {
		byLog[s.LogName] = s
	}

	sec, ok := byLog["Security"]
	if !ok {
		t.Fatal("expected a Security source")
	}
	if !containsInt(sec.EventIDs, 4688) {
		t.Errorf("Security source should request 4688, got %v", sec.EventIDs)
	}
	if _, ok := byLog[sysmonChannel]; !ok {
		t.Error("process_creation should also target the Sysmon channel")
	}
	sys, ok := byLog["System"]
	if !ok {
		t.Fatal("expected a System source for the service:system rule")
	}
	if !containsInt(sys.EventIDs, 7045) {
		t.Errorf("System source should request 7045, got %v", sys.EventIDs)
	}
}

// A rule that matches on something other than EventID means the channel cannot
// be ID-filtered without losing it.
func TestRequiredSources_UnfilteredWhenRuleHasNoEventID(t *testing.T) {
	e := &Engine{rules: []*Rule{
		{
			Title:     "with-id",
			Logsource: map[string]string{"product": "windows", "service": "security"},
			Condition: "selection",
			Detection: map[string]interface{}{"selection": map[string]interface{}{"EventID": "4688"}},
		},
		{
			Title:     "no-id",
			Logsource: map[string]string{"product": "windows", "service": "security"},
			Condition: "selection",
			Detection: map[string]interface{}{"selection": map[string]interface{}{"CommandLine|contains": "whoami"}},
		},
	}}
	for _, s := range e.RequiredSources() {
		if s.LogName == "Security" && len(s.EventIDs) != 0 {
			t.Errorf("Security must be pulled unfiltered when a rule has no EventID, got %v", s.EventIDs)
		}
	}
}

// The shipped ruleset must produce a usable sweep plan, not an empty one.
func TestRequiredSources_ShippedRulesetProducesPlan(t *testing.T) {
	e := &Engine{}
	e.LoadDirectory(shippedRulesDir)
	if e.RuleCount() == 0 {
		t.Fatal("no curated rules loaded")
	}
	sources := e.RequiredSources()
	if len(sources) == 0 {
		t.Fatal("curated ruleset produced no sweep sources")
	}
	seen := map[string]bool{}
	for _, s := range sources {
		if s.LogName == "" {
			t.Error("a source has an empty log name")
		}
		if seen[s.LogName] {
			t.Errorf("duplicate source for %s", s.LogName)
		}
		seen[s.LogName] = true
	}
	if !seen["Security"] {
		t.Error("expected the curated ruleset to sweep the Security channel")
	}
	t.Logf("sweep plan: %d sources", len(sources))
	for _, s := range sources {
		t.Logf("  %-55s ids=%v rules=%d", s.LogName, s.EventIDs, s.Rules)
	}
}

func containsInt(list []int, want int) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

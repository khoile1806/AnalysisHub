package sigma

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Value wildcards are the most common construct in upstream rules; comparing
// them literally meant almost nothing ever matched.
func TestMatchString_ValueWildcards(t *testing.T) {
	cases := []struct {
		expected, actual, modifier string
		want                       bool
	}{
		{`*\mimikatz.exe`, `C:\tools\mimikatz.exe`, "", true},
		{`*\mimikatz.exe`, `C:\tools\mimikatz.exe.bak`, "", false},
		{`C:\Windows\*`, `C:\Windows\System32\cmd.exe`, "", true},
		{`*whoami*`, `cmd.exe /c whoami /all`, "", true},
		{`*whoami*`, `cmd.exe /c hostname`, "", false},
		{`rundll?2.exe`, `RUNDLL32.EXE`, "", true},
		{`rundll?2.exe`, `rundll322.exe`, "", false},
		// A backslash before a wildcard is a path separator, not an escape (see
		// globToRegex); "\\" is the literal backslash.
		{`a\*b`, `a\xb`, "", true},
		{`a\*b`, `ab`, "", false},
		{`C:\Windows\System32`, `c:\windows\system32`, "", true},
		{`C:\\*`, `C:\temp\x.exe`, "", true},
		// Wildcards combine with positional modifiers.
		{`*\powershell.exe`, `X:\bin\PowerShell.exe -nop`, "startswith", true},
		{`\svchost.exe*`, `C:\Windows\System32\svchost.exe -k netsvcs`, "contains", true},
	}
	for _, c := range cases {
		if got := matchString(c.expected, c.actual, c.modifier); got != c.want {
			t.Errorf("matchString(%q,%q,%q)=%v want %v", c.expected, c.actual, c.modifier, got, c.want)
		}
	}
}

// An aggregation condition must disable the rule rather than degrade to the
// bare selection, which would fire on every event the threshold was meant to
// suppress.
func TestCondition_AggregationFailsClosed(t *testing.T) {
	results := map[string]bool{"selection": true}
	for _, cond := range []string{
		"selection | count() by ComputerName > 5",
		"selection | near filter",
		"selection and not filter |count() > 3",
	} {
		if evaluateCondition(cond, results) {
			t.Errorf("condition %q must not evaluate to true (aggregation is unsupported)", cond)
		}
	}
}

func TestCondition_UnbalancedParensFailClosed(t *testing.T) {
	if evaluateCondition("( selection and filter", map[string]bool{"selection": true, "filter": true}) {
		t.Error("unbalanced parentheses must fail closed")
	}
}

func TestCondition_OneOfGroup(t *testing.T) {
	results := map[string]bool{"sel_a": false, "sel_b": true}
	if !evaluateCondition("1 of (sel_a or sel_b)", results) {
		t.Error(`"1 of (sel_a or sel_b)" should match when sel_b matched`)
	}
}

func TestMatchSelection_NullMeansAbsentOrEmpty(t *testing.T) {
	sel := map[string]interface{}{"ParentImage": nil}
	if !matchSelection(sel, map[string]interface{}{"Image": "x.exe"}) {
		t.Error("null must match an absent field")
	}
	if !matchSelection(sel, map[string]interface{}{"ParentImage": ""}) {
		t.Error("null must match an empty field")
	}
	if matchSelection(sel, map[string]interface{}{"ParentImage": `C:\a.exe`}) {
		t.Error("null must not match a populated field")
	}
}

func TestMatchSelection_ExistsModifier(t *testing.T) {
	ev := map[string]interface{}{"CommandLine": "whoami"}
	if !matchSelection(map[string]interface{}{"CommandLine|exists": true}, ev) {
		t.Error("exists:true should match a present field")
	}
	if !matchSelection(map[string]interface{}{"ParentImage|exists": false}, ev) {
		t.Error("exists:false should match an absent field")
	}
	if matchSelection(map[string]interface{}{"ParentImage|exists": true}, ev) {
		t.Error("exists:true must not match an absent field")
	}
}

func TestMatchOne_Base64OffsetContains(t *testing.T) {
	// The canonical encoded-PowerShell detection: the plaintext appears at an
	// arbitrary byte offset inside a base64 blob.
	plain := "IEX (New-Object Net.WebClient)"
	blob := base64.StdEncoding.EncodeToString([]byte("xy" + plain + "; more"))
	mods := modifiers{op: "contains", b64offs: true}
	if !matchOne(plain, blob, mods) {
		t.Error("base64offset|contains should find the value at a shifted offset")
	}
	if matchOne("not-in-there", blob, mods) {
		t.Error("base64offset|contains must not match an absent value")
	}
}

func TestMatchOne_WideBase64(t *testing.T) {
	// PowerShell -EncodedCommand is UTF-16LE then base64.
	enc := base64.StdEncoding.EncodeToString(toWideBytes("Invoke-Mimikatz"))
	if !matchOne("Invoke-Mimikatz", enc, modifiers{op: "contains", base64: true, wide: true}) {
		t.Error("base64+wide should match a UTF-16LE encoded command")
	}
}

func TestMatchOne_Windash(t *testing.T) {
	mods := modifiers{op: "contains", windash: true}
	for _, actual := range []string{"powershell -enc AAAA", "powershell /enc AAAA", "powershell –enc AAAA"} {
		if !matchOne("-enc", actual, mods) {
			t.Errorf("windash should match %q", actual)
		}
	}
	if matchOne("-enc", "powershell noargs", mods) {
		t.Error("windash must not match an absent flag")
	}
}

func TestMatchOne_Cidr(t *testing.T) {
	mods := modifiers{op: "cidr"}
	if !matchOne("10.0.0.0/8", "10.13.37.2", mods) {
		t.Error("cidr should contain the address")
	}
	if matchOne("10.0.0.0/8", "192.168.1.1", mods) {
		t.Error("cidr must not contain an outside address")
	}
}

func TestMatchOne_NumericComparison(t *testing.T) {
	if !matchOne("1024", "8080", modifiers{op: "gt"}) {
		t.Error("gt should compare numerically")
	}
	if matchOne("1024", "80", modifiers{op: "gt"}) {
		t.Error("gt must be false for a smaller value")
	}
}

// Rules written against Sysmon must still work on the Security 4688 events the
// agent actually collects.
func TestLookupField_SysmonToSecurityAliases(t *testing.T) {
	ev := map[string]interface{}{
		"EventID":            "4688",
		"NewProcessName":     `C:\Windows\System32\cmd.exe`,
		"ParentProcessName":  `C:\Windows\explorer.exe`,
		"ProcessCommandLine": "cmd.exe /c whoami",
		"SubjectUserName":    "victim",
	}
	sel := map[string]interface{}{
		"Image|endswith": `\cmd.exe`,
		"ParentImage":    `*\explorer.exe`,
		"CommandLine":    "*whoami*",
		"User":           "victim",
	}
	if !matchSelection(sel, ev) {
		t.Error("a Sysmon-namespace selection should resolve against 4688 field names")
	}
}

func TestLogsourceMatches_Gating(t *testing.T) {
	linuxRule := &Rule{Logsource: map[string]string{"product": "linux", "category": "process_creation"}}
	if logsourceMatches(linuxRule, map[string]interface{}{"EventID": "4688"}) {
		t.Error("a linux rule must not be evaluated against a windows event")
	}

	procRule := &Rule{Logsource: map[string]string{"product": "windows", "category": "process_creation"}}
	if logsourceMatches(procRule, map[string]interface{}{"EventID": "4624"}) {
		t.Error("a process_creation rule must not fire on a logon event")
	}
	if !logsourceMatches(procRule, map[string]interface{}{"EventID": "4688"}) {
		t.Error("a process_creation rule must apply to 4688")
	}
	// An event we cannot classify still sees the rule.
	if !logsourceMatches(procRule, map[string]interface{}{"CommandLine": "x"}) {
		t.Error("gating must be conservative when EventID is unknown")
	}
}

func TestValidateRule_MarksUnsupported(t *testing.T) {
	agg := &Rule{
		Condition: "selection | count() by User > 5",
		Detection: map[string]interface{}{"selection": map[string]interface{}{"EventID": "4625"}},
	}
	if validateRule(agg) == "" {
		t.Error("an aggregation rule must be reported as unsupported")
	}
	dangling := &Rule{
		Condition: "selection and not filter",
		Detection: map[string]interface{}{"selection": map[string]interface{}{"EventID": "4625"}},
	}
	if validateRule(dangling) == "" {
		t.Error("a condition referencing an undefined selection must be unsupported")
	}
	ok := &Rule{
		Condition: "selection and not filter",
		Detection: map[string]interface{}{
			"selection": map[string]interface{}{"EventID": "4625"},
			"filter":    map[string]interface{}{"User": "svc"},
		},
	}
	if reason := validateRule(ok); reason != "" {
		t.Errorf("a well-formed rule must be supported, got %q", reason)
	}
}

// Upstream ships "rule collections": a global document plus per-rule deltas.
func TestLoadRules_MultiDocumentCollection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "collection.yml")
	doc := `
action: global
title: Base
logsource:
  product: windows
  category: process_creation
detection:
  condition: selection
---
title: Child A
detection:
  selection:
    Image|endswith: '\a.exe'
---
title: Child B
detection:
  selection:
    Image|endswith: '\b.exe'
`
	if err := os.WriteFile(path, []byte(strings.TrimSpace(doc)), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadRules(path)
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("want 2 rules from the collection, got %d", len(rules))
	}
	for _, r := range rules {
		if r.Unsupported != "" {
			t.Errorf("rule %q unexpectedly unsupported: %s", r.Title, r.Unsupported)
		}
		if r.Logsource["category"] != "process_creation" {
			t.Errorf("rule %q did not inherit the global logsource", r.Title)
		}
	}
}

func TestConditionString_ListIsOr(t *testing.T) {
	got := conditionString([]interface{}{"selection1", "selection2"})
	if !strings.Contains(got, "or") {
		t.Errorf("a list condition should become an OR, got %q", got)
	}
}

// One noisy rule over a large pull must not produce one row per event.
func TestScanContext_RollsUpPerRule(t *testing.T) {
	e := &Engine{rules: []*Rule{{
		ID:        "test-rule",
		Title:     "Test",
		Condition: "selection",
		Detection: map[string]interface{}{
			"selection": map[string]interface{}{"EventID": "4625"},
		},
	}}}
	events := `[` + strings.TrimSuffix(strings.Repeat(`{"EventID":"4625"},`, 200), ",") + `]`
	alerts, err := e.Scan(events)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) > maxAlertsPerRule+1 {
		t.Errorf("alerts should be capped per rule, got %d", len(alerts))
	}
	if alerts[0].EventCount != 200 {
		t.Errorf("first alert should carry the total count, got %d", alerts[0].EventCount)
	}
}

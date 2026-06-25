package sigma

import "testing"

// event is a convenience constructor for a log event.
func event(kv map[string]interface{}) map[string]interface{} { return kv }

func TestMatchString_Modifiers(t *testing.T) {
	cases := []struct {
		expected, actual, modifier string
		want                       bool
	}{
		// default: case-insensitive exact match
		{"powershell.exe", "PowerShell.exe", "", true},
		{"powershell.exe", "powershell", "", false},
		// contains
		{"mimikatz", "C:\\tools\\Mimikatz.exe", "contains", true},
		{"mimikatz", "C:\\tools\\nc.exe", "contains", false},
		// startswith
		{"c:\\windows", "C:\\Windows\\System32\\cmd.exe", "startswith", true},
		{"system32", "C:\\Windows\\System32", "startswith", false},
		// endswith
		{".exe", "payload.EXE", "endswith", true},
		{".dll", "payload.exe", "endswith", false},
		// regex (case-insensitive via (?i))
		{"p[a4]ssw[o0]rd", "PaSSw0rd", "re", true},
		{"^admin$", "administrator", "re", false},
		{"(", "anything", "re", false}, // invalid regex compiles to no-match
	}
	for _, c := range cases {
		if got := matchString(c.expected, c.actual, c.modifier); got != c.want {
			t.Errorf("matchString(%q,%q,%q)=%v want %v", c.expected, c.actual, c.modifier, got, c.want)
		}
	}
}

func TestMatchValue_ListIsOR(t *testing.T) {
	expected := []interface{}{"cmd.exe", "powershell.exe", "wscript.exe"}
	if !matchValue(expected, "PowerShell.exe", "") {
		t.Error("list value should OR-match a member, got no match")
	}
	if matchValue(expected, "explorer.exe", "") {
		t.Error("list value matched a non-member")
	}
}

func TestMatchValue_NonStringExpected(t *testing.T) {
	// YAML often yields int values (e.g. EventID: 4688). They are compared as strings.
	if !matchValue(4688, 4688, "") {
		t.Error("int 4688 should match int 4688")
	}
	if !matchValue(4688, "4688", "") {
		t.Error("int 4688 should match string \"4688\"")
	}
	if matchValue(4688, 1, "") {
		t.Error("int 4688 should not match int 1")
	}
}

func TestMatchSelection_AndAcrossFields_CaseInsensitiveKeys(t *testing.T) {
	sel := map[string]interface{}{
		"Image":       "cmd.exe",
		"User|contains": "admin",
	}
	// Event keys differ in case from the selection keys — must still match.
	ev := event(map[string]interface{}{
		"image": "C:\\Windows\\System32\\cmd.exe",
		"user":  "CORP\\Administrator",
	})
	// Note: "Image" uses default (exact) match, so it must equal exactly.
	ev["image"] = "cmd.exe"
	if !matchSelection(sel, ev) {
		t.Error("selection should match when all fields match (case-insensitive keys)")
	}

	// One field absent → whole AND selection fails.
	delete(ev, "user")
	if matchSelection(sel, ev) {
		t.Error("selection should fail when a required field is missing")
	}
}

// ruleFor builds a Rule from a detection map + condition.
func ruleFor(det map[string]interface{}, cond string) *Rule {
	return &Rule{Detection: det, Condition: cond}
}

func TestMatchEvent_GuardClauses(t *testing.T) {
	// nil detection
	if MatchEvent(&Rule{Condition: "selection"}, event(nil)) {
		t.Error("nil Detection must not match")
	}
	// empty condition
	if MatchEvent(&Rule{Detection: map[string]interface{}{"selection": map[string]interface{}{}}}, event(nil)) {
		t.Error("empty Condition must not match")
	}
}

func TestMatchEvent_SingleSelection(t *testing.T) {
	r := ruleFor(map[string]interface{}{
		"selection": map[string]interface{}{
			"CommandLine|contains": "Invoke-Mimikatz",
		},
	}, "selection")

	hit := event(map[string]interface{}{"CommandLine": "powershell -enc ... Invoke-Mimikatz ..."})
	miss := event(map[string]interface{}{"CommandLine": "powershell -File update.ps1"})

	if !MatchEvent(r, hit) {
		t.Error("expected match on malicious command line")
	}
	if MatchEvent(r, miss) {
		t.Error("unexpected match on benign command line")
	}
}

func TestMatchEvent_SelectionAsList_IsOR(t *testing.T) {
	// A named selection whose value is a list of maps implies OR between elements.
	r := ruleFor(map[string]interface{}{
		"selection": []interface{}{
			map[string]interface{}{"Image|endswith": "\\cmd.exe"},
			map[string]interface{}{"Image|endswith": "\\powershell.exe"},
		},
	}, "selection")

	if !MatchEvent(r, event(map[string]interface{}{"Image": "C:\\Windows\\System32\\powershell.exe"})) {
		t.Error("list selection should OR-match powershell")
	}
	if MatchEvent(r, event(map[string]interface{}{"Image": "C:\\Windows\\explorer.exe"})) {
		t.Error("list selection matched an unrelated image")
	}
}

func TestEvaluateCondition_Logic(t *testing.T) {
	cases := []struct {
		cond    string
		results map[string]bool
		want    bool
	}{
		{"selection", map[string]bool{"selection": true}, true},
		{"selection", map[string]bool{"selection": false}, false},
		{"unknown", map[string]bool{"selection": true}, false},

		{"1 of them", map[string]bool{"a": false, "b": true}, true},
		{"any of them", map[string]bool{"a": false, "b": false}, false},
		{"all of them", map[string]bool{"a": true, "b": true}, true},
		{"all of them", map[string]bool{"a": true, "b": false}, false},

		{"selection and not filter", map[string]bool{"selection": true, "filter": false}, true},
		{"selection and not filter", map[string]bool{"selection": true, "filter": true}, false},
		{"selection and not filter", map[string]bool{"selection": false, "filter": false}, false},

		{"a or b", map[string]bool{"a": false, "b": true}, true},
		{"a or b", map[string]bool{"a": false, "b": false}, false},

		{"a and b", map[string]bool{"a": true, "b": true}, true},
		{"a and b", map[string]bool{"a": true, "b": false}, false},
	}
	for _, c := range cases {
		if got := evaluateCondition(c.cond, c.results); got != c.want {
			t.Errorf("evaluateCondition(%q, %v)=%v want %v", c.cond, c.results, got, c.want)
		}
	}
}

func TestMatchEvent_SelectionAndNotFilter(t *testing.T) {
	// Classic Sigma pattern: fire on selection unless a benign filter matches.
	r := ruleFor(map[string]interface{}{
		"selection": map[string]interface{}{"EventID": 4688},
		"filter":    map[string]interface{}{"User": "SYSTEM"},
	}, "selection and not filter")

	// selection true, filter false → alert
	if !MatchEvent(r, event(map[string]interface{}{"EventID": 4688, "User": "alice"})) {
		t.Error("expected alert when selection matches and filter does not")
	}
	// selection true, filter true → suppressed
	if MatchEvent(r, event(map[string]interface{}{"EventID": 4688, "User": "SYSTEM"})) {
		t.Error("expected suppression when filter matches")
	}
}

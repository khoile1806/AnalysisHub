package osint

import "testing"

import "github.com/analysishub/backend/internal/models"

// defaultRules mirrors the rule set seeded in database.seedOsintScopePolicy so the
// test locks the shipped behaviour, not just the evaluator mechanics.
func defaultRules() []models.OsintScopeRule {
	return []models.OsintScopeRule{
		{ID: 1, Priority: 10, Name: "Internal — passive", Enabled: true, MatchTargetType: "any", MatchScope: "internal", MatchEgress: "any", Action: "passive_only"},
		{ID: 2, Priority: 20, Name: "Direct — passive", Enabled: true, MatchTargetType: "any", MatchScope: "any", MatchEgress: "direct", Action: "passive_only"},
		{ID: 3, Priority: 30, Name: "External+anon — full", Enabled: true, MatchTargetType: "any", MatchScope: "external", MatchEgress: "anonymized", Action: "all"},
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func TestClassification(t *testing.T) {
	for _, n := range []string{"favicon", "webtech", "portscan", "subbrute"} {
		if ClassOf(n) != ClassActive {
			t.Errorf("%s should be active", n)
		}
	}
	for _, n := range []string{"crtsh", "rdap", "shodan", "virustotal", "breach_leak"} {
		if ClassOf(n) != ClassPassive {
			t.Errorf("%s should be passive", n)
		}
	}
}

func TestExternalDirectIsPassiveOnly(t *testing.T) {
	// A public domain over direct egress must drop active collectors so the real
	// IP is never exposed to the target.
	d := EvaluateScopePolicy(defaultRules(), nil, "example.com", TargetDomain, false, true)
	if d.Mode != ModePassiveOnly {
		t.Fatalf("mode = %s; want passive_only", d.Mode)
	}
	if contains(d.Allowed, "webtech") || contains(d.Allowed, "favicon") {
		t.Errorf("active collectors must not run: allowed=%v", d.Allowed)
	}
	if !contains(d.Blocked, "webtech") {
		t.Errorf("webtech should be blocked: blocked=%v", d.Blocked)
	}
}

func TestExternalAnonymizedIsFull(t *testing.T) {
	d := EvaluateScopePolicy(defaultRules(), nil, "example.com", TargetDomain, true, true)
	if d.Mode != ModeAll {
		t.Fatalf("mode = %s; want all", d.Mode)
	}
	if !contains(d.Allowed, "webtech") {
		t.Errorf("webtech should run when anonymized: allowed=%v", d.Allowed)
	}
}

func TestInternalIPIsPassiveEvenWhenAnonymized(t *testing.T) {
	// Priority: the internal rule (10) wins over the external+anon rule (30).
	d := EvaluateScopePolicy(defaultRules(), nil, "10.0.0.5", TargetIP, true, true)
	if d.Scope != "internal" {
		t.Fatalf("scope = %s; want internal", d.Scope)
	}
	if d.Mode != ModePassiveOnly {
		t.Fatalf("mode = %s; want passive_only", d.Mode)
	}
	if contains(d.Allowed, "portscan") {
		t.Errorf("portscan must not run on internal target: allowed=%v", d.Allowed)
	}
}

func TestInternalSuffixMatch(t *testing.T) {
	suffixes := normalizeSuffixes("corp\nmycompany.com")
	if TargetScope("host.mycompany.com", TargetDomain, suffixes) != "internal" {
		t.Error("host.mycompany.com should match internal suffix")
	}
	if TargetScope("mycompany.com", TargetDomain, suffixes) != "internal" {
		t.Error("exact suffix should match internal")
	}
	if TargetScope("example.com", TargetDomain, suffixes) != "external" {
		t.Error("example.com should be external")
	}
}

func TestEnforceOffAllowsEverything(t *testing.T) {
	d := EvaluateScopePolicy(defaultRules(), nil, "example.com", TargetDomain, false, false)
	if d.Mode != ModeAll || d.Enforced {
		t.Fatalf("enforce off should allow all & report not enforced; got mode=%s enforced=%v", d.Mode, d.Enforced)
	}
}

func TestOverrideOnlyTightens(t *testing.T) {
	names := CollectorNamesFor(TargetDomain)
	// Start from an "all" decision, override to passive_only → tightens.
	base := EvaluateScopePolicy(defaultRules(), nil, "example.com", TargetDomain, true, true)
	if base.Mode != ModeAll {
		t.Fatalf("precondition: want all, got %s", base.Mode)
	}
	tightened := ApplyOverride(base, "passive_only", names)
	if tightened.Mode != ModePassiveOnly {
		t.Errorf("override to passive_only should apply; got %s", tightened.Mode)
	}
	// A looser override (all) on a passive_only decision must be ignored.
	passive := EvaluateScopePolicy(defaultRules(), nil, "example.com", TargetDomain, false, true)
	loosened := ApplyOverride(passive, "all", names)
	if loosened.Mode != ModePassiveOnly {
		t.Errorf("looser override must be ignored; got %s", loosened.Mode)
	}
}

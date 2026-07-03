package osint

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/analysishub/backend/internal/models"
)

func TestGenerateSTIXBundle(t *testing.T) {
	scan := &models.OsintScan{Target: "evil.com", TargetType: TargetDomain, ExposureScore: 70, ExposureGrade: "high"}
	findings := []models.OsintFinding{
		{Source: "typosquat", Category: "reputation", Title: "Registered look-alike domain",
			Value: "evi1.com", RelatedEntities: `[{"type":"domain","value":"evi1.com"}]`},
		{Source: "dns", Category: "dns", Title: "A record", Value: "1.2.3.4",
			RelatedEntities: `[{"type":"ip","value":"1.2.3.4"}]`},
	}
	raw, err := GenerateSTIXBundle(scan, findings)
	if err != nil {
		t.Fatalf("GenerateSTIXBundle: %v", err)
	}
	var b stixBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("bundle is not valid JSON: %v", err)
	}
	if b.Type != "bundle" {
		t.Errorf("expected type bundle, got %q", b.Type)
	}
	var hasIdentity, hasDomainIndicator, hasIPIndicator bool
	for _, o := range b.Objects {
		switch {
		case o.Type == "identity":
			hasIdentity = true
		case o.Type == "indicator" && strings.Contains(o.Pattern, "domain-name:value = 'evi1.com'"):
			hasDomainIndicator = true
		case o.Type == "indicator" && strings.Contains(o.Pattern, "ipv4-addr:value = '1.2.3.4'"):
			hasIPIndicator = true
		}
	}
	if !hasIdentity || !hasDomainIndicator || !hasIPIndicator {
		t.Errorf("missing expected STIX objects: identity=%v domain=%v ip=%v",
			hasIdentity, hasDomainIndicator, hasIPIndicator)
	}
}

func TestGenerateCSV(t *testing.T) {
	scan := &models.OsintScan{Target: "x@y.com", TargetType: TargetEmail}
	csv := string(GenerateCSV(scan, []models.OsintFinding{
		{Source: "hibp", Category: "breach", Title: "Breach: LinkedIn", Value: "2012", Severity: "high"},
	}))
	if !strings.HasPrefix(csv, "target,target_type,source,") {
		t.Error("CSV header missing")
	}
	if !strings.Contains(csv, "Breach: LinkedIn") {
		t.Error("CSV row missing")
	}
}

func TestTypoVariants(t *testing.T) {
	vs := typoVariants("paypal", "com")
	if len(vs) == 0 {
		t.Fatal("expected typo variants")
	}
	joined := strings.Join(vs, " ")
	// Homoglyph (a->4) and TLD swap should both appear.
	if !strings.Contains(joined, "paypal.net") {
		t.Error("expected a TLD-swap variant paypal.net")
	}
}

func TestSplitRegistrable(t *testing.T) {
	cases := map[string][2]string{
		"example.com":    {"example", "com"},
		"foo.co.uk":      {"foo", "co.uk"},
		"a.b.example.io": {"example", "io"},
	}
	for host, want := range cases {
		n, tld := splitRegistrable(host)
		if n != want[0] || tld != want[1] {
			t.Errorf("splitRegistrable(%s) = %q,%q want %q,%q", host, n, tld, want[0], want[1])
		}
	}
}

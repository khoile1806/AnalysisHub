package handlers

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/news"
)

// ── Lifecycle ────────────────────────────────────────────────────────────────

func TestIOCActiveRespectsExpiryAndEnabled(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	cases := []struct {
		name string
		ioc  models.IOC
		want bool
	}{
		{"no expiry, enabled", models.IOC{Enabled: true}, true},
		{"expires later", models.IOC{Enabled: true, ExpiresAt: &future}, true},
		{"already expired", models.IOC{Enabled: true, ExpiresAt: &past}, false},
		{"retired by hand", models.IOC{Enabled: false}, false},
		{"retired and unexpired", models.IOC{Enabled: false, ExpiresAt: &future}, false},
	}
	for _, c := range cases {
		if got := c.ioc.Active(now); got != c.want {
			t.Errorf("%s: Active = %v, want %v", c.name, got, c.want)
		}
	}
}

// ── Export ───────────────────────────────────────────────────────────────────

func TestCSVExportNeutralisesFormulas(t *testing.T) {
	// The values are attacker-controlled. A cell starting with = is executed by
	// Excel when the analyst opens the export of the malware they just analysed.
	rows := []models.IOC{
		{Value: `=cmd|'/c calc'!A1`, Type: "Domain-Name", Source: "Import"},
		{Value: "evil.example", Type: "Domain-Name", Description: "+SUM(1)"},
		{Value: "@SUM(A1)", Type: "URL"},
		{Value: "-2+3", Type: "URL"},
	}
	out := string(iocsToCSV(rows))
	for _, dangerous := range []string{",=cmd", ",+SUM", ",@SUM", ",-2+3"} {
		if strings.Contains(out, dangerous) {
			t.Errorf("an unescaped formula reached the CSV: %q\n%s", dangerous, out)
		}
	}
	if !strings.Contains(out, "'=cmd") {
		t.Errorf("the formula should be prefixed, not dropped:\n%s", out)
	}
	// The benign value must survive untouched.
	if !strings.Contains(out, "evil.example") {
		t.Error("escaping must not mangle ordinary values")
	}
}

func TestSTIXExportShape(t *testing.T) {
	expires := time.Now().UTC().Add(48 * time.Hour)
	rows := []models.IOC{
		{Value: "185.220.101.5", Type: "IPv4-Addr", Confidence: 85, TLP: "white", ExpiresAt: &expires, ATTCK: "T1071.001"},
		{Value: strings.Repeat("a", 64), Type: "File-Hash", Confidence: 90, TLP: "amber"},
		{Value: "no-stix-equivalent", Type: "Mutex"},
	}
	var bundle struct {
		Type    string `json:"type"`
		Objects []struct {
			Type        string   `json:"type"`
			Pattern     string   `json:"pattern"`
			Confidence  int      `json:"confidence"`
			ValidUntil  string   `json:"valid_until"`
			MarkingRefs []string `json:"object_marking_refs"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(iocsToSTIX(rows), &bundle); err != nil {
		t.Fatalf("export is not valid JSON: %v", err)
	}
	if bundle.Type != "bundle" {
		t.Errorf("type = %q, want bundle", bundle.Type)
	}

	var indicators int
	var sawIP, sawHash bool
	for _, o := range bundle.Objects {
		if o.Type != "indicator" {
			continue
		}
		indicators++
		if strings.Contains(o.Pattern, "ipv4-addr:value = '185.220.101.5'") {
			sawIP = true
			if o.ValidUntil == "" {
				t.Error("an expiring indicator must carry valid_until, or a consumer keeps alerting forever")
			}
			if o.Confidence != 85 {
				t.Errorf("confidence = %d, want 85", o.Confidence)
			}
		}
		if strings.Contains(o.Pattern, "SHA-256") {
			sawHash = true
		}
		if len(o.MarkingRefs) == 0 {
			t.Error("every indicator needs a TLP marking; sharing terms are not optional")
		}
	}
	if !sawIP || !sawHash {
		t.Errorf("expected an IP and a hash indicator, got %d indicators", indicators)
	}
	// A type with no STIX equivalent must be omitted rather than guessed at.
	if indicators != 2 {
		t.Errorf("indicators = %d, want 2 (the Mutex has no STIX pattern)", indicators)
	}
}

func TestSTIXHashAlgorithmFollowsLength(t *testing.T) {
	for length, want := range map[int]string{32: "MD5", 40: "SHA-1", 64: "SHA-256"} {
		got := stixPattern("File-Hash", strings.Repeat("a", length))
		if !strings.Contains(got, want) {
			t.Errorf("a %d-char hash produced %q, want %s", length, got, want)
		}
	}
}

func TestMISPExportOnlyTrustsConfidentIndicators(t *testing.T) {
	rows := []models.IOC{
		{Value: "1.1.1.1", Type: "IPv4-Addr", Confidence: 90},
		{Value: "2.2.2.2", Type: "IPv4-Addr", Confidence: 40},
	}
	var event struct {
		Event struct {
			Attribute []struct {
				Value string `json:"value"`
				ToIDS bool   `json:"to_ids"`
			} `json:"Attribute"`
		} `json:"Event"`
	}
	if err := json.Unmarshal(iocsToMISP(rows), &event); err != nil {
		t.Fatalf("export is not valid JSON: %v", err)
	}
	if len(event.Event.Attribute) != 2 {
		t.Fatalf("attributes = %d, want 2", len(event.Event.Attribute))
	}
	for _, a := range event.Event.Attribute {
		// to_ids drives detection in the consumer. A low-confidence indicator that
		// sets it turns somebody else's SIEM into a false-positive generator.
		if a.Value == "1.1.1.1" && !a.ToIDS {
			t.Error("a high-confidence indicator should drive detection")
		}
		if a.Value == "2.2.2.2" && a.ToIDS {
			t.Error("a low-confidence indicator must not drive detection")
		}
	}
}

func TestSuricataExportEscapesRuleTerminators(t *testing.T) {
	rows := []models.IOC{{Value: `evil"; sid:1; content:"x`, Type: "Domain-Name", Source: `a"b;c`}}
	out := string(iocsToSuricata(rows))
	body := out[strings.Index(out, "alert"):]
	if strings.Count(body, `"`)%2 != 0 {
		t.Errorf("unbalanced quotes would break the ruleset:\n%s", body)
	}
	if strings.Contains(body, `sid:1;`) {
		t.Errorf("an injected rule option survived:\n%s", body)
	}
}

// ── Retro-match helpers ──────────────────────────────────────────────────────

func TestIOCsContainIsExactNotSubstring(t *testing.T) {
	raw := `[{"value":"11.2.3.40","type":"ip"},{"value":"evil.example","type":"domain"}]`
	if iocsContain(raw, "1.2.3.4") {
		t.Error("1.2.3.4 must not match inside 11.2.3.40 — that is the whole point of the second pass")
	}
	if !iocsContain(raw, "evil.example") {
		t.Error("an exact value must match")
	}
	if iocsContain("not json", "x") {
		t.Error("unparseable content must not be claimed as a hit")
	}
	if iocsContain("", "x") {
		t.Error("empty content cannot contain anything")
	}
}

func TestNetworkResultContainsSearchesEveryField(t *testing.T) {
	raw := `{"iocs":{"ips":["203.0.113.9"],"domains":["c2.example"]},
	         "dns":[{"query":"lookup.example","answers":["198.51.100.7"]}],
	         "http":[{"host":"panel.example"}],
	         "files":[{"sha256":"` + strings.Repeat("b", 64) + `"}]}`
	for _, want := range []string{"203.0.113.9", "c2.example", "lookup.example",
		"198.51.100.7", "panel.example", strings.Repeat("b", 64)} {
		if !networkResultContains(raw, want) {
			t.Errorf("%s should have been found", want)
		}
	}
	if networkResultContains(raw, "203.0.113.99") {
		t.Error("a longer value must not match a shorter stored one")
	}
	if networkResultContains("{bad", "x") {
		t.Error("unparseable content must not be claimed as a hit")
	}
}

// ── Plugin release watcher ───────────────────────────────────────────────────

func TestPluginWatchStatusReportsMissingAndStale(t *testing.T) {
	// A watcher that has stopped produces silence, which is indistinguishable
	// from a quiet week unless something reports the age of its output.
	h := news.PluginWatchStatus("/nonexistent/report.json")
	if h.Present {
		t.Error("a missing report must not be reported as present")
	}
	if h.Detail == "" {
		t.Error("the reason must be stated, not left blank")
	}
	if news.PluginWatchStaleAfter < 5*time.Minute {
		t.Error("the staleness bound must tolerate a slow cycle")
	}
}

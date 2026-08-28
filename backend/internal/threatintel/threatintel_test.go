package threatintel

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ── Score calibration ────────────────────────────────────────────────────────

func TestVTScoreRewardsDetectionCountNotShare(t *testing.T) {
	// The old formula was flagged*100/total. With VirusTotal's ~70-engine panel
	// this put real malware below every threshold the rest of the system uses:
	// the verdict engine treats >= 50 as a detection and the UI says MALICIOUS at
	// >= 70, so a sample 25 engines agreed on scored 35 and read as "suspicious".
	if got := vtScore(25, 0, 70); got < 70 {
		t.Errorf("25/70 detections scored %d, want >= 70", got)
	}
	if got := vtScore(8, 0, 72); got < 70 {
		t.Errorf("8/72 detections scored %d, want >= 70", got)
	}
	// One engine is the false-positive band: real, but not on its own a verdict.
	if got := vtScore(1, 0, 70); got >= 50 {
		t.Errorf("a single detection scored %d, want < 50", got)
	}
	if got := vtScore(0, 0, 70); got != 0 {
		t.Errorf("no detections scored %d, want 0", got)
	}
	// Score must not fall as evidence grows.
	prev := -1
	for _, n := range []int{0, 1, 2, 3, 5, 10, 30} {
		s := vtScore(n, 0, 70)
		if s < prev {
			t.Errorf("score fell from %d to %d at %d detections", prev, s, n)
		}
		prev = s
	}
}

func TestVTMaliciousNeedsCorroboration(t *testing.T) {
	if vtMalicious(1, 0) {
		t.Error("one engine must not carry a malicious verdict on its own")
	}
	if vtMalicious(2, 0) {
		t.Error("two engines agreeing on a packer is a routine false positive")
	}
	if !vtMalicious(3, 0) {
		t.Error("three independent engines is a detection")
	}
}

func TestOTXPulseIsNotADetection(t *testing.T) {
	// A pulse means somebody listed the indicator, nothing more. `count > 0`
	// promoted that to a verdict, which is how Microsoft's own signed binaries
	// came back suspicious.
	if otxMalicious(1) {
		t.Error("a single community pulse must not be a malicious verdict")
	}
	if otxMalicious(4) {
		t.Error("a handful of pulses is corroboration, not proof")
	}
	if !otxMalicious(25) {
		t.Error("a widely reported indicator should still flag")
	}
	// OTX alone must never reach the score the verdict engine treats as a
	// detection, or it regains the authority this change took away.
	for _, n := range []int{1, 5, 19, 100, 10000} {
		if s := otxScore(n); s >= 50 {
			t.Errorf("otxScore(%d) = %d, want < 50", n, s)
		}
	}
	if !strings.Contains(otxSummary(1), "not a detection") {
		t.Errorf("the summary must say what a pulse is: %q", otxSummary(1))
	}
}

// ── Extraction ───────────────────────────────────────────────────────────────

func TestExtractIsDeterministic(t *testing.T) {
	// Caps used to be applied while ranging over a map, and Go randomises that,
	// so the same evidence yielded a different indicator set on each run.
	var content strings.Builder
	for i := 1; i <= 40; i++ {
		content.WriteString("203.0.113.")
		content.WriteString(string(rune('0' + i%10)))
		content.WriteString(" host")
		content.WriteString(string(rune('a' + i%26)))
		content.WriteString(".example.net\n")
	}
	first := ExtractIOCs(content.String())
	for i := 0; i < 20; i++ {
		if got := ExtractIOCs(content.String()); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d differed:\n first=%v\n got  =%v", i, first, got)
		}
	}
}

func TestExtractRefangsIndicators(t *testing.T) {
	// The form indicators actually arrive in when pasted from a threat report.
	set := ExtractIOCs("C2 at hxxps://evil-panel[.]top/gate.php resolving to 185[.]220[.]101[.]5, " +
		"contact abuse[at]evil-panel[.]top")
	if len(set.IPs) != 1 || set.IPs[0] != "185.220.101.5" {
		t.Errorf("defanged IP not recovered: %v", set.IPs)
	}
	joined := strings.Join(set.Domains, ",")
	if !strings.Contains(joined, "evil-panel.top") {
		t.Errorf("defanged domain not recovered: %v", set.Domains)
	}
	if len(set.URLs) == 0 || !strings.HasPrefix(set.URLs[0], "https://evil-panel.top") {
		t.Errorf("defanged URL not recovered: %v", set.URLs)
	}
}

func TestExtractIPv6(t *testing.T) {
	set := ExtractIOCs("beacon to 2606:4700:4700::1111 and fe80::1 and ::1")
	found := false
	for _, ip := range set.IPs {
		if ip == "2606:4700:4700::1111" {
			found = true
		}
		if ip == "fe80::1" || ip == "::1" {
			t.Errorf("link-local/loopback IPv6 must be skipped: %s", ip)
		}
	}
	if !found {
		t.Errorf("routable IPv6 not extracted: %v", set.IPs)
	}
}

func TestExtractKeepsAbuseHeavyTLDs(t *testing.T) {
	// The extractor's old private TLD list omitted these, so indicators on the
	// infrastructure that matters most were dropped before enrichment.
	set := ExtractIOCs("stage2 from update-svc.app, panel.dev, payload.zip.click, cdn.icu")
	joined := strings.Join(set.Domains, " ")
	for _, want := range []string{"update-svc.app", "panel.dev", "cdn.icu"} {
		if !strings.Contains(joined, want) {
			t.Errorf("%s was dropped; extracted %v", want, set.Domains)
		}
	}
}

func TestExtractDropsFileNamesAndCodeIdentifiers(t *testing.T) {
	set := ExtractIOCs("kernel32.dll api-ms-win-core-heap-l1-1-0.dll curl.pdb url.fragment")
	if len(set.Domains) != 0 {
		t.Errorf("file names and code identifiers must not become domains: %v", set.Domains)
	}
}

func TestValidBTCChecksum(t *testing.T) {
	// The genesis block's coinbase address — a real, checksummed address.
	const real = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	if !validBTC(real) {
		t.Error("a genuine address must validate")
	}
	// One character changed: the checksum no longer holds.
	if validBTC("1A1zP1eP5QGefi2DMPTfTL5SLmv7Divfna") {
		t.Error("a corrupted address must be rejected")
	}
	// Mutating a byte of the PAYLOAD rather than the checksum is the case that
	// matters — the result is still perfectly base58 and the right length, which
	// is exactly what a random run out of a string table looks like.
	mutated := "1A1zP1eP5QGefi2DMPTfTL5SLmv8DivfNa"
	if mutated == real {
		t.Fatal("test fixture is not actually mutated")
	}
	if validBTC(mutated) {
		t.Error("a base58 run of the right length must not pass as a payment address")
	}
}

func TestExtractRejectsFakeBTC(t *testing.T) {
	set := ExtractIOCs("junk 1A1zP1eP5QGefi2DMPTfTL5SLmv8DivfNa real 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
	if len(set.BTCs) != 1 || set.BTCs[0] != "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" {
		t.Errorf("only the checksummed address should survive, got %v", set.BTCs)
	}
}

// ── Budget allocation ────────────────────────────────────────────────────────

func TestEnrichSpreadsBudgetAcrossTypes(t *testing.T) {
	// Ten IPs used to consume ten of the fifteen slots simply because IPs were
	// appended first, leaving domains and URLs unenriched however important they
	// were. No API keys are configured here, so nothing leaves the process.
	c := New(nil, "", "", "")
	set := IOCSet{
		IPs:     []string{"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5", "1.1.1.6", "1.1.1.7", "1.1.1.8", "1.1.1.9", "1.1.1.10"},
		Hashes:  []string{strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)},
		Domains: []string{"a.example", "b.example", "c.example"},
		URLs:    []string{"http://a.example/x", "http://b.example/y"},
	}
	res := c.Enrich(context.Background(), set)

	seen := map[string]int{}
	for _, r := range res.Results {
		seen[r.Type]++
	}
	for _, want := range []string{"hash", "domain", "ip", "url"} {
		if seen[want] == 0 {
			t.Errorf("no %s was enriched — budget starved it: %v", want, seen)
		}
	}
	if res.Considered != 18 {
		t.Errorf("Considered = %d, want 18", res.Considered)
	}
	if !res.Truncated() || res.Skipped != 3 {
		t.Errorf("Skipped = %d, want 3 with Truncated() true", res.Skipped)
	}
	if res.SkippedByType["ip"] == 0 {
		t.Errorf("the over-represented type should absorb the truncation: %v", res.SkippedByType)
	}
}

func TestEnrichReportsNothingSkippedWhenUnderBudget(t *testing.T) {
	c := New(nil, "", "", "")
	res := c.Enrich(context.Background(), IOCSet{IPs: []string{"9.9.9.9"}})
	if res.Truncated() || res.Skipped != 0 {
		t.Errorf("a single indicator cannot be truncated: %+v", res)
	}
}

// ── Availability ─────────────────────────────────────────────────────────────

func TestFormatSummaryDisclosesTruncationAndUnavailability(t *testing.T) {
	res := EnrichResult{
		Considered:    20,
		Skipped:       5,
		SkippedByType: map[string]int{"hash": 3, "domain": 2},
		Results: []EnrichedIOC{{
			IOC: "185.220.101.5", Type: "ip",
			Unavailable: []string{"VirusTotal — rate limited (HTTP 429)"},
			Complete:    false,
		}},
	}
	out := FormatSummary(res)
	if !strings.Contains(out, "Not all indicators were checked") {
		t.Error("truncation must be stated to the model, not left implicit")
	}
	if !strings.Contains(out, "3 hash") || !strings.Contains(out, "2 domain") {
		t.Errorf("the summary must say WHICH kinds were dropped:\n%s", out)
	}
	if !strings.Contains(out, "NOT CHECKED") {
		t.Error("an indicator nobody could check must not be presented as clean")
	}
	if !strings.Contains(out, "rate limited") {
		t.Error("the reason a source was missing is the actionable part")
	}
}

func TestFormatSummaryStableAcrossRuns(t *testing.T) {
	// Extra is a map; ranging it directly made the prompt differ run to run for
	// identical evidence.
	res := EnrichResult{Results: []EnrichedIOC{{
		IOC: "1.2.3.4", Type: "ip", Complete: true,
		Findings: []Finding{{Source: "VirusTotal", Summary: "x", Extra: map[string]string{
			"Country": "US", "ASN Owner": "Example", "City": "NY", "Region": "E", "Org": "O",
		}}},
	}}}
	first := FormatSummary(res)
	for i := 0; i < 20; i++ {
		if FormatSummary(res) != first {
			t.Fatal("identical evidence must produce an identical prompt")
		}
	}
}

func TestUnavailableStatusNamesTheReason(t *testing.T) {
	se, ok := asSourceError(unavailableStatus("VirusTotal", 429))
	if !ok {
		t.Fatal("a status failure must be recognisable as a source error")
	}
	if se.Source != "VirusTotal" || !strings.Contains(se.Reason, "rate limited") {
		t.Errorf("unhelpful reason: %+v", se)
	}
	if _, ok := asSourceError(errNotApplicable); ok {
		t.Error("a source with nothing to say is not an availability failure")
	}
}

// ── Cache ────────────────────────────────────────────────────────────────────

func TestCacheEvictsToStayBounded(t *testing.T) {
	c := New(nil, "", "", "")
	expired := time.Now().Add(-time.Hour)
	for i := 0; i < tiCacheMaxEntries+50; i++ {
		c.cache[string(rune(i))+"k"] = cacheEntry{expiresAt: expired}
	}
	c.cacheMu.Lock()
	c.evictLocked()
	n := len(c.cache)
	c.cacheMu.Unlock()
	if n >= tiCacheMaxEntries {
		t.Errorf("cache still holds %d entries, bound is %d", n, tiCacheMaxEntries)
	}
}

func TestPartialResultGetsShortTTL(t *testing.T) {
	// The policy that matters: an answer missing a source must not be remembered
	// for a day. Asserted on the constants because the decision is made from
	// result.Complete, which the enrich path sets.
	if tiCacheTTLPartial >= tiCacheTTL {
		t.Fatal("a provisional result must expire sooner than a complete one")
	}
	if tiCacheTTLPartial > 15*time.Minute {
		t.Errorf("a throttled lookup should be retried within minutes, not %v", tiCacheTTLPartial)
	}
}

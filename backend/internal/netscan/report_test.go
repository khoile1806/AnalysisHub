package netscan

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/analysishub/backend/internal/models"
)

// sampleCapture is a capture with everything the report has to render: talkers,
// a signature hit, a C2 finding, DNS/TLS/HTTP, a transferred file and geo data.
func sampleCapture() (*models.NetworkScan, *NetworkResult, []NetworkFinding) {
	scan := &models.NetworkScan{
		ID: uuid.New(), FileName: "incident-2026-08-12.pcap", Size: 4_500_000,
		Sha256: strings.Repeat("d", 64), Status: "done", Verdict: "malicious",
		ThreatScore: 82, FlowCount: 128, AlertCount: 3, C2Count: 1,
		AutoSummary: "Workstation 10.0.0.5 beaconed to 203.0.113.77 every 60 seconds over TLS.",
		AutoSummaryKind: "ai", CreatedAt: time.Now(),
	}
	res := &NetworkResult{
		Stats: map[string]int64{"packets": 41234, "bytes": 18_400_000},
		Alerts: []Alert{
			{Signature: "ET MALWARE Cobalt Strike Beacon", Category: "Trojan", Severity: 1, SID: 2027000,
				Src: "10.0.0.5", Dst: "203.0.113.77", Dport: 443, Proto: "TCP"},
		},
		DNS:  []DNSRec{{Query: "cdn.evil.example", Type: "A", Src: "10.0.0.5", Rcode: "NOERROR", Answers: []string{"203.0.113.77"}}},
		TLS:  []TLSRec{{SNI: "cdn.evil.example", JA3: "a0e9f5d64349fb13191bc781f81f42e1", Version: "TLS 1.2", Dst: "203.0.113.77"}},
		HTTP: []HTTPRec{{Host: "cdn.evil.example", URL: "/gate.php", Method: "POST", UA: "python-requests/2.31", Status: 200, Dst: "203.0.113.77"}},
		Files: []FileRec{{Filename: "invoice.exe", Magic: "PE32 executable", Size: 138145,
			SHA256: strings.Repeat("c", 64), Src: "203.0.113.77", Dst: "10.0.0.5", Yara: []string{"Win_Trojan_Generic"}}},
		Conversations: []Conversation{{A: "10.0.0.5", B: "203.0.113.77", AInternal: true, Count: 42,
			Bytes: 1_200_000, Protos: []string{"TCP", "TLS"}, FirstSeen: "2026-08-12T09:00:00Z", LastSeen: "2026-08-12T09:42:00Z"}},
		Geo:         map[string]GeoInfo{"203.0.113.77": {ASN: "64500", CC: "RU", Org: "Bad Hosting LLC"}},
		DomainFront: []FrontingRec{{SNI: "cdn.cloudfront.net", Host: "c2.evil.example", Src: "10.0.0.5", Dst: "203.0.113.77"}},
		Timeline:    &TimelineData{StartTS: "2026-08-12T09:00:00Z", DurationSec: 2520, BucketSec: 60},
	}
	res.IOCs.IPs = []string{"203.0.113.77", "198.51.100.20"}
	res.IOCs.Domains = []string{"cdn.evil.example", "updates.microsoft.com"}
	findings := []NetworkFinding{
		{Severity: "critical", Category: "c2", Title: "Cobalt Strike beacon", Detail: "60s interval to 203.0.113.77:443",
			Source: "suricata", Indicator: "203.0.113.77"},
		{Severity: "medium", Category: "exfil", Title: "Large outbound transfer", Detail: "1.2 MB uploaded to an external host",
			Source: "behaviour", Indicator: "203.0.113.77"},
	}
	return scan, res, findings
}

func TestNetworkReportStructure(t *testing.T) {
	scan, res, findings := sampleCapture()
	md := BuildReport(scan, res, findings, ReportOptions{Lang: "en"})

	for _, want := range []string{
		"# NETWORK TRAFFIC ANALYSIS REPORT",
		"Executive summary", "Capture identification", "Traffic overview",
		"Conversations", "Findings", "Protocol detail", "Files transferred",
		"Indicators of compromise", "Detection rules", "Impact & response", "Appendix",
		"Cobalt Strike beacon", "203.0.113.77", "cdn.evil.example", "invoice.exe",
		"Bad Hosting LLC",    // geo/ASN enrichment reaches the conversation table
		"Win_Trojan_Generic", // YARA on the reconstructed file
		"c2.evil.example",    // domain fronting is called out
		"incident-2026-08-12.pcap",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("network report is missing %q", want)
		}
	}
	// The narrative must be attributed when a model wrote it.
	if !strings.Contains(md, "AI-written narrative") {
		t.Error("an AI-written summary must be labelled as such")
	}
	assertSectionsNumberedContiguously(t, md)
}

// Optional sections are skipped when they have no data, so the numbers must be
// assigned as sections are written — a report that jumps from 6 to 9 reads as a
// bug and makes the reader hunt for a section that was never there.
func assertSectionsNumberedContiguously(t *testing.T, md string) {
	t.Helper()
	re := regexp.MustCompile(`(?m)^## (\d+)\. `)
	var nums []int
	for _, m := range re.FindAllStringSubmatch(md, -1) {
		n, _ := strconv.Atoi(m[1])
		nums = append(nums, n)
	}
	if len(nums) == 0 {
		t.Fatal("no numbered sections found")
	}
	for i, n := range nums {
		if n != i+1 {
			t.Fatalf("section numbering has a gap: got %v", nums)
		}
	}
}

func TestNetworkReportVietnamese(t *testing.T) {
	scan, res, findings := sampleCapture()
	md := BuildReport(scan, res, findings, ReportOptions{Lang: "vi"})
	for _, want := range []string{
		"BÁO CÁO PHÂN TÍCH LƯU LƯỢNG MẠNG", "Tóm tắt điều hành", "Các phiên trao đổi",
		"Chỉ số xâm nhập (IOC)", "Quy tắc phát hiện", "Ảnh hưởng & xử lý",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("Vietnamese network report is missing %q", want)
		}
	}
}

// Provenance drives confidence: what a detector flagged is actionable, what was
// merely observed is not — blocking the latter takes down legitimate traffic.
func TestNetworkIOCProvenance(t *testing.T) {
	scan, res, findings := sampleCapture()
	iocs := CollectIOCs(scan, res, findings)

	by := map[string]NetIOC{}
	for _, i := range iocs {
		by[i.Type+"|"+i.Value] = i
	}
	if e := by["ip|203.0.113.77"]; e.Confidence != "high" {
		t.Errorf("a C2 address flagged by a signature must be high confidence, got %+v", e)
	}
	if e := by["domain|updates.microsoft.com"]; e.Confidence != "low" {
		t.Errorf("a merely-observed domain must stay low confidence, got %+v", e)
	}
	// This table ends up in a firewall: an internal address must never be listed
	// as something to block, or the report itself causes the outage.
	for _, internal := range []string{"10.0.0.5", "10.0.0.1", "192.168.1.1", "172.16.4.9"} {
		if _, ok := by["ip|"+internal]; ok {
			t.Errorf("internal address %s was listed as a blockable indicator", internal)
		}
	}
	if e := by["sha256|"+strings.Repeat("c", 64)]; e.Confidence != "high" {
		t.Errorf("a transferred file with a YARA hit must be high confidence, got %+v", e)
	}
	if e := by["domain|c2.evil.example"]; e.Confidence != "high" {
		t.Errorf("a domain-fronted host must be high confidence, got %+v", e)
	}
	if _, ok := by["user-agent|python-requests/2.31"]; !ok {
		t.Error("a scripted User-Agent should become an indicator")
	}
	if len(iocs) > 0 && iocs[0].Confidence != "high" {
		t.Errorf("indicators are not ordered strongest-first: %+v", iocs[0])
	}
}

// The rule file must be usable: no rules for low-provenance observations, and
// every emitted rule carries a sid.
func TestNetworkSuricataRulesSkipNoise(t *testing.T) {
	scan, res, findings := sampleCapture()
	rules := BuildSuricataRules(scan, CollectIOCs(scan, res, findings))

	if !strings.Contains(rules, "203.0.113.77") {
		t.Error("the flagged C2 address must produce a rule")
	}
	if strings.Contains(rules, "updates.microsoft.com") {
		t.Error("a low-confidence observed domain must NOT become an IDS rule")
	}
	if strings.Contains(rules, "ja3.hash") && !strings.Contains(rules, "a0e9f5d64349fb13191bc781f81f42e1") {
		t.Error("the JA3 rule lost its hash")
	}
	for _, line := range strings.Split(rules, "\n") {
		if strings.HasPrefix(line, "alert ") && !strings.Contains(line, "sid:") {
			t.Errorf("rule without a sid: %s", line)
		}
	}
}

// A quiet capture must still produce a coherent report rather than empty sections.
func TestNetworkReportHandlesEmptyCapture(t *testing.T) {
	scan := &models.NetworkScan{ID: uuid.New(), FileName: "quiet.pcap", Status: "done",
		Verdict: "benign", CreatedAt: time.Now()}
	md := BuildReport(scan, &NetworkResult{}, nil, ReportOptions{Lang: "en"})
	if !strings.Contains(md, "_No findings._") {
		t.Error("an empty capture should say so explicitly")
	}
	if !strings.Contains(md, "No malicious traffic was identified") {
		t.Error("the impact section must still reach a conclusion")
	}
	if strings.Contains(md, "## 7. Files transferred") {
		t.Error("sections with no data should be omitted, not rendered empty")
	}
}

// TLS that could not be decrypted is a limitation of the analysis, and a report
// that hides it lets "nothing found" read as "nothing happened".
func TestNetworkReportStatesLimitations(t *testing.T) {
	scan, res, findings := sampleCapture()
	md := BuildReport(scan, res, findings, ReportOptions{Lang: "en"})
	if !strings.Contains(md, "could not be decrypted") {
		t.Error("undecrypted TLS must be declared as a limitation")
	}
	if !strings.Contains(md, "No AI analysis was run") {
		t.Error("a missing AI stage must be declared")
	}
}

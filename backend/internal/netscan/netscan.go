// Package netscan implements PCAP network-traffic analysis. An uploaded capture
// is run through the Suricata sidecar (offline mode); the distilled result
// (flows, DNS, TLS/JA3, HTTP, ET-Open alerts, a host-flow graph) is stored, and
// the noteworthy connections become findings (C2 by signature, by reputation, or
// by IOC-store match). It reuses the malware feature's async-job shape.
package netscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"

	ai "github.com/analysishub/backend/internal/ai"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/storage"
	"github.com/analysishub/backend/internal/threatintel"
)

const (
	netConcurrency = 2
	netRunTimeout  = 15 * time.Minute
	sidecarTimeout = 14 * time.Minute
)

// NetworkResult mirrors the sidecar's distilled JSON.
type NetworkResult struct {
	Stats  map[string]int64 `json:"stats"`
	Flows  []Flow           `json:"flows"`
	Alerts []Alert          `json:"alerts"`
	DNS    []DNSRec         `json:"dns"`
	TLS    []TLSRec         `json:"tls"`
	HTTP   []HTTPRec        `json:"http"`
	Files  []FileRec        `json:"files"`
	Graph  Graph            `json:"graph"`
	IOCs   struct {
		IPs     []string `json:"ips"`
		Domains []string `json:"domains"`
	} `json:"iocs"`
	MaxSeverity   int                `json:"max_severity"`
	Protocols     []ProtoStat        `json:"protocols,omitempty"`       // tshark protocol hierarchy
	Conversations []Conversation     `json:"conversations,omitempty"`   // host↔host aggregation
	Timeline      *TimelineData      `json:"timeline,omitempty"`        // traffic over time
	Zeek          *ZeekResult        `json:"zeek,omitempty"`            // deep protocol logs (Zeek)
	Geo           map[string]GeoInfo `json:"geo,omitempty"`             // external IP → ASN/country
	DecryptedHTTP []HTTPRec          `json:"decrypted_http,omitempty"`  // HTTP requests decrypted from TLS via keylog
	DomainFront   []FrontingRec      `json:"domain_fronting,omitempty"` // TLS SNI ≠ HTTP Host
	Carved        []CarvedFile       `json:"carved,omitempty"`          // reconstructed files (base64), stripped after saving
	Error         string             `json:"error,omitempty"`
}

// FrontingRec is a domain-fronting case: the TLS SNI presented on the wire
// differs from the (decrypted) HTTP Host actually requested.
type FrontingRec struct {
	SNI  string `json:"sni"`
	Host string `json:"host"`
	Src  string `json:"src"`
	Dst  string `json:"dst"`
}

// GeoInfo is the ASN/country enrichment for one external IP (iptoasn dataset).
type GeoInfo struct {
	ASN string `json:"asn"`
	CC  string `json:"cc"`
	Org string `json:"org"`
}

// ZeekResult holds the distilled Zeek logs we surface (provenance + auth + notices).
type ZeekResult struct {
	Notices  []ZeekNotice `json:"notices,omitempty"`
	Files    []ZeekFile   `json:"files,omitempty"`
	SSL      []ZeekSSL    `json:"ssl,omitempty"`
	Kerberos []ZeekAuth   `json:"kerberos,omitempty"`
	NTLM     []ZeekNTLM   `json:"ntlm,omitempty"`
	SMB      []ZeekSMB    `json:"smb,omitempty"`
	SSH      []ZeekSSH    `json:"ssh,omitempty"`
}
type ZeekNotice struct {
	Note string `json:"note"`
	Msg  string `json:"msg"`
	Sub  string `json:"sub"`
	Src  string `json:"src"`
	Dst  string `json:"dst"`
}
type ZeekFile struct {
	Tx       string `json:"tx"`
	Rx       string `json:"rx"`
	Source   string `json:"source"`
	Mime     string `json:"mime"`
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	MD5      string `json:"md5"`
	Bytes    int64  `json:"bytes"`
}
type ZeekSSL struct {
	ServerName string `json:"server_name"`
	Version    string `json:"version"`
	JA3        string `json:"ja3"`
	JA3S       string `json:"ja3s"`
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	Validation string `json:"validation"`
	Dst        string `json:"dst"`
}
type ZeekAuth struct {
	Client  string `json:"client"`
	Service string `json:"service"`
	Success *bool  `json:"success"`
	Src     string `json:"src"`
	Dst     string `json:"dst"`
}
type ZeekNTLM struct {
	User   string `json:"user"`
	Host   string `json:"host"`
	Domain string `json:"domain"`
	Src    string `json:"src"`
	Dst    string `json:"dst"`
}
type ZeekSMB struct {
	Action string `json:"action"`
	Path   string `json:"path"`
	Name   string `json:"name"`
	Src    string `json:"src"`
	Dst    string `json:"dst"`
}
type ZeekSSH struct {
	Success *bool  `json:"success"`
	Client  string `json:"client"`
	Server  string `json:"server"`
	Src     string `json:"src"`
	Dst     string `json:"dst"`
}

// ProtoStat is one node of the tshark protocol-hierarchy tree.
type ProtoStat struct {
	Name   string `json:"name"`
	Level  int    `json:"level"`
	Frames int    `json:"frames"`
	Bytes  int64  `json:"bytes"`
}

// CarvedFile is a file reconstructed from the wire by Suricata's file-store,
// returned inline (base64) so the backend can move it into the Evidence Store.
// Yara holds any bundled-ruleset matches from scanning the reconstructed bytes.
type CarvedFile struct {
	SHA256 string   `json:"sha256"`
	Size   int64    `json:"size"`
	Yara   []string `json:"yara,omitempty"`
	B64    string   `json:"b64"`
}

type Flow struct {
	Src      string `json:"src"`
	Sport    int    `json:"sport"`
	Dst      string `json:"dst"`
	Dport    int    `json:"dport"`
	Proto    string `json:"proto"`
	App      string `json:"app"`
	Bytes    int64  `json:"bytes"`
	ToServer int64  `json:"to_server"` // client→server bytes (upload / exfil direction)
	ToClient int64  `json:"to_client"` // server→client bytes (download direction)
	Pkts     int64  `json:"pkts"`
	Start    string `json:"start"` // Suricata flow start timestamp (for beaconing)
	End      string `json:"end"`
	State    string `json:"state"`
}
type Alert struct {
	Signature string `json:"signature"`
	Category  string `json:"category"`
	Severity  int    `json:"severity"`
	SID       int    `json:"sid"`
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	Dport     int    `json:"dport"`
	Proto     string `json:"proto"`
}
type DNSRec struct {
	Query   string   `json:"query"`
	Type    string   `json:"type"`
	Src     string   `json:"src"`
	Rcode   string   `json:"rcode"`   // e.g. NOERROR, NXDOMAIN (NXDOMAIN bursts → DGA)
	Answers []string `json:"answers"` // resolved A/AAAA addresses (fast-flux)
}
type TLSRec struct {
	SNI     string `json:"sni"`
	JA3     string `json:"ja3"`
	JA3S    string `json:"ja3s"`
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
	Version string `json:"version"`
	Dst     string `json:"dst"`
}
type HTTPRec struct {
	Host   string `json:"host"`
	URL    string `json:"url"`
	Method string `json:"method"`
	UA     string `json:"ua"`
	Status int    `json:"status"`
	Dst    string `json:"dst"`
}
type FileRec struct {
	Filename  string   `json:"filename"`
	Magic     string   `json:"magic"`
	Size      int64    `json:"size"`
	SHA256    string   `json:"sha256"`
	MD5       string   `json:"md5"`
	Src       string   `json:"src"`
	Dst       string   `json:"dst"`
	Yara      []string `json:"yara,omitempty"`      // YARA matches on the reconstructed file
	Decrypted bool     `json:"decrypted,omitempty"` // reconstructed from decrypted TLS
}
type Graph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}
type GraphNode struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}
type GraphEdge struct {
	Src   string   `json:"src"`
	Dst   string   `json:"dst"`
	Proto string   `json:"proto"`
	Bytes int64    `json:"bytes"`
	Flows int      `json:"flows"`
	Ports []string `json:"ports"`
}

// NetworkFinding is one noteworthy connection (C2 / malicious traffic).
type NetworkFinding struct {
	Severity  string `json:"severity"` // critical|high|medium|low|info
	Category  string `json:"category"` // c2 | signature | reputation | ioc | exfil
	Title     string `json:"title"`
	Detail    string `json:"detail"`
	Source    string `json:"source"` // suricata | reputation | ioc-store
	Indicator string `json:"indicator,omitempty"`
}

// ChainStep mirrors the shared progress step.
type ChainStep struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// Engine orchestrates one pcap analysis.
type Engine struct {
	db        *gorm.DB
	store     *storage.LocalStorage
	sidecar   string
	enrich    *threatintel.EnrichClient
	localOnly bool
	hc        *http.Client
	sem       chan struct{}
}

func NewEngine(db *gorm.DB, store *storage.LocalStorage, sidecarURL string, enrich *threatintel.EnrichClient, localOnly bool) *Engine {
	sidecarURL = strings.TrimRight(strings.TrimSpace(sidecarURL), "/")
	e := &Engine{db: db, store: store, sidecar: sidecarURL, enrich: enrich, localOnly: localOnly,
		hc: &http.Client{Timeout: sidecarTimeout}, sem: make(chan struct{}, netConcurrency)}
	// Sweep interrupted runs on restart so nothing hangs "running".
	db.Model(&models.NetworkScan{}).Where("status IN ?", []string{"running", "pending"}).
		Updates(map[string]interface{}{"status": "failed", "error": "interrupted by a server restart"})
	return e
}

// Available reports whether the sidecar is configured.
func (e *Engine) Available() bool { return e.sidecar != "" }

// Health checks the sidecar.
func (e *Engine) Health(ctx context.Context) map[string]interface{} {
	if e.sidecar == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.sidecar+"/health", nil)
	if err != nil {
		return nil
	}
	hc := &http.Client{Timeout: 4 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var h map[string]interface{}
	if json.Unmarshal(raw, &h) != nil {
		return nil
	}
	return h
}

func netSteps() []ChainStep {
	return []ChainStep{
		{ID: "suricata", Label: "Suricata analysis (flows, DNS, TLS, alerts, file carving)", Status: "pending"},
		{ID: "c2", Label: "Detection (beaconing, exfil, TLS/DNS anomalies, JA3/IOC, reputation)", Status: "pending"},
		{ID: "verdict", Label: "Verdict synthesis", Status: "pending"},
		{ID: "summary", Label: "Analyst summary (auto)", Status: "pending"},
	}
}

// Analyze runs the full pcap pipeline for an already-persisted scan row. When a
// non-nil AI client is passed it also auto-writes a narrative summary; otherwise
// a deterministic summary is produced.
func (e *Engine) Analyze(parent context.Context, scanID string, data []byte, filename string, keylog []byte, client ai.Client, maxTokens int) {
	e.sem <- struct{}{}
	defer func() { <-e.sem }()
	defer func() {
		if r := recover(); r != nil {
			e.db.Model(&models.NetworkScan{}).Where("id = ?", scanID).
				Updates(map[string]interface{}{"status": "failed", "error": fmt.Sprintf("crashed: %v", r)})
		}
	}()
	ctx, cancel := context.WithTimeout(parent, netRunTimeout)
	defer cancel()

	steps := netSteps()
	var scan models.NetworkScan
	if e.db.First(&scan, "id = ?", scanID).Error != nil {
		return
	}
	e.db.Model(&scan).Update("status", "running")
	e.mark(&scan, &steps, "suricata", "running", "")

	res, err := e.callSidecar(ctx, filename, data, keylog)
	if err != nil {
		e.fail(&scan, &steps, "suricata", err.Error())
		return
	}
	// Move any carved files into the Evidence Store, then strip their bytes so the
	// stored result JSON never carries base64 payloads.
	carvedFindings := e.saveCarved(scanID, scan.CaseID, res)
	res.Carved = nil
	res.Conversations = buildConversations(res) // host↔host aggregation for the UI + summary
	res.Timeline = buildTimeline(res)           // traffic-over-time series

	resJSON, _ := json.Marshal(res)
	scan.Result = string(resJSON)
	scan.FlowCount = int(res.Stats["flows"])
	scan.AlertCount = len(res.Alerts)
	e.mark(&scan, &steps, "suricata", "done",
		fmt.Sprintf("%d flow(s), %d alert(s), %d DNS, %d TLS", scan.FlowCount, len(res.Alerts), len(res.DNS), len(res.TLS)))

	// ── C2 / behavioural detection ──────────────────────────────────────────────
	e.mark(&scan, &steps, "c2", "running", "")
	findings, _ := e.buildFindings(ctx, res) // Suricata signatures + reputation
	behavior, _ := analyzeBehavior(res)      // beaconing, exfil, TLS/DNS anomalies
	findings = append(findings, behavior...)
	findings = append(findings, e.intelFindings(res)...)  // JA3 blocklist + IOC store
	findings = append(findings, zeekFindings(res)...)     // Zeek notices + TLS validation
	findings = append(findings, frontingFindings(res)...) // domain fronting (decrypted)
	findings = append(findings, carvedFindings...)
	c2 := countC2(findings)
	scan.C2Count = c2
	fJSON, _ := json.Marshal(findings)
	scan.Findings = string(fJSON)
	e.mark(&scan, &steps, "c2", "done", fmt.Sprintf("%d C2/malicious indicator(s)", c2))

	// ── Verdict ───────────────────────────────────────────────────────────────
	verdict, score, summary := verdictFrom(res, findings)
	scan.Verdict, scan.ThreatScore, scan.Summary = verdict, score, summary
	e.mark(&scan, &steps, "verdict", "done", verdict)

	// ── Analyst summary (auto) — AI narrative when a provider is set, else a
	// deterministic one. Always present with every analysis.
	e.mark(&scan, &steps, "summary", "running", "")
	autoText, autoKind := e.autoSummarize(ctx, res, findings, verdict, score, client, maxTokens)
	e.mark(&scan, &steps, "summary", "done", autoKind)

	now := time.Now()
	e.db.Model(&scan).Updates(map[string]interface{}{
		"result": scan.Result, "findings": scan.Findings, "flow_count": scan.FlowCount,
		"alert_count": scan.AlertCount, "c2_count": scan.C2Count, "verdict": scan.Verdict,
		"threat_score": scan.ThreatScore, "summary": scan.Summary, "auto_summary": autoText,
		"auto_summary_kind": autoKind, "status": "done", "finished_at": &now,
	})
}

func (e *Engine) callSidecar(ctx context.Context, filename string, data, keylog []byte) (*NetworkResult, error) {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	fw, err := w.CreateFormFile("file", filename)
	if err != nil {
		return nil, err
	}
	if _, err := fw.Write(data); err != nil {
		return nil, err
	}
	if len(keylog) > 0 {
		if kw, kerr := w.CreateFormFile("keylog", "keys.log"); kerr == nil {
			_, _ = kw.Write(keylog)
		}
	}
	w.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.sidecar+"/analyze", &body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := e.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network-analyzer sidecar unreachable: %w", err)
	}
	defer resp.Body.Close()
	raw, rerr := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if rerr != nil {
		return nil, fmt.Errorf("reading sidecar response: %w", rerr)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("sidecar HTTP %d", resp.StatusCode)
	}
	var res NetworkResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("sidecar: bad response")
	}
	if res.Error != "" {
		return nil, fmt.Errorf("%s", res.Error)
	}
	return &res, nil
}

// buildFindings turns Suricata alerts + threat-intel enrichment into findings.
func (e *Engine) buildFindings(ctx context.Context, res *NetworkResult) ([]NetworkFinding, int) {
	var out []NetworkFinding
	c2 := 0
	seenSig := map[string]bool{}
	for _, a := range res.Alerts {
		key := a.Signature + "|" + a.Dst
		if seenSig[key] {
			continue
		}
		seenSig[key] = true
		sev := "medium"
		if a.Severity <= 1 {
			sev = "high"
		} else if a.Severity == 2 {
			sev = "medium"
		} else {
			sev = "low"
		}
		cat := "signature"
		lc := strings.ToLower(a.Category + " " + a.Signature)
		if strings.Contains(lc, "cnc") || strings.Contains(lc, "command and control") || strings.Contains(lc, "trojan") || strings.Contains(lc, "malware") || strings.Contains(lc, "c2") {
			cat = "c2"
			c2++
			if sev != "high" {
				sev = "high"
			}
		}
		out = append(out, NetworkFinding{Severity: sev, Category: cat, Source: "suricata",
			Title: a.Signature, Detail: fmt.Sprintf("%s → %s:%d (%s)", a.Src, a.Dst, a.Dport, a.Category),
			Indicator: a.Dst})
		if len(out) >= 400 {
			break
		}
	}

	// Reputation enrichment on dest IPs + domains (hash-only lookups; file never
	// leaves the box). Skipped in strict local-only mode.
	if !e.localOnly && e.enrich != nil && e.enrich.Configured() {
		set := threatintel.IOCSet{IPs: capStr(res.IOCs.IPs, 40), Domains: capStr(res.IOCs.Domains, 40)}
		if set.Total() > 0 {
			for _, r := range e.enrich.Enrich(ctx, set) {
				if !r.Threat {
					continue
				}
				c2++
				src := ""
				if len(r.Findings) > 0 {
					src = r.Findings[0].Source
				}
				out = append(out, NetworkFinding{Severity: sevForScore(r.MaxScore), Category: "reputation",
					Source: "reputation", Title: "Malicious network endpoint: " + r.IOC,
					Detail: fmt.Sprintf("flagged by %s (score %d/100)", src, r.MaxScore), Indicator: r.IOC})
			}
		}
	}
	return out, c2
}

// countC2 counts findings that assert a confirmed malicious endpoint (signature
// C2, threat-intel reputation, JA3 blocklist, or a local IOC-store match).
func countC2(findings []NetworkFinding) int {
	n := 0
	for _, f := range findings {
		switch f.Category {
		case "c2", "reputation", "ioc", "malware-file":
			n++
		}
	}
	return n
}

func verdictFrom(res *NetworkResult, findings []NetworkFinding) (string, int, string) {
	high := 0
	c2 := countC2(findings)
	for _, f := range findings {
		if f.Severity == "high" || f.Severity == "critical" {
			high++
		}
	}
	verdict, score := "benign", 5
	switch {
	case c2 > 0:
		verdict, score = "malicious", 80
	case high > 0:
		verdict, score = "suspicious", 55
	case len(findings) > 0:
		verdict, score = "suspicious", 40
	case res.Stats["flows"] == 0:
		verdict, score = "unknown", 0
	}
	summary := fmt.Sprintf("%d flow(s), %d alert(s), %d C2/malicious indicator(s).",
		res.Stats["flows"], len(res.Alerts), c2)
	return verdict, score, summary
}

func sevForScore(s int) string {
	switch {
	case s >= 70:
		return "high"
	case s >= 40:
		return "medium"
	default:
		return "low"
	}
}

func capStr(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (e *Engine) mark(scan *models.NetworkScan, steps *[]ChainStep, id, status, detail string) {
	if id == "" {
		return
	}
	for i := range *steps {
		if (*steps)[i].ID == id {
			(*steps)[i].Status = status
			if detail != "" {
				(*steps)[i].Detail = detail
			}
		}
	}
	b, _ := json.Marshal(*steps)
	scan.Steps = string(b)
	e.db.Model(scan).Update("steps", scan.Steps)
}

func (e *Engine) fail(scan *models.NetworkScan, steps *[]ChainStep, stepID, msg string) {
	e.mark(scan, steps, stepID, "failed", msg)
	now := time.Now()
	e.db.Model(scan).Updates(map[string]interface{}{"status": "failed", "error": msg, "finished_at": &now})
}

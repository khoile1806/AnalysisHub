package netscan

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/analysishub/backend/internal/models"
)

// detect.go — deterministic, offline behavioural detection over the distilled
// capture: real beaconing (flow periodicity), exfiltration (upload asymmetry),
// TLS/DNS anomalies (self-signed certs, NXDOMAIN bursts, fast-flux) plus local
// intel matching (a malicious-JA3 blocklist and the platform's IOC store) and
// file carving into the Evidence Store. None of it needs the internet.

// analyzeBehavior returns deterministic findings (for the verdict/UI) plus
// human-readable observations (for the AI's independent Section B), both computed
// purely from the parsed protocol data — never from Suricata signatures.
func analyzeBehavior(res *NetworkResult) (findings []NetworkFinding, observations []string) {
	obs := func(s string) { observations = append(observations, s) }

	// ── Beaconing: regular, repeated contact to the same external endpoint. ──
	for _, bc := range beaconingCandidates(res) {
		detail := fmt.Sprintf("%d connections to %s over %s, mean interval %.0fs (jitter %.0f%%)",
			bc.Count, bc.Dst, bc.Src, bc.MeanSec, bc.CV*100)
		if bc.Regular {
			findings = append(findings, NetworkFinding{Severity: "high", Category: "behavior",
				Source: "beaconing", Title: "Beaconing / periodic C2 check-in", Detail: detail, Indicator: hostOf(bc.Dst)})
			obs("Beaconing detected: " + detail + " — highly regular timing is characteristic of automated C2 check-in")
		} else {
			obs("Repeated contact: " + detail + " (repeated but irregular — could be polling or C2)")
		}
	}

	// ── Exfiltration: large, upload-heavy egress to an external host. ──
	for _, ex := range exfilCandidates(res) {
		detail := fmt.Sprintf("%s uploaded %s to %s:%d (%.0f%% of traffic was outbound)",
			ex.Src, humanBytes(ex.ToServer), ex.Dst, ex.Dport, ex.OutRatio*100)
		findings = append(findings, NetworkFinding{Severity: "high", Category: "exfil",
			Source: "behavior", Title: "Possible data exfiltration", Detail: detail, Indicator: ex.Dst})
		obs("Exfiltration candidate: " + detail)
	}

	// ── TLS: self-signed certs + bare-IP/no-SNI sessions. ──
	selfSigned, noSNI, ipSNI := 0, 0, 0
	for _, t := range res.TLS {
		if t.Subject != "" && t.Subject == t.Issuer {
			selfSigned++
		}
		if t.SNI == "" {
			noSNI++
		} else if isIPLiteral(t.SNI) {
			ipSNI++
		}
	}
	if selfSigned > 0 {
		findings = append(findings, NetworkFinding{Severity: "medium", Category: "tls",
			Source: "behavior", Title: "Self-signed TLS certificate(s)",
			Detail: fmt.Sprintf("%d TLS session(s) presented a self-signed certificate (subject == issuer)", selfSigned)})
		obs(fmt.Sprintf("%d self-signed TLS certificate(s) — common for C2 / interception", selfSigned))
	}
	if noSNI > 0 {
		obs(fmt.Sprintf("%d TLS session(s) with NO SNI — encrypted channel to an unnamed host (evasive)", noSNI))
	}
	if ipSNI > 0 {
		obs(fmt.Sprintf("%d TLS session(s) whose SNI is a bare IP address", ipSNI))
	}

	// ── DNS: NXDOMAIN bursts (DGA), DGA-looking names, fast-flux. ──
	nx, dga := 0, 0
	answersByDomain := map[string]map[string]struct{}{}
	for _, d := range res.DNS {
		if strings.EqualFold(d.Rcode, "NXDOMAIN") {
			nx++
		}
		if looksDGA(d.Query) {
			dga++
		}
		for _, a := range d.Answers {
			m := answersByDomain[d.Query]
			if m == nil {
				m = map[string]struct{}{}
				answersByDomain[d.Query] = m
			}
			m[a] = struct{}{}
		}
	}
	if nx >= 20 {
		findings = append(findings, NetworkFinding{Severity: "high", Category: "dns",
			Source: "behavior", Title: "NXDOMAIN burst (DGA-like)",
			Detail: fmt.Sprintf("%d NXDOMAIN responses — typical of domain-generation-algorithm C2 rendezvous", nx)})
		obs(fmt.Sprintf("%d NXDOMAIN responses — DGA malware sweeping generated domains", nx))
	}
	if dga >= 5 {
		findings = append(findings, NetworkFinding{Severity: "medium", Category: "dns",
			Source: "behavior", Title: "Algorithmically-generated domains",
			Detail: fmt.Sprintf("%d DNS lookups look algorithmically generated (high entropy)", dga)})
		obs(fmt.Sprintf("%d DGA-like domain lookups (high entropy / unpronounceable)", dga))
	}
	for dom, ips := range answersByDomain {
		if len(ips) >= 8 {
			findings = append(findings, NetworkFinding{Severity: "medium", Category: "dns",
				Source: "behavior", Title: "Fast-flux domain", Detail: fmt.Sprintf("%s resolved to %d distinct IPs", sanitizeLine(dom), len(ips)), Indicator: dom})
			obs(fmt.Sprintf("Fast-flux: %s resolved to %d different IPs (evasive hosting)", sanitizeLine(dom), len(ips)))
		}
	}

	// ── Odd external ports + suspicious plaintext downloads (observations only). ──
	oddPorts := map[int]int{}
	for _, f := range res.Flows {
		if !isPrivateIP(f.Dst) && f.Dst != "" && f.Dport != 0 && !commonPorts[f.Dport] {
			oddPorts[f.Dport]++
		}
	}
	for p, n := range oddPorts {
		if n >= 3 {
			obs(fmt.Sprintf("Uncommon destination port %d used by %d external connection(s)", p, n))
		}
	}
	badDL := 0
	for _, h := range res.HTTP {
		low := strings.ToLower(h.URL)
		if hasAnySuffix(low, ".exe", ".dll", ".ps1", ".scr", ".hta", ".bin", ".jar") ||
			(strings.EqualFold(h.Method, "POST") && isIPLiteral(h.Host)) {
			badDL++
		}
	}
	if badDL > 0 {
		obs(fmt.Sprintf("%d plaintext-HTTP request(s) for executables/scripts or POST to a bare-IP host (staging / C2 over HTTP)", badDL))
	}

	if len(observations) > 50 {
		observations = observations[:50]
	}
	return findings, observations
}

// ── Beaconing ────────────────────────────────────────────────────────────────

type beacon struct {
	Src, Dst string
	Dport    int
	Count    int
	MeanSec  float64
	CV       float64 // coefficient of variation of inter-arrival times (lower = more regular)
	Regular  bool
}

func beaconingCandidates(res *NetworkResult) []beacon {
	type grp struct {
		src, dst string
		dport    int
		times    []time.Time
	}
	groups := map[string]*grp{}
	for _, f := range res.Flows {
		if f.Dst == "" || isPrivateIP(f.Dst) || f.Start == "" {
			continue
		}
		t, ok := parseSuriTime(f.Start)
		if !ok {
			continue
		}
		k := fmt.Sprintf("%s|%s|%d", f.Src, f.Dst, f.Dport)
		g := groups[k]
		if g == nil {
			g = &grp{src: f.Src, dst: fmt.Sprintf("%s:%d", f.Dst, f.Dport), dport: f.Dport}
			groups[k] = g
		}
		g.times = append(g.times, t)
	}
	var out []beacon
	for _, g := range groups {
		if len(g.times) < 6 {
			continue
		}
		sort.Slice(g.times, func(i, j int) bool { return g.times[i].Before(g.times[j]) })
		var deltas []float64
		for i := 1; i < len(g.times); i++ {
			d := g.times[i].Sub(g.times[i-1]).Seconds()
			if d >= 0 {
				deltas = append(deltas, d)
			}
		}
		if len(deltas) < 5 {
			continue
		}
		mean, cv := meanCV(deltas)
		if mean < 1 || mean > 3600 {
			continue // sub-second or >1h intervals aren't the beaconing we flag
		}
		out = append(out, beacon{Src: g.src, Dst: g.dst, Dport: g.dport, Count: len(g.times),
			MeanSec: mean, CV: cv, Regular: cv < 0.30 && len(g.times) >= 6})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CV < out[j].CV })
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

// ── Exfiltration ─────────────────────────────────────────────────────────────

type exfil struct {
	Src, Dst string
	Dport    int
	ToServer int64
	OutRatio float64
}

const exfilMinBytes = 50 << 20 // 50 MB uploaded to a single external host

func exfilCandidates(res *NetworkResult) []exfil {
	type agg struct {
		toServer, toClient int64
		dport              int
	}
	byDst := map[string]*agg{}
	srcOf := map[string]string{}
	for _, f := range res.Flows {
		if f.Dst == "" || isPrivateIP(f.Dst) || !isPrivateIP(f.Src) {
			continue
		}
		a := byDst[f.Dst]
		if a == nil {
			a = &agg{dport: f.Dport}
			byDst[f.Dst] = a
			srcOf[f.Dst] = f.Src
		}
		a.toServer += f.ToServer
		a.toClient += f.ToClient
	}
	var out []exfil
	for dst, a := range byDst {
		total := a.toServer + a.toClient
		if a.toServer < exfilMinBytes || total == 0 {
			continue
		}
		ratio := float64(a.toServer) / float64(total)
		if ratio < 0.6 { // must be upload-dominant
			continue
		}
		out = append(out, exfil{Src: srcOf[dst], Dst: dst, Dport: a.dport, ToServer: a.toServer, OutRatio: ratio})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ToServer > out[j].ToServer })
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}

// ── Offline intel: malicious-JA3 blocklist + local IOC store ─────────────────

// intelFindings matches the capture against offline intel sources: a bundled
// malicious-JA3 fingerprint blocklist and the platform's own IOC store (known-bad
// from prior cases). Both work without any external API.
func (e *Engine) intelFindings(res *NetworkResult) []NetworkFinding {
	var out []NetworkFinding

	// Malicious JA3 client fingerprints (offline blocklist).
	seenJA3 := map[string]bool{}
	for _, t := range res.TLS {
		if t.JA3 == "" || seenJA3[t.JA3] {
			continue
		}
		if label, bad := maliciousJA3[strings.ToLower(t.JA3)]; bad {
			seenJA3[t.JA3] = true
			out = append(out, NetworkFinding{Severity: "high", Category: "c2", Source: "ja3-blocklist",
				Title:     "Known-malicious TLS fingerprint (JA3): " + label,
				Detail:    fmt.Sprintf("JA3 %s → %s (client TLS stack matches a known malware/C2 tool)", t.JA3, label),
				Indicator: hostOf(t.Dst)})
		}
	}

	// Local IOC-store cross-reference (IPs, domains, file hashes).
	if e.db != nil {
		values := map[string]bool{}
		for _, ip := range res.IOCs.IPs {
			values[ip] = true
		}
		for _, d := range res.IOCs.Domains {
			values[strings.ToLower(strings.TrimSuffix(d, "."))] = true
		}
		for _, f := range res.Files {
			if f.SHA256 != "" {
				values[strings.ToLower(f.SHA256)] = true
			}
			if f.MD5 != "" {
				values[strings.ToLower(f.MD5)] = true
			}
		}
		if len(values) > 0 {
			list := make([]string, 0, len(values))
			for v := range values {
				list = append(list, v)
			}
			var hits []models.IOC
			// Case-insensitive match on value; cap the IN-list to stay bounded.
			e.db.Where("lower(value) IN ?", capStr(lowerAll(list), 800)).Find(&hits)
			for _, h := range hits {
				out = append(out, NetworkFinding{Severity: "high", Category: "ioc", Source: "ioc-store",
					Title:     "IOC-store match: " + h.Value,
					Detail:    fmt.Sprintf("%s known-bad from %s%s", h.Type, orDash(h.Source), descSuffix(h.Description)),
					Indicator: h.Value})
			}
		}
	}
	return out
}

// TimelineBucket is traffic volume in one time slice of the capture.
type TimelineBucket struct {
	T       int   `json:"t"` // offset seconds from capture start
	Packets int64 `json:"packets"`
	Bytes   int64 `json:"bytes"`
	Flows   int   `json:"flows"`
}

// TimelineData is the per-time-bucket traffic series (bucketed by flow start),
// so bursts and beaconing are visible over the capture's timeline.
type TimelineData struct {
	StartTS     string           `json:"start_ts"`
	DurationSec int              `json:"duration_sec"`
	BucketSec   int              `json:"bucket_sec"`
	Buckets     []TimelineBucket `json:"buckets"`
}

func buildTimeline(res *NetworkResult) *TimelineData {
	var mn, mx time.Time
	have := false
	for _, f := range res.Flows {
		if t, ok := parseSuriTime(f.Start); ok {
			if !have || t.Before(mn) {
				mn = t
			}
			if !have || t.After(mx) {
				mx = t
			}
			have = true
		}
		if t, ok := parseSuriTime(f.End); ok && t.After(mx) {
			mx = t
		}
	}
	if !have {
		return nil
	}
	span := mx.Sub(mn).Seconds()
	if span < 1 {
		span = 1
	}
	n := 48
	bucketSec := span / float64(n)
	if bucketSec < 1 {
		bucketSec = 1
		n = int(span) + 1
	}
	buckets := make([]TimelineBucket, n)
	for i := range buckets {
		buckets[i].T = int(float64(i) * bucketSec)
	}
	for _, f := range res.Flows {
		t, ok := parseSuriTime(f.Start)
		if !ok {
			continue
		}
		idx := int(t.Sub(mn).Seconds() / bucketSec)
		if idx < 0 {
			idx = 0
		}
		if idx >= n {
			idx = n - 1
		}
		buckets[idx].Bytes += f.Bytes
		buckets[idx].Packets += f.Pkts
		buckets[idx].Flows++
	}
	return &TimelineData{StartTS: mn.UTC().Format("2006-01-02 15:04:05"),
		DurationSec: int(span), BucketSec: int(bucketSec), Buckets: buckets}
}

// Conversation is one host-to-host relationship over the capture: who initiated,
// when it started/ended, how many flows, how many bytes, and over what protocols.
type Conversation struct {
	A         string   `json:"a"` // initiator (src)
	B         string   `json:"b"` // responder (dst)
	AInternal bool     `json:"a_internal"`
	FirstSeen string   `json:"first_seen,omitempty"`
	LastSeen  string   `json:"last_seen,omitempty"`
	Count     int      `json:"count"`
	Bytes     int64    `json:"bytes"`
	Protos    []string `json:"protos,omitempty"`
	Ports     []string `json:"ports,omitempty"`
}

// buildConversations aggregates the flows into host-to-host conversations (by
// src→dst), sorted by bytes. This is the "IP A talked to IP B, N times, from T1
// to T2, over these protocols/ports" view that feeds the auto summary and UI.
func buildConversations(res *NetworkResult) []Conversation {
	type agg struct {
		a, b         string
		aInternal    bool
		first, last  time.Time
		count        int
		bytes        int64
		protos, port map[string]bool
	}
	m := map[string]*agg{}
	for _, f := range res.Flows {
		if f.Src == "" || f.Dst == "" {
			continue
		}
		k := f.Src + "|" + f.Dst
		g := m[k]
		if g == nil {
			g = &agg{a: f.Src, b: f.Dst, aInternal: isPrivateIP(f.Src), protos: map[string]bool{}, port: map[string]bool{}}
			m[k] = g
		}
		g.count++
		g.bytes += f.Bytes
		if f.App != "" {
			g.protos[strings.ToLower(f.App)] = true
		} else if f.Proto != "" {
			g.protos[strings.ToLower(f.Proto)] = true
		}
		if f.Dport != 0 {
			g.port[strconv.Itoa(f.Dport)] = true
		}
		if t, ok := parseSuriTime(f.Start); ok && (g.first.IsZero() || t.Before(g.first)) {
			g.first = t
		}
		end := f.End
		if end == "" {
			end = f.Start
		}
		if t, ok := parseSuriTime(end); ok && t.After(g.last) {
			g.last = t
		}
	}
	out := make([]Conversation, 0, len(m))
	for _, g := range m {
		c := Conversation{A: g.a, B: g.b, AInternal: g.aInternal, Count: g.count, Bytes: g.bytes,
			Protos: sortedKeys(g.protos), Ports: sortedKeys(g.port)}
		if !g.first.IsZero() {
			c.FirstSeen = g.first.UTC().Format("2006-01-02 15:04:05")
		}
		if !g.last.IsZero() {
			c.LastSeen = g.last.UTC().Format("2006-01-02 15:04:05")
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}

// frontingFindings flags domain-fronting: the TLS SNI on the wire differs from
// the decrypted HTTP Host — a classic C2 / censorship-evasion technique.
func frontingFindings(res *NetworkResult) []NetworkFinding {
	var out []NetworkFinding
	for _, f := range res.DomainFront {
		out = append(out, NetworkFinding{Severity: "high", Category: "tls", Source: "domain-fronting",
			Title:     "Domain fronting: SNI ≠ Host",
			Detail:    fmt.Sprintf("TLS SNI %q but HTTP Host %q on %s→%s", sanitizeLine(f.SNI), sanitizeLine(f.Host), f.Src, f.Dst),
			Indicator: f.Dst})
	}
	return out
}

// zeekFindings turns high-signal Zeek output into findings: Zeek notices and TLS
// certificate-validation failures. These are contextual (medium/low) — they add
// depth without inflating the deterministic verdict.
func zeekFindings(res *NetworkResult) []NetworkFinding {
	if res.Zeek == nil {
		return nil
	}
	var out []NetworkFinding
	for i, n := range res.Zeek.Notices {
		if i >= 40 {
			break
		}
		sev := "low"
		lc := strings.ToLower(n.Note + " " + n.Msg)
		switch {
		case strings.Contains(lc, "malware") || strings.Contains(lc, "intel::") || strings.Contains(lc, "teamcymru"):
			sev = "high"
		case strings.Contains(lc, "scan") || strings.Contains(lc, "invalid_server_cert") || strings.Contains(lc, "certificate") || strings.Contains(lc, "bruteforce") || strings.Contains(lc, "password"):
			sev = "medium"
		}
		out = append(out, NetworkFinding{Severity: sev, Category: "zeek", Source: "zeek",
			Title: "Zeek notice: " + n.Note, Detail: sanitizeLine(n.Msg), Indicator: n.Dst})
	}
	seenTLS := map[string]bool{}
	for _, s := range res.Zeek.SSL {
		v := strings.ToLower(strings.TrimSpace(s.Validation))
		if v == "" || v == "ok" || seenTLS[s.Dst+v] {
			continue
		}
		seenTLS[s.Dst+v] = true
		out = append(out, NetworkFinding{Severity: "medium", Category: "tls", Source: "zeek",
			Title:  "TLS certificate not trusted: " + s.Validation,
			Detail: fmt.Sprintf("%s (%s) → %s", sanitizeLine(s.ServerName), s.Version, s.Dst), Indicator: s.Dst})
		if len(out) >= 80 {
			break
		}
	}
	return out
}

// saveCarved moves the files Suricata reconstructed from the wire into the
// Evidence Store (admin-download only, like the pcap itself) and returns a finding
// per carved file. Bytes never touch the DB; only the stored path is recorded.
func (e *Engine) saveCarved(scanID string, caseID *uuid.UUID, res *NetworkResult) []NetworkFinding {
	if e.store == nil || len(res.Carved) == 0 {
		return nil
	}
	nameBySha := map[string]string{}
	for _, f := range res.Files {
		if f.SHA256 != "" && f.Filename != "" {
			nameBySha[strings.ToLower(f.SHA256)] = f.Filename
		}
	}
	var out []NetworkFinding
	for _, cf := range res.Carved {
		data, err := base64.StdEncoding.DecodeString(cf.B64)
		if err != nil || len(data) == 0 {
			continue
		}
		name := nameBySha[strings.ToLower(cf.SHA256)]
		if name == "" {
			name = cf.SHA256 + ".bin"
		}
		rel, serr := e.store.SaveAnalysisUpload("network-carved/"+scanID, cf.SHA256+".bin", bytes.NewReader(data))
		if serr != nil {
			continue
		}
		// Dedupe on stored_path, then register in the Evidence Store.
		var existing int64
		e.db.Model(&models.CaseEvidence{}).Where("stored_path = ?", rel).Count(&existing)
		if existing == 0 {
			ev := models.CaseEvidence{CaseID: caseID, Kind: "carved-file", Source: "network-analysis",
				FileName: name, StoredPath: rel, Size: cf.Size, Sha256: cf.SHA256}
			e.db.Create(&ev)
		}
		// Propagate YARA matches onto the matching files-table entry for the UI.
		if len(cf.Yara) > 0 {
			for i := range res.Files {
				if strings.EqualFold(res.Files[i].SHA256, cf.SHA256) {
					res.Files[i].Yara = cf.Yara
				}
			}
			// A malware hit on a transferred file is a strong, high-severity signal.
			out = append(out, NetworkFinding{Severity: "high", Category: "malware-file", Source: "yara",
				Title:     "Malware in transferred file: " + sanitizeLine(name),
				Detail:    fmt.Sprintf("YARA match [%s] on a file reconstructed from the capture (sha256 %s)", strings.Join(cf.Yara, ", "), cf.SHA256),
				Indicator: cf.SHA256})
		}
		out = append(out, NetworkFinding{Severity: "info", Category: "carved", Source: "file-store",
			Title:     "File carved from capture: " + sanitizeLine(name),
			Detail:    fmt.Sprintf("%s bytes, sha256 %s — saved to Evidence Store (admin download)", humanBytes(cf.Size), cf.SHA256),
			Indicator: cf.SHA256})
	}
	return out
}

// ── small helpers ────────────────────────────────────────────────────────────

func parseSuriTime(s string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02T15:04:05.999999-0700", "2006-01-02T15:04:05.999999Z07:00", time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func meanCV(xs []float64) (mean, cv float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	sum := 0.0
	for _, x := range xs {
		sum += x
	}
	mean = sum / float64(len(xs))
	if mean == 0 {
		return 0, 0
	}
	varsum := 0.0
	for _, x := range xs {
		d := x - mean
		varsum += d * d
	}
	std := math.Sqrt(varsum / float64(len(xs)))
	return mean, std / mean
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(1<<10))
	default:
		return strconv.FormatInt(n, 10) + " B"
	}
}

func hasAnySuffix(s string, suf ...string) bool {
	for _, x := range suf {
		if strings.HasSuffix(s, x) {
			return true
		}
	}
	return false
}

// hostOf strips a ":port" suffix so an indicator is the bare host/IP.
func hostOf(s string) string {
	if i := strings.LastIndexByte(s, ':'); i > 0 && !strings.Contains(s[:i], ":") {
		return s[:i]
	}
	return s
}

func lowerAll(xs []string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = strings.ToLower(x)
	}
	return out
}

func orDash(s string) string {
	if s == "" {
		return "unknown source"
	}
	return s
}

func descSuffix(s string) string {
	if s == "" {
		return ""
	}
	return " — " + sanitizeLine(s)
}

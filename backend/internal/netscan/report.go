package netscan

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/analysishub/backend/internal/models"
)

// report.go — the capture analysis as a written report. A pcap answers a
// different question from a malware sample: not "what is this file" but "what
// happened on the wire, who talked to whom, and what do I block". So the report
// leads with the conversations and the infrastructure, then the detections, then
// the indicators an operator actually acts on.
//
// It produces Markdown; internal/report turns it into the same self-contained,
// bilingual HTML document the malware reports use.

// ReportOptions parameterise one rendering.
type ReportOptions struct {
	Lang    string // "en" (default) | "vi"
	TLP     string
	Analyst string
	CaseRef string
}

// t is the two-string localiser for report chrome.
func t(vi bool, viText, enText string) string {
	if vi {
		return viText
	}
	return enText
}

// NetIOC is one normalised indicator from a capture.
type NetIOC struct {
	Type       string `json:"type"`  // ip | domain | url | ja3 | ja3s | sha256 | user-agent
	Value      string `json:"value"`
	Context    string `json:"context,omitempty"`
	Confidence string `json:"confidence,omitempty"` // high | medium | low
}

// CollectIOCs turns the capture into the block list. Provenance decides
// confidence: an address a signature or reputation source flagged is high; a
// domain merely observed in DNS is low — a responder must not block their own
// CDN because it appeared in the capture.
func CollectIOCs(scan *models.NetworkScan, res *NetworkResult, findings []NetworkFinding) []NetIOC {
	var out []NetIOC
	seen := map[string]bool{}
	add := func(typ, val, ctx, conf string) {
		val = strings.TrimSpace(val)
		if val == "" || len(val) > 2048 {
			return
		}
		key := typ + "|" + strings.ToLower(val)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, NetIOC{Type: typ, Value: val, Context: ctx, Confidence: conf})
	}

	// Findings first: these are the ones something actually flagged.
	for _, f := range findings {
		if f.Indicator == "" {
			continue
		}
		conf := "medium"
		if f.Severity == "critical" || f.Severity == "high" {
			conf = "high"
		}
		ctx := f.Category + ": " + f.Title
		// An internal address in a finding is a host to investigate, not something to
		// block — say so, because this table is read as a block list.
		if isInternalIP(f.Indicator) {
			ctx += " (internal host — investigate, do not block)"
		}
		add(iocKind(f.Indicator), f.Indicator, ctx, conf)
	}
	// Alert endpoints are flagged infrastructure too.
	for _, a := range res.Alerts {
		conf := "medium"
		if a.Severity <= 1 {
			conf = "high"
		}
		add("ip", a.Dst, "Suricata: "+a.Signature, conf)
	}
	// Carved/transferred files: a hash is the cheapest thing to hunt on.
	for _, f := range res.Files {
		ctx := t(false, "", "") + "file transferred over the network"
		if len(f.Yara) > 0 {
			add("sha256", f.SHA256, "file transferred, YARA: "+strings.Join(f.Yara, ", "), "high")
			continue
		}
		add("sha256", f.SHA256, ctx, "medium")
	}
	// Everything else is observation, not detection.
	for _, ip := range res.IOCs.IPs {
		// Never list an internal address as an indicator to block: this table ends up
		// in a firewall, and blocking the site's own DNS server or gateway because it
		// appeared in the capture would be an outage caused by the report.
		if isInternalIP(ip) {
			continue
		}
		add("ip", ip, "external address contacted", "low")
	}
	for _, d := range res.IOCs.Domains {
		add("domain", d, "domain resolved/requested", "low")
	}
	for _, h := range res.HTTP {
		if h.Host != "" {
			add("domain", h.Host, "HTTP Host header", "low")
		}
		if h.UA != "" && looksOddUA(h.UA) {
			add("user-agent", h.UA, "unusual HTTP User-Agent", "medium")
		}
	}
	for _, tl := range res.TLS {
		if tl.JA3 != "" {
			add("ja3", tl.JA3, "TLS client fingerprint"+sniSuffix(tl.SNI), "medium")
		}
		if tl.SNI != "" {
			add("domain", tl.SNI, "TLS SNI", "low")
		}
	}
	for _, df := range res.DomainFront {
		add("domain", df.Host, "domain fronting: SNI "+df.SNI+" ≠ Host "+df.Host, "high")
	}

	rank := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].Confidence] < rank[out[j].Confidence] })
	if len(out) > 400 {
		out = out[:400]
	}
	return out
}

// isInternalIP reports whether an address belongs to the estate rather than to
// the internet: RFC1918, CGNAT, loopback, link-local and IPv6 unique-local.
func isInternalIP(ip string) bool {
	p := net.ParseIP(strings.TrimSpace(ip))
	if p == nil {
		return false
	}
	if p.IsLoopback() || p.IsLinkLocalUnicast() || p.IsLinkLocalMulticast() || p.IsUnspecified() {
		return true
	}
	if v4 := p.To4(); v4 != nil {
		switch {
		case v4[0] == 10:
			return true
		case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
			return true
		case v4[0] == 192 && v4[1] == 168:
			return true
		case v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127: // CGNAT
			return true
		}
		return false
	}
	return len(p) == net.IPv6len && p[0]&0xfe == 0xfc // fc00::/7 unique-local
}

func sniSuffix(sni string) string {
	if sni == "" {
		return ""
	}
	return " (SNI " + sni + ")"
}

// looksOddUA flags the User-Agent strings that are worth an indicator: empty-ish,
// scripted clients, or a bare tool name. A normal browser UA is noise.
func looksOddUA(ua string) bool {
	low := strings.ToLower(ua)
	if len(ua) < 12 {
		return true
	}
	for _, s := range []string{"python", "curl", "wget", "powershell", "go-http", "java/", "libwww", "winhttp", "urllib", "axios", "okhttp"} {
		if strings.Contains(low, s) {
			return true
		}
	}
	return false
}

func iocKind(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	switch {
	case strings.Contains(s, "://"):
		return "url"
	case strings.Count(s, ".") == 3 && strings.IndexFunc(s, func(r rune) bool {
		return r != '.' && (r < '0' || r > '9')
	}) < 0:
		return "ip"
	case len(s) == 32 && !strings.Contains(s, "."):
		return "ja3"
	case len(s) == 64 && !strings.Contains(s, "."):
		return "sha256"
	case strings.Contains(s, "."):
		return "domain"
	}
	return "indicator"
}

// severityRank orders findings worst-first.
var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

// BuildReport renders the capture analysis as Markdown in one language.
func BuildReport(scan *models.NetworkScan, res *NetworkResult, findings []NetworkFinding, opt ReportOptions) string {
	vi := opt.Lang == "vi"
	var b strings.Builder
	// Sections are numbered as they are written: an optional one that has no data
	// is skipped entirely, and a report that jumps from 6 to 9 reads like a bug.
	sec := 0
	h2 := func(viTitle, enTitle string) {
		sec++
		fmt.Fprintf(&b, "## %d. %s\n\n", sec, t(vi, viTitle, enTitle))
	}

	if vi {
		b.WriteString("# BÁO CÁO PHÂN TÍCH LƯU LƯỢNG MẠNG\n\n")
	} else {
		b.WriteString("# NETWORK TRAFFIC ANALYSIS REPORT\n\n")
	}

	// ── 1. Executive summary ──────────────────────────────────────────────────
	h2("Tóm tắt điều hành", "Executive summary")
	fmt.Fprintf(&b, "**%s:** %s · **%s:** %d/100 · %d %s · %d %s · %d %s\n\n",
		t(vi, "Kết luận", "Verdict"), strings.ToUpper(scan.Verdict),
		t(vi, "Điểm nguy hại", "Threat score"), scan.ThreatScore,
		scan.FlowCount, t(vi, "luồng", "flows"),
		scan.AlertCount, t(vi, "cảnh báo", "alerts"),
		scan.C2Count, t(vi, "kết nối C2/độc hại", "C2/malicious connections"))

	if scan.AutoSummary != "" {
		kind := t(vi, "mô tả tự động", "auto-generated narrative")
		if scan.AutoSummaryKind == "ai" {
			kind = t(vi, "mô tả do AI viết", "AI-written narrative")
		}
		fmt.Fprintf(&b, "**%s** (%s)\n\n%s\n\n", t(vi, "Diễn giải", "Narrative"), kind, scan.AutoSummary)
	} else if scan.Summary != "" {
		b.WriteString(scan.Summary + "\n\n")
	}

	// The AI stage has its own opinion; it is shown, never silently merged.
	var ai NetVerdict
	hasAI := scan.NetworkAI != "" && json.Unmarshal([]byte(scan.NetworkAI), &ai) == nil && ai.Verdict != ""
	if hasAI {
		fmt.Fprintf(&b, "**%s:** %s (%d%%)%s\n\n", t(vi, "Kết luận của AI", "AI verdict"),
			strings.ToUpper(ai.Verdict), ai.Confidence,
			map[bool]string{true: " · " + ai.Family, false: ""}[ai.Family != ""])
		if ai.BehaviorSummary != "" {
			b.WriteString(ai.BehaviorSummary + "\n\n")
		}
		if ai.SignalAgreement != "" {
			b.WriteString("> " + ai.SignalAgreement + "\n\n")
		}
		writeBullets(&b, t(vi, "Chỉ dấu chính", "Key indicators"), ai.KeyIndicators)
		writeBullets(&b, t(vi, "Phát hiện độc lập của AI (Suricata không gắn cờ)",
			"Independent AI findings (not flagged by Suricata)"), ai.IndependentFindings)
	}

	// ── 2. Capture identification ─────────────────────────────────────────────
	h2("Định danh bản ghi & chuỗi bảo quản", "Capture identification & chain of custody")
	b.WriteString("| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| %s | `%s` |\n", t(vi, "Tệp", "File"), mdEsc(scan.FileName))
	if scan.Sha256 != "" {
		fmt.Fprintf(&b, "| SHA256 | `%s` |\n", scan.Sha256)
	}
	fmt.Fprintf(&b, "| %s | %d bytes |\n", t(vi, "Kích thước", "Size"), scan.Size)
	fmt.Fprintf(&b, "| %s | %s |\n", t(vi, "Tiếp nhận", "Received"), scan.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"))
	if scan.FinishedAt != nil {
		fmt.Fprintf(&b, "| %s | %s |\n", t(vi, "Hoàn tất phân tích", "Analysis completed"), scan.FinishedAt.UTC().Format("2006-01-02 15:04 UTC"))
	}
	if tl := res.Timeline; tl != nil && tl.StartTS != "" {
		fmt.Fprintf(&b, "| %s | %s (+%ds) |\n", t(vi, "Khoảng thời gian bắt", "Capture window"), tl.StartTS, tl.DurationSec)
	}
	if scan.CaseID != nil {
		fmt.Fprintf(&b, "| %s | %s |\n", t(vi, "Mã vụ việc", "Case"), scan.CaseID.String())
	}
	b.WriteString("\n")

	// ── 3. Traffic overview ───────────────────────────────────────────────────
	h2("Tổng quan lưu lượng", "Traffic overview")
	if len(res.Stats) > 0 {
		keys := make([]string, 0, len(res.Stats))
		for k := range res.Stats {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s: %d", k, res.Stats[k]))
		}
		b.WriteString(strings.Join(parts, " · ") + "\n\n")
	}
	if len(res.Protocols) > 0 {
		fmt.Fprintf(&b, "**%s**\n\n| %s | %s | %s |\n|---|---|---|\n",
			t(vi, "Phân tầng giao thức", "Protocol hierarchy"), t(vi, "Giao thức", "Protocol"),
			t(vi, "Gói tin", "Frames"), "Bytes")
		for _, p := range capProtos(res.Protocols, 15) {
			fmt.Fprintf(&b, "| %s%s | %d | %d |\n", strings.Repeat("· ", p.Level), mdEsc(p.Name), p.Frames, p.Bytes)
		}
		b.WriteString("\n")
	}

	// ── 4. Conversations ──────────────────────────────────────────────────────
	if len(res.Conversations) > 0 {
		h2("Các phiên trao đổi", "Conversations")
		fmt.Fprintf(&b, "| %s | %s | %s | Bytes | %s | %s |\n|---|---|---|---|---|---|\n",
			t(vi, "Bên khởi tạo → Bên nhận", "Initiator → Responder"), "Geo / ASN",
			t(vi, "Số lần", "Times"), t(vi, "Giao thức", "Protocols"), t(vi, "Từ → Đến (UTC)", "First → Last (UTC)"))
		for _, c := range capConvs(res.Conversations, 30) {
			geo := ""
			if g, ok := res.Geo[c.B]; ok {
				geo = strings.TrimSpace(g.CC + " AS" + g.ASN + " " + g.Org)
			}
			window := c.FirstSeen
			if c.LastSeen != "" {
				window += " → " + c.LastSeen
			}
			fmt.Fprintf(&b, "| `%s → %s` | %s | %d | %d | %s | %s |\n",
				c.A, c.B, mdEsc(geo), c.Count, c.Bytes, strings.Join(c.Protos, " "), mdEsc(window))
		}
		b.WriteString("\n")
	}

	// ── 5. Findings ───────────────────────────────────────────────────────────
	h2("Phát hiện", "Findings")
	if len(findings) == 0 {
		b.WriteString(t(vi, "_Không có phát hiện nào._\n\n", "_No findings._\n\n"))
	} else {
		sorted := append([]NetworkFinding{}, findings...)
		sort.SliceStable(sorted, func(i, j int) bool {
			return severityRank[sorted[i].Severity] < severityRank[sorted[j].Severity]
		})
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n|---|---|---|---|\n",
			t(vi, "Mức", "Severity"), t(vi, "Nhóm", "Category"), t(vi, "Tiêu đề", "Title"), t(vi, "Chi tiết", "Detail"))
		for _, f := range capFindings(sorted, 60) {
			fmt.Fprintf(&b, "| **%s** | %s | %s | %s |\n", strings.ToUpper(f.Severity), f.Category, mdEsc(f.Title), mdEsc(f.Detail))
		}
		b.WriteString("\n")
	}
	if len(res.Alerts) > 0 {
		fmt.Fprintf(&b, "**%s (%d)**\n\n| SID | %s | %s | %s |\n|---|---|---|---|\n",
			t(vi, "Cảnh báo Suricata", "Suricata alerts"), len(res.Alerts),
			t(vi, "Chữ ký", "Signature"), t(vi, "Nhóm", "Category"), t(vi, "Nguồn → Đích", "Src → Dst"))
		for _, a := range capAlerts(res.Alerts, 40) {
			fmt.Fprintf(&b, "| %d | %s | %s | `%s → %s:%d` |\n", a.SID, mdEsc(a.Signature), mdEsc(a.Category), a.Src, a.Dst, a.Dport)
		}
		b.WriteString("\n")
	}

	// ── 6. Protocol detail (DNS / TLS / HTTP) ─────────────────────────────────
	h2("Chi tiết giao thức", "Protocol detail")
	if len(res.DNS) > 0 {
		fmt.Fprintf(&b, "**DNS (%d)**\n\n| %s | %s | Rcode | %s |\n|---|---|---|---|\n",
			len(res.DNS), t(vi, "Truy vấn", "Query"), t(vi, "Kiểu", "Type"), t(vi, "Trả lời", "Answers"))
		for _, d := range capDNS(res.DNS, 30) {
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", mdEsc(d.Query), d.Type, d.Rcode, mdEsc(strings.Join(capStrings(d.Answers, 4), ", ")))
		}
		b.WriteString("\n")
	}
	if len(res.TLS) > 0 {
		fmt.Fprintf(&b, "**TLS (%d)**\n\n| SNI | %s | JA3 | %s |\n|---|---|---|---|\n",
			len(res.TLS), t(vi, "Phiên bản", "Version"), t(vi, "Đích", "Destination"))
		for _, s := range capTLS(res.TLS, 30) {
			fmt.Fprintf(&b, "| `%s` | %s | `%s` | %s |\n", mdEsc(s.SNI), s.Version, s.JA3, s.Dst)
		}
		b.WriteString("\n")
	}
	if len(res.HTTP) > 0 || len(res.DecryptedHTTP) > 0 {
		all := append(append([]HTTPRec{}, res.HTTP...), res.DecryptedHTTP...)
		fmt.Fprintf(&b, "**HTTP (%d%s)**\n\n| %s | Host | URL | UA | %s |\n|---|---|---|---|---|\n",
			len(all), map[bool]string{true: t(vi, ", gồm cả phần giải mã TLS", ", incl. TLS-decrypted"), false: ""}[len(res.DecryptedHTTP) > 0],
			t(vi, "Phương thức", "Method"), t(vi, "Mã", "Status"))
		for _, h := range capHTTP(all, 30) {
			fmt.Fprintf(&b, "| %s | `%s` | `%s` | %s | %d |\n", h.Method, mdEsc(h.Host), mdEsc(capText(h.URL, 120)), mdEsc(capText(h.UA, 60)), h.Status)
		}
		b.WriteString("\n")
	}
	if len(res.DomainFront) > 0 {
		fmt.Fprintf(&b, "**%s**\n\n", t(vi, "Domain fronting (SNI khác Host — che giấu đích thật)",
			"Domain fronting (SNI ≠ Host — the real destination is hidden)"))
		for _, d := range res.DomainFront {
			fmt.Fprintf(&b, "- SNI `%s` ≠ Host `%s` (%s → %s)\n", mdEsc(d.SNI), mdEsc(d.Host), d.Src, d.Dst)
		}
		b.WriteString("\n")
	}
	if z := res.Zeek; z != nil {
		writeZeek(&b, z, vi)
	}

	// ── 7. Files transferred ──────────────────────────────────────────────────
	if len(res.Files) > 0 {
		h2("Tệp truyền qua mạng", "Files transferred")
		fmt.Fprintf(&b, "| %s | %s | %s | SHA256 | YARA |\n|---|---|---|---|---|\n",
			t(vi, "Tên tệp", "Filename"), t(vi, "Định dạng", "Type"), t(vi, "Kích thước", "Size"))
		for _, f := range capFiles(res.Files, 40) {
			fmt.Fprintf(&b, "| %s | %s | %d | `%s` | %s |\n", mdEsc(f.Filename), mdEsc(f.Magic), f.Size,
				shortHash(f.SHA256), mdEsc(strings.Join(f.Yara, ", ")))
		}
		b.WriteString("\n")
		b.WriteString(t(vi,
			"_Tệp tái dựng từ luồng mạng có thể đưa thẳng sang phân tích mã độc để có kết luận riêng._\n\n",
			"_Files reconstructed from the traffic can be pushed straight into malware analysis for their own verdict._\n\n"))
	}

	// ── 8. ATT&CK ─────────────────────────────────────────────────────────────
	if hasAI && len(ai.ATTCK) > 0 {
		h2("Ánh xạ MITRE ATT&CK", "MITRE ATT&CK mapping")
		b.WriteString("`" + strings.Join(ai.ATTCK, "`, `") + "`\n\n")
	}

	// ── 9. IOCs ───────────────────────────────────────────────────────────────
	iocs := CollectIOCs(scan, res, findings)
	h2("Chỉ số xâm nhập (IOC)", "Indicators of compromise")
	if len(iocs) == 0 {
		b.WriteString(t(vi, "_Không có chỉ số nào._\n\n", "_No indicators._\n\n"))
	} else {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n|---|---|---|---|\n",
			t(vi, "Loại", "Type"), t(vi, "Giá trị", "Value"), t(vi, "Ngữ cảnh", "Context"), t(vi, "Tin cậy", "Confidence"))
		for _, i := range capIOCs(iocs, 150) {
			fmt.Fprintf(&b, "| %s | `%s` | %s | %s |\n", i.Type, mdEsc(i.Value), mdEsc(i.Context), i.Confidence)
		}
		b.WriteString("\n")
		b.WriteString(t(vi,
			"_Chỉ chặn các chỉ số mức **high/medium**: mục \"low\" chỉ là quan sát (có thể là hạ tầng hợp lệ của chính bạn)._\n\n",
			"_Block the **high/medium** rows only: \"low\" entries are observations and may be your own legitimate infrastructure._\n\n"))
	}

	// ── 10. Detection ─────────────────────────────────────────────────────────
	h2("Quy tắc phát hiện", "Detection rules")
	rules := BuildSuricataRules(scan, iocs)
	b.WriteString("```\n" + rules + "```\n\n")

	// ── 11. Impact & response ─────────────────────────────────────────────────
	h2("Ảnh hưởng & xử lý", "Impact & response")
	writeImpact(&b, vi, scan, res, findings)
	if hasAI {
		writeBullets(&b, t(vi, "Khuyến nghị của AI", "AI recommendations"), ai.Recommendations)
	}

	// ── 12. Appendix ──────────────────────────────────────────────────────────
	h2("Phụ lục", "Appendix")
	b.WriteString("- " + t(vi, "Công cụ: Suricata (chế độ offline) + Zeek + tshark, phát hiện hành vi trong AnalysisHub",
		"Tooling: Suricata (offline mode) + Zeek + tshark, plus AnalysisHub behavioural detection") + "\n")
	if scan.AutoSummaryKind == "ai" || hasAI {
		b.WriteString("- " + t(vi, "Có sử dụng AI cho phần diễn giải/nhận định (được nêu rõ ở mục tương ứng)",
			"AI was used for narrative/assessment (marked where it applies)") + "\n")
	}
	for _, l := range analysisLimits(vi, scan, res) {
		b.WriteString("- " + l + "\n")
	}
	fmt.Fprintf(&b, "- %s: %s\n\n", t(vi, "Thời điểm lập báo cáo", "Report generated"),
		time.Now().UTC().Format("2006-01-02 15:04 UTC"))
	return b.String()
}

// writeZeek adds the deep-protocol observations Zeek contributes (auth, SMB, SSH)
// — the ones that turn "traffic" into "someone authenticated as X".
func writeZeek(b *strings.Builder, z *ZeekResult, vi bool) {
	if len(z.Notices) > 0 {
		fmt.Fprintf(b, "**%s (%d)**\n\n", t(vi, "Cảnh báo Zeek", "Zeek notices"), len(z.Notices))
		for _, n := range z.Notices {
			fmt.Fprintf(b, "- `%s` %s %s\n", mdEsc(n.Note), mdEsc(n.Msg), mdEsc(n.Sub))
		}
		b.WriteString("\n")
	}
	if len(z.NTLM) > 0 || len(z.Kerberos) > 0 {
		fmt.Fprintf(b, "**%s**\n\n", t(vi, "Xác thực quan sát được", "Observed authentication"))
		for _, n := range z.NTLM {
			fmt.Fprintf(b, "- NTLM: `%s\\%s` from %s → %s (host %s)\n", mdEsc(n.Domain), mdEsc(n.User), n.Src, n.Dst, mdEsc(n.Host))
		}
		for _, k := range z.Kerberos {
			ok := "?"
			if k.Success != nil {
				ok = fmt.Sprintf("%v", *k.Success)
			}
			fmt.Fprintf(b, "- Kerberos: `%s` → `%s` success=%s (%s → %s)\n", mdEsc(k.Client), mdEsc(k.Service), ok, k.Src, k.Dst)
		}
		b.WriteString("\n")
	}
	if len(z.SMB) > 0 {
		fmt.Fprintf(b, "**SMB (%d)**\n\n", len(z.SMB))
		for _, s := range z.SMB {
			fmt.Fprintf(b, "- %s `%s` %s (%s → %s)\n", mdEsc(s.Action), mdEsc(s.Path), mdEsc(s.Name), s.Src, s.Dst)
		}
		b.WriteString("\n")
	}
	if len(z.SSH) > 0 {
		fmt.Fprintf(b, "**SSH (%d)**\n\n", len(z.SSH))
		for _, s := range z.SSH {
			ok := "?"
			if s.Success != nil {
				ok = fmt.Sprintf("%v", *s.Success)
			}
			fmt.Fprintf(b, "- %s → %s success=%s (client `%s`, server `%s`)\n", s.Src, s.Dst, ok, mdEsc(s.Client), mdEsc(s.Server))
		}
		b.WriteString("\n")
	}
}

// BuildSuricataRules emits IDS rules for the infrastructure the capture exposed.
// Low-confidence observations are deliberately skipped: a rule per observed
// domain would drown the sensor and get the whole rule set switched off.
func BuildSuricataRules(scan *models.NetworkScan, iocs []NetIOC) string {
	var b strings.Builder
	label := "AnalysisHub capture " + baseName(scan.FileName)
	fmt.Fprintf(&b, "# Suricata rules generated by AnalysisHub for %s\n", baseName(scan.FileName))
	fmt.Fprintf(&b, "# Verdict: %s | Generated: %s\n\n", scan.Verdict, time.Now().UTC().Format(time.RFC3339))
	sid := 9100000
	esc := func(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, `"`, ""), ";", "") }
	for _, i := range iocs {
		if i.Confidence == "low" {
			continue
		}
		switch i.Type {
		case "domain":
			fmt.Fprintf(&b, `alert dns $HOME_NET any -> any any (msg:"%s DNS lookup %s"; dns.query; content:"%s"; nocase; sid:%d; rev:1;)`+"\n",
				esc(label), esc(i.Value), esc(i.Value), sid)
			sid++
		case "ip":
			fmt.Fprintf(&b, `alert ip $HOME_NET any -> %s any (msg:"%s traffic to %s"; sid:%d; rev:1;)`+"\n",
				esc(i.Value), esc(label), esc(i.Value), sid)
			sid++
		case "ja3":
			fmt.Fprintf(&b, `alert tls $HOME_NET any -> any any (msg:"%s JA3 %s"; ja3.hash; content:"%s"; sid:%d; rev:1;)`+"\n",
				esc(label), esc(i.Value), esc(i.Value), sid)
			sid++
		case "user-agent":
			fmt.Fprintf(&b, `alert http $HOME_NET any -> any any (msg:"%s User-Agent %s"; http.user_agent; content:"%s"; sid:%d; rev:1;)`+"\n",
				esc(label), esc(capText(i.Value, 40)), esc(i.Value), sid)
			sid++
		}
	}
	if sid == 9100000 {
		b.WriteString("# (no medium/high-confidence network indicators were produced by this capture)\n")
	}
	return b.String()
}

// writeImpact states what the capture means for the estate and what to do next.
func writeImpact(b *strings.Builder, vi bool, scan *models.NetworkScan, res *NetworkResult, findings []NetworkFinding) {
	var lines []string
	switch scan.Verdict {
	case "malicious":
		lines = append(lines, t(vi,
			"Bản ghi cho thấy lưu lượng **độc hại**. Các máy nội bộ xuất hiện trong phần phát hiện phải được coi là đã bị xâm nhập cho tới khi chứng minh ngược lại.",
			"The capture contains **malicious** traffic. Internal hosts appearing in the findings must be treated as compromised until proven otherwise."))
	case "suspicious":
		lines = append(lines, t(vi,
			"Có lưu lượng **đáng ngờ** nhưng chưa đủ kết luận — cần đối chiếu với log endpoint/EDR của các máy liên quan.",
			"The capture contains **suspicious** traffic but is not conclusive — correlate with endpoint/EDR logs for the hosts involved."))
	case "benign":
		lines = append(lines, t(vi,
			"Không phát hiện lưu lượng độc hại trong phạm vi bản ghi này.",
			"No malicious traffic was identified within this capture."))
	default:
		lines = append(lines, t(vi,
			"Chưa đủ căn cứ kết luận từ bản ghi này — xem phần giới hạn ở phụ lục.",
			"Inconclusive from this capture — see the limitations in the appendix."))
	}
	c2 := 0
	exfil := false
	for _, f := range findings {
		if f.Category == "c2" {
			c2++
		}
		if f.Category == "exfil" {
			exfil = true
		}
	}
	if c2 > 0 {
		lines = append(lines, fmt.Sprintf(t(vi,
			"Có %d kết nối mang đặc trưng C2: cách ly máy nguồn, chặn hạ tầng ở mục 9 và truy vết theo quy tắc ở mục 10.",
			"%d connection(s) show C2 characteristics: isolate the source host, block the infrastructure in section 9 and hunt with the rules in section 10."), c2))
	}
	if exfil {
		lines = append(lines, t(vi,
			"Có dấu hiệu **rò rỉ dữ liệu ra ngoài**: xác định dữ liệu nào đã rời mạng và mở quy trình thông báo vi phạm nếu cần.",
			"There are signs of **data leaving the network**: determine what was exfiltrated and start the breach-notification process if required."))
	}
	if len(res.Files) > 0 {
		lines = append(lines, fmt.Sprintf(t(vi,
			"%d tệp được truyền qua mạng đã được tái dựng — đưa từng tệp qua phân tích mã độc và truy quét hash trên toàn hệ thống.",
			"%d file(s) transferred over the network were reconstructed — run each through malware analysis and sweep the estate by hash."), len(res.Files)))
	}
	lines = append(lines, t(vi,
		"Chặn các chỉ số mức high/medium ở mục 9 tại firewall/proxy/DNS, nạp quy tắc ở mục 10 vào IDS/EDR.",
		"Block the high/medium indicators from section 9 at the firewall/proxy/DNS layer and load the section 10 rules into the IDS/EDR."))
	for _, l := range lines {
		b.WriteString("- " + l + "\n")
	}
	b.WriteString("\n")
}

func analysisLimits(vi bool, scan *models.NetworkScan, res *NetworkResult) []string {
	var out []string
	encrypted := 0
	for range res.TLS {
		encrypted++
	}
	if encrypted > 0 && len(res.DecryptedHTTP) == 0 {
		out = append(out, fmt.Sprintf(t(vi,
			"%d phiên TLS không giải mã được (không có keylog) — nội dung của chúng nằm ngoài phạm vi phân tích.",
			"%d TLS session(s) could not be decrypted (no keylog supplied) — their content is outside the scope of this analysis."), encrypted))
	}
	if scan.NetworkAIStatus != "done" {
		out = append(out, t(vi,
			"Chưa chạy phân tích AI cho bản ghi này; kết luận dựa trên engine xác định (chữ ký + hành vi).",
			"No AI analysis was run for this capture; the verdict rests on the deterministic engine (signatures + behaviour)."))
	}
	if res.Error != "" {
		out = append(out, t(vi, "Sidecar báo lỗi một phần: ", "The sidecar reported a partial error: ")+mdEsc(res.Error))
	}
	if len(out) == 0 {
		out = append(out, t(vi, "Không có giới hạn đáng kể.", "No material limitations."))
	}
	return out
}

// ── small helpers ─────────────────────────────────────────────────────────────

func writeBullets(b *strings.Builder, title string, items []string) {
	var kept []string
	seen := map[string]bool{}
	for _, s := range items {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		kept = append(kept, s)
	}
	if len(kept) == 0 {
		return
	}
	fmt.Fprintf(b, "**%s**\n\n", title)
	for _, s := range capStrings(kept, 40) {
		b.WriteString("- " + s + "\n")
	}
	b.WriteString("\n")
}

// mdEsc neutralises pipes/newlines so a value cannot break a Markdown table.
func mdEsc(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return s
}

func capText(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func shortHash(h string) string {
	if len(h) > 16 {
		return h[:16] + "…"
	}
	return h
}

func baseName(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func capStrings(in []string, n int) []string {
	if len(in) > n {
		return in[:n]
	}
	return in
}
func capProtos(in []ProtoStat, n int) []ProtoStat {
	if len(in) > n {
		return in[:n]
	}
	return in
}
func capConvs(in []Conversation, n int) []Conversation {
	if len(in) > n {
		return in[:n]
	}
	return in
}
func capFindings(in []NetworkFinding, n int) []NetworkFinding {
	if len(in) > n {
		return in[:n]
	}
	return in
}
func capAlerts(in []Alert, n int) []Alert {
	if len(in) > n {
		return in[:n]
	}
	return in
}
func capDNS(in []DNSRec, n int) []DNSRec {
	if len(in) > n {
		return in[:n]
	}
	return in
}
func capTLS(in []TLSRec, n int) []TLSRec {
	if len(in) > n {
		return in[:n]
	}
	return in
}
func capHTTP(in []HTTPRec, n int) []HTTPRec {
	if len(in) > n {
		return in[:n]
	}
	return in
}
func capFiles(in []FileRec, n int) []FileRec {
	if len(in) > n {
		return in[:n]
	}
	return in
}
func capIOCs(in []NetIOC, n int) []NetIOC {
	if len(in) > n {
		return in[:n]
	}
	return in
}

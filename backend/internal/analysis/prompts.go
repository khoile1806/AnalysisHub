// Package analysis centralizes the AI-orchestration logic shared by the
// forensic AI features (DFIR analysis, timeline extraction, compliance
// assessment): prompt templates, the evidence/context pipeline, and the
// inference seam. Handlers stay thin — they bind the request, call this
// package, and render the result.
package analysis

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// PromptVersion tags the prompt templates. Bump it when wording changes so a
// stored result can be traced back to the template that produced it.
const PromptVersion = "2026-06-20"

// EnvIntKB reads a positive integer (in KB) from an environment variable,
// falling back to def when unset or invalid. Used for content budgeting.
func EnvIntKB(name string, def int) int {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// ── DFIR analysis ─────────────────────────────────────────────────────────────

var dfirSourceLabels = map[string]string{
	"job":            "kết quả chạy tool",
	"checklist_run":  "kết quả thu thập bằng chứng (Evidence Checklist)",
	"elk_result":     "kết quả ELK Threat Hunt",
	"upload":         "file upload từ bên ngoài",
	"offline_report": "báo cáo forensic hunting offline (chạy trên endpoint không có mạng)",
}

// BuildDFIRPrompt constructs the comprehensive forensic analysis prompt.
// enrichSummary is an optional threat-intel block injected between the raw
// content and the analysis instructions; pass "" to omit it. Content budgeting
// is the pipeline's responsibility — pass already-capped content here, and set
// truncated when it was shortened.
// buildUserActivityPrompt frames a user's audit trail as an accountability
// briefing in Vietnamese, grounded strictly in the recorded actions. The output
// is a flowing narrative — when did they log in, what did they do and how many
// times, what data did they take — not a malware verdict.
func buildUserActivityPrompt(content string, truncated bool) string {
	truncateNote := ""
	if truncated {
		truncateNote = "\n\n⚠️ *Nhật ký đã bị cắt bớt do giới hạn token — chỉ phần gần nhất được phân tích.*"
	}
	return fmt.Sprintf(`Bạn là trợ lý bảo mật và tuân thủ cho một nền tảng DFIR. Một quản trị viên đang xem lại hoạt động của một người dùng để trả lời câu hỏi trách nhiệm: "người này đã làm những gì trên hệ thống".

Dưới đây là NHẬT KÝ HOẠT ĐỘNG của người dùng đó, mỗi dòng một hành động (thời gian UTC, tên hành động, agent đích, tài nguyên, chi tiết, IP nguồn). Đây là NGUỒN SỰ THẬT DUY NHẤT — tuyệt đối không bịa, không suy diễn, không thêm bất cứ điều gì không có trong nhật ký.%s

%s

---

Hãy viết một bản mô tả bằng TIẾNG VIỆT, dạng văn xuôi mạch lạc dễ đọc (dùng Markdown), theo cấu trúc sau:

## Tổng quan
Một đoạn văn 3-5 câu: người dùng này đăng nhập lần đầu lúc mấy giờ, hoạt động trong khoảng thời gian nào, và nhìn chung đã làm gì. Nêu tổng số hành động.

## Diễn biến hoạt động
Thuật lại theo trình tự thời gian những gì người dùng đã làm, nhóm các hành động lặp lại và **nêu rõ số lần** (ví dụ: "chạy quét YARA trên agent linux-test 3 lần", "thu thập 5 file bằng chứng từ velociraptor"). Nêu đích danh tên agent và tên tính năng.

## Dữ liệu đã truy cập / lấy đi
Liệt kê cụ thể: đã đụng tới máy agent nào, đã xem/duyệt file gì, đã thu thập hoặc **tải bằng chứng nào ra khỏi hệ thống** (kèm hash nếu có trong nhật ký). Đây là phần quan trọng nhất cho trách nhiệm dữ liệu.

## Điểm cần lưu ý
Những gì người soát an toàn dữ liệu nên kiểm tra kỹ: bằng chứng tải về máy cá nhân, thao tác xóa, thay đổi cấu hình/thông tin xác thực, truy cập nhiều máy. Nếu không có gì bất thường, hãy nói thẳng — KHÔNG được tạo ra mối lo không có thật.

Yêu cầu: trình bày chính xác, trích đúng tên agent và số lượng từ nhật ký. Không đưa vào hành động không có trong nhật ký.`, truncateNote, content)
}

func BuildDFIRPrompt(sourceType, content, enrichSummary string, truncated bool) string {
	// A user-activity trail is an accountability review, not a malware analysis,
	// so it gets its own prompt rather than the threat-hunting structure below.
	if sourceType == "user_activity" {
		return buildUserActivityPrompt(content, truncated)
	}

	sourceLabel := dfirSourceLabels[sourceType]
	if sourceLabel == "" {
		sourceLabel = "dữ liệu forensic"
	}

	truncateNote := ""
	if truncated {
		truncateNote = "\n\n⚠️ *Nội dung đã được cắt bớt do giới hạn token của API. Chỉ phần đầu được phân tích.*"
	}

	enrichSection := ""
	iocInstruction := "Liệt kê các IOC được phát hiện (IP, domain, hash, path, v.v.) nếu có."
	enrichInstruction := ""
	if enrichSummary != "" {
		enrichSection = "\n\n---\n\n" + enrichSummary
		iocInstruction = `Dựa trên kết quả Threat Intelligence ở trên, liệt kê từng IOC kèm đánh giá:
- Với mỗi IOC: ghi rõ giá trị, loại (IP/hash/domain), điểm reputation và verdict (MALICIOUS / SUSPICIOUS / CLEAN)
- Tham chiếu nguồn cụ thể: VirusTotal score, AbuseIPDB confidence, OTX pulses
- Nếu IOC là CLEAN, ghi rõ để loại bỏ khỏi danh sách nghi vấn`
		enrichInstruction = `
⚠️ **Lưu ý quan trọng**: Kết quả Threat Intelligence thực tế đã được tra cứu tự động và đính kèm bên trên.
Hãy:
- Dựa HOÀN TOÀN vào dữ liệu reputation thực tế (VT score, AbuseIPDB score, OTX pulses) — không được phỏng đoán
- Phân loại mức độ nguy hiểm dựa trên số liệu cụ thể, không phải nhận xét chung chung
- Nêu rõ tên malware family / threat label khi VT cung cấp (ví dụ: "Emotet", "Cobalt Strike", "Mirai")
- Phân biệt rõ IOC đã được xác nhận độc hại vs. chưa tìm thấy trong database

`
	}

	return fmt.Sprintf(`Bạn là chuyên gia DFIR (Digital Forensics & Incident Response) với nhiều năm kinh nghiệm.

Dưới đây là %s cần được phân tích:%s

%s
%s
---

%sHãy thực hiện phân tích toàn diện theo cấu trúc sau (dùng Markdown):

## Tóm tắt tổng quan
Mô tả ngắn gọn về dữ liệu và những điểm đáng chú ý nhất. Nêu số lượng IOC phát hiện được và mức độ nguy hiểm tổng thể dựa trên dữ liệu thực tế.

## Phát hiện chính
Liệt kê các phát hiện quan trọng, phân loại theo mức độ nghiêm trọng (dựa trên dữ liệu threat intel thực tế nếu có):
- 🔴 **Critical** — xác nhận là malicious, cần xử lý ngay
- 🟠 **High** — suspicious hoặc có dấu hiệu rõ ràng
- 🟡 **Medium** — cần điều tra thêm
- 🟢 **Low/Info** — clean hoặc không đủ bằng chứng

## Phân tích chi tiết
Giải thích từng phát hiện: nguyên nhân, tác động, threat family (nếu có từ VT labels), bằng chứng cụ thể với số liệu reputation.

## Indicators of Compromise (IOC)
%s

## Đề xuất hành động
Các bước điều tra và khắc phục cụ thể, theo thứ tự ưu tiên. Bao gồm cách block/quarantine IOC đã được xác nhận độc hại.

## Kết luận
Đánh giá tổng thể mức độ rủi ro dựa trên kết quả threat intel. Nêu rõ: bao nhiêu IOC được xác nhận malicious, loại mối đe dọa, và mức độ khẩn cấp cần phản hồi.`,
		sourceLabel, truncateNote, content, enrichSection, enrichInstruction, iocInstruction)
}

// ── Timeline ──────────────────────────────────────────────────────────────────

// BuildTimelinePrompt asks the model to extract time-stamped events from one
// evidence blob, returning a JSON array.
func BuildTimelinePrompt(content, host string) string {
	hostNote := ""
	if host != "" {
		hostNote = fmt.Sprintf(" The evidence was collected from host %q.", host)
	}
	return fmt.Sprintf(`You are a DFIR analyst reconstructing an attack timeline from forensic evidence.%s

Below is tool output / forensic evidence. Extract every event that has a REAL timestamp inside the evidence (file creation, login, process start, network connection, persistence change, etc.). Do NOT invent timestamps. Ignore events without a clear time.

Return ONLY a JSON array (no markdown, no prose, no code fences). Each element:
{
  "time": "ISO8601 timestamp from the evidence (e.g. 2026-06-15T03:42:00Z)",
  "host": "hostname if known, else empty",
  "severity": "critical | high | medium | low | info",
  "tactic": "MITRE ATT&CK tactic in lowercase-dashed form (e.g. initial-access, execution, persistence, exfiltration) or empty",
  "technique": "MITRE technique id (e.g. T1059) or empty",
  "title": "short one-line description of what happened",
  "detail": "supporting evidence / context"
}

If there are no time-stamped events, return [].

EVIDENCE:
%s`, hostNote, content)
}

// BuildRebuildPrompt asks the model to merge raw evidence + existing analyst
// notes into one authoritative, deduplicated timeline (JSON array).
func BuildRebuildPrompt(evidence, existingEvents string) string {
	return fmt.Sprintf(`You are a senior DFIR analyst producing the FINAL attack timeline for an incident report.

You are given two inputs:
1. RAW EVIDENCE: aggregated output from forensic tools run across the affected hosts.
2. EXISTING ANALYST NOTES: timeline entries an analyst added during triage. These may be rough, inconsistently worded, duplicated, or out of order.

Your task: reconstruct ONE authoritative attack timeline by reviewing everything from the beginning. Requirements:
- Merge and DEDUPLICATE events that describe the same activity.
- Use clear, consistent, professional incident-report wording for every title.
- Order strictly by real timestamp (ascending).
- Keep ONLY events with a real timestamp found in the evidence or notes. Do NOT invent times.
- Map each event to a MITRE ATT&CK tactic (lowercase-dashed) and technique id where possible.
- Assign accurate severity based on impact.
- Prefer evidence-derived facts over vague notes; refine the analyst notes into precise statements.

Return ONLY a JSON array (no markdown, no prose, no code fences). Each element:
{
  "time": "ISO8601 timestamp",
  "host": "hostname or empty",
  "severity": "critical | high | medium | low | info",
  "tactic": "initial-access | execution | persistence | ... or empty",
  "technique": "T1059 or empty",
  "title": "clear professional one-line description",
  "detail": "supporting evidence / reasoning"
}

If nothing has a real timestamp, return [].

=== EXISTING ANALYST NOTES ===
%s

=== RAW EVIDENCE ===
%s`, existingEvents, evidence)
}

// ── OSINT triage ──────────────────────────────────────────────────────────────

// BuildOsintTriagePrompt asks the model to triage an OSINT footprint from a
// defensive/DFIR angle: what the entity is, whether it looks malicious, related
// infrastructure to pivot on, and recommended next steps.
func BuildOsintTriagePrompt(target, targetType, findings string) string {
	return fmt.Sprintf(`Bạn là chuyên gia DFIR / Cyber Threat Intelligence. Dưới đây là kết quả OSINT footprinting cho %s "%s".

Phân tích theo góc nhìn PHÒNG THỦ và trả về Markdown gồm:

## Tóm tắt thực thể
Thực thể này là gì (hạ tầng / dịch vụ / danh tính), đăng ký/sở hữu bởi ai, vị trí, đặc điểm chính.

## Đánh giá rủi ro
Có dấu hiệu độc hại không? Dựa trên reputation thực tế (VirusTotal / Shodan / AbuseIPDB), có nằm trong IOC store nội bộ không (nguồn "local_intel"), lộ lọt (HIBP)... Cho mức độ tổng thể: 🔴 Critical / 🟠 High / 🟡 Medium / 🟢 Low — kèm lý do dựa trên số liệu.

## Hạ tầng & pivot liên quan
Các IOC/định danh liên quan đáng điều tra tiếp (subdomain, IP, certificate, email...).

## Đề xuất hành động (DFIR)
Bước tiếp theo cụ thể: thêm IOC nào vào watchlist, hunt gì trên SIEM/ELK, chặn gì.

CHỈ dựa trên dữ liệu thực tế bên dưới — KHÔNG bịa thêm.

=== DỮ LIỆU OSINT (%s) ===
%s`, targetType, target, targetType, findings)
}

// ── Compliance ────────────────────────────────────────────────────────────────

// AssessItem is one compliance check submitted for AI evaluation. JSON tags
// match the request body so handlers can bind into it directly.
type AssessItem struct {
	ItemID     string   `json:"item_id"`
	Control    string   `json:"control"`
	Frameworks []string `json:"frameworks"`
	Title      string   `json:"title"`
	Purpose    string   `json:"purpose"`
	Output     string   `json:"output"`
	Host       string   `json:"host"`
}

// BuildAssessPrompt builds the compliance-audit prompt (JSON array out).
func BuildAssessPrompt(items []AssessItem) string {
	var sb strings.Builder
	sb.WriteString(`You are a security compliance auditor (ISO 27001 / SOC 2 / PCI-DSS / NIST / CIS).
For EACH check below you are given: its purpose (the expected secure baseline) and the ACTUAL command output collected from the host. Decide whether the host meets the control.

Return ONLY a JSON array (no markdown, no prose, no code fences). One element per check:
{
  "item_id": "<the id given>",
  "status": "compliant | non_compliant | partial | na",
  "severity": "critical | high | medium | low | info",
  "rationale": "one concise sentence explaining the verdict, citing the evidence",
  "remediation": "short concrete fix if not compliant, else empty"
}

Rules:
- "compliant" = output clearly meets the secure baseline.
- "non_compliant" = output clearly violates it (assign severity by impact).
- "partial" = partially meets / needs review.
- "na" = output empty/insufficient or check not applicable.
- Base the verdict ONLY on the actual output; do not assume.

CHECKS:
`)
	for i, it := range items {
		fmt.Fprintf(&sb, "\n[%d] item_id=%s | control=%s\n", i+1, it.ItemID, it.Control)
		fmt.Fprintf(&sb, "check: %s\n", it.Title)
		if it.Purpose != "" {
			fmt.Fprintf(&sb, "expected/purpose: %s\n", it.Purpose)
		}
		out := it.Output
		if strings.TrimSpace(out) == "" {
			out = "(no output)"
		}
		fmt.Fprintf(&sb, "actual output:\n%s\n", out)
	}
	return sb.String()
}

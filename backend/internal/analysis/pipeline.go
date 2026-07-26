package analysis

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/storage"
)

// Source describes where an analysis pulls its evidence from.
type Source struct {
	Type       string // job | checklist_run | elk_result | upload | offline_report
	ID         string // UUID of the source (empty for uploads)
	UploadPath string // relative upload path (upload / offline_report)
}

// Pipeline turns a Source into bounded text ready for an AI prompt. It owns the
// per-source collectors and the (future) pre-filter/budget stages so that every
// AI feature collects evidence the same way instead of duplicating the logic.
type Pipeline struct {
	db    *gorm.DB
	store *storage.LocalStorage
}

// NewPipeline builds a Pipeline bound to the given DB and storage.
func NewPipeline(db *gorm.DB, store *storage.LocalStorage) *Pipeline {
	return &Pipeline{db: db, store: store}
}

// Collect gathers text content from the source.
func (p *Pipeline) Collect(source Source) (string, error) {
	switch source.Type {
	case "job":
		return p.collectJob(source.ID)
	case "checklist_run":
		return p.collectChecklistRun(source.ID)
	case "elk_result":
		return p.collectELKResult(source.ID)
	case "upload":
		return p.collectUpload(source.UploadPath)
	case "offline_report":
		return p.collectOfflineReport(source.UploadPath)
	case "evidence":
		return p.collectEvidence(source.ID)
	case "user_activity":
		return p.collectUserActivity(source.ID)
	default:
		return "", fmt.Errorf("unknown source type: %q", source.Type)
	}
}

// userActivityMaxRows bounds how many audit rows feed the summary. Newest-first,
// so a busy operator's recent activity is what the AI narrates.
const userActivityMaxRows = 800

// collectUserActivity renders one user's audit trail as text for the AI to
// narrate — the "what has this operator done" briefing, produced through the
// same session pipeline as evidence analysis so it lands in AI Analysis. An
// empty ID means the system/automated actor.
func (p *Pipeline) collectUserActivity(userID string) (string, error) {
	q := p.db.Table("audit_logs AS a").
		Select(`a.action, a.resource, a.detail, a.ip, a.created_at,
			COALESCE(u.email, '') AS user_email,
			COALESCE(ag.hostname, '') AS agent_host`).
		Joins("LEFT JOIN users u ON u.id = a.user_id").
		Joins("LEFT JOIN agents ag ON ag.id = a.agent_id")
	if strings.TrimSpace(userID) != "" {
		q = q.Where("a.user_id = ?", userID)
	} else {
		q = q.Where("a.user_id IS NULL")
	}

	type actRow struct {
		Action    string
		Resource  string
		Detail    string
		IP        string
		UserEmail string
		AgentHost string
		CreatedAt time.Time
	}
	var rows []actRow
	q.Order("a.id desc").Limit(userActivityMaxRows).Scan(&rows)
	if len(rows) == 0 {
		return "", fmt.Errorf("no recorded activity for this user")
	}

	who := rows[0].UserEmail
	if who == "" {
		who = "system / automated"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "=== USER ACTIVITY AUDIT TRAIL ===\n")
	fmt.Fprintf(&sb, "Operator: %s\n", who)
	fmt.Fprintf(&sb, "Actions: %d (from %s to %s UTC)\n",
		len(rows),
		rows[len(rows)-1].CreatedAt.UTC().Format("2006-01-02 15:04"),
		rows[0].CreatedAt.UTC().Format("2006-01-02 15:04"))
	sb.WriteString("\n=== ACTIONS (oldest first) ===\n")
	// Oldest-first so the narrative reads forward through time.
	for i := len(rows) - 1; i >= 0; i-- {
		r := rows[i]
		fmt.Fprintf(&sb, "%s  %s", r.CreatedAt.UTC().Format("2006-01-02 15:04:05"), r.Action)
		if r.AgentHost != "" {
			fmt.Fprintf(&sb, "  agent=%s", r.AgentHost)
		}
		if r.Resource != "" {
			fmt.Fprintf(&sb, "  resource=%s", truncStr(r.Resource, 80))
		}
		if r.Detail != "" {
			fmt.Fprintf(&sb, "  %s", truncStr(r.Detail, 160))
		}
		if r.IP != "" {
			fmt.Fprintf(&sb, "  ip=%s", r.IP)
		}
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// collectEvidence loads a file from the central Evidence Store and returns its
// text for AI analysis. Binary content is reduced to printable strings; oversized
// files are capped (the StreamSession is a narrative view, not a full scan).
func (p *Pipeline) collectEvidence(idStr string) (string, error) {
	id, err := uuid.Parse(idStr)
	if err != nil {
		return "", fmt.Errorf("invalid evidence ID: %w", err)
	}
	var ev models.CaseEvidence
	if err := p.db.First(&ev, "id = ?", id).Error; err != nil {
		return "", fmt.Errorf("evidence not found: %w", err)
	}
	f, oerr := os.Open(p.store.GetEvidencePath(ev.StoredPath))
	if oerr != nil {
		return "", fmt.Errorf("failed to read evidence file: %w", oerr)
	}
	defer f.Close()

	const cap = 2 << 20 // 2 MB
	raw, rerr := io.ReadAll(io.LimitReader(f, cap+1))
	if rerr != nil {
		return "", fmt.Errorf("failed to read evidence file: %w", rerr)
	}
	truncated := len(raw) > cap
	if truncated {
		raw = raw[:cap]
	}
	body := string(raw)
	if strings.IndexByte(body, 0) >= 0 {
		body = ExtractStrings(body, cap) // binary → printable strings
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "=== EVIDENCE FILE ===\n")
	fmt.Fprintf(&sb, "File: %s\n", ev.FileName)
	fmt.Fprintf(&sb, "Kind: %s\n", ev.Kind)
	if ev.Source != "" {
		fmt.Fprintf(&sb, "Source: %s\n", ev.Source)
	}
	if ev.Host != "" {
		fmt.Fprintf(&sb, "Host: %s\n", ev.Host)
	}
	if ev.Sha256 != "" {
		fmt.Fprintf(&sb, "SHA256: %s\n", ev.Sha256)
	}
	sb.WriteString("\n=== CONTENT ===\n")
	sb.WriteString(body)
	if truncated {
		sb.WriteString("\n... [truncated]")
	}
	return sb.String(), nil
}

func (p *Pipeline) collectJob(jobIDStr string) (string, error) {
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		return "", fmt.Errorf("invalid job ID: %w", err)
	}
	var job models.Job
	if err := p.db.Preload("Tool").Preload("Agent").First(&job, "id = ?", jobID).Error; err != nil {
		return "", fmt.Errorf("job not found: %w", err)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "=== JOB EXECUTION RESULT ===\n")
	fmt.Fprintf(&sb, "Tool: %s\n", job.Tool.Name)
	fmt.Fprintf(&sb, "Agent: %s (OS: %s, IP: %s)\n", job.Agent.Name, job.Agent.OS, job.Agent.IPAddress)
	fmt.Fprintf(&sb, "Args: %s\n", job.Args)
	fmt.Fprintf(&sb, "Status: %s\n", job.Status)
	if job.StartedAt != nil {
		fmt.Fprintf(&sb, "Started: %s\n", job.StartedAt.Format(time.RFC3339))
	}
	if job.FinishedAt != nil {
		fmt.Fprintf(&sb, "Finished: %s\n", job.FinishedAt.Format(time.RFC3339))
	}
	sb.WriteString("\n=== OUTPUT ===\n")
	sb.WriteString(job.Output)

	// If there's a JSON artifact, include it (capped at 16KB).
	if job.ArtifactPath != "" {
		fullPath := p.store.GetArtifactByRelPath(job.ArtifactPath)
		ext := strings.ToLower(filepath.Ext(fullPath))
		if ext == ".json" || ext == ".txt" || ext == ".csv" || ext == ".log" || ext == ".xml" {
			data, readErr := os.ReadFile(fullPath)
			if readErr == nil {
				sb.WriteString("\n=== ARTIFACT (" + filepath.Base(job.ArtifactPath) + ") ===\n")
				artifact := string(data)
				if len(artifact) > 16*1024 {
					artifact = artifact[:16*1024] + "\n... [truncated]"
				}
				sb.WriteString(artifact)
			}
		}
	}

	// Append collected tool result files flagged for AI (normalized form preferred).
	p.appendToolResults(&sb, jobID)
	return sb.String(), nil
}

// appendToolResults appends the content of a job's ToolResult files that are
// marked for AI. The parsed/normalized form is used when available, else the raw
// file; each is capped so one large result can't blow the content budget.
func (p *Pipeline) appendToolResults(sb *strings.Builder, jobID uuid.UUID) {
	var results []models.ToolResult
	if err := p.db.Where("job_id = ? AND for_ai = ? AND process_status = ?", jobID, true, "done").
		Order("created_at asc").Find(&results).Error; err != nil {
		return
	}
	if len(results) == 0 {
		return
	}

	iocSet := p.loadIOCSet()
	const (
		readCap      = 4 << 20  // read at most 4 MB of a result file
		perResultCap = 24 * 1024 // budget of selected text per result
	)
	for i := range results {
		r := &results[i]
		rel := r.ParsedStoredPath // normalized form preferred; falls back to raw
		if rel == "" {
			rel = r.RawStoredPath
		}
		if rel == "" {
			continue
		}
		content := readFileCapped(p.store.AbsPath(rel), readCap)
		if content == "" {
			continue
		}
		// Rule-based pre-filter: keep the header + lines that hit a known IOC or a
		// DFIR keyword, so a huge result contributes its *interesting* rows instead
		// of an arbitrary head-truncation that may miss the signal.
		selected := selectInteresting(content, iocSet, perResultCap)

		fmt.Fprintf(sb, "\n=== TOOL RESULT (%s · %s · %d rows) ===\n", r.FileName, r.Kind, r.RowCount)
		if r.Summary != "" {
			fmt.Fprintf(sb, "[summary] %s\n", r.Summary)
		}
		sb.WriteString(selected)
		sb.WriteString("\n")
	}
}

// ResultChunk is one for-AI tool result, pre-filtered to its interesting lines,
// ready to feed a map-reduce analysis.
type ResultChunk struct {
	FileName string
	Kind     string
	RowCount int
	Content  string
}

// ToolResultChunks returns a job's processed, for-AI tool results as pre-filtered
// chunks (header + IOC/keyword-matching lines) for map-reduce analysis.
func (p *Pipeline) ToolResultChunks(jobID uuid.UUID) []ResultChunk {
	var results []models.ToolResult
	if err := p.db.Where("job_id = ? AND for_ai = ? AND process_status = ?", jobID, true, "done").
		Order("created_at asc").Find(&results).Error; err != nil {
		return nil
	}
	iocSet := p.loadIOCSet()
	const readCap = 4 << 20
	const perResultCap = 24 * 1024
	var out []ResultChunk
	for i := range results {
		r := &results[i]
		rel := r.ParsedStoredPath
		if rel == "" {
			rel = r.RawStoredPath
		}
		if rel == "" {
			continue
		}
		content := readFileCapped(p.store.AbsPath(rel), readCap)
		if content == "" {
			continue
		}
		out = append(out, ResultChunk{
			FileName: r.FileName,
			Kind:     r.Kind,
			RowCount: r.RowCount,
			Content:  selectInteresting(content, iocSet, perResultCap),
		})
	}
	return out
}

// loadIOCSet loads a bounded set of lowercased indicator values from the IOC
// store for the pre-filter. Bounded so a huge store can't blow memory.
func (p *Pipeline) loadIOCSet() map[string]struct{} {
	var vals []string
	p.db.Model(&models.IOC{}).Limit(20000).Pluck("value", &vals)
	set := make(map[string]struct{}, len(vals))
	for _, v := range vals {
		v = strings.ToLower(strings.TrimSpace(v))
		if len(v) >= 4 { // skip tiny values that would match everything
			set[v] = struct{}{}
		}
	}
	return set
}

// dfirKeywords are lowercase markers of security-relevant activity used to
// surface interesting lines from large tool output before it reaches the LLM.
var dfirKeywords = []string{
	"error", "fail", "alert", "warning", "malware", "suspicious", "malicious",
	"mimikatz", "cobalt", "ransom", "encrypt", "backdoor", "trojan", "exploit",
	"powershell", "cmd.exe", "rundll32", "regsvr32", "wscript", "cscript",
	"mshta", "certutil", "bitsadmin", "psexec", "wmic", "schtasks", "at.exe",
	"downloadstring", "invoke-", "frombase64", "-enc", "iex", "base64",
	"lateral", "persistence", "privilege", "4625", "4688", "4720", "1102", "7045",
}

// selectInteresting keeps the header line plus lines that hit a known IOC or a
// DFIR keyword, up to cap bytes. Falls back to the head of the content when
// nothing matches (so a clean result still contributes context).
func selectInteresting(content string, iocSet map[string]struct{}, capBytes int) string {
	lines := strings.Split(content, "\n")
	var b strings.Builder
	start := 0
	if len(lines) > 0 { // keep header/first line for column context
		b.WriteString(lines[0])
		b.WriteByte('\n')
		start = 1
	}
	kept, scanned := 0, 0
	for _, ln := range lines[start:] {
		if b.Len() >= capBytes {
			b.WriteString("... [more interesting lines omitted]\n")
			break
		}
		low := strings.ToLower(ln)
		if lineMatches(low, iocSet) {
			b.WriteString(ln)
			b.WriteByte('\n')
			kept++
		}
		scanned++
	}
	// Nothing flagged → give the model the head so it still has context.
	if kept == 0 {
		head := content
		if len(head) > capBytes {
			head = head[:capBytes] + "\n... [truncated]"
		}
		return head
	}
	fmt.Fprintf(&b, "[pre-filter] %d interesting line(s) of %d selected by IOC/keyword match\n", kept, scanned)
	return b.String()
}

func lineMatches(low string, iocSet map[string]struct{}) bool {
	for _, kw := range dfirKeywords {
		if strings.Contains(low, kw) {
			return true
		}
	}
	for ioc := range iocSet {
		if strings.Contains(low, ioc) {
			return true
		}
	}
	return false
}

// readFileCapped reads at most n bytes of a file (open + limited read), avoiding
// loading a multi-GB parsed file whole.
func readFileCapped(path string, n int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, n)
	read, _ := io.ReadFull(f, buf)
	return string(buf[:read])
}

func (p *Pipeline) collectChecklistRun(runIDStr string) (string, error) {
	runID, err := uuid.Parse(runIDStr)
	if err != nil {
		return "", fmt.Errorf("invalid run ID: %w", err)
	}
	var run models.ChecklistRun
	if err := p.db.Preload("Batches").First(&run, "id = ?", runID).Error; err != nil {
		return "", fmt.Errorf("checklist run not found: %w", err)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "=== EVIDENCE COLLECTION CHECKLIST RESULTS ===\n")
	fmt.Fprintf(&sb, "Platform: %s | Analyst: %s | Label: %s\n", run.Platform, run.Analyst, run.Label)
	fmt.Fprintf(&sb, "Status: %s | Created: %s\n\n", run.Status, run.CreatedAt.Format(time.RFC3339))

	// Per-batch cap: keep first 2KB of each batch output. The total is further
	// capped by the caller's content budget.
	const batchCap = 2 * 1024
	for _, batch := range run.Batches {
		if batch.Output == "" {
			continue
		}
		out := batch.Output
		if len(out) > batchCap {
			out = out[:batchCap] + "\n... [truncated]"
		}
		fmt.Fprintf(&sb, "--- [%s] %s ---\n", batch.BatchKey, batch.BatchLabel)
		sb.WriteString(out)
		sb.WriteString("\n")
	}
	return sb.String(), nil
}

func (p *Pipeline) collectELKResult(resultIDStr string) (string, error) {
	resultID, err := uuid.Parse(resultIDStr)
	if err != nil {
		return "", fmt.Errorf("invalid ELK result ID: %w", err)
	}
	var result models.ELKHuntResult
	if err := p.db.First(&result, "id = ?", resultID).Error; err != nil {
		return "", fmt.Errorf("ELK result not found: %w", err)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "=== ELK THREAT HUNT RESULTS ===\n")
	fmt.Fprintf(&sb, "Title: %s\n", result.Title)
	fmt.Fprintf(&sb, "IOCs used: %d | Total hits: %d | Status: %s\n\n", result.IOCsUsed, result.TotalHits, result.Status)

	if result.Results != "" {
		data := result.Results
		if len(data) > 16*1024 {
			data = data[:16*1024] + "\n... [truncated]"
		}
		sb.WriteString("=== HITS ===\n")
		sb.WriteString(data)
	}
	return sb.String(), nil
}

// collectOfflineReport reads and formats an offline-agent JSON report for AI
// analysis. Each tool's output is included up to 4 KB; total is further capped
// by the caller's content budget.
func (p *Pipeline) collectOfflineReport(uploadPath string) (string, error) {
	if uploadPath == "" {
		return "", fmt.Errorf("no upload file associated with this session")
	}
	fullPath := p.store.GetAnalysisUploadPath(uploadPath)
	raw, err := os.ReadFile(fullPath)
	if err != nil {
		return "", fmt.Errorf("read offline report: %w", err)
	}

	var rep models.OfflineReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		// Not a valid bundle JSON — treat as plain text
		return string(raw), nil
	}

	var sb strings.Builder
	sb.WriteString("=== ANALYSISHUB OFFLINE HUNTING REPORT ===\n")
	fmt.Fprintf(&sb, "Bundle   : %s\n", rep.BundleName)
	if rep.CaseName != "" {
		fmt.Fprintf(&sb, "Case     : %s\n", rep.CaseName)
	}
	fmt.Fprintf(&sb, "Host     : %s\n", rep.Hostname)
	fmt.Fprintf(&sb, "IP       : %s\n", rep.IP)
	fmt.Fprintf(&sb, "OS/Arch  : %s / %s\n", rep.OS, rep.Arch)
	if rep.GeneratedAt != "" {
		fmt.Fprintf(&sb, "Generated: %s\n", rep.GeneratedAt)
	}
	fmt.Fprintf(&sb, "Summary  : %d tools — %d done, %d failed, %d stopped\n\n",
		rep.Summary.TotalTools, rep.Summary.Done, rep.Summary.Failed, rep.Summary.Stopped)

	const perToolCap = 4 * 1024
	for i, job := range rep.Jobs {
		dur := ""
		if job.DurationSec > 0 {
			dur = fmt.Sprintf(" (%.1fs)", job.DurationSec)
		}
		fmt.Fprintf(&sb, "--- [%d/%d] %s | %s%s | args: %s ---\n",
			i+1, len(rep.Jobs), job.ToolName, job.Status, dur, job.Args)
		if job.Error != "" {
			fmt.Fprintf(&sb, "ERROR: %s\n", job.Error)
		}
		output := job.Output
		if len(output) > perToolCap {
			output = output[:perToolCap] + "\n... [truncated]"
		}
		sb.WriteString(output)
		sb.WriteString("\n\n")
	}
	return sb.String(), nil
}

// collectUpload reads a sampled portion of the uploaded file without loading the
// whole thing into memory. Memory dumps and disk images can be multiple
// gigabytes; reading them whole OOMs the server. Instead we sample head/middle/
// tail (≤ 2 MB total). For binary uploads the caller runs ExtractStrings next.
func (p *Pipeline) collectUpload(uploadPath string) (string, error) {
	if uploadPath == "" {
		return "", fmt.Errorf("no upload file associated with this session")
	}
	fullPath := p.store.GetAnalysisUploadPath(uploadPath)

	f, err := os.Open(fullPath)
	if err != nil {
		return "", fmt.Errorf("open upload file: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat upload file: %w", err)
	}
	size := info.Size()

	const (
		headBytes   = 1 * 1024 * 1024 // 1 MB from start
		middleBytes = 512 * 1024      // 512 KB from middle
		tailBytes   = 512 * 1024      // 512 KB from end
	)

	if size <= int64(headBytes+middleBytes+tailBytes) {
		data, rerr := io.ReadAll(io.LimitReader(f, int64(headBytes+middleBytes+tailBytes)))
		if rerr != nil {
			return "", fmt.Errorf("read upload file: %w", rerr)
		}
		return string(data), nil
	}

	var sb strings.Builder
	sb.Grow(headBytes + middleBytes + tailBytes + 64)

	head := make([]byte, headBytes)
	n, _ := io.ReadFull(f, head)
	sb.Write(head[:n])

	midOffset := (size / 2) - int64(middleBytes/2)
	if _, seekErr := f.Seek(midOffset, io.SeekStart); seekErr == nil {
		mid := make([]byte, middleBytes)
		n, _ = io.ReadFull(f, mid)
		sb.WriteString("\n\n[... middle sample ...]\n\n")
		sb.Write(mid[:n])
	}

	tailOffset := size - int64(tailBytes)
	if tailOffset < 0 {
		tailOffset = 0
	}
	if _, seekErr := f.Seek(tailOffset, io.SeekStart); seekErr == nil {
		tail := make([]byte, tailBytes)
		n, _ = io.ReadFull(f, tail)
		sb.WriteString("\n\n[... tail sample ...]\n\n")
		sb.Write(tail[:n])
	}

	return sb.String(), nil
}

// ExtractStrings extracts printable ASCII sequences (≥4 chars) from binary data,
// returning at most maxBytes of extracted strings.
func ExtractStrings(data string, maxBytes int) string {
	raw := []byte(data)
	var sb strings.Builder
	var current strings.Builder

	for _, b := range raw {
		if b >= 0x20 && b < 0x7f && unicode.IsPrint(rune(b)) {
			current.WriteByte(b)
		} else {
			if current.Len() >= 4 {
				sb.WriteString(current.String())
				sb.WriteByte('\n')
				if sb.Len() >= maxBytes {
					sb.WriteString("\n... [truncated]")
					return sb.String()
				}
			}
			current.Reset()
		}
	}
	if current.Len() >= 4 {
		sb.WriteString(current.String())
	}
	return sb.String()
}

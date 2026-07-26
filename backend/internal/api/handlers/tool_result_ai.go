package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	ai "github.com/analysishub/backend/internal/ai"
	"github.com/analysishub/backend/internal/analysis"
	"github.com/analysishub/backend/internal/models"
)

// aiFinding is one structured finding the reduce step returns.
type aiFinding struct {
	EventTime     string `json:"event_time"`
	Severity      string `json:"severity"`
	Confidence    string `json:"confidence"` // high|medium|low
	Title         string `json:"title"`
	Technique     string `json:"technique"`
	Host          string `json:"host"`
	Detail        string `json:"detail"`
	Indicator     string `json:"indicator"`
	IndicatorType string `json:"indicator_type"`
}

// AnalyzeJobResults runs a map-reduce AI pass over a job's for-AI tool results:
// large results are summarized individually (map), then a single reduce call
// extracts structured findings, which are promoted into the case attack timeline
// (and any indicators into the IOC store).
//
// POST /api/v1/jobs/:id/analyze-results   { "provider_id"?: "...", "case_id"?: "..." }
func (h *AIHandler) AnalyzeJobResults(c *gin.Context) {
	jobID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid job id"})
		return
	}
	var input struct {
		ProviderID string `json:"provider_id"`
		CaseID     string `json:"case_id"`
	}
	_ = c.ShouldBindJSON(&input)

	var job models.Job
	if err := h.db.Preload("Agent").Preload("Tool").First(&job, "id = ?", jobID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "job not found"})
		return
	}

	// Resolve the target case: explicit case_id, else the agent's linked case.
	var caseUUID uuid.UUID
	if input.CaseID != "" {
		caseUUID, _ = uuid.Parse(input.CaseID)
	}
	if caseUUID == uuid.Nil && job.Agent.CaseID != nil {
		caseUUID = *job.Agent.CaseID
	}
	if caseUUID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "job/agent is not linked to a case — provide case_id"})
		return
	}

	provider, client, perr := h.resolveProvider(input.ProviderID)
	if perr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": perr.Error()})
		return
	}
	userUUID := userIDFromCtx(c)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 240*time.Second)
	defer cancel()

	findings, created, iocs, aerr := h.analyzeOneJob(ctx, &job, caseUUID, client, provider.MaxTokens, userUUID)
	if aerr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "AI error: " + aerr.Error()})
		return
	}
	agentID := job.AgentID
	writeAudit(c, h.db, &userUUID, &agentID, "job.analyze-results", job.ID.String(),
		fmt.Sprintf("AI extracted %d finding(s) -> %d timeline event(s), %d IOC(s)", findings, created, iocs))

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"findings": findings, "created": created, "iocs_promoted": iocs, "case_id": caseUUID,
	}})
}

// AnalyzeCaseResults runs the same map-reduce findings extraction across EVERY
// job in a case (agents assigned to the case + scenario deployments), promoting
// findings from all hosts into one correlated case timeline. This is the
// case-level counterpart to AnalyzeJobResults — the natural investigation unit.
//
// POST /api/v1/cases/:id/analyze-results   { "provider_id"?: "..." }
func (h *AIHandler) AnalyzeCaseResults(c *gin.Context) {
	caseID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case id"})
		return
	}
	var input struct {
		ProviderID string `json:"provider_id"`
	}
	_ = c.ShouldBindJSON(&input)

	var caseObj models.Case
	if h.db.First(&caseObj, "id = ?", caseID).Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "case not found"})
		return
	}
	provider, client, perr := h.resolveProvider(input.ProviderID)
	if perr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": perr.Error()})
		return
	}
	userUUID := userIDFromCtx(c)

	jobs := h.jobsForCase(caseID)
	if len(jobs) == 0 {
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"jobs_analyzed": 0, "note": "no jobs linked to this case"}})
		return
	}

	// Generous budget for a multi-job case; bounded so one big case can't run
	// unbounded AI calls or exceed the HTTP write timeout.
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Minute)
	defer cancel()
	const maxJobs = 100

	totalF, totalCreated, totalIOC, jobsAnalyzed := 0, 0, 0, 0
	for i := range jobs {
		if i >= maxJobs || ctx.Err() != nil {
			break
		}
		f, cr, io, aerr := h.analyzeOneJob(ctx, &jobs[i], caseID, client, provider.MaxTokens, userUUID)
		if aerr != nil {
			continue // skip a failed job, keep going
		}
		if f > 0 {
			jobsAnalyzed++
		}
		totalF += f
		totalCreated += cr
		totalIOC += io
	}

	writeAudit(c, h.db, &userUUID, nil, "case.analyze-results", caseID.String(),
		fmt.Sprintf("AI analyzed %d job(s): %d finding(s) -> %d timeline event(s), %d IOC(s)", jobsAnalyzed, totalF, totalCreated, totalIOC))

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"jobs_analyzed": jobsAnalyzed, "findings": totalF, "created": totalCreated, "iocs_promoted": totalIOC,
	}})
}

// AnalyzeArtifacts runs findings extraction over an arbitrary set of forensic
// artifact rows (an agent's native EdgeForensics scan, an EVTX export, etc.)
// that are NOT tied to a tool job, promoting findings into the case timeline.
// This lets AI triage native agent forensics — not only uploaded-tool results.
//
// POST /api/v1/cases/:id/analyze-artifacts
//
//	{ "source":"processes|autoruns|...", "host":"HOST01", "items":[...], "provider_id"?:"..." }
func (h *AIHandler) AnalyzeArtifacts(c *gin.Context) {
	caseID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case id"})
		return
	}
	var input struct {
		Source     string          `json:"source"`
		Host       string          `json:"host"`
		Items      json.RawMessage `json:"items"`
		ProviderID string          `json:"provider_id"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid body"})
		return
	}
	if len(input.Items) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "no items to analyze"})
		return
	}
	var caseObj models.Case
	if h.db.First(&caseObj, "id = ?", caseID).Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "case not found"})
		return
	}
	provider, client, perr := h.resolveProvider(input.ProviderID)
	if perr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": perr.Error()})
		return
	}
	userUUID := userIDFromCtx(c)
	source := firstNonEmpty(strings.TrimSpace(input.Source), "artifacts")
	host := strings.TrimSpace(input.Host)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 240*time.Second)
	defer cancel()

	fs, rErr := h.reduceFindings(ctx, client, provider.MaxTokens, host,
		source+" (native forensic artifacts)", artifactSection(input.Items, 48*1024))
	if rErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "AI error: " + rErr.Error()})
		return
	}
	created, iocs := h.promoteFindings(fs, caseID, host, "artifact:"+source, "ai:artifact:"+source, time.Now().UTC(), userUUID)

	writeAudit(c, h.db, &userUUID, nil, "case.analyze-artifacts", caseID.String(),
		fmt.Sprintf("AI triaged %q artifacts from %s: %d finding(s) -> %d event(s), %d IOC(s)", source, host, len(fs), created, iocs))

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"findings": len(fs), "created": created, "iocs_promoted": iocs, "case_id": caseID,
	}})
}

// AnalyzeEvidence runs findings extraction over a single Evidence Store file and
// promotes findings into the linked case timeline (+IOC store). Used by the
// per-file "Analyze with AI" button in the Evidence Store.
//
// POST /api/v1/evidence/:id/analyze   { "provider_id"?: "..." }
func (h *AIHandler) AnalyzeEvidence(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	var input struct {
		ProviderID string `json:"provider_id"`
	}
	_ = c.ShouldBindJSON(&input)

	var ev models.CaseEvidence
	if h.db.First(&ev, "id = ?", id).Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "evidence not found"})
		return
	}

	// Read up to the hard analysis cap. We chunk large content (below) instead of
	// truncating, so only files beyond this generous cap lose their tail.
	fh, oerr := os.Open(h.store.GetEvidencePath(ev.StoredPath))
	if oerr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to read evidence file"})
		return
	}
	content, rerr := io.ReadAll(io.LimitReader(fh, evidenceReadCap+1))
	fh.Close()
	if rerr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to read evidence file"})
		return
	}
	truncated := len(content) > evidenceReadCap
	if truncated {
		content = content[:evidenceReadCap]
	}
	if bytes.IndexByte(content, 0) >= 0 {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": "binary file — cannot be AI-analyzed as text"})
		return
	}

	provider, client, perr := h.resolveProvider(input.ProviderID)
	if perr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": perr.Error()})
		return
	}
	userUUID := userIDFromCtx(c)
	label := firstNonEmpty(ev.Source, ev.FileName)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 300*time.Second)
	defer cancel()

	fs, aerr := h.analyzeTextContent(ctx, client, provider.MaxTokens, ev.Host, label, content)
	if aerr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "AI error: " + aerr.Error()})
		return
	}

	resp := gin.H{"findings": len(fs), "truncated": truncated}
	if ev.CaseID != nil {
		created, iocs := h.promoteFindings(fs, *ev.CaseID, ev.Host, "evidence:"+id.String(), "ai:evidence:"+id.String(), ev.CreatedAt, userUUID)
		h.db.Model(&ev).Update("extracted", true)
		resp["created"] = created
		resp["iocs_promoted"] = iocs
		resp["case_id"] = ev.CaseID
	} else {
		resp["created"] = 0
		resp["note"] = "no case linked — findings were not added to a timeline"
	}

	writeAudit(c, h.db, &userUUID, ev.AgentID, "evidence.analyze", id.String(),
		fmt.Sprintf("AI analyzed evidence %q: %d finding(s)", ev.FileName, len(fs)))
	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

// Budgets for chunked evidence analysis.
const (
	evidenceReadCap  = 4 << 20   // hard cap on bytes read into memory for analysis (~4 MB of text)
	evChunkSize      = 96 * 1024 // size of each MAP chunk
	evReduceBudget   = 48 * 1024 // max evidence/summary text fed to a single REDUCE call
	evMapConcurrency = 6         // parallel MAP calls
	evMapSummaryMax  = 1024      // output tokens per MAP summary
)

// analyzeTextContent extracts findings from arbitrary evidence text. Small content
// is reduced in one call; large content is split into chunks, each summarized in
// parallel (MAP), then the summaries are reduced in budget-sized batches so the
// WHOLE file is covered — nothing is dropped. Findings are merged and deduped.
func (h *AIHandler) analyzeTextContent(ctx context.Context, client ai.Client, maxTokens int, host, label string, content []byte) ([]aiFinding, error) {
	if len(content) == 0 {
		return nil, nil
	}
	// Small file: reduce directly.
	if len(content) <= evReduceBudget {
		return h.reduceFindings(ctx, client, maxTokens, host, label, string(content))
	}

	chunks := splitBytes(content, evChunkSize)

	// MAP: summarize each chunk in parallel (bounded) to keep the reduce inputs small.
	summaries := make([]string, len(chunks))
	sem := make(chan struct{}, evMapConcurrency)
	var wg sync.WaitGroup
	for i := range chunks {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			s, _, err := analysis.Chat(ctx, client,
				buildResultMapPrompt(fmt.Sprintf("%s part %d/%d", label, i+1, len(chunks)), "text", host, string(chunks[i])),
				ai.Options{MaxTokens: evMapSummaryMax, Temperature: 0.2})
			if err == nil {
				summaries[i] = strings.TrimSpace(s)
			}
		}(i)
	}
	wg.Wait()

	// REDUCE: run the summaries through findings extraction in budget-sized batches,
	// then merge + dedupe across batches.
	var all []aiFinding
	var batch strings.Builder
	flush := func() {
		if batch.Len() == 0 {
			return
		}
		fs, err := h.reduceFindings(ctx, client, maxTokens, host, label, batch.String())
		if err == nil {
			all = append(all, fs...)
		}
		batch.Reset()
	}
	for i, s := range summaries {
		if s == "" {
			continue
		}
		sec := fmt.Sprintf("### part %d/%d\n%s\n\n", i+1, len(chunks), s)
		if batch.Len()+len(sec) > evReduceBudget {
			flush()
		}
		batch.WriteString(sec)
	}
	flush()
	return dedupeFindings(all), nil
}

// splitBytes cuts b into contiguous pieces of at most size bytes.
func splitBytes(b []byte, size int) [][]byte {
	if size <= 0 {
		size = 48 * 1024
	}
	var out [][]byte
	for i := 0; i < len(b); i += size {
		end := i + size
		if end > len(b) {
			end = len(b)
		}
		out = append(out, b[i:end])
	}
	return out
}

// dedupeFindings collapses duplicate findings (same title + indicator) that can
// arise when the same evidence appears across chunk boundaries.
func dedupeFindings(fs []aiFinding) []aiFinding {
	seen := make(map[string]bool, len(fs))
	var out []aiFinding
	for i := range fs {
		key := strings.ToLower(strings.TrimSpace(fs[i].Title) + "|" + strings.TrimSpace(fs[i].Indicator))
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, fs[i])
	}
	return out
}

// artifactSection renders artifact items as compact JSON, capped to capBytes so
// a huge scan is truncated rather than blowing the reduce budget.
func artifactSection(items json.RawMessage, capBytes int) string {
	var buf bytes.Buffer
	if json.Indent(&buf, items, "", " ") == nil && buf.Len() > 0 {
		if buf.Len() > capBytes {
			return buf.String()[:capBytes] + "\n… (truncated)"
		}
		return buf.String()
	}
	s := string(items)
	if len(s) > capBytes {
		return s[:capBytes] + "… (truncated)"
	}
	return s
}

// analyzeOneJob runs map-reduce over a single job's for-AI tool results and
// promotes findings into caseUUID's timeline (+IOC store). Returns counts;
// (0,0,0,nil) when the job has no processed for-AI results.
func (h *AIHandler) analyzeOneJob(ctx context.Context, job *models.Job, caseUUID uuid.UUID, client ai.Client, maxTokens int, userUUID uuid.UUID) (findings, created, iocs int, err error) {
	host := firstNonEmpty(job.Agent.Hostname, job.Agent.Name)
	chunks := analysis.NewPipeline(h.db, h.store).ToolResultChunks(job.ID)
	if len(chunks) == 0 {
		return 0, 0, 0, nil
	}

	// MAP: summarize any large chunk individually to stay within the reduce budget.
	var sections []string
	const mapThreshold = 8 * 1024
	const reduceBudget = 48 * 1024
	total := 0
	for _, ch := range chunks {
		txt := ch.Content
		if len(txt) > mapThreshold {
			if s, _, mErr := analysis.Chat(ctx, client,
				buildResultMapPrompt(ch.FileName, ch.Kind, host, txt),
				ai.Options{MaxTokens: 1024, Temperature: 0.2}); mErr == nil && strings.TrimSpace(s) != "" {
				txt = strings.TrimSpace(s)
			}
		}
		section := fmt.Sprintf("### %s (%s, %d rows)\n%s", ch.FileName, ch.Kind, ch.RowCount, txt)
		if total+len(section) > reduceBudget {
			break
		}
		total += len(section)
		sections = append(sections, section)
	}

	// REDUCE: structured findings JSON.
	fs, rErr := h.reduceFindings(ctx, client, maxTokens, host, job.Tool.Name, strings.Join(sections, "\n\n"))
	if rErr != nil {
		return 0, 0, 0, rErr
	}
	fallback := time.Now().UTC()
	if job.FinishedAt != nil {
		fallback = *job.FinishedAt
	}
	created, iocs = h.promoteFindings(fs, caseUUID, host, job.ID.String(), "ai:"+job.ID.String(), fallback, userUUID)
	return len(fs), created, iocs, nil
}

// reduceFindings runs the reduce step (structured findings JSON) over the given
// evidence sections. Unparseable output yields no findings rather than an error.
func (h *AIHandler) reduceFindings(ctx context.Context, client ai.Client, maxTokens int, host, label, sections string) ([]aiFinding, error) {
	out, _, err := analysis.Chat(ctx, client,
		buildResultFindingsPrompt(host, label, sections),
		ai.Options{MaxTokens: maxTokens, JSON: true, Temperature: 0.1})
	if err != nil {
		return nil, err
	}
	var fs []aiFinding
	if uerr := json.Unmarshal([]byte(ai.ExtractJSON(out)), &fs); uerr != nil {
		// Not a hard error, but log a snippet so a silent "0 findings" caused by a
		// model returning prose/invalid JSON is diagnosable.
		log.Printf("[ai-findings] unparseable model output (%s): %.280q", label, strings.TrimSpace(out))
		return nil, nil
	}
	return fs, nil
}

// promoteFindings writes findings onto caseUUID's attack timeline (deduped) and
// promotes any indicators into the IOC store. Shared by job, case and artifact
// analysis so behaviour stays identical everywhere. Returns counts.
func (h *AIHandler) promoteFindings(fs []aiFinding, caseUUID uuid.UUID, host, sourceRef, iocSource string, fallback time.Time, userUUID uuid.UUID) (created, iocs int) {
	for i := range fs {
		f := &fs[i]
		if strings.TrimSpace(f.Title) == "" {
			continue
		}
		detail := truncStr(f.Detail, 4000)
		if conf := strings.ToLower(strings.TrimSpace(f.Confidence)); conf == "high" || conf == "medium" || conf == "low" {
			detail = "[confidence: " + conf + "] " + detail
		}
		ev := models.TimelineEvent{
			CaseID:    caseUUID,
			EventTime: parseFindingTimeAt(f.EventTime, fallback),
			Source:    "ai",
			SourceRef: sourceRef,
			Host:      firstNonEmpty(f.Host, host),
			Severity:  normFindingSeverity(f.Severity),
			Technique: strings.TrimSpace(f.Technique),
			Title:     truncStr(f.Title, 200),
			Detail:    detail,
			CreatedBy: userUUID,
		}
		if insertAutoTimelineEvent(h.db, &ev) {
			created++
		}
		if ind := strings.TrimSpace(f.Indicator); ind != "" {
			ioc := models.IOC{
				Value:       ind,
				Type:        firstNonEmpty(strings.TrimSpace(f.IndicatorType), "unknown"),
				Source:      iocSource,
				Description: truncStr(f.Title, 200),
			}
			if h.db.Where("value = ? AND type = ?", ioc.Value, ioc.Type).FirstOrCreate(&ioc).Error == nil {
				iocs++
			}
		}
	}
	return created, iocs
}

// resolveProvider returns the provider (explicit id or the first configured one)
// and a ready-to-use decrypted client.
func (h *AIHandler) resolveProvider(idStr string) (*models.AIProvider, ai.Client, error) {
	var provider models.AIProvider
	if idStr != "" {
		pid, perr := uuid.Parse(idStr)
		if perr != nil {
			return nil, nil, fmt.Errorf("invalid provider_id")
		}
		if h.db.First(&provider, "id = ?", pid).Error != nil {
			return nil, nil, fmt.Errorf("provider not found")
		}
	} else if h.db.Order("created_at asc").First(&provider).Error != nil {
		return nil, nil, fmt.Errorf("no AI provider configured")
	}
	client, err := h.newDecryptedClient(&provider)
	if err != nil {
		return nil, nil, err
	}
	return &provider, client, nil
}

// jobsForCase returns the deduplicated jobs linked to a case, via agents
// assigned to the case and via scenario deployments tagged with the case.
func (h *AIHandler) jobsForCase(caseID uuid.UUID) []models.Job {
	var agentIDs []uuid.UUID
	h.db.Model(&models.Agent{}).Where("case_id = ?", caseID).Pluck("id", &agentIDs)
	var depIDs []uuid.UUID
	h.db.Model(&models.HuntingDeployment{}).Where("case_id = ?", caseID).Pluck("id", &depIDs)

	seen := map[uuid.UUID]bool{}
	var out []models.Job
	add := func(js []models.Job) {
		for i := range js {
			if !seen[js[i].ID] {
				seen[js[i].ID] = true
				out = append(out, js[i])
			}
		}
	}
	if len(agentIDs) > 0 {
		var js []models.Job
		h.db.Preload("Agent").Preload("Tool").Where("agent_id IN ?", agentIDs).Find(&js)
		add(js)
	}
	if len(depIDs) > 0 {
		var js []models.Job
		h.db.Preload("Agent").Preload("Tool").Where("deployment_id IN ?", depIDs).Find(&js)
		add(js)
	}
	return out
}

// userIDFromCtx extracts the authenticated user UUID from the gin context.
func userIDFromCtx(c *gin.Context) uuid.UUID {
	if v, ok := c.Get("userID"); ok {
		if uid, perr := uuid.Parse(v.(string)); perr == nil {
			return uid
		}
	}
	return uuid.UUID{}
}

func buildResultMapPrompt(fileName, kind, host, content string) string {
	return fmt.Sprintf(`You are a senior DFIR analyst. Summarize the security-relevant observations in this %q output (%s) collected from host %q.
List only concrete, evidence-backed items (values, hashes, IPs, timestamps, commands). Be terse. Ignore benign/noise lines.

%s`, fileName, kind, host, content)
}

func buildResultFindingsPrompt(host, toolName, sections string) string {
	return fmt.Sprintf(`You are a senior DFIR analyst reviewing forensic tool output from host %q (tool: %s).
Extract concrete SECURITY FINDINGS that belong on an incident attack timeline.

Return ONLY a JSON array (no prose). Each element:
{"event_time":"ISO8601 (from the evidence) or empty","severity":"critical|high|medium|low|info","confidence":"high|medium|low","title":"short specific title","technique":"MITRE ATT&CK technique id e.g. T1059.001 or empty","host":%q,"detail":"the exact evidence: values, paths, hashes, cmdlines, timestamps","indicator":"a single hash/IP/domain/filename or empty","indicator_type":"File-Hash|IPv4-Addr|Domain-Name|File-Name or empty"}

Rules:
- Only findings directly supported by the evidence below. NO speculation, NO generic best-practice advice.
- Severity: critical = active compromise/known-malicious; high = strong attacker TTP; medium = suspicious/needs review; low/info = context. Do not inflate.
- Confidence reflects how certain the evidence makes this finding (high = unambiguous, low = weak/circumstantial).
- Prefer real event_time from the data; leave empty if none.
- One finding per distinct observation; do NOT duplicate the same indicator across multiple items.
- Put a concrete indicator in "indicator" whenever one exists so it can be promoted to the IOC store.
- If nothing security-relevant is present, return [].

EVIDENCE:
%s`, host, toolName, host, sections)
}

// parseFindingTimeAt parses the AI-provided timestamp, falling back to the given
// anchor (job finish time / now) so every promoted event has a real time.
func parseFindingTimeAt(s string, fallback time.Time) time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return fallback
}

func normFindingSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if validSeverity(s) {
		return s
	}
	return "info"
}

func truncStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

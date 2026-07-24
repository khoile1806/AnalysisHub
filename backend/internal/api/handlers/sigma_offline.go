package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/analysishub/backend/internal/crypto"
	"github.com/analysishub/backend/internal/hunting/sigma"
	"github.com/analysishub/backend/internal/logsearch"
	"github.com/analysishub/backend/internal/models"
)

// Sigma against already-ingested logs (dead-box forensics): an uploaded .evtx
// from a machine that never had an agent, or a re-hunt of logs collected weeks
// ago. The live sweep in sigma_sweep.go can only reach an online agent, so
// everything already sitting in the log store was previously unreachable.

const (
	// offlineCollectBudget bounds the ES walk and offlineScanBudget the matching
	// that follows. They are separate so a slow store cannot leave the scan with
	// an already-expired deadline — the events pulled before the cut-off are
	// still worth evaluating.
	offlineCollectBudget = 3 * time.Minute
	offlineScanBudget    = 3 * time.Minute
	// offlinePageSize is one search_after page. Small enough that a page fits
	// comfortably in memory, large enough to keep the round trips down.
	offlinePageSize = 1000
	// offlinePageTimeout bounds a single _search call.
	offlinePageTimeout = 60 * time.Second
	// defaultOfflineMax / maxOfflineMax bound how many events are held at once.
	// Sigma matching is O(events × rules) and every event is decoded into a map,
	// so this is the memory ceiling of the whole feature.
	defaultOfflineMax = 20000
	maxOfflineMax     = 50000
	// maxIndexTargets caps how many comma-separated indices one request may name.
	// An archive upload legitimately produces several, but not dozens.
	maxIndexTargets = 20
)

// sigmaOfflineRequest selects what to scan. Exactly one of index/job_id/
// (case_id|host) is needed; they are tried in that order.
type sigmaOfflineRequest struct {
	Index     string `json:"index"`
	JobID     string `json:"job_id"`
	CaseID    string `json:"case_id"`
	Host      string `json:"host"`
	Hours     int    `json:"hours"`      // 0 = no time filter (dead-box logs are old)
	Max       int    `json:"max"`        // event ceiling, clamped to maxOfflineMax
	AllEvents bool   `json:"all_events"` // skip the channel/EventID pre-filter
}

// SigmaOfflineScan runs the loaded Sigma ruleset against logs already indexed in
// the built-in log store.
//
// POST /api/v1/logsearch/sigma/scan
// Body: {"index":"hunt-windows-case-host-evtx","job_id":"","hours":0,"max":20000}
func (h *LogSearchHandler) SigmaOfflineScan(c *gin.Context) {
	if h.ES == nil || strings.TrimSpace(h.ES.BaseURL()) == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Log Search is disabled on this server - no Elasticsearch is configured, so there are no ingested logs to scan",
		})
		return
	}
	engine := sigma.DefaultEngine
	if engine == nil || engine.RuleCount() == 0 {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "no Sigma rules are loaded on the server - rebuild the backend image or run a rule sync",
		})
		return
	}

	var req sigmaOfflineRequest
	_ = c.ShouldBindJSON(&req) // every field is optional on its own
	if req.Max <= 0 {
		req.Max = defaultOfflineMax
	}
	if req.Max > maxOfflineMax {
		req.Max = maxOfflineMax
	}

	targets, job, err := h.resolveScanTargets(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	indices := h.expandIndexTargets(targets)
	if len(indices) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no log store index matches " + strings.Join(targets, ",")})
		return
	}

	// Ask the ruleset what it needs rather than pulling every document: a
	// channel whose rules all key off EventID is filtered down to those IDs, a
	// channel with a rule matching on anything else is pulled whole.
	var selector map[string]interface{}
	var channels []string
	if !req.AllEvents {
		selector, channels = sigmaChannelSelector(engine.RequiredSources())
	}

	collectCtx, cancelCollect := context.WithTimeout(c.Request.Context(), offlineCollectBudget)
	defer cancelCollect()

	baseURL, authHeader := h.localLogStoreTarget(c)
	events, truncated, err := collectOfflineEvents(collectCtx, baseURL, authHeader, indices, selector, req.Hours, req.Max)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	scanCtx, cancelScan := context.WithTimeout(c.Request.Context(), offlineScanBudget)
	defer cancelScan()
	alerts, err := scanSigmaEvents(scanCtx, engine, events)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sigma scan failed: " + err.Error()})
		return
	}
	if alerts == nil {
		alerts = []sigma.Alert{}
	}

	out := gin.H{
		"alerts":         alerts,
		"events_scanned": len(events),
		"index":          strings.Join(indices, ","),
		"indices":        indices,
		"rules_count":    engine.RuleCount(),
		"load_stats":     engine.Stats(),
		"truncated":      truncated,
		"hours":          req.Hours,
		"filtered":       selector != nil,
		"channels":       channels,
	}

	// Same marked trail every other scan leaves, when we know the case.
	caseID, host := scanAttribution(req, job)
	if snapshot, mErr := json.Marshal(out); mErr == nil {
		h.recordOfflineScanEvidence(caseID, host, strings.Join(indices, ","), snapshot)
	}

	c.JSON(http.StatusOK, out)
}

// sigmaScanTarget is one scannable ingest job, as the picker needs it.
type sigmaScanTarget struct {
	JobID       string     `json:"job_id"`
	Filename    string     `json:"filename"`
	Host        string     `json:"host"`
	Case        string     `json:"case,omitempty"`
	CaseID      *uuid.UUID `json:"case_id,omitempty"`
	Index       string     `json:"index"`
	LogType     string     `json:"log_type"`
	DocsIndexed int        `json:"docs_indexed"`
	CreatedAt   time.Time  `json:"created_at"`
}

// SigmaTargets lists what can be scanned: finished ingest jobs that actually
// landed in an index.
//
// GET /api/v1/logsearch/sigma/targets
func (h *LogSearchHandler) SigmaTargets(c *gin.Context) {
	var jobs []models.LogIngestJob
	q := h.DB.Where("status = ?", "done").Where("\"index\" <> ?", "").
		Order("created_at desc").Limit(200)
	if cid := strings.TrimSpace(c.Query("case_id")); cid != "" {
		q = q.Where("case_id = ?", cid)
	}
	if host := strings.TrimSpace(c.Query("host")); host != "" {
		q = q.Where("host = ?", host)
	}
	if err := q.Find(&jobs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list scan targets"})
		return
	}

	targets := make([]sigmaScanTarget, 0, len(jobs))
	for _, j := range jobs {
		logType := j.DetectedType
		if logType == "" {
			logType = j.LogType
		}
		targets = append(targets, sigmaScanTarget{
			JobID:       j.ID.String(),
			Filename:    j.Filename,
			Host:        j.Host,
			Case:        j.Case,
			CaseID:      j.CaseID,
			Index:       j.Index,
			LogType:     logType,
			DocsIndexed: j.DocsIndexed,
			CreatedAt:   j.CreatedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{"targets": targets})
}

// resolveScanTargets turns the request into a validated list of index names or
// patterns, plus the ingest job it came from when there is one.
func (h *LogSearchHandler) resolveScanTargets(req sigmaOfflineRequest) ([]string, *models.LogIngestJob, error) {
	if strings.TrimSpace(req.Index) != "" {
		targets, err := sanitizeIndexTarget(req.Index)
		return targets, nil, err
	}

	if jid := strings.TrimSpace(req.JobID); jid != "" {
		id, err := uuid.Parse(jid)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid job_id")
		}
		var job models.LogIngestJob
		if err := h.DB.First(&job, "id = ?", id).Error; err != nil {
			return nil, nil, fmt.Errorf("ingest job not found")
		}
		if strings.TrimSpace(job.Index) == "" {
			return nil, nil, fmt.Errorf("ingest job %s has no index (status %s)", jid, job.Status)
		}
		targets, err := sanitizeIndexTarget(job.Index)
		if err != nil {
			return nil, nil, err
		}
		return targets, &job, nil
	}

	// No explicit target: derive it from what was ingested for this case/host.
	// Reading the actual index names off the jobs beats guessing a pattern —
	// the case segment of an index name is a sanitised case *name*, not the id.
	caseID := strings.TrimSpace(req.CaseID)
	host := strings.TrimSpace(req.Host)
	if caseID == "" && host == "" {
		return nil, nil, fmt.Errorf("specify one of index, job_id, case_id or host")
	}
	q := h.DB.Where("status = ?", "done").Where("\"index\" <> ?", "")
	if caseID != "" {
		if _, err := uuid.Parse(caseID); err != nil {
			return nil, nil, fmt.Errorf("invalid case_id")
		}
		q = q.Where("case_id = ?", caseID)
	}
	if host != "" {
		q = q.Where("host = ?", host)
	}
	var jobs []models.LogIngestJob
	if err := q.Order("created_at desc").Limit(500).Find(&jobs).Error; err != nil {
		return nil, nil, fmt.Errorf("failed to look up ingested logs")
	}

	seen := map[string]bool{}
	var targets []string
	for _, j := range jobs {
		parts, err := sanitizeIndexTarget(j.Index)
		if err != nil {
			continue // a row written before the naming rules cannot be trusted
		}
		for _, p := range parts {
			if !seen[p] {
				seen[p] = true
				targets = append(targets, p)
			}
		}
	}
	if len(targets) == 0 && host != "" {
		// Nothing recorded in the job table (agent-side ingest, pruned rows) —
		// fall back to the host segment of the index naming scheme.
		targets = []string{fmt.Sprintf("%s-*-%s-*", logsearch.IndexPrefix, logsearch.Sanitize(host))}
	}
	if len(targets) == 0 {
		return nil, nil, fmt.Errorf("no ingested logs found for that case/host")
	}
	if len(targets) > maxIndexTargets {
		targets = targets[:maxIndexTargets]
	}
	return targets, nil, nil
}

// indexTargetChars is the whole alphabet an index target may use. Everything
// that could change the meaning of the ES path (/, comma inside an element, ?,
// #, whitespace, quotes) is rejected rather than escaped.
var indexTargetChars = regexp.MustCompile(`^[a-z0-9][a-z0-9_.*-]*$`)

// sanitizeIndexTarget validates a caller-supplied index name or pattern before
// it is pasted into an Elasticsearch URL path.
//
// The rules are deliberately narrow: every element must stay inside the
// "hunt-" namespace this module owns, so neither a wildcard nor a comma can
// reach an index belonging to something else (or _all). Commas are allowed
// because one archive upload legitimately writes several indices and the job
// row stores them comma-joined — but each element is validated on its own.
func sanitizeIndexTarget(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("index is required")
	}
	if len(raw) > 1024 {
		return nil, fmt.Errorf("index is too long")
	}
	parts := strings.Split(raw, ",")
	if len(parts) > maxIndexTargets {
		return nil, fmt.Errorf("too many indices (max %d)", maxIndexTargets)
	}

	prefix := logsearch.IndexPrefix + "-"
	seen := map[string]bool{}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if len(p) > 255 {
			return nil, fmt.Errorf("index name is too long: %s", truncate(p, 64))
		}
		if !strings.HasPrefix(p, prefix) {
			return nil, fmt.Errorf("index must start with %q: %s", prefix, truncate(p, 64))
		}
		if strings.Contains(p, "..") {
			return nil, fmt.Errorf("invalid index: %s", truncate(p, 64))
		}
		if !indexTargetChars.MatchString(p) {
			return nil, fmt.Errorf("invalid characters in index: %s", truncate(p, 64))
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("index is required")
	}
	return out, nil
}

// expandIndexTargets resolves patterns against the indices that actually exist,
// so each concrete index can be paged on its own (search_after is only exact
// within a single shard, and every hunt-* index is single-shard). If the store
// cannot be listed the targets are passed through untouched.
func (h *LogSearchHandler) expandIndexTargets(targets []string) []string {
	live, err := h.ES.CatIndices()
	if err != nil || len(live) == 0 {
		return targets
	}
	seen := map[string]bool{}
	var out []string
	for _, ix := range live {
		if ix.Index == "" || seen[ix.Index] {
			continue
		}
		for _, t := range targets {
			if matchIndexPattern(t, ix.Index) {
				seen[ix.Index] = true
				out = append(out, ix.Index)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// matchIndexPattern implements the only wildcard Elasticsearch index patterns
// use: "*" for any run of characters.
func matchIndexPattern(pattern, name string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == name
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(name, parts[0]) {
		return false
	}
	rest := name[len(parts[0]):]
	for _, mid := range parts[1 : len(parts)-1] {
		if mid == "" {
			continue
		}
		idx := strings.Index(rest, mid)
		if idx < 0 {
			return false
		}
		rest = rest[idx+len(mid):]
	}
	return strings.HasSuffix(rest, parts[len(parts)-1])
}

// sigmaChannelSelector builds the ES filter that pulls only what the ruleset can
// actually match, and returns the channels it covers. Nil means "no usable
// filter — scan everything".
func sigmaChannelSelector(sources []sigma.Source) (map[string]interface{}, []string) {
	should := make([]interface{}, 0, len(sources))
	channels := make([]string, 0, len(sources))
	for _, src := range sources {
		if strings.TrimSpace(src.LogName) == "" {
			continue
		}
		channels = append(channels, src.LogName)
		channelTerm := map[string]interface{}{
			"term": map[string]interface{}{"winlog.channel": src.LogName},
		}
		// An empty ID list means at least one rule on this channel matches on
		// something other than EventID, so the channel has to be pulled whole.
		if len(src.EventIDs) == 0 {
			should = append(should, channelTerm)
			continue
		}
		codes := make([]string, 0, len(src.EventIDs))
		for _, id := range src.EventIDs {
			codes = append(codes, strconv.Itoa(id))
		}
		should = append(should, map[string]interface{}{
			"bool": map[string]interface{}{"filter": []interface{}{
				channelTerm,
				map[string]interface{}{"terms": map[string]interface{}{"event.code": codes}},
			}},
		})
	}
	if len(should) == 0 {
		return nil, nil
	}
	sort.Strings(channels)
	return map[string]interface{}{
		"bool": map[string]interface{}{"should": should, "minimum_should_match": 1},
	}, channels
}

// esScanHit is one document plus its sort key (the search_after cursor).
type esScanHit struct {
	Source map[string]interface{} `json:"_source"`
	Sort   []interface{}          `json:"sort"`
}

type esScanResponse struct {
	Hits struct {
		Hits []esScanHit `json:"hits"`
	} `json:"hits"`
	Error json.RawMessage `json:"error"`
}

// collectOfflineEvents pages every target index with search_after and returns
// the hits flattened into the shape the rules match on. truncated reports that
// the event cap or the deadline stopped the walk before the data ran out.
func collectOfflineEvents(ctx context.Context, baseURL, authHeader string, indices []string,
	selector map[string]interface{}, hours, max int) ([]map[string]interface{}, bool, error) {

	events := make([]map[string]interface{}, 0, min(max, offlinePageSize))
	truncated := false

	for _, index := range indices {
		var after []interface{}
		for len(events) < max {
			if err := ctx.Err(); err != nil {
				return events, true, nil
			}
			size := max - len(events)
			if size > offlinePageSize {
				size = offlinePageSize
			}
			body, err := json.Marshal(offlineSearchBody(selector, hours, size, after))
			if err != nil {
				return nil, false, fmt.Errorf("failed to build search query")
			}
			raw, status, err := elkSearch(baseURL, authHeader, index, body, offlinePageTimeout)
			if err != nil {
				return nil, false, fmt.Errorf("log store is not reachable: %v", err)
			}
			if status >= 300 {
				return nil, false, fmt.Errorf("log store rejected the query on %s (status %d): %s",
					index, status, truncate(strings.TrimSpace(string(raw)), 300))
			}
			var resp esScanResponse
			if err := json.Unmarshal(raw, &resp); err != nil {
				return nil, false, fmt.Errorf("unreadable response from the log store")
			}
			hits := resp.Hits.Hits
			if len(hits) == 0 {
				break
			}
			for _, hit := range hits {
				if ev := flattenESEvent(hit.Source); len(ev) > 0 {
					events = append(events, ev)
				}
			}
			after = hits[len(hits)-1].Sort
			if len(hits) < size || len(after) == 0 {
				break // last page, or no cursor to continue from
			}
			if len(events) >= max {
				truncated = true
			}
		}
		if len(events) >= max {
			truncated = true
			break
		}
	}
	return events, truncated, nil
}

// offlineSearchBody builds one page of the walk. Sorting on @timestamp with a
// _doc tiebreaker gives search_after a stable cursor; hunt-* indices are
// single-shard, so the pair is unique within the index being paged.
func offlineSearchBody(selector map[string]interface{}, hours, size int, after []interface{}) map[string]interface{} {
	var filters []interface{}
	if hours > 0 {
		filters = append(filters, map[string]interface{}{
			"range": map[string]interface{}{
				"@timestamp": map[string]interface{}{"gte": fmt.Sprintf("now-%dh", hours)},
			},
		})
	}
	if selector != nil {
		filters = append(filters, selector)
	}

	query := map[string]interface{}{"match_all": map[string]interface{}{}}
	if len(filters) > 0 {
		query = map[string]interface{}{"bool": map[string]interface{}{"filter": filters}}
	}

	body := map[string]interface{}{
		"size":             size,
		"track_total_hits": false,
		"query":            query,
		"sort": []interface{}{
			map[string]interface{}{"@timestamp": map[string]interface{}{"order": "asc", "unmapped_type": "date"}},
			map[string]interface{}{"_doc": map[string]interface{}{"order": "asc"}},
		},
	}
	if len(after) > 0 {
		body["search_after"] = after
	}
	return body
}

// flattenESEvent turns one ECS document from the log store into the flat map the
// Sigma evaluator matches on. The evaluator only looks at top-level keys, so a
// document left as {"winlog":{"event_data":{"CommandLine":...}}} would miss
// every rule.
func flattenESEvent(src map[string]interface{}) map[string]interface{} {
	if len(src) == 0 {
		return nil
	}
	winlog, _ := src["winlog"].(map[string]interface{})
	out := make(map[string]interface{}, 16)

	if winlog != nil {
		if ed, ok := winlog["event_data"].(map[string]interface{}); ok {
			for k, v := range ed {
				if k != "" {
					out[k] = v
				}
			}
		}
	} else {
		// Non-EVTX sources (syslog, web access, json/csv) carry no event_data;
		// expose their top-level scalars so a rule still has something to read.
		for k, v := range src {
			switch v.(type) {
			case map[string]interface{}, []interface{}:
				continue
			}
			out[k] = v
		}
	}

	// Identity fields are layered on top: an EventData element named EventID or
	// Provider must not shadow the values logsource gating relies on. Empty
	// values are skipped so an absent ECS field cannot blank out a usable
	// EventData one.
	eventObj, _ := src["event"].(map[string]interface{})
	if code := scalarString(eventObj["code"]); code != "" {
		if n, err := strconv.Atoi(code); err == nil {
			out["EventID"] = n
		} else {
			out["EventID"] = code
		}
	}
	provider := scalarString(eventObj["provider"])
	if provider == "" && winlog != nil {
		provider = scalarString(winlog["provider_name"])
	}
	if provider != "" {
		out["Provider"] = provider
	}
	if winlog != nil {
		if ch := scalarString(winlog["channel"]); ch != "" {
			// Not part of the agent's shape, but serviceMatches reads Channel
			// first — with it, service-scoped rules gate correctly.
			out["Channel"] = ch
		}
		if lvl := scalarString(winlog["level"]); lvl != "" {
			out["Level"] = lvl
		}
		if rid := scalarString(winlog["record_id"]); rid != "" {
			out["RecordID"] = rid
		}
	}
	computer := ""
	if winlog != nil {
		computer = scalarString(winlog["computer_name"])
	}
	if computer == "" {
		if host, ok := src["host"].(map[string]interface{}); ok {
			computer = scalarString(host["name"])
		}
	}
	if computer != "" {
		out["Computer"] = computer
	}
	if msg := scalarString(src["message"]); msg != "" {
		out["Message"] = msg
	}
	if ts := scalarString(src["@timestamp"]); ts != "" {
		out["TimeCreated"] = ts
	}
	return out
}

// scalarString renders a JSON scalar the way the rules expect to see it —
// notably without float formatting on whole numbers ("4688", not "4688.000000").
func scalarString(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(t)
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 1e15 {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", t))
	}
}

// sigmaEventScanner is satisfied by *sigma.Engine when it exposes the decoded
// slice entry point. Asserting for it keeps this handler compiling either way.
type sigmaEventScanner interface {
	ScanEvents(ctx context.Context, events []map[string]interface{}) ([]sigma.Alert, error)
}

// scanSigmaEvents evaluates the events, preferring the allocation-free entry
// point and falling back to the JSON one.
func scanSigmaEvents(ctx context.Context, engine *sigma.Engine, events []map[string]interface{}) ([]sigma.Alert, error) {
	if len(events) == 0 {
		return nil, nil
	}
	if fast, ok := interface{}(engine).(sigmaEventScanner); ok {
		return fast.ScanEvents(ctx, events)
	}
	payload, err := json.Marshal(events)
	if err != nil {
		return nil, fmt.Errorf("failed to assemble events")
	}
	return engine.ScanContext(ctx, string(payload))
}

// localLogStoreTarget returns the endpoint and auth header for the built-in
// store. The seeded "Local Log Store" ELK profile is preferred so a deployment
// that later put credentials on it keeps working; the store itself normally
// runs on the internal network with security disabled.
func (h *LogSearchHandler) localLogStoreTarget(c *gin.Context) (string, string) {
	base := strings.TrimRight(h.ES.BaseURL(), "/")
	if h.DB == nil {
		return base, ""
	}
	var cfg models.ELKConfig
	if err := h.DB.Where("url IN ?", []string{base, base + "/"}).First(&cfg).Error; err != nil {
		return base, ""
	}
	return base, elkConfigAuthHeader(cfg, c.GetString("aesEncryptionKey"))
}

// elkConfigAuthHeader derives the Authorization header for a profile, or "" when
// it carries no credentials (which is the normal case for the built-in store).
func elkConfigAuthHeader(cfg models.ELKConfig, aesKey string) string {
	if aesKey == "" {
		return ""
	}
	if cfg.APIKey != "" {
		if key, err := crypto.Decrypt(cfg.APIKey, aesKey); err == nil {
			return "ApiKey " + key
		}
		return ""
	}
	if cfg.Username != "" && cfg.Password != "" {
		if pass, err := crypto.Decrypt(cfg.Password, aesKey); err == nil {
			return "Basic " + base64.StdEncoding.EncodeToString([]byte(cfg.Username+":"+pass))
		}
	}
	return ""
}

// scanAttribution resolves which case and host the result belongs to, preferring
// the ingest job the scan was launched from.
func scanAttribution(req sigmaOfflineRequest, job *models.LogIngestJob) (*uuid.UUID, string) {
	if job != nil {
		return job.CaseID, job.Host
	}
	host := strings.TrimSpace(req.Host)
	if cid := strings.TrimSpace(req.CaseID); cid != "" {
		if id, err := uuid.Parse(cid); err == nil {
			return &id, host
		}
	}
	return nil, host
}

// recordOfflineScanEvidence snapshots the result into the Evidence Store, off
// the response path. No case, no evidence row — an unattributed blob would just
// be noise in the store.
func (h *LogSearchHandler) recordOfflineScanEvidence(caseID *uuid.UUID, host, index string, payload []byte) {
	if caseID == nil || h.DB == nil || h.Store == nil || len(payload) == 0 {
		return
	}
	buf := make([]byte, len(payload))
	copy(buf, payload)
	label := logsearch.Sanitize(index) // ascii-safe, so a byte cut is safe
	if len(label) > 60 {
		label = label[:60]
	}
	fileName := fmt.Sprintf("sigma-offline-%s-%d.json", label, time.Now().Unix())
	go recordEvidenceBytes(h.DB, h.Store, caseID, nil, host, "sigma-offline", "logsearch:sigma-offline", fileName, buf)
}

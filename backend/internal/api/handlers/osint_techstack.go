package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/osint"
)

const (
	// techStackTTL caches a full lookup so re-running the same URL is instant.
	techStackTTL = time.Hour
	// techCVEFetch bounds how many NVD rows we pull per product and techCVEKeep how
	// many we keep after ranking, so a widely-vulnerable component can't dominate.
	techCVEFetch = 25
	techCVEKeep  = 8
	// techMaxProducts caps how many versioned products we run CVE lookups for, to
	// bound total NVD round-trips (and wall time) on a fat stack.
	techMaxProducts = 12
	// techPocLookup bounds how many top CVEs we query GitHub for public PoCs (that
	// API is heavily rate-limited).
	techPocLookup    = 10
	techLookupBudget = 50 * time.Second
)

// techCVE is a matched CVE plus public-exploit (PoC) availability.
type techCVE struct {
	CveSummary
	POCCount   int    `json:"poc_count"`
	TopPocURL  string `json:"top_poc_url,omitempty"`
	TopPocName string `json:"top_poc_name,omitempty"`
	HasExploit bool   `json:"has_exploit"`
}

// techWithCVEs is a detected technology plus its ranked known CVEs.
type techWithCVEs struct {
	osint.Technology
	CVECount int       `json:"cve_count"` // real NVD total, not the fetched slice length
	TopCVEs  []techCVE `json:"top_cves,omitempty"`
}

// techStackResponse is the full standalone lookup payload sent to the UI.
type techStackResponse struct {
	InputURL        string                 `json:"input_url"`
	FinalURL        string                 `json:"final_url"`
	Host            string                 `json:"host"`
	StatusCode      int                    `json:"status_code"`
	Title           string                 `json:"title,omitempty"`
	Server          string                 `json:"server,omitempty"`
	PoweredBy       string                 `json:"powered_by,omitempty"`
	Active          bool                   `json:"active"`
	Deep            bool                   `json:"deep"`
	Risk            *techRisk              `json:"risk,omitempty"`
	Technologies    []techWithCVEs         `json:"technologies"`
	EdgeServices    []osint.EdgeService    `json:"edge_services,omitempty"`
	SecurityHeaders []osint.SecurityHeader `json:"security_headers"`
	MissingHeaders  []string               `json:"missing_security_headers"`
	Cookies         []osint.CookieInfo     `json:"cookies,omitempty"`
	CORS            *osint.CORSInfo        `json:"cors,omitempty"`
	TLS             *osint.TLSInfo         `json:"tls,omitempty"`
	Exposures       []osint.ExposedPath    `json:"exposures,omitempty"`
	ProbedPaths     []string               `json:"probed_paths,omitempty"`
	CVESummary      techCVESummary         `json:"cve_summary"`
	ScopeNote       string                 `json:"scope_note,omitempty"`
}

type techCVESummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	KEV      int `json:"kev"`
	Exploit  int `json:"exploit"` // CVEs with a public PoC/exploit repo
}

// techRisk is an at-a-glance triage score + prioritized action list for the target.
type techRisk struct {
	Score   int          `json:"score"` // 0-100
	Level   string       `json:"level"` // critical | high | medium | low
	Actions []riskAction `json:"actions,omitempty"`
}

type riskAction struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	CVE      string `json:"cve,omitempty"`
	URL      string `json:"url,omitempty"`
}

// OsintTechStack fingerprints a URL's technology stack and suggests possible CVEs
// for each versioned component. Standalone, synchronous, cached — it does not
// create a scan.
//
// POST /api/v1/osint/techstack  { "url": "https://example.com", "active": true }
func OsintTechStack(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	var body struct {
		URL    string `json:"url" binding:"required"`
		Active *bool  `json:"active"`
		Deep   *bool  `json:"deep"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	active := body.Active == nil || *body.Active
	// Deep (exposed-file/panel) probing is aggressive → opt-in only, default off.
	deep := body.Deep != nil && *body.Deep

	ctx, cancel := context.WithTimeout(c.Request.Context(), techLookupBudget)
	defer cancel()

	resp, status, err := computeTechStack(ctx, c, db, body.URL, active, deep)
	if err != nil {
		c.JSON(status, gin.H{"success": false, "error": err.Error()})
		return
	}
	// Persist the run as a browsable session (upsert per user+url+options).
	sid := saveTechStackSession(c, db, resp, active, deep)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp, "session_id": sid})
}

// saveTechStackSession upserts a session record for the current user, keyed by
// url+options, and returns its id. Best-effort: a persistence failure never fails
// the lookup itself.
func saveTechStackSession(c *gin.Context, db *gorm.DB, resp *techStackResponse, active, deep bool) string {
	uid, _ := middleware.GetUserID(c)
	blob, err := json.Marshal(resp)
	if err != nil {
		return ""
	}
	var sess models.TechStackSession
	db.Where("created_by = ? AND url = ? AND active = ? AND deep = ?", uid, resp.InputURL, active, deep).First(&sess)
	sess.CreatedBy = uid
	sess.URL = resp.InputURL
	sess.Host = resp.Host
	sess.Title = resp.Title
	sess.Active = active
	sess.Deep = deep
	if resp.Risk != nil {
		sess.RiskScore = resp.Risk.Score
		sess.RiskLevel = resp.Risk.Level
	}
	sess.TechCount = len(resp.Technologies)
	sess.CVETotal = resp.CVESummary.Total
	sess.Critical = resp.CVESummary.Critical
	sess.KEV = resp.CVESummary.KEV
	sess.Exploit = resp.CVESummary.Exploit
	sess.Result = string(blob)
	if sess.ID == uuid.Nil {
		if err := db.Create(&sess).Error; err != nil {
			return ""
		}
	} else {
		db.Save(&sess)
	}
	return sess.ID.String()
}

// ListTechStackSessions lists the current user's saved Tech-Stack runs (newest
// first), without the heavy result blob.
//
// GET /api/v1/osint/techstack/sessions
func ListTechStackSessions(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	uid, _ := middleware.GetUserID(c)
	var sessions []models.TechStackSession
	db.Where("created_by = ?", uid).Order("updated_at desc").Limit(200).Find(&sessions)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": sessions})
}

// GetTechStackSession returns the full stored result of one session, in the same
// shape as a live lookup so the UI renders it identically.
//
// GET /api/v1/osint/techstack/sessions/:id
func GetTechStackSession(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	uid, _ := middleware.GetUserID(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid session id"})
		return
	}
	var sess models.TechStackSession
	if err := db.Where("id = ? AND created_by = ?", id, uid).First(&sess).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "session not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": json.RawMessage(sess.Result)})
}

// DeleteTechStackSession removes one saved session.
//
// DELETE /api/v1/osint/techstack/sessions/:id
func DeleteTechStackSession(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	uid, _ := middleware.GetUserID(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid session id"})
		return
	}
	db.Where("id = ? AND created_by = ?", id, uid).Delete(&models.TechStackSession{})
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// computeTechStack runs the full lookup for one URL (validation + scope + cache +
// fingerprint + CVE/risk build), returning the response, an HTTP status hint, and
// an error. Shared by the single-URL handler and the batch handler.
func computeTechStack(ctx context.Context, c *gin.Context, db *gorm.DB, rawURL string, active, deep bool) (*techStackResponse, int, error) {
	host := hostFromRawURL(rawURL)
	if host == "" {
		return nil, http.StatusBadRequest, fmt.Errorf("could not parse a host from the URL")
	}
	ttype, derr := osint.DetectTargetType(host)
	if derr != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("the URL host is not a valid domain or IP")
	}
	// Reject private/loopback/link-local (SSRF) up-front as a client error.
	if verr := osint.ValidateTarget(host, ttype); verr != nil {
		return nil, http.StatusBadRequest, verr
	}

	// Scope policy: a blocked target is refused; passive-only proceeds with a warning
	// (this tool is inherently active and user-initiated on an authorized target).
	var scopeNote string
	decision := osint.DecideScope(db, host, ttype)
	if decision.Enforced {
		switch decision.Mode {
		case osint.ModeBlock:
			return nil, http.StatusForbidden, fmt.Errorf("target is out of scope (blocked by policy: %s)", decision.MatchedRule)
		case osint.ModePassiveOnly:
			scopeNote = "Scope policy marks this target passive-only (" + decision.Reason +
				"). This tool sends active requests directly — ensure you are authorized; route OSINT egress through a proxy to avoid exposing your IP."
		}
	}

	rdb := getRedis(c)
	cacheKey := fmt.Sprintf("osint:techstack:v4:%s:%t:%t", sha1Hex(strings.ToLower(strings.TrimSpace(rawURL))), active, deep)
	if rdb != nil {
		if b, err := rdb.Get(ctx, cacheKey).Bytes(); err == nil {
			var cached techStackResponse
			if json.Unmarshal(b, &cached) == nil {
				return &cached, http.StatusOK, nil
			}
		}
	}

	fp, err := osint.FingerprintURL(ctx, rawURL, osint.FingerprintOptions{Active: active, Deep: deep})
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	resp := buildTechStackResponse(ctx, c, fp, active, deep, scopeNote)
	if rdb != nil {
		if b, e := json.Marshal(resp); e == nil {
			rdb.Set(context.Background(), cacheKey, b, techStackTTL)
		}
	}
	return &resp, http.StatusOK, nil
}

// techBatchRow is the compact per-URL result in a batch lookup.
type techBatchRow struct {
	URL        string   `json:"url"`
	Host       string   `json:"host,omitempty"`
	Error      string   `json:"error,omitempty"`
	StatusCode int      `json:"status_code,omitempty"`
	Title      string   `json:"title,omitempty"`
	TechCount  int      `json:"tech_count"`
	CVETotal   int      `json:"cve_total"`
	Critical   int      `json:"critical"`
	KEV        int      `json:"kev"`
	Exploit    int      `json:"exploit"`
	Exposures  int      `json:"exposures"`
	RiskScore  int      `json:"risk_score"`
	RiskLevel  string   `json:"risk_level,omitempty"`
	Edge       []string `json:"edge,omitempty"`
}

// techBatchMax caps how many URLs one batch request may scan.
const techBatchMax = 25

// OsintTechStackBatch fingerprints several URLs at once (asset inventory), returning
// one compact risk row per URL. Full detail is available by looking up a single URL
// (served instantly from the same cache).
//
// POST /api/v1/osint/techstack/batch  { "urls": ["a.com", "b.com"], "active": true }
func OsintTechStackBatch(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	var body struct {
		URLs   []string `json:"urls" binding:"required"`
		Active *bool    `json:"active"`
		Deep   *bool    `json:"deep"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	active := body.Active == nil || *body.Active
	deep := body.Deep != nil && *body.Deep

	// Dedup + cap the URL list.
	seen := map[string]bool{}
	var urls []string
	for _, u := range body.URLs {
		u = strings.TrimSpace(u)
		if u == "" || seen[strings.ToLower(u)] {
			continue
		}
		seen[strings.ToLower(u)] = true
		urls = append(urls, u)
		if len(urls) >= techBatchMax {
			break
		}
	}
	if len(urls) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "provide at least one URL"})
		return
	}

	rows := make([]techBatchRow, len(urls))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for i, u := range urls {
		wg.Add(1)
		go func(i int, u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(c.Request.Context(), techLookupBudget)
			defer cancel()
			resp, _, err := computeTechStack(ctx, c, db, u, active, deep)
			if err != nil {
				rows[i] = techBatchRow{URL: u, Error: err.Error()}
				return
			}
			rows[i] = compactBatchRow(u, resp)
		}(i, u)
	}
	wg.Wait()
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"results": rows}})
}

func compactBatchRow(u string, r *techStackResponse) techBatchRow {
	row := techBatchRow{
		URL: u, Host: r.Host, StatusCode: r.StatusCode, Title: r.Title,
		TechCount: len(r.Technologies), CVETotal: r.CVESummary.Total,
		Critical: r.CVESummary.Critical, KEV: r.CVESummary.KEV,
		Exploit: r.CVESummary.Exploit, Exposures: len(r.Exposures),
	}
	if r.Risk != nil {
		row.RiskScore, row.RiskLevel = r.Risk.Score, r.Risk.Level
	}
	for _, e := range r.EdgeServices {
		row.Edge = append(row.Edge, e.Name)
	}
	return row
}

// buildTechStackResponse runs CVE matching for each versioned technology, folds in
// EPSS/KEV + public-exploit availability, computes a triage risk score, and
// assembles the response.
func buildTechStackResponse(ctx context.Context, c *gin.Context, fp *osint.TechStackResult, active, deep bool, scopeNote string) techStackResponse {
	f := cveFetchFromCtx(c)

	// Per-tech CVE lookup (CPE-accurate first, keyword fallback), bounded.
	type rawTech struct {
		tech  osint.Technology
		total int
		cves  []CveSummary
	}
	var raws []rawTech
	byID := map[string]*CveSummary{} // dedup + single enrichment pass
	productsDone := 0
	for _, t := range fp.Technologies {
		rt := rawTech{tech: t}
		if t.Version != "" && productsDone < techMaxProducts {
			// JS libraries carry retire.js's exact per-version CVEs — use those
			// directly (far more accurate than a fuzzy NVD keyword search). Everything
			// else goes to NVD (CPE-accurate first, keyword fallback).
			var cves []CveSummary
			var total int
			if len(t.KnownVulns) > 0 {
				cves = cvesFromRetire(t.KnownVulns)
				total = len(cves)
			} else {
				cves, total = lookupTechCVEs(ctx, c, f, t)
			}
			if len(cves) > 0 {
				productsDone++
				rt.total, rt.cves = total, cves
				for i := range cves {
					if _, exists := byID[cves[i].ID]; !exists {
						cp := cves[i]
						byID[cves[i].ID] = &cp
					}
				}
			}
		}
		raws = append(raws, rt)
	}

	// One EPSS+KEV enrichment pass over the union of all matched CVEs.
	enriched := map[string]CveSummary{}
	if len(byID) > 0 {
		union := make([]CveSummary, 0, len(byID))
		for _, v := range byID {
			union = append(union, *v)
		}
		enrichWithRiskData(ctx, union)
		for _, s := range union {
			enriched[s.ID] = s
		}
	}

	// Public-exploit (PoC) availability for the top-ranked unique CVEs.
	pocByID := lookupTopPoCs(ctx, c, enriched, techPocLookup)

	// Assemble per-tech CVE lists (enriched + PoC), ranked and capped.
	techs := make([]techWithCVEs, 0, len(raws))
	for _, rt := range raws {
		tw := techWithCVEs{Technology: rt.tech, CVECount: rt.total}
		for _, cve := range rt.cves {
			s := cve
			if e, ok := enriched[cve.ID]; ok {
				s = e
			}
			tc := techCVE{CveSummary: s}
			if p, ok := pocByID[cve.ID]; ok {
				tc.POCCount, tc.TopPocURL, tc.TopPocName, tc.HasExploit = p.count, p.url, p.name, p.count > 0
			}
			tw.TopCVEs = append(tw.TopCVEs, tc)
		}
		rankTechCVEs(tw.TopCVEs)
		if len(tw.TopCVEs) > techCVEKeep {
			tw.TopCVEs = tw.TopCVEs[:techCVEKeep]
		}
		techs = append(techs, tw)
	}

	// Aggregate CVE summary across unique CVEs.
	var summary techCVESummary
	summary.Total = len(byID)
	for id := range byID {
		v := byID[id]
		if e, ok := enriched[id]; ok {
			v = &e
		}
		switch v.Severity {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		}
		if v.IsKEV {
			summary.KEV++
		}
		if _, ok := pocByID[id]; ok {
			summary.Exploit++
		}
	}

	return techStackResponse{
		InputURL:        fp.InputURL,
		FinalURL:        fp.FinalURL,
		Host:            fp.Host,
		StatusCode:      fp.StatusCode,
		Title:           fp.Title,
		Server:          fp.Server,
		PoweredBy:       fp.PoweredBy,
		Active:          active,
		Deep:            deep,
		Risk:            computeRisk(techs, fp),
		Technologies:    techs,
		EdgeServices:    fp.EdgeServices,
		SecurityHeaders: fp.SecurityHeaders,
		MissingHeaders:  fp.MissingHeaders,
		Cookies:         fp.Cookies,
		CORS:            fp.CORS,
		TLS:             fp.TLS,
		Exposures:       fp.Exposures,
		ProbedPaths:     fp.ProbedPaths,
		CVESummary:      summary,
		ScopeNote:       scopeNote,
	}
}

// lookupTechCVEs returns CVEs for a versioned technology plus NVD's real total
// match count. It matches by CPE (version-range accurate) whenever possible: the
// fingerprint's own CPE first, else one resolved from NVD's CPE dictionary and
// cached — falling back to a keyword search only when no CPE can be found.
func lookupTechCVEs(ctx context.Context, c *gin.Context, f cveFetch, t osint.Technology) ([]CveSummary, int) {
	cpe := cpeWithVersion(t.CPE, t.Version)
	if cpe == "" {
		if vp, ok := resolvedProductCPE(ctx, c, f, t.Name); ok {
			cpe = cpeWithVersion(vp, t.Version)
		}
	}
	if cpe != "" {
		p := url.Values{}
		p.Set("virtualMatchString", cpe)
		if cves, total, err := nvdCVEsWithTotal(ctx, f, p); err == nil && total > 0 {
			return cves, total
		}
	}
	p := url.Values{}
	p.Set("keywordSearch", strings.TrimSpace(t.Name+" "+t.Version))
	cves, total, _ := nvdCVEsWithTotal(ctx, f, p)
	return cves, total
}

// resolvedProductCPE resolves a product name to a "cpe:2.3:a:vendor:product" via
// the NVD CPE dictionary, cached in Redis (7d) since the mapping is stable. A
// cached empty string means "no CPE found" and avoids re-querying.
func resolvedProductCPE(ctx context.Context, c *gin.Context, f cveFetch, product string) (string, bool) {
	key := "cve:cperesolve:v1:" + sha1Hex(strings.ToLower(strings.TrimSpace(product)))
	rdb := getRedis(c)
	if rdb != nil {
		if v, err := rdb.Get(ctx, key).Result(); err == nil {
			return v, v != ""
		}
	}
	vp, ok := resolveProductCPE(ctx, f, product)
	if rdb != nil {
		rdb.Set(context.Background(), key, vp, 7*24*time.Hour)
	}
	return vp, ok
}

// cvesFromRetire converts retire.js library vulnerabilities into CveSummary rows
// (severity + summary from retire.js; EPSS/KEV are folded in later). CVE-less
// advisories are dropped since the downstream pipeline keys on a CVE id.
func cvesFromRetire(vulns []osint.LibVuln) []CveSummary {
	seen := map[string]bool{}
	out := make([]CveSummary, 0, len(vulns))
	for _, v := range vulns {
		if v.CVE == "" || seen[v.CVE] {
			continue
		}
		seen[v.CVE] = true
		out = append(out, CveSummary{
			ID:          v.CVE,
			Severity:    normalizeSeverity(v.Severity, 0),
			Description: v.Summary,
		})
	}
	return out
}

// nvdCVEsWithTotal runs one NVD query and returns the parsed summaries plus the
// real totalResults, so callers can show "N known · showing top M".
func nvdCVEsWithTotal(ctx context.Context, f cveFetch, params url.Values) ([]CveSummary, int, error) {
	params.Set("resultsPerPage", strconv.Itoa(techCVEFetch))
	raw, status, err := fetchNVD(ctx, f, params)
	if err != nil {
		return nil, 0, err
	}
	if status != http.StatusOK {
		return nil, 0, nvdStatusError(status)
	}
	var meta struct {
		TotalResults int `json:"totalResults"`
	}
	_ = json.Unmarshal(raw, &meta)
	sums, err := parseNVDSummaries(raw)
	return sums, meta.TotalResults, err
}

// pocInfo is the compact public-exploit availability for one CVE.
type pocInfo struct {
	count int
	url   string
	name  string
}

// lookupTopPoCs fetches public GitHub PoC/exploit repos for the highest-priority
// CVEs (KEV/CVSS/EPSS ranked), bounded and cached to respect GitHub rate limits.
func lookupTopPoCs(ctx context.Context, c *gin.Context, enriched map[string]CveSummary, limit int) map[string]pocInfo {
	if len(enriched) == 0 {
		return nil
	}
	ranked := make([]CveSummary, 0, len(enriched))
	for _, v := range enriched {
		ranked = append(ranked, v)
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].IsKEV != ranked[j].IsKEV {
			return ranked[i].IsKEV
		}
		if ranked[i].CVSSScore != ranked[j].CVSSScore {
			return ranked[i].CVSSScore > ranked[j].CVSSScore
		}
		return ranked[i].EPSSScore > ranked[j].EPSSScore
	})
	if len(ranked) > limit {
		ranked = ranked[:limit]
	}

	out := map[string]pocInfo{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for _, cve := range ranked {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			repos := cachedPocsForCVE(ctx, c, id)
			if len(repos) == 0 {
				return
			}
			mu.Lock()
			out[id] = pocInfo{count: len(repos), url: repos[0].HTMLURL, name: repos[0].Owner + "/" + repos[0].Name}
			mu.Unlock()
		}(cve.ID)
	}
	wg.Wait()
	return out
}

// cachedPocsForCVE reuses the same Redis cache as the CVE detail page.
func cachedPocsForCVE(ctx context.Context, c *gin.Context, id string) []PocRepo {
	rdb := getRedis(c)
	key := "cve:pocs:" + id
	if rdb != nil {
		if b, err := rdb.Get(ctx, key).Bytes(); err == nil {
			var p []PocRepo
			if json.Unmarshal(b, &p) == nil {
				return p
			}
		}
	}
	repos, status, err := fetchGitHubPocs(ctx, c, id)
	if err != nil || status != http.StatusOK {
		return nil
	}
	if rdb != nil {
		if b, e := json.Marshal(repos); e == nil {
			rdb.Set(context.Background(), key, b, cvePoCsTTL)
		}
	}
	return repos
}

// rankTechCVEs orders CVEs by exploitation priority: KEV, then public exploit,
// then CVSS, then EPSS.
func rankTechCVEs(cves []techCVE) {
	sort.SliceStable(cves, func(i, j int) bool {
		if cves[i].IsKEV != cves[j].IsKEV {
			return cves[i].IsKEV
		}
		if cves[i].HasExploit != cves[j].HasExploit {
			return cves[i].HasExploit
		}
		if cves[i].CVSSScore != cves[j].CVSSScore {
			return cves[i].CVSSScore > cves[j].CVSSScore
		}
		return cves[i].EPSSScore > cves[j].EPSSScore
	})
}

// computeRisk derives a 0-100 triage score and a prioritized action list from the
// matched CVEs, exposed files, and posture weaknesses.
func computeRisk(techs []techWithCVEs, fp *osint.TechStackResult) *techRisk {
	score := 0
	var actions []riskAction
	seenCVE := map[string]bool{}

	for _, tw := range techs {
		for _, cve := range tw.TopCVEs {
			switch cve.Severity {
			case "critical":
				score += 10
			case "high":
				score += 6
			case "medium":
				score += 2
			}
			if cve.IsKEV {
				score += 20
			}
			if cve.HasExploit {
				score += 8
			}
			// Action for the genuinely urgent ones.
			if (cve.IsKEV || cve.HasExploit || cve.Severity == "critical") && !seenCVE[cve.ID] {
				seenCVE[cve.ID] = true
				sev := cve.Severity
				if cve.IsKEV {
					sev = "critical"
				}
				var d []string
				if cve.IsKEV {
					d = append(d, "actively exploited (CISA KEV)")
				}
				if cve.HasExploit {
					d = append(d, "public exploit available")
				}
				actions = append(actions, riskAction{
					Severity: sev,
					Title:    fmt.Sprintf("Patch %s — %s %s", cve.ID, tw.Name, tw.Version),
					Detail:   strings.Join(d, "; "),
					CVE:      cve.ID,
					URL:      "https://nvd.nist.gov/vuln/detail/" + cve.ID,
				})
			}
		}
		if tw.EOL {
			actions = append(actions, riskAction{Severity: "high", Title: fmt.Sprintf("Replace end-of-life %s %s", tw.Name, tw.Version), Detail: "no longer receives security updates"})
			score += 8
		}
	}

	for _, e := range fp.Exposures {
		switch e.Severity {
		case "critical":
			score += 30
		case "high":
			score += 15
		case "medium":
			score += 5
		}
		if e.Severity == "critical" || e.Severity == "high" {
			actions = append(actions, riskAction{Severity: e.Severity, Title: e.Title, Detail: "exposed at " + e.Path, URL: e.URL})
		}
	}

	if fp.CORS != nil {
		switch fp.CORS.Severity {
		case "high":
			score += 15
			actions = append(actions, riskAction{Severity: "high", Title: "Fix permissive CORS policy", Detail: fp.CORS.Note})
		case "medium":
			score += 7
			actions = append(actions, riskAction{Severity: "medium", Title: "Review CORS policy", Detail: fp.CORS.Note})
		}
	}
	score += len(fp.MissingHeaders) * 2
	if score > 100 {
		score = 100
	}

	level := "low"
	switch {
	case score >= 70:
		level = "critical"
	case score >= 45:
		level = "high"
	case score >= 20:
		level = "medium"
	}

	sort.SliceStable(actions, func(i, j int) bool {
		return severityRank(actions[i].Severity) < severityRank(actions[j].Severity)
	})
	if len(actions) > 10 {
		actions = actions[:10]
	}
	return &techRisk{Score: score, Level: level, Actions: actions}
}

// cpeWithVersion rewrites a Wappalyzer CPE (often version-less, e.g.
// "cpe:2.3:a:nginx:nginx") into a concrete "cpe:2.3:a:vendor:product:version"
// suitable for NVD's virtualMatchString. Returns "" when the CPE has no usable
// vendor/product.
func cpeWithVersion(cpe, version string) string {
	if version == "" || !strings.HasPrefix(cpe, "cpe:2.3:") {
		return ""
	}
	parts := strings.Split(cpe, ":")
	if len(parts) < 5 {
		return ""
	}
	part, vendor, product := parts[2], parts[3], parts[4]
	if vendor == "" || vendor == "*" || product == "" || product == "*" {
		return ""
	}
	return fmt.Sprintf("cpe:2.3:%s:%s:%s:%s", part, vendor, product, version)
}

// hostFromRawURL extracts the hostname from a possibly scheme-less URL.
func hostFromRawURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

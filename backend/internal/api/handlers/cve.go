package handlers

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/sync/singleflight"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/config"
	"github.com/analysishub/backend/internal/models"
)

// cveHTTPClient is the shared client used for NVD + GitHub outbound calls.
// 30s is generous: NVD frequently takes 1-2s and GitHub <500ms, but we'd
// rather a single slow upstream not pile up retries.
var cveHTTPClient = &http.Client{Timeout: 30 * time.Second}

// cveIDRegex matches well-formed CVE identifiers per MITRE format.
var cveIDRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// errNVDRateLimited flags an upstream throttle (403/429/503) so the handler can
// return a clear 429 with actionable advice instead of a generic 502 — NVD's
// unauthenticated limit is only 5 req / 30s, so this is the common failure.
var errNVDRateLimited = errors.New("NVD rate limited")

// cveSearchSF collapses concurrent identical searches into a single upstream
// NVD round-trip (thundering-herd protection), so many users searching the same
// keyword while the cache is cold/refreshing only cost ONE slow NVD call.
var cveSearchSF singleflight.Group

// cveCacheEntry wraps cached search results with the time they were produced, so
// stale-while-revalidate can decide whether to refresh in the background.
type cveCacheEntry struct {
	Data     []CveSummary `json:"data"`
	CachedAt time.Time    `json:"cached_at"`
}

const (
	githubBaseURL = "https://api.github.com/search/repositories"

	// cveSearchTTL is how long a cached search survives in Redis. It is long so
	// stale entries remain available for stale-while-revalidate; cveSoftTTL marks
	// when an entry is considered fresh — past it, the cache is still served
	// instantly but a background refresh is kicked off.
	cveSearchTTL = 24 * time.Hour
	cveSoftTTL   = 15 * time.Minute
	cveDetailTTL = 6 * time.Hour
	cvePoCsTTL   = time.Hour

	cveMaxQueryLen   = 500
	cveMaxVersionLen = 32
	cveDefaultLimit  = 200
	cveMaxLimit      = 500
	cvePoCsPerPage   = 10

	// cveSearchBudget caps the total upstream time a single cold search may spend
	// on NVD + EPSS. With the cheap-count-probe strategy a typical search is a
	// sub-second probe + one data page, so this rarely bites; it exists so a genuine
	// NVD slow spell fails cleanly instead of hanging on the client's 30s timeout.
	cveSearchBudget = 20 * time.Second
)

// CveSummary is the trimmed CVE shape returned in search results.
//
// EPSSScore is the FIRST.org Exploit Prediction Scoring System probability
// (0-1) that the CVE will be exploited in the wild within the next 30 days.
// EPSSPercentile (0-1) is the rank of this CVE's EPSS score relative to all
// scored CVEs. IsKEV is true if the CVE appears in CISA's Known Exploited
// Vulnerabilities catalog — i.e., already observed being exploited.
type CveSummary struct {
	ID               string   `json:"id"`
	Description      string   `json:"description"`
	CVSSScore        float64  `json:"cvss_score"`
	Severity         string   `json:"severity"` // critical | high | medium | low | none
	EPSSScore        float64  `json:"epss_score"`
	EPSSPercentile   float64  `json:"epss_percentile"`
	IsKEV            bool     `json:"is_kev"`
	PublishedDate    string   `json:"published_date"`
	LastModified     string   `json:"last_modified"`
	AffectedProducts []string `json:"affected_products"`
}

// CveReference is a single advisory/exploit URL referenced by a CVE.
type CveReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}

// CveDetail extends CveSummary with full references and CPE configurations.
type CveDetail struct {
	CveSummary
	References     []CveReference `json:"references"`
	Configurations []string       `json:"configurations"`
}

// PocRepo represents one GitHub repository matching a CVE search.
type PocRepo struct {
	Name        string `json:"name"`
	HTMLURL     string `json:"html_url"`
	Description string `json:"description"`
	Stars       int    `json:"stars"`
	Owner       string `json:"owner"`
}

// SearchCVE handles GET /api/v1/cve/search?q=<keyword>&limit=20
func SearchCVE(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	q := strings.TrimSpace(c.Query("q"))
	if q == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "query required"})
		return
	}
	if len(q) > cveMaxQueryLen {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "query too long (max 500 chars)"})
		return
	}
	version := strings.TrimSpace(c.Query("version"))
	if len(version) > cveMaxVersionLen {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "version too long (max 32 chars)"})
		return
	}

	parts := strings.Split(q, ",")
	var queries []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			queries = append(queries, p)
		}
	}

	if len(queries) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "query required"})
		return
	}
	if len(queries) > 5 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "maximum 5 concurrent queries allowed"})
		return
	}

	limit := cveDefaultLimit
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > cveMaxLimit {
		limit = cveMaxLimit
	}

	ctx := c.Request.Context()
	rdb := getRedis(c)
	f := cveFetchFromCtx(c)
	// v6: cache entry now wraps results + timestamp for stale-while-revalidate.
	cacheKey := "cve:search:v6:" + sha1Hex(fmt.Sprintf("%s|%s|%d", strings.ToLower(q), strings.ToLower(version), limit))

	audit := func(n int, note string) {
		userID, _ := middleware.GetUserID(c)
		var uidPtr *uuid.UUID
		if userID != uuid.Nil {
			uidPtr = &userID
		}
		res := q
		if version != "" {
			res = q + "@" + version
		}
		writeAudit(c, db, uidPtr, nil, "cve.search", res, fmt.Sprintf("%s: %d results", note, n))
	}

	// runSearch performs the actual upstream NVD work. It takes a plain context
	// (no gin.Context) so it is safe to run in a detached background refresh.
	// Returns the summaries and whether at least one query succeeded.
	runSearch := func(rctx context.Context) ([]CveSummary, bool, bool) {
		sctx, cancel := context.WithTimeout(rctx, cveSearchBudget)
		defer cancel()
		var (
			all         []CveSummary
			failures    int
			rateLimited bool
			mu          sync.Mutex
			wg          sync.WaitGroup
		)
		for _, singleQ := range queries {
			keyword := singleQ
			if version != "" {
				keyword = singleQ + " " + version
			}
			wg.Add(1)
			go func(kw string) {
				defer wg.Done()
				res, err := searchNVD(sctx, f, kw, limit)
				mu.Lock()
				if err != nil {
					log.Printf("[cve] nvd search error for %q: %v", kw, err)
					failures++
					if errors.Is(err, errNVDRateLimited) {
						rateLimited = true
					}
				} else {
					all = append(all, res...)
				}
				mu.Unlock()
			}(keyword)
		}
		wg.Wait()
		if failures == len(queries) {
			return nil, false, rateLimited // every query failed → don't cache, surface error
		}
		s := mergeCveSummaries(all)
		enrichWithRiskData(sctx, s) // EPSS + KEV folded in before caching
		return s, true, false
	}

	// loadFresh fetches + caches, collapsing concurrent identical calls via
	// singleflight so a stampede of the same query hits NVD only once.
	loadFresh := func(rctx context.Context) ([]CveSummary, bool, bool) {
		v, _, _ := cveSearchSF.Do(cacheKey, func() (interface{}, error) {
			s, ok, rl := runSearch(rctx)
			if ok && rdb != nil {
				if b, e := json.Marshal(cveCacheEntry{Data: s, CachedAt: time.Now().UTC()}); e == nil {
					rdb.Set(context.Background(), cacheKey, b, cveSearchTTL)
				}
			}
			return cveResult{sums: s, ok: ok, rateLimited: rl}, nil
		})
		r, _ := v.(cveResult)
		return r.sums, r.ok, r.rateLimited
	}

	// ── Stale-while-revalidate: serve cache instantly, refresh if stale ──
	if rdb != nil {
		if b, err := rdb.Get(ctx, cacheKey).Bytes(); err == nil {
			var entry cveCacheEntry
			if json.Unmarshal(b, &entry) == nil && entry.Data != nil {
				c.JSON(http.StatusOK, gin.H{"success": true, "data": entry.Data})
				if time.Since(entry.CachedAt) > cveSoftTTL {
					// Stale → refresh in the background (detached context).
					go loadFresh(context.Background())
				}
				audit(len(entry.Data), "cache")
				return
			}
		}
	}

	// ── Cache miss: fetch synchronously ──
	summaries, ok, rateLimited := loadFresh(ctx)
	if !ok {
		if rateLimited {
			c.JSON(http.StatusTooManyRequests, gin.H{"success": false, "error": "NVD is rate-limiting requests right now. Configure an NVD API key (NVD_API_KEY) or retry in a few seconds."})
			return
		}
		c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": "failed to fetch from NVD"})
		return
	}
	audit(len(summaries), "live")
	c.JSON(http.StatusOK, gin.H{"success": true, "data": summaries})
}

// cveResult is the singleflight payload for a search (results + success flag).
type cveResult struct {
	sums        []CveSummary
	ok          bool
	rateLimited bool
}

// GetCVE handles GET /api/v1/cve/:id
func GetCVE(c *gin.Context) {
	id := strings.ToUpper(strings.TrimSpace(c.Param("id")))
	if !cveIDRegex.MatchString(id) {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid CVE ID format"})
		return
	}

	ctx := c.Request.Context()
	rdb := getRedis(c)
	// v2: shape gained EPSS score/percentile + IsKEV flag.
	cacheKey := "cve:detail:v2:" + id

	if rdb != nil {
		if b, err := rdb.Get(ctx, cacheKey).Bytes(); err == nil {
			var cached CveDetail
			if json.Unmarshal(b, &cached) == nil {
				c.JSON(http.StatusOK, gin.H{"success": true, "data": cached})
				return
			}
		}
	}

	params := url.Values{}
	params.Set("cveId", id)
	raw, status, err := fetchNVD(ctx, cveFetchFromCtx(c), params)
	if err != nil {
		log.Printf("[cve] nvd detail error: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": "failed to fetch from NVD"})
		return
	}
	if status != http.StatusOK {
		log.Printf("[cve] nvd detail non-200: %d", status)
		c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": fmt.Sprintf("NVD returned status %d", status)})
		return
	}

	detail, err := parseNVDDetail(raw)
	if err != nil {
		log.Printf("[cve] nvd parse detail error: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": "failed to parse NVD response"})
		return
	}
	if detail == nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "CVE not found"})
		return
	}

	// Single-CVE enrichment: inline (the batch helper takes a slice by value
	// and we have a pointer here, so calling it would no-op on the detail).
	updateCISACatalog()
	if m := fetchEPSSBatch(ctx, []string{detail.ID}); m != nil {
		if e, ok := m[detail.ID]; ok {
			detail.EPSSScore = e.Score
			detail.EPSSPercentile = e.Percentile
		}
	}
	detail.IsKEV = isCISAExploited(detail.ID)

	if rdb != nil {
		if b, err := json.Marshal(detail); err == nil {
			rdb.Set(ctx, cacheKey, b, cveDetailTTL)
		}
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": detail})
}

// GetCVEPoCs handles GET /api/v1/cve/:id/pocs
func GetCVEPoCs(c *gin.Context) {
	id := strings.ToUpper(strings.TrimSpace(c.Param("id")))
	if !cveIDRegex.MatchString(id) {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid CVE ID format"})
		return
	}

	ctx := c.Request.Context()
	rdb := getRedis(c)
	cacheKey := "cve:pocs:" + id

	if rdb != nil {
		if b, err := rdb.Get(ctx, cacheKey).Bytes(); err == nil {
			var cached []PocRepo
			if json.Unmarshal(b, &cached) == nil {
				c.JSON(http.StatusOK, gin.H{"success": true, "data": cached})
				return
			}
		}
	}

	repos, status, err := fetchGitHubPocs(ctx, c, id)
	if err != nil {
		log.Printf("[cve] github pocs error: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": "failed to fetch from GitHub"})
		return
	}
	if status != http.StatusOK {
		log.Printf("[cve] github pocs non-200: %d", status)
		c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": fmt.Sprintf("GitHub returned status %d", status)})
		return
	}

	if rdb != nil {
		if b, err := json.Marshal(repos); err == nil {
			rdb.Set(ctx, cacheKey, b, cvePoCsTTL)
		}
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": repos})
}

// GetCVERelatedIOCs handles GET /api/v1/cve/:id/iocs
// It searches the local IOC database for indicators related to the given CVE ID.
func GetCVERelatedIOCs(c *gin.Context) {
	id := strings.ToUpper(strings.TrimSpace(c.Param("id")))
	if !cveIDRegex.MatchString(id) {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid CVE ID format"})
		return
	}

	db := c.MustGet("db").(*gorm.DB)

	var iocs []models.IOC
	// Search in Value, Type, or Description for the CVE ID
	// Usually OpenCTI IOCs have the CVE ID in the description or as a tag (which we store in description for now)
	err := db.Where("description LIKE ? OR value LIKE ?", "%"+id+"%", "%"+id+"%").
		Order("created_at desc").
		Limit(100).
		Find(&iocs).Error

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Database error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": iocs})
}

// ───────────────────────── helpers ─────────────────────────

// searchNVD does the two-call NVD search (meta probe + last-page fetch) and
// returns parsed summaries sorted by published date desc. Extracted from the
// old SearchCVE so it can run in parallel with the WPScan source.
//
// We fetch the LAST page (startIndex = total - limit) because NVD's natural
// order is roughly CVE-ID ascending; the last page therefore contains the
// newest CVEs for the keyword. The 50-result hard cap that motivated the
// original "last page" hack is now 500, so the cliff is far less sharp.
func searchNVD(ctx context.Context, f cveFetch, keyword string, limit int) ([]CveSummary, error) {
	upper := strings.ToUpper(strings.TrimSpace(keyword))
	var paramKey, paramVal string

	if cveIDRegex.MatchString(upper) {
		paramKey = "cveId"
		paramVal = upper
	} else if match, _ := regexp.MatchString(`^CWE-\d+$`, upper); match {
		paramKey = "cweId"
		paramVal = upper
	} else {
		paramKey = "keywordSearch"
		paramVal = strings.TrimSpace(keyword)
	}

	// Exact CVE/CWE lookups return a small, bounded result set — a single direct
	// call is enough, no need to probe for the total first.
	if paramKey != "keywordSearch" {
		params := url.Values{}
		params.Set(paramKey, paramVal)
		params.Set("resultsPerPage", strconv.Itoa(limit))
		raw, status, err := fetchNVD(ctx, f, params)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, nvdStatusError(status)
		}
		return parseNVDSummaries(raw)
	}

	// NVD API 2.0 orders matches by published date ASCENDING with no sort param,
	// so the NEWEST CVEs live on the LAST page. Reading totalResults used to cost a
	// full `limit`-row page (100 hydrated CVE records ≈ 400KB); for a broad keyword
	// like "windows 11" that probe alone took ~15s and, together with the last-page
	// fetch, blew the request budget → 502. Instead probe the count with a 1-row
	// page (a few hundred bytes, sub-second) and then fetch ONLY the newest page.
	countParams := url.Values{}
	countParams.Set(paramKey, paramVal)
	countParams.Set("resultsPerPage", "1")
	raw, status, err := fetchNVD(ctx, f, countParams)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, nvdStatusError(status)
	}
	var meta struct {
		TotalResults int `json:"totalResults"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil, err
	}
	if meta.TotalResults == 0 {
		return nil, nil
	}

	// Fetch a single page ending at the newest result. When the whole match set
	// fits in one page startIdx is 0 and this returns everything.
	startIdx := meta.TotalResults - limit
	if startIdx < 0 {
		startIdx = 0
	}
	dataParams := url.Values{}
	dataParams.Set(paramKey, paramVal)
	dataParams.Set("resultsPerPage", strconv.Itoa(limit))
	dataParams.Set("startIndex", strconv.Itoa(startIdx))
	raw, status, err = fetchNVD(ctx, f, dataParams)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, nvdStatusError(status)
	}
	return parseNVDSummaries(raw)
}

// nvdStatusError maps a non-200 NVD status to an error, tagging throttle
// responses (403/429/503) with errNVDRateLimited so the handler can surface a
// distinct, actionable message.
func nvdStatusError(status int) error {
	switch status {
	case http.StatusForbidden, http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return fmt.Errorf("NVD search status %d: %w", status, errNVDRateLimited)
	default:
		return fmt.Errorf("NVD search status %d", status)
	}
}

// resolveProductCPE looks up a product name in NVD's CPE dictionary and returns a
// "cpe:2.3:a:vendor:product" (no version) for the best application match. This lets
// CVE matching stay CPE-accurate (version-range aware) even when the fingerprinter
// didn't supply a CPE — far less noisy than a bare keyword search.
func resolveProductCPE(ctx context.Context, f cveFetch, product string) (string, bool) {
	product = strings.ToLower(strings.TrimSpace(product))
	if product == "" {
		return "", false
	}
	base := f.nvdURL
	if base == "" {
		base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	}
	cpeBase := strings.Replace(base, "/cves/2.0", "/cpes/2.0", 1)

	params := url.Values{}
	params.Set("keywordSearch", product)
	params.Set("resultsPerPage", "50")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cpeBase+"?"+params.Encode(), nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Accept", "application/json")
	if f.apiKey != "" {
		req.Header.Set("apiKey", f.apiKey)
	}
	resp, err := cveHTTPClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return "", false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false
	}

	var r struct {
		Products []struct {
			CPE struct {
				CpeName    string `json:"cpeName"`
				Deprecated bool   `json:"deprecated"`
			} `json:"cpe"`
		} `json:"products"`
	}
	if json.Unmarshal(body, &r) != nil {
		return "", false
	}

	// Prefer a non-deprecated application ("a") CPE whose product component equals
	// the search term; fall back to the first product that contains it.
	var exact, contains string
	target := strings.ReplaceAll(product, " ", "_")
	for _, p := range r.Products {
		if p.CPE.Deprecated {
			continue
		}
		parts := strings.Split(p.CPE.CpeName, ":")
		if len(parts) < 5 || parts[2] != "a" {
			continue
		}
		vendor, prod := parts[3], parts[4]
		if vendor == "" || vendor == "*" || prod == "" || prod == "*" {
			continue
		}
		vp := fmt.Sprintf("cpe:2.3:a:%s:%s", vendor, prod)
		if prod == target || prod == product {
			exact = vp
			break
		}
		if contains == "" && strings.Contains(prod, target) {
			contains = vp
		}
	}
	if exact != "" {
		return exact, true
	}
	if contains != "" {
		return contains, true
	}
	return "", false
}

// mergeCveSummaries deduplicates by CVE-ID across multiple parallel NVD
// query results and returns them sorted by published_date desc.
func mergeCveSummaries(results []CveSummary) []CveSummary {
	seen := make(map[string]struct{}, len(results))
	out := make([]CveSummary, 0, len(results))
	for _, s := range results {
		if s.ID == "" {
			continue
		}
		if _, dup := seen[s.ID]; dup {
			continue
		}
		seen[s.ID] = struct{}{}
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].PublishedDate > out[j].PublishedDate
	})
	return out
}

// cveFetch carries the NVD endpoint + API key, captured from the gin context so
// background (stale-while-revalidate) refreshes can run after the request ends.
type cveFetch struct {
	nvdURL string
	apiKey string
}

func cveFetchFromCtx(c *gin.Context) cveFetch {
	f := cveFetch{nvdURL: "https://services.nvd.nist.gov/rest/json/cves/2.0"}
	if c != nil {
		if cfg, ok := c.Get("config"); ok {
			f.nvdURL = cfg.(*config.Config).APINvdURL
		}
		if v, _ := c.Get("nvdAPIKey"); v != nil {
			if key, _ := v.(string); key != "" {
				f.apiKey = key
			}
		}
	}
	return f
}

func fetchNVD(ctx context.Context, f cveFetch, params url.Values) ([]byte, int, error) {
	nvdURL := f.nvdURL
	if nvdURL == "" {
		nvdURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, nvdURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	if f.apiKey != "" {
		req.Header.Set("apiKey", f.apiKey)
	}
	resp, err := cveHTTPClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func fetchGitHubPocs(ctx context.Context, c *gin.Context, cveID string) ([]PocRepo, int, error) {
	params := url.Values{}
	params.Set("q", cveID)
	params.Set("sort", "stars")
	params.Set("order", "desc")
	params.Set("per_page", strconv.Itoa(cvePoCsPerPage))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubBaseURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if c != nil {
		if v, _ := c.Get("githubToken"); v != nil {
			if t, _ := v.(string); t != "" {
				req.Header.Set("Authorization", "Bearer "+t)
			}
		}
	}

	resp, err := cveHTTPClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, nil
	}

	var payload struct {
		Items []struct {
			Name        string `json:"name"`
			HTMLURL     string `json:"html_url"`
			Description string `json:"description"`
			Stargazers  int    `json:"stargazers_count"`
			Owner       struct {
				Login string `json:"login"`
			} `json:"owner"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, resp.StatusCode, err
	}
	out := make([]PocRepo, 0, len(payload.Items))
	for _, it := range payload.Items {
		out = append(out, PocRepo{
			Name:        it.Name,
			HTMLURL:     it.HTMLURL,
			Description: it.Description,
			Stars:       it.Stargazers,
			Owner:       it.Owner.Login,
		})
	}
	return out, resp.StatusCode, nil
}

// nvdCveItem is the subset of the NVD payload we care about. The full schema
// is large; only fields actually rendered in the dashboard are mapped.
type nvdCveItem struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		CvssMetricV31 []nvdCvssMetric `json:"cvssMetricV31"`
		CvssMetricV30 []nvdCvssMetric `json:"cvssMetricV30"`
		CvssMetricV2  []nvdCvssMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	Configurations []struct {
		Nodes []struct {
			CpeMatch []struct {
				Criteria string `json:"criteria"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
	References []struct {
		URL    string   `json:"url"`
		Source string   `json:"source"`
		Tags   []string `json:"tags"`
	} `json:"references"`
}

type nvdCvssMetric struct {
	CvssData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE nvdCveItem `json:"cve"`
	} `json:"vulnerabilities"`
}

func parseNVDSummaries(raw []byte) ([]CveSummary, error) {
	var resp nvdResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	out := make([]CveSummary, 0, len(resp.Vulnerabilities))
	for _, v := range resp.Vulnerabilities {
		out = append(out, summaryFromCVE(v.CVE))
	}
	// NVD does not support a sort parameter; results are returned in an
	// implementation-defined order. Sort by published date descending so the
	// most recently disclosed CVEs surface first in the dashboard.
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].PublishedDate > out[j].PublishedDate
	})
	return out, nil
}

func parseNVDDetail(raw []byte) (*CveDetail, error) {
	var resp nvdResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	if len(resp.Vulnerabilities) == 0 {
		return nil, nil
	}
	cve := resp.Vulnerabilities[0].CVE
	summary := summaryFromCVE(cve)

	refs := make([]CveReference, 0, len(cve.References))
	for _, r := range cve.References {
		refs = append(refs, CveReference{URL: r.URL, Source: r.Source, Tags: r.Tags})
	}
	cfgs := make([]string, 0)
	seen := make(map[string]struct{})
	for _, conf := range cve.Configurations {
		for _, node := range conf.Nodes {
			for _, m := range node.CpeMatch {
				if _, dup := seen[m.Criteria]; dup {
					continue
				}
				seen[m.Criteria] = struct{}{}
				cfgs = append(cfgs, m.Criteria)
			}
		}
	}
	return &CveDetail{
		CveSummary:     summary,
		References:     refs,
		Configurations: cfgs,
	}, nil
}

func summaryFromCVE(cve nvdCveItem) CveSummary {
	desc := ""
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			desc = d.Value
			break
		}
	}
	score, sev := pickCvss(cve)

	products := make([]string, 0)
	seen := make(map[string]struct{})
	for _, conf := range cve.Configurations {
		for _, node := range conf.Nodes {
			for _, m := range node.CpeMatch {
				name := productFromCPE(m.Criteria)
				if name == "" {
					continue
				}
				if _, dup := seen[name]; dup {
					continue
				}
				seen[name] = struct{}{}
				products = append(products, name)
			}
		}
	}

	return CveSummary{
		ID:               cve.ID,
		Description:      desc,
		CVSSScore:        score,
		Severity:         sev,
		PublishedDate:    cve.Published,
		LastModified:     cve.LastModified,
		AffectedProducts: products,
	}
}

// pickCvss prefers CVSS v3.1, falls back to v3.0, then v2. Severity is derived
// from the score when the upstream string is missing (CVSS v2 stores it on the
// outer metric instead of cvssData).
func pickCvss(cve nvdCveItem) (float64, string) {
	if len(cve.Metrics.CvssMetricV31) > 0 {
		m := cve.Metrics.CvssMetricV31[0]
		return m.CvssData.BaseScore, normalizeSeverity(m.CvssData.BaseSeverity, m.CvssData.BaseScore)
	}
	if len(cve.Metrics.CvssMetricV30) > 0 {
		m := cve.Metrics.CvssMetricV30[0]
		return m.CvssData.BaseScore, normalizeSeverity(m.CvssData.BaseSeverity, m.CvssData.BaseScore)
	}
	if len(cve.Metrics.CvssMetricV2) > 0 {
		m := cve.Metrics.CvssMetricV2[0]
		return m.CvssData.BaseScore, normalizeSeverity(m.BaseSeverity, m.CvssData.BaseScore)
	}
	return 0, "none"
}

func normalizeSeverity(label string, score float64) string {
	if s := strings.ToLower(label); s != "" {
		return s
	}
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}

// productFromCPE extracts "vendor:product" from a CPE 2.3 string like
// "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*". Returns "" on malformed input.
func productFromCPE(cpe string) string {
	parts := strings.Split(cpe, ":")
	if len(parts) < 6 {
		return ""
	}
	vendor := parts[3]
	product := parts[4]
	if vendor == "" || product == "" || vendor == "*" || product == "*" {
		return ""
	}
	return vendor + ":" + product
}

func sha1Hex(s string) string {
	sum := sha1.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// epssData holds EPSS metrics for a single CVE.
//
// Score is the probability (0-1) of exploitation in the next 30 days.
// Percentile (0-1) is the rank against all CVEs that have an EPSS score.
type epssData struct {
	Score      float64
	Percentile float64
}

// epssChunkSize bounds how many CVE IDs go in one EPSS request. The FIRST.org
// endpoint defaults to 100 results per page, so passing more than 100 IDs would
// silently drop the overflow — chunking keeps every requested CVE covered.
const epssChunkSize = 100

// fetchEPSSBatch queries FIRST.org EPSS API for many CVEs, splitting the request
// into <=100-ID chunks so no result is silently truncated by the API's page
// limit. CVEs without an EPSS score (too new, withdrawn, etc.) are simply absent
// from the returned map — callers should treat absence as "no data" (zero
// values), not failure.
//
// A failing chunk is skipped (best-effort) rather than failing the whole batch,
// so partial risk data still renders.
func fetchEPSSBatch(ctx context.Context, ids []string) map[string]epssData {
	if len(ids) == 0 {
		return nil
	}
	out := make(map[string]epssData, len(ids))
	for start := 0; start < len(ids); start += epssChunkSize {
		end := start + epssChunkSize
		if end > len(ids) {
			end = len(ids)
		}
		for k, v := range fetchEPSSChunk(ctx, ids[start:end]) {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// fetchEPSSChunk fetches EPSS metrics for up to epssChunkSize CVE IDs in one
// request. Returns nil on any network/parse error.
func fetchEPSSChunk(ctx context.Context, ids []string) map[string]epssData {
	if len(ids) == 0 {
		return nil
	}
	u := "https://api.first.org/data/v1/epss?cve=" + strings.Join(ids, ",")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := cveHTTPClient.Do(req)
	if err != nil {
		log.Printf("[cve] epss fetch error: %v", err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("[cve] epss non-200: %d", resp.StatusCode)
		return nil
	}

	var res struct {
		Data []struct {
			CVE        string `json:"cve"`
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		log.Printf("[cve] epss parse error: %v", err)
		return nil
	}

	out := make(map[string]epssData, len(res.Data))
	for _, d := range res.Data {
		score, _ := strconv.ParseFloat(d.EPSS, 64)
		pct, _ := strconv.ParseFloat(d.Percentile, 64)
		out[d.CVE] = epssData{Score: score, Percentile: pct}
	}
	return out
}

// enrichWithRiskData populates EPSSScore, EPSSPercentile, and IsKEV on each
// summary in place. Modifications go through slice indexing so the caller's
// slice header is updated. Best-effort: a failing EPSS call leaves scores at
// zero and the KEV flag still works from the locally cached CISA catalog.
func enrichWithRiskData(ctx context.Context, summaries []CveSummary) {
	if len(summaries) == 0 {
		return
	}
	// CISA KEV refresh and the EPSS batch hit different upstreams; run them
	// concurrently so a cold search pays one round-trip, not two. updateCISACatalog
	// is 24h-debounced (and warmed at startup), so this is usually a no-op.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		updateCISACatalog()
	}()

	ids := make([]string, 0, len(summaries))
	for _, s := range summaries {
		ids = append(ids, s.ID)
	}
	epssMap := fetchEPSSBatch(ctx, ids)
	wg.Wait()

	for i := range summaries {
		if e, ok := epssMap[summaries[i].ID]; ok {
			summaries[i].EPSSScore = e.Score
			summaries[i].EPSSPercentile = e.Percentile
		}
		summaries[i].IsKEV = isCISAExploited(summaries[i].ID)
	}
}

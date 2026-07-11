package osint

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/analysishub/backend/internal/models"
)

// rlNVD paces NVD queries. The public API allows ~5 requests / 30s without a key
// (~6s spacing); a configured NVD_API_KEY raises this, but 6s is the safe floor.
var rlNVD = newRateLimiter(6 * time.Second)

// rlEPSS paces FIRST.org EPSS queries (generous public limit; 1s spacing is safe).
var rlEPSS = newRateLimiter(1 * time.Second)

// maxCVEFindings bounds how many CVEs a single product lookup contributes, so a
// widely-vulnerable product cannot flood the report. Highest CVSS first.
const maxCVEFindings = 12

// productCPE map has been removed in favor of Dynamic Fuzzy Matching (Keyword Search).

// versionRe extracts a dotted numeric version (e.g. "1.18.0", "8.2", "2.4.49")
// from a banner or header value. Suffixes like "p1" or "-Ubuntu" are dropped so
// the version matches NVD's CPE version component.
var versionRe = regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`)

// extractVersion returns the first dotted numeric version in s, or "".
func extractVersion(s string) string {
	return versionRe.FindString(s)
}

// nvdCVEResponse is the minimal slice of the NVD 2.0 schema the matcher reads.
type nvdCVEResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				V31 []nvdMetric `json:"cvssMetricV31"`
				V30 []nvdMetric `json:"cvssMetricV30"`
				V2  []nvdMetric `json:"cvssMetricV2"`
			} `json:"metrics"`
			CisaExploitAdd string `json:"cisaExploitAdd"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdMetric struct {
	CvssData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

// cveHit is one matched CVE with its score, used for sorting before emission.
type cveHit struct {
	id    string
	score float64
	sev   string
	desc  string
	isKEV bool
	epss  float64 // FIRST.org EPSS probability (0-1); 0 when unknown
}

// lookupCVEs queries NVD for CVEs affecting product@version. It first resolves
// the product to a CPE and runs a precise version-aware match (virtualMatchString);
// if no CPE is found it falls back to fuzzy keyword search. Matched CVEs are then
// enriched with EPSS exploitation probabilities. Results are cached.
func lookupCVEs(ctx context.Context, env *collectorEnv, sourceLabel, product, version string) []models.OsintFinding {
	product = strings.ToLower(strings.TrimSpace(product))
	version = extractVersion(version)
	if product == "" || version == "" {
		return nil
	}
	// Precise path (CPE resolve + version-range match) costs 1-2 extra NVD calls
	// per product. That's only affordable at the fast (API-key) rate limit —
	// without a key NVD is throttled to ~6s/call, so we keep the original single
	// keyword call to avoid slowing/blowing the collector's time budget.
	if env.cfg.NVDAPIKey != "" {
		if cpe, ok := resolveProductCPE(ctx, env, product); ok {
			if out := cveByCPE(ctx, env, sourceLabel, cpe, product, version); out != nil {
				return out
			}
		}
	}
	// Fallback / no-key path: fuzzy keyword search (enriched with EPSS).
	return cveByKeyword(ctx, env, sourceLabel, product, version)
}

// resolveProductCPE queries NVD's CPE dictionary for a product name and returns
// the vendor:product portion of the best-matching CPE as "cpe:2.3:a:<vendor>:<product>".
// Cached for a week — product→CPE mappings are effectively static.
func resolveProductCPE(ctx context.Context, env *collectorEnv, product string) (string, bool) {
	base := "https://services.nvd.nist.gov/rest/json/cpes/2.0"
	u := base + "?resultsPerPage=1&keywordSearch=" + url.QueryEscape(product)
	headers := map[string]string{}
	if env.cfg.NVDAPIKey != "" {
		headers["apiKey"] = env.cfg.NVDAPIKey
	}
	nctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	var r struct {
		Products []struct {
			CPE struct {
				CPEName string `json:"cpeName"`
			} `json:"cpe"`
		} `json:"products"`
	}
	status, err := cachedGetJSON(nctx, env.cache, "nvd_cpe:"+product, rlNVD, u, headers, &r, ttlCPE)
	if err != nil || status != 200 || len(r.Products) == 0 {
		return "", false
	}
	vendor, prod, ok := parseCPEVendorProduct(r.Products[0].CPE.CPEName)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("cpe:2.3:a:%s:%s", vendor, prod), true
}

// parseCPEVendorProduct extracts the vendor and product from a CPE 2.3 string
// (cpe:2.3:a:<vendor>:<product>:<version>:...). Returns ok=false when the CPE is
// malformed or carries no concrete vendor/product.
func parseCPEVendorProduct(cpe string) (vendor, product string, ok bool) {
	parts := strings.Split(cpe, ":")
	if len(parts) < 5 || !strings.HasPrefix(cpe, "cpe:2.3:") {
		return "", "", false
	}
	vendor, product = parts[3], parts[4]
	if vendor == "" || vendor == "*" || product == "" || product == "*" {
		return "", "", false
	}
	return vendor, product, true
}

// nvdBaseURL returns the configured NVD CVE endpoint (or the public default) and
// applies the faster rate-limit spacing when an API key is present.
func nvdBaseURL(env *collectorEnv) (string, map[string]string) {
	base := env.cfg.APINvdURL
	if base == "" {
		base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	}
	headers := map[string]string{}
	if env.cfg.NVDAPIKey != "" {
		headers["apiKey"] = env.cfg.NVDAPIKey
		// With an API key NVD allows 50 req/30s (vs 5); tighten the shared limiter.
		rlNVD.mu.Lock()
		rlNVD.interval = 600 * time.Millisecond
		rlNVD.mu.Unlock()
	}
	return base, headers
}

// parseCVEHits maps an NVD response into cveHit records.
func parseCVEHits(r *nvdCVEResponse) []cveHit {
	hits := make([]cveHit, 0, len(r.Vulnerabilities))
	for i := range r.Vulnerabilities {
		c := &r.Vulnerabilities[i].CVE
		score, sev := nvdScore(c.Metrics.V31, c.Metrics.V30, c.Metrics.V2)
		desc := ""
		for _, d := range c.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}
		hits = append(hits, cveHit{id: c.ID, score: score, sev: sev, desc: desc, isKEV: c.CisaExploitAdd != ""})
	}
	return hits
}

// cveByCPE queries NVD with a version-aware virtualMatchString (precise: only CVEs
// whose CPE configuration actually covers this version), then builds findings.
func cveByCPE(ctx context.Context, env *collectorEnv, sourceLabel, cpePrefix, prod, version string) []models.OsintFinding {
	base, headers := nvdBaseURL(env)
	// cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:* — NVD expands version ranges.
	vms := fmt.Sprintf("%s:%s:*:*:*:*:*:*:*", cpePrefix, version)
	u := base + "?resultsPerPage=20&virtualMatchString=" + url.QueryEscape(vms)

	nctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	var r nvdCVEResponse
	status, err := cachedGetJSON(nctx, env.cache, "nvd_cpe_match:"+cpePrefix+":"+version, rlNVD, u, headers, &r, ttlNVD)
	if err != nil || status != 200 || len(r.Vulnerabilities) == 0 {
		return nil
	}
	return buildCVEFindings(nctx, env, sourceLabel, prod, version, r.TotalResults, parseCVEHits(&r), "CPE")
}

// cveByKeyword queries NVD for CVEs affecting product@version using Fuzzy Matching
// via keywordSearch, returning findings (highest CVSS first), cached.
func cveByKeyword(ctx context.Context, env *collectorEnv, sourceLabel, prod, version string) []models.OsintFinding {
	if prod == "" || version == "" {
		return nil
	}
	base, headers := nvdBaseURL(env)
	u := base + "?resultsPerPage=20&keywordSearch=" + url.QueryEscape(fmt.Sprintf("%s %s", prod, version))

	// Cap each NVD call so a slow/throttled response can't drain the collector's
	// whole time budget (CVE matching is best-effort enrichment).
	nctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	var r nvdCVEResponse
	status, err := cachedGetJSON(nctx, env.cache, "nvd_kw:"+prod+":"+version, rlNVD, u, headers, &r, ttlNVD)
	if err != nil || status != 200 || len(r.Vulnerabilities) == 0 {
		return nil
	}
	return buildCVEFindings(nctx, env, sourceLabel, prod, version, r.TotalResults, parseCVEHits(&r), "NVD")
}

// buildCVEFindings sorts hits (highest CVSS first), caps them, enriches the top
// matches with EPSS exploitation probabilities, and emits the summary + per-CVE
// findings. `method` labels the match path in the emit log (CPE vs NVD keyword).
func buildCVEFindings(ctx context.Context, env *collectorEnv, sourceLabel, prod, version string, total int, hits []cveHit, method string) []models.OsintFinding {
	// Highest CVSS first so the most serious CVEs lead the report.
	sort.Slice(hits, func(i, j int) bool { return hits[i].score > hits[j].score })
	if len(hits) > maxCVEFindings {
		hits = hits[:maxCVEFindings]
	}

	// EPSS enrichment: batch-fetch exploitation probabilities for the capped hits.
	if ids := make([]string, 0, len(hits)); len(hits) > 0 {
		for _, h := range hits {
			ids = append(ids, h.id)
		}
		if epss := fetchEPSSScores(ctx, env, ids); len(epss) > 0 {
			for i := range hits {
				hits[i].epss = epss[hits[i].id]
			}
		}
	}

	prettyProduct := strings.Title(prod) //nolint:staticcheck // ASCII product names only
	out := make([]models.OsintFinding, 0, len(hits)+1)
	summary := newFinding(sourceLabel, "vulnerability",
		fmt.Sprintf("%s %s - %d known CVE(s)", prettyProduct, version, total),
		fmt.Sprintf("NVD lists %d CVE(s) for %s %s", total, prettyProduct, version))
	summary.Severity = "medium"
	if len(hits) > 0 && hits[0].score >= 9.0 {
		summary.Severity = "critical"
	} else if len(hits) > 0 && hits[0].score >= 7.0 {
		summary.Severity = "high"
	}
	summary = withSource(summary, "https://nvd.nist.gov/vuln/search/results?query="+
		url.QueryEscape(prettyProduct+" "+version))
	out = append(out, summary)

	for _, h := range hits {
		title := h.id
		if h.isKEV {
			title = fmt.Sprintf("[KEV] %s", h.id)
		}
		if h.score > 0 {
			title = fmt.Sprintf("%s (CVSS %.1f)", title, h.score)
		}
		if h.epss >= 0.10 {
			title = fmt.Sprintf("%s [EPSS %.0f%%]", title, h.epss*100)
		}
		f := newFinding(sourceLabel, "vulnerability", title, truncate(h.desc, 280))
		f.Severity = cvssToSeverity(h.score, h.sev)
		if h.isKEV {
			f.Severity = "critical"
		}
		f.Data = toJSON(map[string]interface{}{
			"cve": h.id, "cvss": h.score, "product": prettyProduct, "version": version,
			"kev": h.isKEV, "epss": h.epss,
		})
		f = withSource(f, "https://nvd.nist.gov/vuln/detail/"+h.id) // verifiable CVE record
		out = append(out, f)
	}
	env.emit(fmt.Sprintf("[+] %s: %s %s -> %d CVE(s) (%s)", sourceLabel, prettyProduct, version, total, method))
	return out
}

// fetchEPSSScores batch-queries FIRST.org EPSS for CVE IDs (chunked at 100 to
// respect the API's default page size), returning id→probability. Best-effort: a
// failing chunk is skipped. Self-contained so the osint package needs no handler
// import.
func fetchEPSSScores(ctx context.Context, env *collectorEnv, ids []string) map[string]float64 {
	if len(ids) == 0 {
		return nil
	}
	out := make(map[string]float64, len(ids))
	const chunk = 100
	for start := 0; start < len(ids); start += chunk {
		end := start + chunk
		if end > len(ids) {
			end = len(ids)
		}
		part := ids[start:end]
		u := "https://api.first.org/data/v1/epss?cve=" + strings.Join(part, ",")
		var r struct {
			Data []struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		status, err := cachedGetJSON(ctx, env.cache, "epss:"+strings.Join(part, ","), rlEPSS, u, nil, &r, ttlEPSS)
		if err != nil || status != 200 {
			continue
		}
		for _, d := range r.Data {
			if v, e := strconv.ParseFloat(d.EPSS, 64); e == nil {
				out[d.CVE] = v
			}
		}
	}
	return out
}

// nvdScore returns the highest-priority CVSS base score + severity available.
func nvdScore(v31, v30, v2 []nvdMetric) (float64, string) {
	for _, set := range [][]nvdMetric{v31, v30, v2} {
		if len(set) > 0 {
			m := set[0]
			sev := m.CvssData.BaseSeverity
			if sev == "" {
				sev = m.BaseSeverity
			}
			return m.CvssData.BaseScore, sev
		}
	}
	return 0, ""
}

// cvssToSeverity maps a CVSS base score (or NVD label) to the OSINT severity band.
func cvssToSeverity(score float64, label string) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	}
	switch strings.ToUpper(label) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	}
	return "medium"
}

// truncate shortens s to n runes, appending an ellipsis when cut.
func truncate(s string, n int) string {
	rs := []rune(strings.TrimSpace(s))
	if len(rs) <= n {
		return string(rs)
	}
	return string(rs[:n]) + "…"
}

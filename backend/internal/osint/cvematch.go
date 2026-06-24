package osint

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/forensichub/backend/internal/models"
)

// rlNVD paces NVD queries. The public API allows ~5 requests / 30s without a key
// (~6s spacing); a configured NVD_API_KEY raises this, but 6s is the safe floor.
var rlNVD = newRateLimiter(6 * time.Second)

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
	TotalResults  int `json:"totalResults"`
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
	id     string
	score  float64
	sev    string
	desc   string
	isKEV  bool
}

// lookupCVEs queries NVD for CVEs affecting product@version using Fuzzy Matching
// (Keyword Search). Results are cached.
func lookupCVEs(ctx context.Context, env *collectorEnv, sourceLabel, product, version string) []models.OsintFinding {
	product = strings.ToLower(strings.TrimSpace(product))
	version = extractVersion(version)
	if product == "" || version == "" {
		return nil
	}
	return cveByKeyword(ctx, env, sourceLabel, product, version)
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

// cveByKeyword queries NVD for CVEs affecting product@version using Fuzzy Matching
// via keywordSearch, returning findings (highest CVSS first), cached.
func cveByKeyword(ctx context.Context, env *collectorEnv, sourceLabel, prod, version string) []models.OsintFinding {
	if prod == "" || version == "" {
		return nil
	}
	keyword := fmt.Sprintf("%s %s", prod, version)

	base := env.cfg.APINvdURL
	if base == "" {
		base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	}
	u := base + "?resultsPerPage=20&keywordSearch=" + url.QueryEscape(keyword)

	headers := map[string]string{}
	if env.cfg.NVDAPIKey != "" {
		headers["apiKey"] = env.cfg.NVDAPIKey
		// If an API key is provided, the NVD rate limit increases from 5 req/30s to 50 req/30s.
		// Dynamically adjust the shared rate limiter to allow faster lookups (600ms spacing).
		rlNVD.mu.Lock()
		rlNVD.interval = 600 * time.Millisecond
		rlNVD.mu.Unlock()
	}

	// Cap each NVD call so a slow/throttled response can't drain the collector's
	// whole time budget (CVE matching is best-effort enrichment).
	nctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	var r nvdCVEResponse
	cacheKey := "nvd_kw:" + prod + ":" + version
	status, err := cachedGetJSON(nctx, env.cache, cacheKey, rlNVD, u, headers, &r, ttlNVD)
	if err != nil || status != 200 || len(r.Vulnerabilities) == 0 {
		return nil
	}

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
		isKEV := c.CisaExploitAdd != ""
		hits = append(hits, cveHit{id: c.ID, score: score, sev: sev, desc: desc, isKEV: isKEV})
	}
	// Highest CVSS first so the most serious CVEs lead the report.
	sort.Slice(hits, func(i, j int) bool { return hits[i].score > hits[j].score })
	if len(hits) > maxCVEFindings {
		hits = hits[:maxCVEFindings]
	}

	prettyProduct := strings.Title(prod) //nolint:staticcheck // ASCII product names only
	out := make([]models.OsintFinding, 0, len(hits)+1)
	summary := newFinding(sourceLabel, "vulnerability",
		fmt.Sprintf("%s %s - %d known CVE(s)", prettyProduct, version, r.TotalResults),
		fmt.Sprintf("NVD lists %d CVE(s) for %s %s", r.TotalResults, prettyProduct, version))
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
		f := newFinding(sourceLabel, "vulnerability", title, truncate(h.desc, 280))
		f.Severity = cvssToSeverity(h.score, h.sev)
		if h.isKEV {
			f.Severity = "critical"
		}
		f.Data = toJSON(map[string]interface{}{"cve": h.id, "cvss": h.score, "product": prettyProduct, "version": version, "kev": h.isKEV})
		f = withSource(f, "https://nvd.nist.gov/vuln/detail/"+h.id) // verifiable CVE record
		out = append(out, f)
	}
	env.emit(fmt.Sprintf("[+] %s: %s %s -> %d CVE(s) (NVD)", sourceLabel, prettyProduct, version, r.TotalResults))
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

package handlers

import (
	"context"

	"github.com/analysishub/backend/internal/vulnscan"
)

// cveEnricher implements vulnscan.Enricher using the platform's EPSS + CISA-KEV
// lookups (which live, unexported, in this package). Injected into the vuln-scan
// engine from main.go so the engine stays decoupled from the CVE data source.
type cveEnricher struct{}

// NewCVEEnricher returns the handler-backed CVE enricher for the vuln-scan engine.
func NewCVEEnricher() vulnscan.Enricher { return cveEnricher{} }

// maxPocLookups bounds the per-scan public-PoC searches. GitHub's unauthenticated
// code-search allows ~10 requests/minute, so PoC discovery is limited to the most
// exploitable CVEs (KEV or high-EPSS) and capped to stay under that budget.
const maxPocLookups = 8

// pocEPSSThreshold is the EPSS above which a non-KEV CVE still warrants a PoC hunt.
const pocEPSSThreshold = 0.5

func (cveEnricher) EnrichCVEs(ctx context.Context, cveIDs []string) map[string]vulnscan.CVEIntel {
	out := make(map[string]vulnscan.CVEIntel, len(cveIDs))
	if len(cveIDs) == 0 {
		return out
	}
	// Ensure the CISA-KEV catalog is loaded (24h-debounced), then batch EPSS.
	updateCISACatalog()
	epss := fetchEPSSBatch(ctx, cveIDs)
	for _, id := range cveIDs {
		out[id] = vulnscan.CVEIntel{
			EPSS: epss[id].Score,
			KEV:  isCISAExploited(id),
		}
	}

	// Public-exploit discovery for the CVEs that actually matter — a pentester
	// prioritises a CVE with a working public PoC. Bounded to respect API limits.
	lookups := 0
	for _, id := range cveIDs {
		if lookups >= maxPocLookups {
			break
		}
		in := out[id]
		if !in.KEV && in.EPSS < pocEPSSThreshold {
			continue
		}
		repos, status, err := fetchGitHubPocs(ctx, nil, id)
		lookups++
		if err != nil || status != 200 || len(repos) == 0 {
			continue
		}
		in.PocCount = len(repos)
		in.PocURL = repos[0].HTMLURL // fetchGitHubPocs sorts by stars desc
		out[id] = in
	}
	return out
}

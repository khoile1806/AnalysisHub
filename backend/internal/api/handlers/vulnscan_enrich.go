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
	return out
}

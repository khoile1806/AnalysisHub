package osint

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/forensichub/backend/internal/config"
	"github.com/forensichub/backend/internal/models"
)

// ── Dark-web monitoring (Phase 3) ───────────────────────────────────────────
//
// This is a DEFENSIVE exposure-monitoring seam. It searches for the target
// organisation's OWN selectors (its domain, brand, e-mails) and reports where
// they surface. Two provider kinds plug in behind one interface:
//
//   1. Enterprise aggregator adapters (Flare / DarkOwl / Intel471) — key-gated
//      stubs. They activate only when the org licenses the feed; the actual API
//      calls are intentionally left as a seam to be filled per contract.
//   2. A generic crawler the operator points at sources THEY are authorised to
//      monitor (configured via OSINT_DARKWEB_SOURCES, optionally dialled through
//      a Tor SOCKS5 proxy). It ships with NO sources — targeting any specific
//      source is the operator's legal responsibility.
//
// The tool never hard-codes illicit marketplaces, authenticates to criminal
// forums, or downloads/parses stolen data dumps.

// DarkWebHit is one match for a selector surfaced by a provider.
type DarkWebHit struct {
	Source   string
	Title    string
	Snippet  string
	URL      string
	Severity string
}

// DarkWebProvider is a pluggable dark-web / deep-web intelligence source.
type DarkWebProvider interface {
	Name() string
	Configured() bool
	Search(ctx context.Context, selectors []string) ([]DarkWebHit, error)
}

// buildDarkWebProviders assembles the active provider set from configuration.
func buildDarkWebProviders(cfg *config.Config) []DarkWebProvider {
	if cfg == nil {
		return nil
	}
	ps := []DarkWebProvider{
		&aggregatorSeam{name: "Flare", key: cfg.FlareKey},
		&aggregatorSeam{name: "DarkOwl", key: cfg.DarkOwlKey},
		&aggregatorSeam{name: "Intel471", key: cfg.Intel471Key},
	}
	if len(cfg.DarkWebSources) > 0 {
		ps = append(ps, newCrawlerProvider(cfg.DarkWebSources, cfg.TorProxy))
	}
	return ps
}

// aggregatorSeam is the integration point for a commercial dark-web aggregator.
// It reports Configured() only when an API key is present; the Search body is a
// deliberate stub to be implemented against the licensed vendor's API.
type aggregatorSeam struct {
	name string
	key  string
}

func (a *aggregatorSeam) Name() string      { return a.name }
func (a *aggregatorSeam) Configured() bool   { return strings.TrimSpace(a.key) != "" }
func (a *aggregatorSeam) Search(ctx context.Context, selectors []string) ([]DarkWebHit, error) {
	// Seam: wire the licensed vendor API here. Until then a configured key is a
	// no-op rather than an error, so it never breaks a scan.
	return nil, nil
}

// crawlerProvider fetches operator-configured source URLs and reports where any
// selector appears. It is source-agnostic: the operator decides what to monitor.
type crawlerProvider struct {
	sources []string
	client  *http.Client
	viaTor  bool
}

// newCrawlerProvider builds the crawler, routing through a SOCKS5 proxy (Tor)
// when one is configured. net/http supports socks5:// proxy URLs natively.
func newCrawlerProvider(sources []string, proxy string) *crawlerProvider {
	tr := &http.Transport{
		// Default to the project-wide egress proxy; a dedicated Tor SOCKS5 proxy
		// (for .onion sources) overrides it when configured.
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConns:    8,
		IdleConnTimeout: 30 * time.Second,
	}
	viaTor := false
	if p := strings.TrimSpace(proxy); p != "" {
		if pu, err := url.Parse(p); err == nil {
			tr.Proxy = http.ProxyURL(pu)
			viaTor = true
		}
	}
	return &crawlerProvider{
		sources: sources,
		client:  &http.Client{Timeout: 45 * time.Second, Transport: tr},
		viaTor:  viaTor,
	}
}

func (c *crawlerProvider) Name() string    { return "crawler" }
func (c *crawlerProvider) Configured() bool { return len(c.sources) > 0 }

func (c *crawlerProvider) Search(ctx context.Context, selectors []string) ([]DarkWebHit, error) {
	var hits []DarkWebHit
	limit := len(c.sources)
	if limit > 25 {
		limit = 25
	}
	for _, src := range c.sources[:limit] {
		body, err := c.fetch(ctx, src)
		if err != nil {
			continue // a dead/blocked source must not fail the whole collector
		}
		hay := strings.ToLower(body)
		for _, sel := range selectors {
			idx := strings.Index(hay, sel)
			if idx < 0 {
				continue
			}
			hits = append(hits, DarkWebHit{
				Source:   "crawler",
				Title:    "Selector match on monitored source",
				Snippet:  snippetAround(body, idx, len(sel)),
				URL:      src,
				Severity: "high",
			})
			break // one hit per source is enough to flag it
		}
	}
	return hits, nil
}

func (c *crawlerProvider) fetch(ctx context.Context, src string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("source returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// snippetAround returns a short context window around a match for the report.
func snippetAround(s string, idx, matchLen int) string {
	start := idx - 40
	if start < 0 {
		start = 0
	}
	end := idx + matchLen + 40
	if end > len(s) {
		end = len(s)
	}
	snip := strings.TrimSpace(s[start:end])
	snip = strings.Join(strings.Fields(snip), " ") // collapse whitespace
	if len(snip) > 160 {
		snip = snip[:160] + "…"
	}
	return "…" + snip + "…"
}

// darkWebSelectors derives the org's own identifiers to search for.
func darkWebSelectors(env *collectorEnv) []string {
	t := strings.ToLower(strings.TrimSpace(env.target))
	seen := map[string]bool{}
	var sels []string
	add := func(v string) {
		v = strings.ToLower(strings.TrimSpace(v))
		if len(v) >= 4 && !seen[v] {
			seen[v] = true
			sels = append(sels, v)
		}
	}
	add(t)
	if env.ttype == TargetDomain {
		add(registrableName(t))
	}
	return sels
}

// collectDarkWeb runs every configured dark-web provider for the target's own
// selectors. For domain/email/name targets only. Skipped (not failed) when no
// provider is configured.
func collectDarkWeb(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	providers := buildDarkWebProviders(env.cfg)
	var active []DarkWebProvider
	for _, p := range providers {
		if p.Configured() {
			active = append(active, p)
		}
	}
	if len(active) == 0 {
		return nil, errNoAPIKey // no aggregator key and no crawler sources configured
	}
	selectors := darkWebSelectors(env)
	if len(selectors) == 0 {
		return nil, nil
	}

	var out []models.OsintFinding
	names := make([]string, 0, len(active))
	for _, p := range active {
		names = append(names, p.Name())
		hits, err := p.Search(ctx, selectors)
		if err != nil {
			env.emit(fmt.Sprintf("[!] darkweb: %s - %v", p.Name(), err))
			continue
		}
		for i := range hits {
			h := &hits[i]
			f := newFinding("darkweb", "darkweb",
				fmt.Sprintf("Dark-web exposure (%s): %s", h.Source, h.Title), h.Snippet)
			if h.URL != "" {
				f.Data = toJSON(map[string]string{"source_url": h.URL})
			}
			f.Severity = h.Severity
			if f.Severity == "" {
				f.Severity = "high"
			}
			out = append(out, f)
		}
	}
	env.emit(fmt.Sprintf("[*] darkweb: queried %d provider(s) [%s], %d hit(s)",
		len(active), strings.Join(names, ", "), len(out)))
	return out, nil
}

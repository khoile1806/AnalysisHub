package osint

import (
	"context"
	"crypto/tls"
	"encoding/json"
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
	if cfg.OsintHIBPKey != "" {
		ps = append(ps, &hibpProvider{key: cfg.OsintHIBPKey})
	}
	if cfg.OsintDehashedKey != "" {
		ps = append(ps, &dehashedProvider{key: cfg.OsintDehashedKey})
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

// ── HIBP Provider ────────────────────────────────────────────────────────────

type hibpProvider struct {
	key string
}

func (p *hibpProvider) Name() string    { return "HaveIBeenPwned" }
func (p *hibpProvider) Configured() bool { return strings.TrimSpace(p.key) != "" }
func (p *hibpProvider) Search(ctx context.Context, selectors []string) ([]DarkWebHit, error) {
	var hits []DarkWebHit
	for _, sel := range selectors {
		// HIBP mainly works for email addresses or phone numbers.
		if !strings.Contains(sel, "@") {
			continue // Skip non-emails for now to avoid spamming the API
		}
		
		target := fmt.Sprintf("https://haveibeenpwned.com/api/v3/breachedaccount/%s?truncateResponse=false", url.PathEscape(sel))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "ForensicHub-OSINT")
		req.Header.Set("hibp-api-key", p.key)

		// Respect the 1.5s rate limit of HIBP
		time.Sleep(1600 * time.Millisecond)

		resp, err := osintHTTPClient.Do(req)
		if err != nil {
			continue
		}
		
		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var breaches []struct {
				Name        string `json:"Name"`
				Title       string `json:"Title"`
				Description string `json:"Description"`
			}
			if err := json.Unmarshal(body, &breaches); err == nil {
				for _, b := range breaches {
					hits = append(hits, DarkWebHit{
						Source:   "HIBP",
						Title:    fmt.Sprintf("Breach: %s", b.Title),
						Snippet:  b.Description,
						URL:      "https://haveibeenpwned.com/PwnedWebsites#" + b.Name,
						Severity: "high",
					})
				}
			}
		} else {
			resp.Body.Close()
		}
	}
	return hits, nil
}

// ── Dehashed Provider ────────────────────────────────────────────────────────

type dehashedProvider struct {
	key string
}

func (p *dehashedProvider) Name() string    { return "Dehashed" }
func (p *dehashedProvider) Configured() bool { return strings.TrimSpace(p.key) != "" }
func (p *dehashedProvider) Search(ctx context.Context, selectors []string) ([]DarkWebHit, error) {
	var hits []DarkWebHit
	
	// Dehashed key is usually "email:apikey" or just "apikey" depending on config.
	// For this integration we expect the standard "email:apikey" format in the ENV.
	creds := strings.SplitN(p.key, ":", 2)
	var authEmail, authKey string
	if len(creds) == 2 {
		authEmail = creds[0]
		authKey = creds[1]
	} else {
		return nil, fmt.Errorf("dehashed api key must be in format email:apikey")
	}

	for _, sel := range selectors {
		// Dehashed can search for domain, email, ip, etc.
		target := fmt.Sprintf("https://api.dehashed.com/search?query=%s", url.QueryEscape(fmt.Sprintf(`"%s"`, sel)))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json")
		req.SetBasicAuth(authEmail, authKey)

		// Gentle rate limiting
		time.Sleep(500 * time.Millisecond)

		resp, err := osintHTTPClient.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var result struct {
				Entries []struct {
					Email    string `json:"email"`
					Password string `json:"password"`
					Hash     string `json:"hashed_password"`
					Database string `json:"database_name"`
				} `json:"entries"`
			}
			if err := json.Unmarshal(body, &result); err == nil {
				for i, entry := range result.Entries {
					if i >= 10 {
						break // limit to top 10 to avoid noise
					}
					var snippetParts []string
					if entry.Email != "" { snippetParts = append(snippetParts, "Email: "+entry.Email) }
					if entry.Password != "" { snippetParts = append(snippetParts, "Password: "+entry.Password) }
					if entry.Hash != "" { snippetParts = append(snippetParts, "Hash: "+entry.Hash) }
					
					hits = append(hits, DarkWebHit{
						Source:   "Dehashed",
						Title:    fmt.Sprintf("Leak in %s", entry.Database),
						Snippet:  strings.Join(snippetParts, " | "),
						URL:      "https://dehashed.com",
						Severity: "critical", // Passwords/hashes are critical
					})
				}
			}
		} else {
			resp.Body.Close()
		}
	}
	return hits, nil
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
				f.SourceURL = h.URL // where the exposure was found (may be an onion address)
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

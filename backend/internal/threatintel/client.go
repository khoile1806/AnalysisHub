// Package threatintel provides concurrent IOC enrichment via external threat
// intelligence APIs: VirusTotal, AbuseIPDB, AlienVault OTX, and Shodan.
// The two-pass workflow in analysis.go uses this package to automatically
// look up suspicious indicators found in forensic tool output before sending
// the final prompt to the AI, giving the model curated reputation data to
// reason about rather than raw unknowns.
package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

type cacheEntry struct {
	result    EnrichedIOC
	expiresAt time.Time
}

// tiCacheTTL is how long a COMPLETE enrichment result is cached (in-memory +
// Redis) — one where every configured source actually answered.
const tiCacheTTL = 24 * time.Hour

// tiCacheTTLPartial is how long a result is kept when a source could not be
// reached. Short on purpose: a throttled lookup must be retried soon, not
// remembered for a day. Caching it at all is still worth it — it stops a burst
// of requests from hammering a source that has just said "slow down".
const tiCacheTTLPartial = 5 * time.Minute

// tiCacheMaxEntries bounds the in-memory map. Entries were only ever checked for
// expiry on read, so a long-running server sweeping a large IOC store grew it
// without limit.
const tiCacheMaxEntries = 20000

// tiCachePrefix namespaces threat-intel entries in the shared Redis instance.
const tiCachePrefix = "ti:enrich:"

// IOCSet holds extracted indicators of compromise from raw content.
type IOCSet struct {
	IPs     []string
	Hashes  []string // MD5 / SHA1 / SHA256 (lower-cased)
	Domains []string
	URLs    []string
	Emails  []string
	BTCs    []string
	XMRs    []string
}

// Total returns the total number of IOCs across all categories.
func (s IOCSet) Total() int {
	return len(s.IPs) + len(s.Hashes) + len(s.Domains) + len(s.URLs) + len(s.Emails) + len(s.BTCs) + len(s.XMRs)
}

// Finding is a single threat-intel result from one data source.
type Finding struct {
	Source    string            // "VirusTotal" | "AbuseIPDB" | "AlienVault OTX" | "Shodan"
	Score     int               // 0-100 maliciousness score
	Malicious bool              // true → source considers the IOC malicious/suspicious
	Summary   string            // one-line human-readable summary
	Labels    []string          // threat category labels / pulse names / tags (up to 5)
	Extra     map[string]string // additional key-value details (Country, ISP, …)
}

// EnrichedIOC aggregates findings from all configured sources for one IOC.
type EnrichedIOC struct {
	IOC      string    // indicator value, e.g. "185.220.101.5"
	Type     string    // "ip" | "hash" | "domain"
	Findings []Finding // one entry per source that returned usable data
	Threat   bool      // true if any source flagged as malicious/suspicious
	MaxScore int       // highest score across all findings

	// Unavailable names the sources that could not be consulted (rate limit,
	// network, rejected credentials). Without this, "no source returned data"
	// reads as a clean verdict when it may mean nothing was ever asked.
	Unavailable []string `json:"unavailable,omitempty"`
	// Complete is true when every configured source answered. A false value is
	// the signal that the verdict below is provisional.
	Complete bool `json:"complete"`
}

// EnrichResult is what one Enrich call produced, including what it did NOT get
// to. Truncation used to be invisible: the caller received a slice and had no
// way to know that half the indicators were dropped to stay inside a rate limit.
type EnrichResult struct {
	Results []EnrichedIOC
	// Considered is how many indicators were offered, Skipped how many were left
	// unchecked because the per-call budget ran out.
	Considered int
	Skipped    int
	// SkippedByType says WHICH kinds were dropped, since that is what tells an
	// analyst whether the thing they cared about was looked at.
	SkippedByType map[string]int
}

// Truncated reports whether anything was left unchecked.
func (r EnrichResult) Truncated() bool { return r.Skipped > 0 }

// EnrichClient holds credentials for all supported threat intel sources.
// Instantiate with New; safe for concurrent use.
type EnrichClient struct {
	vtKeys     []string // VirusTotal API key pool (round-robin)
	vtKeyIdx   uint64   // atomic round-robin index
	abuseIPDB  string
	alienVault string
	shodan     string
	hc         *http.Client

	rdb *redis.Client // optional shared Redis cache (nil → in-memory only)

	cacheMu sync.RWMutex
	cache   map[string]cacheEntry
}

// UseRedis attaches a Redis client so enrichment results survive restarts and are
// shared across instances. Safe to pass nil (keeps in-memory-only behaviour).
func (c *EnrichClient) UseRedis(rdb *redis.Client) { c.rdb = rdb }

// New creates an EnrichClient. Pass empty strings for keys you don't have;
// the corresponding source will be silently skipped during enrichment.
func New(vtKeys []string, abuseIPDB, alienVault, shodan string) *EnrichClient {
	var cleaned []string
	for _, k := range vtKeys {
		if k = strings.TrimSpace(k); k != "" {
			cleaned = append(cleaned, k)
		}
	}
	return &EnrichClient{
		vtKeys:     cleaned,
		abuseIPDB:  strings.TrimSpace(abuseIPDB),
		alienVault: strings.TrimSpace(alienVault),
		shodan:     strings.TrimSpace(shodan),
		hc:         &http.Client{Timeout: 15 * time.Second},
		cache:      make(map[string]cacheEntry),
	}
}

// Configured returns true if at least one API key is available.
func (c *EnrichClient) Configured() bool {
	return len(c.vtKeys) > 0 || c.abuseIPDB != "" || c.alienVault != "" || c.shodan != ""
}

// nextVTKey returns the next VirusTotal key using round-robin rotation so
// the four free-tier keys share the per-minute quota evenly.
func (c *EnrichClient) nextVTKey() string {
	if len(c.vtKeys) == 0 {
		return ""
	}
	idx := atomic.AddUint64(&c.vtKeyIdx, 1) % uint64(len(c.vtKeys))
	return c.vtKeys[idx]
}

// Enrich concurrently looks up the IOCs in the set. At most maxIOCs are
// processed to stay within free-tier rate limits, and the result says what was
// left out.
//
// The budget is spent ROUND-ROBIN across indicator types rather than in list
// order. The old code appended every IP, then every hash, then domains, then
// URLs, and cut the flat list at fifteen — so a sample carrying ten IPs spent
// ten of the fifteen slots on them, left five for hashes and never enriched a
// single domain or URL. The file hash is usually the most decisive indicator
// there is, and it was being starved by whatever happened to sort first.
func (c *EnrichClient) Enrich(ctx context.Context, iocs IOCSet) EnrichResult {
	const maxIOCs = 15

	type job struct {
		ioc   string
		itype string
	}

	// Queues in priority order: a hash identifies a file exactly, an IP or domain
	// identifies infrastructure, the rest are contextual.
	queues := []struct {
		itype  string
		values []string
	}{
		{"hash", iocs.Hashes},
		{"domain", iocs.Domains},
		{"ip", iocs.IPs},
		{"url", iocs.URLs},
		{"email", iocs.Emails},
		{"btc", iocs.BTCs},
		{"xmr", iocs.XMRs},
	}

	var jobs []job
	considered := 0
	for _, q := range queues {
		considered += len(q.values)
	}
	for round := 0; len(jobs) < maxIOCs; round++ {
		progressed := false
		for _, q := range queues {
			if round >= len(q.values) {
				continue
			}
			progressed = true
			jobs = append(jobs, job{q.values[round], q.itype})
			if len(jobs) >= maxIOCs {
				break
			}
		}
		if !progressed {
			break
		}
	}

	taken := map[string]int{}
	for _, j := range jobs {
		taken[j.itype]++
	}
	skippedByType := map[string]int{}
	for _, q := range queues {
		if n := len(q.values) - taken[q.itype]; n > 0 {
			skippedByType[q.itype] = n
		}
	}

	results := make([]EnrichedIOC, len(jobs))
	var wg sync.WaitGroup
	// 3 concurrent slots: each slot may fire up to 4 sub-goroutines (one per
	// source), so peak concurrency is ~12 outbound requests at any time.
	sem := make(chan struct{}, 3)

	for i, j := range jobs {
		wg.Add(1)
		go func(idx int, jb job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = c.enrichOne(ctx, jb.ioc, jb.itype)
		}(i, j)
	}
	wg.Wait()
	return EnrichResult{
		Results:       results,
		Considered:    considered,
		Skipped:       considered - len(jobs),
		SkippedByType: skippedByType,
	}
}

func (c *EnrichClient) enrichOne(ctx context.Context, ioc, itype string) EnrichedIOC {
	cacheKey := itype + ":" + ioc
	c.cacheMu.RLock()
	if entry, ok := c.cache[cacheKey]; ok && time.Now().Before(entry.expiresAt) {
		c.cacheMu.RUnlock()
		return entry.result
	}
	c.cacheMu.RUnlock()

	// Shared Redis cache: survives restarts and is shared across instances. A hit
	// also warms the in-memory cache so subsequent lookups skip Redis entirely.
	if c.rdb != nil {
		if raw, err := c.rdb.Get(ctx, tiCachePrefix+cacheKey).Bytes(); err == nil {
			var cached EnrichedIOC
			if json.Unmarshal(raw, &cached) == nil {
				c.cacheMu.Lock()
				c.cache[cacheKey] = cacheEntry{result: cached, expiresAt: time.Now().Add(tiCacheTTL)}
				c.cacheMu.Unlock()
				return cached
			}
		}
	}

	result := EnrichedIOC{IOC: ioc, Type: itype}

	var mu sync.Mutex
	var wg sync.WaitGroup

	// record folds one source's outcome into the result. An unavailable source is
	// named rather than dropped: that name is the difference between "checked and
	// clean" and "never asked".
	record := func(f Finding, err error) {
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			if se, ok := asSourceError(err); ok {
				result.Unavailable = append(result.Unavailable, se.Source+" — "+se.Reason)
			}
			return // errNotApplicable is silent by design
		}
		result.Findings = append(result.Findings, f)
		if f.Score > result.MaxScore {
			result.MaxScore = f.Score
		}
		if f.Malicious {
			result.Threat = true
		}
	}

	// VirusTotal — IP, hash, domain, URL
	if key := c.nextVTKey(); key != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			record(c.lookupVT(ctx, ioc, itype, key))
		}()
	}

	// AbuseIPDB — IP only
	if itype == "ip" && c.abuseIPDB != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			record(c.lookupAbuseIPDB(ctx, ioc))
		}()
	}

	// AlienVault OTX — IP, hash, domain
	if c.alienVault != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			record(c.lookupAlienVault(ctx, ioc, itype))
		}()
	}

	// Shodan — IP only
	if itype == "ip" && c.shodan != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			record(c.lookupShodan(ctx, ioc))
		}()
	}

	wg.Wait()
	result.Complete = len(result.Unavailable) == 0

	// Sort findings: highest score first so the AI sees the most alarming data first.
	sort.Slice(result.Findings, func(i, j int) bool {
		return result.Findings[i].Score > result.Findings[j].Score
	})

	// Two TTLs, because the two outcomes mean different things. A complete answer
	// is worth remembering for a day. An answer missing a source is provisional,
	// and remembering it for a day is how a momentary rate limit turned into a
	// day-long "clean" verdict for an indicator nobody ever checked.
	ttl := tiCacheTTL
	if !result.Complete {
		ttl = tiCacheTTLPartial
	}

	c.cacheMu.Lock()
	c.evictLocked()
	c.cache[cacheKey] = cacheEntry{
		result:    result,
		expiresAt: time.Now().Add(ttl),
	}
	c.cacheMu.Unlock()

	// Persist to Redis (best-effort, detached from ctx so a cancelled request
	// still populates the shared cache).
	if c.rdb != nil {
		if raw, err := json.Marshal(result); err == nil {
			c.rdb.Set(context.Background(), tiCachePrefix+cacheKey, raw, ttl)
		}
	}

	return result
}

// evictLocked keeps the in-memory map bounded. Callers must hold cacheMu.
//
// Expired entries were only ever noticed when the same key was read again, so a
// server that sweeps a large IOC store accumulated one entry per indicator and
// never released any of them. Dropping the expired ones first is usually enough;
// if it is not, entries are removed arbitrarily to restore the bound — an
// eviction only costs a repeat lookup.
func (c *EnrichClient) evictLocked() {
	if len(c.cache) < tiCacheMaxEntries {
		return
	}
	now := time.Now()
	for k, v := range c.cache {
		if now.After(v.expiresAt) {
			delete(c.cache, k)
		}
	}
	for k := range c.cache {
		if len(c.cache) < tiCacheMaxEntries {
			break
		}
		delete(c.cache, k)
	}
}

// FormatSummary formats enrichment results as a Markdown block suitable for
// injection into the AI analysis prompt.
func FormatSummary(res EnrichResult) string {
	results := res.Results
	if len(results) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("### Threat Intelligence Results (auto-enriched)\n")
	sb.WriteString(fmt.Sprintf("Auto-enriched **%d IOC(s)** from the analyzed content:\n\n", len(results)))

	// State the limits of the evidence before presenting it. A model told only
	// what was found will reason as though that is everything there was.
	if res.Truncated() {
		parts := make([]string, 0, len(res.SkippedByType))
		for _, t := range sortedKeys(res.SkippedByType) {
			parts = append(parts, fmt.Sprintf("%d %s", res.SkippedByType[t], t))
		}
		sb.WriteString(fmt.Sprintf(
			"> **Not all indicators were checked.** %d of %d were enriched; %s were left unchecked "+
				"because of the per-analysis lookup budget. Absence of a finding below is not evidence of safety "+
				"for those.\n\n", len(results), res.Considered, strings.Join(parts, ", ")))
	}

	for _, r := range results {
		threatTag := "🟢 CLEAN"
		if r.Threat {
			if r.MaxScore >= 70 {
				threatTag = "🔴 MALICIOUS"
			} else {
				threatTag = "🟠 SUSPICIOUS"
			}
		} else if !r.Complete && len(r.Findings) == 0 {
			// Nothing was learned. Saying CLEAN here is the specific claim that
			// must not be made.
			threatTag = "⚪ NOT CHECKED"
		}

		sb.WriteString(fmt.Sprintf("**[%s] %s** — %s\n", strings.ToUpper(r.Type), r.IOC, threatTag))

		if len(r.Findings) == 0 && r.Complete {
			sb.WriteString("- No source returned data (all configured sources answered)\n")
		}
		for _, f := range r.Findings {
			sb.WriteString(fmt.Sprintf("- **%s**: %s\n", f.Source, f.Summary))
			if len(f.Labels) > 0 {
				sb.WriteString(fmt.Sprintf("  *Labels*: %s\n", strings.Join(f.Labels, ", ")))
			}
			// Sorted: a map's iteration order changes between runs, which made the
			// prompt differ for identical evidence.
			for _, k := range sortedKeys(f.Extra) {
				sb.WriteString(fmt.Sprintf("  *%s*: %s\n", k, f.Extra[k]))
			}
		}
		for _, u := range r.Unavailable {
			sb.WriteString(fmt.Sprintf("- ⚠️ **could not check** — %s\n", u))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// sortedKeys gives map iteration a stable order, so identical evidence produces
// an identical prompt.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

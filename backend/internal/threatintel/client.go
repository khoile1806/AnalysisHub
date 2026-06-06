// Package threatintel provides concurrent IOC enrichment via external threat
// intelligence APIs: VirusTotal, AbuseIPDB, AlienVault OTX, and Shodan.
// The two-pass workflow in analysis.go uses this package to automatically
// look up suspicious indicators found in forensic tool output before sending
// the final prompt to the AI, giving the model curated reputation data to
// reason about rather than raw unknowns.
package threatintel

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// IOCSet holds extracted indicators of compromise from raw content.
type IOCSet struct {
	IPs     []string
	Hashes  []string // MD5 / SHA1 / SHA256 (lower-cased)
	Domains []string
}

// Total returns the total number of IOCs across all categories.
func (s IOCSet) Total() int {
	return len(s.IPs) + len(s.Hashes) + len(s.Domains)
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
}

// EnrichClient holds credentials for all supported threat intel sources.
// Instantiate with New; safe for concurrent use.
type EnrichClient struct {
	vtKeys     []string // VirusTotal API key pool (round-robin)
	vtKeyIdx   uint64   // atomic round-robin index
	abuseIPDB  string
	alienVault string
	shodan     string
	hc         *http.Client
}

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

// Enrich concurrently looks up all IOCs in the set and returns enriched results.
// At most 15 IOCs are processed total to stay within free-tier rate limits.
func (c *EnrichClient) Enrich(ctx context.Context, iocs IOCSet) []EnrichedIOC {
	const maxIOCs = 15

	type job struct {
		ioc   string
		itype string
	}

	var jobs []job
	for _, ip := range iocs.IPs {
		jobs = append(jobs, job{ip, "ip"})
	}
	for _, h := range iocs.Hashes {
		jobs = append(jobs, job{h, "hash"})
	}
	for _, d := range iocs.Domains {
		jobs = append(jobs, job{d, "domain"})
	}
	if len(jobs) > maxIOCs {
		jobs = jobs[:maxIOCs]
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
	return results
}

func (c *EnrichClient) enrichOne(ctx context.Context, ioc, itype string) EnrichedIOC {
	result := EnrichedIOC{IOC: ioc, Type: itype}

	var mu sync.Mutex
	var wg sync.WaitGroup

	addFinding := func(f Finding) {
		mu.Lock()
		result.Findings = append(result.Findings, f)
		if f.Score > result.MaxScore {
			result.MaxScore = f.Score
		}
		if f.Malicious {
			result.Threat = true
		}
		mu.Unlock()
	}

	// VirusTotal — IP, hash, domain
	if key := c.nextVTKey(); key != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f, ok := c.lookupVT(ctx, ioc, itype, key); ok {
				addFinding(f)
			}
		}()
	}

	// AbuseIPDB — IP only
	if itype == "ip" && c.abuseIPDB != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f, ok := c.lookupAbuseIPDB(ctx, ioc); ok {
				addFinding(f)
			}
		}()
	}

	// AlienVault OTX — IP, hash, domain
	if c.alienVault != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f, ok := c.lookupAlienVault(ctx, ioc, itype); ok {
				addFinding(f)
			}
		}()
	}

	// Shodan — IP only
	if itype == "ip" && c.shodan != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f, ok := c.lookupShodan(ctx, ioc); ok {
				addFinding(f)
			}
		}()
	}

	wg.Wait()

	// Sort findings: highest score first so the AI sees the most alarming data first.
	sort.Slice(result.Findings, func(i, j int) bool {
		return result.Findings[i].Score > result.Findings[j].Score
	})

	return result
}

// FormatSummary formats enrichment results as a Markdown block suitable for
// injection into the AI analysis prompt.
func FormatSummary(results []EnrichedIOC) string {
	if len(results) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("### Kết quả Threat Intelligence (tự động tra cứu)\n")
	sb.WriteString(fmt.Sprintf("Đã tra cứu **%d IOC** tự động từ nội dung phân tích:\n\n", len(results)))

	for _, r := range results {
		threatTag := "🟢 CLEAN"
		if r.Threat {
			if r.MaxScore >= 70 {
				threatTag = "🔴 MALICIOUS"
			} else {
				threatTag = "🟠 SUSPICIOUS"
			}
		}

		sb.WriteString(fmt.Sprintf("**[%s] %s** — %s\n", strings.ToUpper(r.Type), r.IOC, threatTag))

		if len(r.Findings) == 0 {
			sb.WriteString("- Không có nguồn nào trả về dữ liệu\n")
		}
		for _, f := range r.Findings {
			sb.WriteString(fmt.Sprintf("- **%s**: %s\n", f.Source, f.Summary))
			if len(f.Labels) > 0 {
				sb.WriteString(fmt.Sprintf("  *Labels*: %s\n", strings.Join(f.Labels, ", ")))
			}
			for k, v := range f.Extra {
				sb.WriteString(fmt.Sprintf("  *%s*: %s\n", k, v))
			}
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

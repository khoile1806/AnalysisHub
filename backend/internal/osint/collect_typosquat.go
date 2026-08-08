package osint

import (
	"context"
	"encoding/json"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/analysishub/backend/internal/models"
)

// maxTypoVariants bounds how many look-alike candidates are generated and
// resolved, so the collector stays fast and never fans out unboundedly.
const maxTypoVariants = 48

// altTLDs are the TLDs brand-abuse registrations most often swap in.
var altTLDs = []string{"com", "net", "org", "co", "io", "info", "online", "site", "app", "xyz"}

// homoglyphs are visually-confusable single-character substitutions.
var homoglyphs = map[rune][]rune{
	'l': {'1', 'i'}, 'i': {'1', 'l'}, 'o': {'0'}, '0': {'o'},
	'e': {'3'}, 'a': {'4'}, 's': {'5'}, 'g': {'9'},
}

// collectTyposquat generates common typo / homoglyph / TLD-swap variants of the
// target domain, resolves each, and flags the ones that are actually registered
// as potential look-alike (typosquat / phishing-impersonation) domains. Every
// registered look-alike is emitted as a pivot so the analyst can investigate it
// in one click. Detection is purely DNS-based and bounded.
func collectTyposquat(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	host := strings.ToLower(strings.TrimSpace(env.target))
	name, tld := splitRegistrable(host)
	if name == "" || tld == "" {
		return nil, nil
	}

	// Served from cache when a recent run already resolved the variant set.
	cacheKey := "typosquat:" + host
	if _, body, ok := env.cache.get(ctx, cacheKey); ok && len(body) > 0 {
		var cached []string
		if json.Unmarshal(body, &cached) == nil {
			return typosquatFindings(host, cached), nil
		}
	}

	variants := typoVariants(name, tld)
	if len(variants) > maxTypoVariants {
		variants = variants[:maxTypoVariants]
	}

	resolver := &net.Resolver{}
	// Wildcard / NXDOMAIN-hijack guard: if a definitely-non-existent sibling name
	// resolves, the resolver or registry answers EVERYTHING, so LookupHost cannot
	// distinguish a registered look-alike from an unregistered one — every variant
	// would resolve and flood the report + STIX with false positives. Bail out.
	for _, probe := range []string{"zqx9v7q3nonexistentprobe." + tld, "qh3z8w1x9probe." + name + "." + tld} {
		if addrs, err := resolver.LookupHost(ctx, probe); err == nil && len(addrs) > 0 {
			env.emit("[*] typosquat: resolver/registry answers non-existent names (wildcard / NXDOMAIN hijack) — skipping to avoid false positives")
			return nil, nil
		}
	}

	var (
		mu         sync.Mutex
		registered []string
	)
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	for _, v := range variants {
		if v == host {
			continue
		}
		wg.Add(1)
		go func(cand string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			if addrs, err := resolver.LookupHost(ctx, cand); err == nil && len(addrs) > 0 {
				mu.Lock()
				registered = append(registered, cand)
				mu.Unlock()
			}
		}(v)
	}
	wg.Wait()
	sort.Strings(registered)

	if b, err := json.Marshal(registered); err == nil {
		env.cache.set(ctx, cacheKey, 200, b, ttlTyposquat)
	}

	if len(registered) == 0 {
		env.emit("[*] typosquat: no registered look-alike domains found")
		return nil, nil
	}
	env.emit("[+] typosquat: " + strconv.Itoa(len(registered)) + " registered look-alike domain(s) found")
	return typosquatFindings(host, registered), nil
}

// typosquatFindings turns the registered look-alike list into findings + pivots.
func typosquatFindings(host string, registered []string) []models.OsintFinding {
	out := make([]models.OsintFinding, 0, len(registered)+1)
	summary := newFinding("typosquat", "reputation", "Look-alike domains registered",
		strconv.Itoa(len(registered))+" typo/homoglyph variant(s) of "+host+" resolve")
	summary.Severity = "medium"
	out = append(out, summary)
	for _, d := range registered {
		f := newFinding("typosquat", "reputation", "Registered look-alike domain", d)
		f.Severity = "medium"
		out = append(out, withRelated(f, RelatedEntity{Type: TargetDomain, Value: d}))
	}
	return out
}

// splitRegistrable splits a host into its second-level label and the remaining
// TLD ("example.com" -> "example","com"; "foo.co.uk" -> "foo","co.uk"). It is a
// heuristic - good enough for generating typo variants.
func splitRegistrable(host string) (name, tld string) {
	host = strings.Trim(strings.ToLower(host), ".")
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return "", ""
	}
	// Treat a known two-label public suffix (co.uk, com.au …) as the TLD.
	twoLabel := map[string]bool{"co.uk": true, "com.au": true, "co.jp": true, "com.br": true, "co.nz": true, "com.vn": true}
	if len(parts) >= 3 {
		last2 := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if twoLabel[last2] {
			return parts[len(parts)-3], last2
		}
	}
	return parts[len(parts)-2], parts[len(parts)-1]
}

// typoVariants generates look-alike candidates for name+tld.
func typoVariants(name, tld string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(n, t string) {
		if n == "" || len(n) < 2 {
			return
		}
		d := n + "." + t
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}

	rs := []rune(name)
	// Character omission.
	for i := range rs {
		add(string(append(append([]rune{}, rs[:i]...), rs[i+1:]...)), tld)
	}
	// Adjacent transposition.
	for i := 0; i+1 < len(rs); i++ {
		sw := append([]rune{}, rs...)
		sw[i], sw[i+1] = sw[i+1], sw[i]
		add(string(sw), tld)
	}
	// Character doubling.
	for i := range rs {
		add(string(append(append(append([]rune{}, rs[:i+1]...), rs[i]), rs[i+1:]...)), tld)
	}
	// Homoglyph substitution.
	for i, c := range rs {
		for _, sub := range homoglyphs[c] {
			cp := append([]rune{}, rs...)
			cp[i] = sub
			add(string(cp), tld)
		}
	}
	// Hyphen insertion (mid-word).
	if len(rs) > 3 {
		mid := len(rs) / 2
		add(string(rs[:mid])+"-"+string(rs[mid:]), tld)
	}
	// TLD swaps of the exact name.
	for _, t := range altTLDs {
		if t != tld {
			add(name, t)
		}
	}
	return out
}

package osint

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/forensichub/backend/internal/models"
)

// HackerTarget's free tier is rate-limited (a few queries/sec, ~50/day per IP).
var rlHackerTarget = newRateLimiter(2 * time.Second)

// htError reports whether a HackerTarget plain-text response is an error / quota
// body rather than real data.
func htError(body string) bool {
	b := strings.ToLower(strings.TrimSpace(body))
	return b == "" ||
		strings.Contains(b, "error") ||
		strings.Contains(b, "api count exceeded") ||
		strings.Contains(b, "no records") ||
		strings.Contains(b, "no dns")
}

// collectReverseIP finds other domains hosted on the same IP (HackerTarget, no
// API key). Each co-hosted domain is a pivot - it expands the infrastructure
// graph toward the rest of an operator's hosting footprint.
func collectReverseIP(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	u := "https://api.hackertarget.com/reverseiplookup/?q=" + url.QueryEscape(env.target)
	body, status, err := httpGetBody(ctx, rlHackerTarget, u, nil)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("hackertarget returned HTTP %d", status)
	}
	text := string(body)
	if htError(text) {
		env.emit("[*] reverse_ip: no co-hosted domains found")
		return nil, nil
	}

	var out []models.OsintFinding
	for _, line := range strings.Split(text, "\n") {
		host := strings.TrimSpace(line)
		if host == "" || host == env.target {
			continue
		}
		f := newFinding("reverse_ip", "network", "Domain co-hosted on IP", host)
		out = append(out, withRelated(f, RelatedEntity{Type: TargetDomain, Value: host}))
		if len(out) >= 100 {
			break
		}
	}
	env.emit(fmt.Sprintf("[+] reverse_ip: %d co-hosted domain(s)", len(out)))
	return stampSource(out, u), nil
}

// collectHostSearch enumerates a domain's subdomains + their resolved IPs
// (HackerTarget). Every subdomain and IP becomes a pivot - strong fuel for the
// infrastructure graph.
func collectHostSearch(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	u := "https://api.hackertarget.com/hostsearch/?q=" + url.QueryEscape(env.target)
	body, status, err := httpGetBody(ctx, rlHackerTarget, u, nil)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("hackertarget returned HTTP %d", status)
	}
	text := string(body)
	if htError(text) {
		env.emit("[*] host_search: no subdomains found")
		return nil, nil
	}

	var out []models.OsintFinding
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		host := strings.TrimSpace(parts[0])
		if host == "" {
			continue
		}
		ip := ""
		if len(parts) == 2 {
			ip = strings.TrimSpace(parts[1])
		}
		val := host
		if ip != "" {
			val = host + " -> " + ip
		}
		f := newFinding("host_search", "dns", "Subdomain", val)
		rels := []RelatedEntity{{Type: TargetDomain, Value: host}}
		if ip != "" {
			rels = append(rels, RelatedEntity{Type: TargetIP, Value: ip})
		}
		out = append(out, withRelated(f, rels...))
		if len(out) >= 200 {
			break
		}
	}
	env.emit(fmt.Sprintf("[+] host_search: %d subdomain(s)", len(out)))
	return stampSource(out, u), nil
}

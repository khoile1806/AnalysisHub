package osint

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/threatintel"
)

var (
	rlPulsedive = newRateLimiter(1500 * time.Millisecond)
	rlGreyNoise = newRateLimiter(1 * time.Second)
)

// collectThreatIntel runs the shared multi-source enrichment client (VirusTotal,
// AbuseIPDB, AlienVault OTX, Shodan) against the target and folds every source's
// verdict into the OSINT findings. This is the unification point: the same
// reputation engine the AI analysis pipeline uses now feeds the entity
// investigation, so a domain/IP/hash gets one coherent, multi-source threat
// picture instead of scattered per-tool lookups.
func collectThreatIntel(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	if env.enrich == nil || !env.enrich.Configured() {
		return nil, errNoAPIKey
	}
	var set threatintel.IOCSet
	switch env.ttype {
	case TargetIP:
		set.IPs = []string{env.target}
	case TargetDomain:
		set.Domains = []string{env.target}
	case TargetHash:
		set.Hashes = []string{strings.ToLower(env.target)}
	default:
		return nil, nil
	}

	results := env.enrich.Enrich(ctx, set)
	var out []models.OsintFinding
	for _, r := range results.Results {
		if len(r.Findings) == 0 {
			continue
		}
		verdict := "clean"
		if r.Threat {
			verdict = "MALICIOUS"
			if r.MaxScore < 70 {
				verdict = "SUSPICIOUS"
			}
		}
		vtURL := vtGUIURL(env.target, env.ttype)
		summary := newFinding("threatintel", "reputation",
			fmt.Sprintf("Threat-intel consensus: %s (max score %d)", verdict, r.MaxScore),
			fmt.Sprintf("%d source(s) returned data", len(r.Findings)))
		summary.Severity = scoreSeverity(r.MaxScore, r.Threat)
		out = append(out, withSource(summary, vtURL))

		for _, f := range r.Findings {
			ff := newFinding("threatintel", "reputation",
				f.Source+": "+f.Summary, joinLabels(f.Labels))
			ff.Severity = scoreSeverity(f.Score, f.Malicious)
			out = append(out, withSource(ff, reputationSourceURL(f.Source, env.target, env.ttype)))
		}
	}
	if len(out) == 0 {
		env.emit("[*] threatintel: no source returned reputation data")
	} else {
		env.emit(fmt.Sprintf("[+] threatintel: %d reputation finding(s)", len(out)))
	}
	return out, nil
}

func scoreSeverity(score int, malicious bool) string {
	switch {
	case malicious && score >= 70:
		return "critical"
	case malicious:
		return "high"
	case score >= 40:
		return "medium"
	default:
		return "info"
	}
}

func joinLabels(labels []string) string {
	if len(labels) == 0 {
		return ""
	}
	return "labels: " + strings.Join(labels, ", ")
}

// collectPulsedive enriches an IP/domain with Pulsedive's risk score. Free tier
// requires an API key; skipped (not failed) when unset.
func collectPulsedive(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	if env.keys.Pulsedive == "" {
		return nil, errNoAPIKey
	}
	u := "https://pulsedive.com/api/info.php?indicator=" + url.QueryEscape(env.target) +
		"&key=" + url.QueryEscape(env.keys.Pulsedive)
	var r struct {
		Risk    string `json:"risk"`
		Type    string `json:"type"`
		Threats []struct {
			Name string `json:"name"`
		} `json:"threats"`
		Error string `json:"error"`
	}
	// Cached by indicator (the API key in the URL doesn't change the verdict).
	status, err := cachedGetJSON(ctx, env.cache, "pulsedive:"+strings.ToLower(env.target), rlPulsedive, u, nil, &r, ttlReputation)
	if err != nil {
		return nil, err
	}
	if status == 401 || status == 403 {
		return nil, fmt.Errorf("Pulsedive rejected the API key (HTTP %d)", status)
	}
	if status < 200 || status >= 300 || r.Error != "" || r.Risk == "" {
		env.emit("[*] pulsedive: no risk data for this indicator")
		return nil, nil
	}

	var threats []string
	for _, t := range r.Threats {
		if t.Name != "" {
			threats = append(threats, t.Name)
		}
	}
	detail := "risk: " + r.Risk
	if len(threats) > 0 {
		detail += " - threats: " + strings.Join(threats, ", ")
	}
	f := newFinding("pulsedive", "reputation", "Pulsedive risk", detail)
	switch strings.ToLower(r.Risk) {
	case "critical":
		f.Severity = "critical"
	case "high":
		f.Severity = "high"
	case "medium":
		f.Severity = "medium"
	case "low":
		f.Severity = "low"
	}
	return []models.OsintFinding{withSource(f, pulsediveURL(env.target))}, nil
}

// collectGreyNoise classifies an IP using GreyNoise's community API: is it
// internet-background-noise (mass scanner), a known-benign service (RIOT), or
// flagged malicious. This is a strong false-positive reducer for IP targets.
// The community endpoint is open to unauthenticated use (with a daily limit), so
// no key is required; a configured key only raises the rate limit.
func collectGreyNoise(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	u := "https://api.greynoise.io/v3/community/" + url.PathEscape(env.target)
	headers := map[string]string{}
	if env.keys.GreyNoise != "" {
		headers["key"] = env.keys.GreyNoise // optional - raises the community rate limit
	}
	var r struct {
		Noise          bool   `json:"noise"`
		Riot           bool   `json:"riot"`
		Classification string `json:"classification"`
		Name           string `json:"name"`
		LastSeen       string `json:"last_seen"`
	}
	status, err := cachedGetJSON(ctx, env.cache, "greynoise:"+strings.ToLower(env.target), rlGreyNoise, u, headers, &r, ttlReputation)
	if err != nil {
		return nil, err
	}
	if status == 401 || status == 403 {
		// Without a key the endpoint is open, so this only happens with a bad key
		// or once the keyless daily limit is hit - degrade quietly, don't fail.
		if env.keys.GreyNoise == "" {
			env.emit("[*] greynoise: community lookup limit reached (set GREYNOISE_API_KEY to raise it)")
			return nil, nil
		}
		return nil, fmt.Errorf("GreyNoise rejected the API key (HTTP %d)", status)
	}
	if status == 404 {
		env.emit("[*] greynoise: IP not observed by GreyNoise")
		return nil, nil
	}
	if status == 429 {
		env.emit("[*] greynoise: rate-limited")
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("GreyNoise returned HTTP %d", status)
	}

	detail := fmt.Sprintf("classification: %s", r.Classification)
	if r.Name != "" && r.Name != "unknown" {
		detail += " - " + r.Name
	}
	if r.Noise {
		detail += " - internet background noise (mass scanner)"
	}
	if r.Riot {
		detail += " - RIOT (common benign service)"
	}
	f := newFinding("greynoise", "reputation", "GreyNoise context", detail)
	switch strings.ToLower(r.Classification) {
	case "malicious":
		f.Severity = "high"
	case "benign":
		f.Severity = "info"
	default:
		f.Severity = "low"
	}
	return []models.OsintFinding{withSource(f, greynoiseURL(env.target))}, nil
}

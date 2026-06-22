package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/forensichub/backend/internal/models"
)

// abuse.ch (ThreatFox / URLhaus / MalwareBazaar) collectors. These are free
// community threat feeds that map an indicator to the malware campaign, botnet,
// or malicious-URL infrastructure behind it - the reputation depth a passive
// OSINT scan otherwise lacks. abuse.ch now gates its APIs behind a free
// Auth-Key; when none is configured the collector tries anyway and degrades to
// "skipped" on an auth error rather than failing the scan.
var (
	rlAbuseCh = newRateLimiter(1500 * time.Millisecond)
)

// abuseChHeaders attaches the shared Auth-Key when configured.
func abuseChHeaders(env *collectorEnv) map[string]string {
	h := map[string]string{}
	if env.keys.AbuseCh != "" {
		h["Auth-Key"] = env.keys.AbuseCh
	}
	return h
}

// collectThreatFox queries abuse.ch ThreatFox for an IOC (ip/domain/hash),
// surfacing the malware family / threat type and confidence behind it.
func collectThreatFox(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	reqBody, _ := json.Marshal(map[string]interface{}{
		"query":       "search_ioc",
		"search_term": env.target,
	})
	body, status, err := httpPostBody(ctx, rlAbuseCh,
		"https://threatfox-api.abuse.ch/api/v1/", "application/json", reqBody, abuseChHeaders(env))
	if err != nil {
		return nil, err
	}
	if status == 401 || status == 403 {
		return nil, errNoAPIKey // needs a free abuse.ch Auth-Key
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("ThreatFox returned HTTP %d", status)
	}

	var r struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			IOC             string `json:"ioc"`
			ThreatType      string `json:"threat_type"`
			Malware         string `json:"malware"`
			MalwarePrintable string `json:"malware_printable"`
			ConfidenceLevel int    `json:"confidence_level"`
			FirstSeen       string `json:"first_seen"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &r) != nil || r.QueryStatus != "ok" || len(r.Data) == 0 {
		env.emit("[*] threatfox: indicator not present in ThreatFox")
		return nil, nil
	}

	out := make([]models.OsintFinding, 0, len(r.Data))
	for i, d := range r.Data {
		mal := d.MalwarePrintable
		if mal == "" {
			mal = d.Malware
		}
		f := newFinding("threatfox", "reputation",
			"ThreatFox: "+strings.TrimSpace(joinNonEmpty(" / ", d.ThreatType, mal)),
			fmt.Sprintf("confidence %d%% - first seen %s", d.ConfidenceLevel, d.FirstSeen))
		f.Severity = "critical" // listed in ThreatFox = actively malicious infrastructure
		out = append(out, f)
		if i >= 9 {
			break
		}
	}
	env.emit(fmt.Sprintf("[+] threatfox: %d malware association(s)", len(out)))
	return out, nil
}

// collectURLhaus queries abuse.ch URLhaus for malicious URLs hosted on the
// target host (domain or IP).
func collectURLhaus(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	form := url.Values{}
	form.Set("host", env.target)
	body, status, err := httpPostBody(ctx, rlAbuseCh,
		"https://urlhaus-api.abuse.ch/v1/host/", "application/x-www-form-urlencoded",
		[]byte(form.Encode()), abuseChHeaders(env))
	if err != nil {
		return nil, err
	}
	if status == 401 || status == 403 {
		return nil, errNoAPIKey
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("URLhaus returned HTTP %d", status)
	}

	var r struct {
		QueryStatus string `json:"query_status"`
		URLs        []struct {
			URL       string `json:"url"`
			URLStatus string `json:"url_status"`
			Threat    string `json:"threat"`
			DateAdded string `json:"date_added"`
		} `json:"urls"`
	}
	if json.Unmarshal(body, &r) != nil || r.QueryStatus != "ok" || len(r.URLs) == 0 {
		env.emit("[*] urlhaus: host not present in URLhaus")
		return nil, nil
	}

	var out []models.OsintFinding
	summary := newFinding("urlhaus", "reputation", "URLhaus: malicious URLs on this host",
		fmt.Sprintf("%d malicious URL(s) recorded by URLhaus", len(r.URLs)))
	summary.Severity = "critical"
	out = append(out, summary)
	for i, u := range r.URLs {
		f := newFinding("urlhaus", "reputation",
			"Malicious URL ("+joinNonEmpty(", ", u.Threat, u.URLStatus)+")", u.URL)
		f.Severity = "high"
		out = append(out, f)
		if i >= 9 {
			break
		}
	}
	env.emit(fmt.Sprintf("[+] urlhaus: %d malicious URL(s)", len(r.URLs)))
	return out, nil
}

// collectMalwareBazaar queries abuse.ch MalwareBazaar for a file hash, returning
// the malware family / signature of the matching sample.
func collectMalwareBazaar(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	form := url.Values{}
	form.Set("query", "get_info")
	form.Set("hash", env.target)
	body, status, err := httpPostBody(ctx, rlAbuseCh,
		"https://mb-api.abuse.ch/api/v1/", "application/x-www-form-urlencoded",
		[]byte(form.Encode()), abuseChHeaders(env))
	if err != nil {
		return nil, err
	}
	if status == 401 || status == 403 {
		return nil, errNoAPIKey
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("MalwareBazaar returned HTTP %d", status)
	}

	var r struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			FileName  string `json:"file_name"`
			FileType  string `json:"file_type"`
			Signature string `json:"signature"`
			FirstSeen string `json:"first_seen"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &r) != nil || r.QueryStatus != "ok" || len(r.Data) == 0 {
		env.emit("[*] malwarebazaar: hash not present in MalwareBazaar")
		return nil, nil
	}
	d := r.Data[0]
	sig := d.Signature
	if sig == "" {
		sig = "unclassified sample"
	}
	f := newFinding("malwarebazaar", "reputation", "MalwareBazaar: known malware sample",
		fmt.Sprintf("%s - %s (%s) first seen %s", sig, d.FileName, d.FileType, d.FirstSeen))
	f.Severity = "critical"
	env.emit("[+] malwarebazaar: known sample - " + sig)
	return []models.OsintFinding{f}, nil
}

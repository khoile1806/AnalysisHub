package osint

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/analysishub/backend/internal/models"
)

// rlLeakCheck paces LeakCheck's free public API, which is tightly rate-limited
// (a handful of requests per minute). Be polite so the key-less endpoint stays
// usable across concurrent scans.
var rlLeakCheck = newRateLimiter(3 * time.Second)

// leakCheckResponse is the LeakCheck public API shape. A hit lists the breach
// source names (and dates) the identifier appeared in - never any password - so
// it serves the same role as the HIBP/XposedOrNot named-breach collectors and
// folds into the same corroboration pass, with no API key required.
type leakCheckResponse struct {
	Success bool     `json:"success"`
	Found   int      `json:"found"`
	Fields  []string `json:"fields"`
	Sources []struct {
		Name string `json:"name"`
		Date string `json:"date"`
	} `json:"sources"`
	Error string `json:"error"`
}

// collectLeakCheck checks an e-mail or username against LeakCheck's free public
// breach index. It names every breach the identifier was found in (with a date
// when present), giving an independent, key-less corroborator for HIBP and
// XposedOrNot. It surfaces only breach metadata, never leaked secrets.
func collectLeakCheck(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	if env.ttype != TargetEmail && env.ttype != TargetUsername {
		return nil, nil
	}
	q := strings.TrimSpace(env.target)
	if q == "" {
		return nil, nil
	}

	api := "https://leakcheck.io/api/public?check=" + url.QueryEscape(q)
	var r leakCheckResponse
	status, err := cachedGetJSON(ctx, env.cache, "leakcheck:"+strings.ToLower(q), rlLeakCheck, api, nil, &r, ttlReputation)
	if err != nil {
		return nil, err
	}
	// The public endpoint signals throttling with HTTP 429 or an error string;
	// treat it as "unavailable", not a hard failure (the keyed sources still run).
	if status == 429 || (r.Error != "" && strings.Contains(strings.ToLower(r.Error), "limit")) {
		env.emit("[*] leakcheck: public API rate-limited - skipping")
		return nil, nil
	}
	if status == 404 || (!r.Success && r.Found == 0) {
		f := newFinding("leakcheck", "breach", "Breach exposure (LeakCheck)",
			"identifier not found in any known breach")
		return []models.OsintFinding{f}, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("LeakCheck returned HTTP %d", status)
	}
	if r.Found == 0 || len(r.Sources) == 0 {
		f := newFinding("leakcheck", "breach", "Breach exposure (LeakCheck)",
			"identifier not found in any known breach")
		return []models.OsintFinding{f}, nil
	}

	source := "https://leakcheck.io/"
	out := make([]models.OsintFinding, 0, len(r.Sources)+1)
	summary := newFinding("leakcheck", "breach", "Breach exposure (LeakCheck)",
		fmt.Sprintf("identifier appears in %d known breach(es)", r.Found))
	summary.Severity = "high"
	summary.SourceURL = source
	out = append(out, summary)

	const leakCheckCap = 60
	for i, s := range r.Sources {
		name := strings.TrimSpace(s.Name)
		if name == "" {
			continue
		}
		if i >= leakCheckCap {
			break
		}
		detail := "listed by LeakCheck breach index"
		if s.Date != "" {
			detail = "breach date " + s.Date + " - listed by LeakCheck"
		}
		f := newFinding("leakcheck", "breach", "Breach: "+name, detail)
		f.Severity = "high"
		f.SourceURL = source
		out = append(out, f)
	}
	env.emit(fmt.Sprintf("[+] leakcheck: identifier appears in %d breach(es)", r.Found))
	return out, nil
}

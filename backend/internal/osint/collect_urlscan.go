package osint

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/forensichub/backend/internal/models"
)

var rlURLScan = newRateLimiter(2 * time.Second)

// collectURLScan queries urlscan.io's public search for URLs recently scanned on
// the target domain. It is a free, no-key, high-signal source for brand abuse
// and phishing: attacker-submitted scans of rogue paths, look-alike landing
// pages and credential-harvest kits hosted on (or impersonating) the domain show
// up here. Each distinct page is reported; pages on a DIFFERENT host that still
// reference the brand are flagged as possible impersonation and pivoted.
func collectURLScan(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	if env.ttype != TargetDomain {
		return nil, nil
	}
	target := strings.ToLower(strings.TrimSpace(env.target))
	u := "https://urlscan.io/api/v1/search/?size=50&q=" +
		url.QueryEscape("page.domain:"+target+" OR domain:"+target)

	var r struct {
		Total   int `json:"total"`
		Results []struct {
			Task struct {
				URL    string `json:"url"`
				Domain string `json:"domain"`
				Time   string `json:"time"`
			} `json:"task"`
			Page struct {
				URL     string `json:"url"`
				Domain  string `json:"domain"`
				IP      string `json:"ip"`
				Country string `json:"country"`
				Server  string `json:"server"`
			} `json:"page"`
		} `json:"results"`
	}
	status, err := httpGetJSON(ctx, rlURLScan, u, nil, &r)
	if err != nil {
		return nil, err
	}
	if status == 429 {
		return nil, fmt.Errorf("urlscan rate-limited (HTTP 429)")
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("urlscan returned HTTP %d", status)
	}
	if r.Total == 0 || len(r.Results) == 0 {
		env.emit("[*] urlscan: no scanned URLs for this domain")
		return nil, nil
	}

	var out []models.OsintFinding
	out = append(out, newFinding("urlscan", "reputation", "URLScan: recently scanned URLs",
		fmt.Sprintf("%d scan(s) reference this domain on urlscan.io", r.Total)))

	seen := map[string]bool{}
	impersonation := 0
	for i := range r.Results {
		res := &r.Results[i]
		pageURL := res.Page.URL
		if pageURL == "" {
			pageURL = res.Task.URL
		}
		if pageURL == "" || seen[pageURL] {
			continue
		}
		seen[pageURL] = true

		host := strings.ToLower(res.Page.Domain)
		// A page hosted on a DIFFERENT domain that still carries the brand string
		// is a likely look-alike / impersonation rather than the brand's own page.
		lookalike := host != "" && host != target && !strings.HasSuffix(host, "."+target) &&
			strings.Contains(host, registrableName(target))

		title := "Scanned URL on domain"
		f := newFinding("urlscan", "reputation", title, pageURL)
		f.Severity = "low"
		if loc := joinNonEmpty(" ", res.Page.IP, res.Page.Country); loc != "" {
			f.Data = toJSON(map[string]string{"host": host, "ip": res.Page.IP, "country": res.Page.Country})
		}
		if lookalike {
			impersonation++
			f.Title = "Possible look-alike / impersonation page"
			f.Severity = "high"
			f = withRelated(f, RelatedEntity{Type: TargetDomain, Value: host})
		}
		out = append(out, f)
		if len(out) >= 40 {
			break
		}
	}
	env.emit(fmt.Sprintf("[+] urlscan: %d page(s), %d possible impersonation(s)", len(out)-1, impersonation))
	return out, nil
}

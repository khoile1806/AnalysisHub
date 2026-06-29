package osint

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/forensichub/backend/internal/models"
)

var rlRansomware = newRateLimiter(1500 * time.Millisecond)

// collectRansomwareWatch checks whether the target organisation has been posted
// on a ransomware group's Dedicated Leak Site (DLS), via the free
// ransomware.live API. For a bank this is among the most consequential exposure
// signals: a DLS listing means data was exfiltrated and is being extorted /
// published. Runs for domain and name targets (the org's identifiers).
func collectRansomwareWatch(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	keyword := strings.TrimSpace(env.target)
	if env.ttype == TargetDomain {
		// match the registrable name, not the FQDN, so "banka.com" hits "Bank A".
		keyword = registrableName(keyword)
	}
	if len(keyword) < 3 {
		return nil, nil
	}

	u := "https://api.ransomware.live/v2/searchvictims/" + url.PathEscape(keyword)
	var victims []struct {
		Victim      string `json:"victim"`
		Group       string `json:"group"` // ransomware group (was wrongly "group_name" -> blank)
		Domain      string `json:"domain"`
		Published   string `json:"published"`
		Attackdate  string `json:"attackdate"`
		Discovered  string `json:"discovered"`
		Country     string `json:"country"`
		Description string `json:"description"`
		URL         string `json:"url"`        // ransomware.live clearweb victim page (verifiable)
		ClaimURL    string `json:"claim_url"`  // group's DLS post (often an onion address)
		Screenshot  string `json:"screenshot"` // clearweb screenshot of the leak post
	}
	status, err := httpGetJSON(ctx, rlRansomware, u, nil, &victims)
	if err != nil {
		return nil, err
	}
	if status == 404 {
		env.emit("[*] ransomwatch: no DLS listing found")
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("ransomware.live returned HTTP %d", status)
	}

	target := strings.ToLower(env.target)
	kw := strings.ToLower(keyword)
	var out []models.OsintFinding
	for i := range victims {
		v := &victims[i]
		// Guard against loose matches - require the keyword/domain to actually
		// appear in the victim name or domain.
		hay := strings.ToLower(v.Victim + " " + v.Domain)
		if !strings.Contains(hay, kw) && !strings.Contains(hay, target) {
			continue
		}
		when := v.Published
		if when == "" {
			when = v.Discovered
		}
		if when == "" {
			when = v.Attackdate
		}
		group := v.Group
		if group == "" {
			group = "unknown group"
		}
		f := newFinding("ransomwatch", "ransomware",
			fmt.Sprintf("RANSOMWARE LEAK-SITE LISTING - posted by %q", group),
			fmt.Sprintf("victim %q%s - published %s", v.Victim,
				ifNonEmpty(v.Country, " ("+v.Country+")"), when))
		f.Severity = "critical"
		// Source of evidence: the ransomware.live clearweb victim page (viewable),
		// else the group's DLS claim post, else the verifiable API record.
		src := strings.TrimSpace(v.URL)
		if src == "" {
			src = strings.TrimSpace(v.ClaimURL)
		}
		if src == "" {
			src = u
		}
		f = withSource(f, src)
		// Keep the onion DLS post + screenshot as extra evidence on the finding.
		evidence := map[string]string{"group": group}
		if v.ClaimURL != "" {
			evidence["dls_post"] = v.ClaimURL
		}
		if v.Screenshot != "" {
			evidence["screenshot"] = v.Screenshot
		}
		f.Data = toJSON(evidence)
		out = append(out, f)
		if len(out) >= 15 {
			break
		}
	}

	if len(out) == 0 {
		env.emit("[*] ransomwatch: no matching DLS listing")
		return nil, nil
	}
	env.emit(fmt.Sprintf("[+] ransomwatch: %d ransomware leak-site listing(s)", len(out)))
	return out, nil
}

// registrableName returns the label before the public suffix of a domain
// (a naive eTLD+1 first-label heuristic): "banka.com" -> "banka",
// "bank-a.com.vn" -> "bank-a". Good enough as a ransomware-DLS search keyword.
func registrableName(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimPrefix(d, "www.")
	parts := strings.Split(d, ".")
	if len(parts) < 2 {
		return d
	}
	// Skip trailing 2-letter ccTLD + common second-level (com.vn, co.uk).
	end := len(parts) - 1
	if len(parts) >= 3 && len(parts[end]) == 2 {
		second := parts[end-1]
		if second == "com" || second == "co" || second == "org" || second == "net" || second == "gov" || second == "edu" {
			end--
		}
	}
	if end-1 >= 0 {
		return parts[end-1]
	}
	return parts[0]
}

func ifNonEmpty(v, s string) string {
	if strings.TrimSpace(v) == "" {
		return ""
	}
	return s
}

package osint

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/forensichub/backend/internal/models"
)

// Organization-exposure collectors. These run for a domain target and answer
// the question a SOC asks about its own brand: "what of ours is already leaked
// or for sale?" - leaked corporate/customer credentials, machines infected by
// info-stealers, and brand mentions on breach forums / paste sites / Telegram.
// They surface exposure through public threat-intel APIs and assisted searches;
// they never touch illicit marketplaces.

var rlHudsonRock = newRateLimiter(2 * time.Second)

// collectStealerIntel queries Hudson Rock's free Cavalier API for the domain's
// info-stealer exposure: how many employees, users (customers), and third
// parties have appeared in stealer logs. For a bank this is the highest-value
// signal - a stealer-infected customer leaks live banking session cookies.
func collectStealerIntel(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	if env.ttype != TargetDomain {
		return nil, nil
	}
	domain := strings.ToLower(strings.TrimSpace(env.target))

	body, status, err := hudsonRockPost(ctx,
		"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain",
		map[string]string{"domain": domain})
	if err != nil {
		return nil, err
	}
	if status == 429 {
		return nil, fmt.Errorf("Hudson Rock rate-limited (HTTP 429)")
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("Hudson Rock returned HTTP %d", status)
	}

	var r struct {
		Message string `json:"message"`
		Data    struct {
			Total         int `json:"total"`
			TotalStealers int `json:"totalStealers"`
			Employees     int `json:"employees"`
			Users         int `json:"users"`
			ThirdParties  int `json:"third_parties"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &r) != nil {
		return nil, fmt.Errorf("could not decode Hudson Rock response")
	}

	d := r.Data
	exposed := d.Total + d.Employees + d.Users + d.ThirdParties + d.TotalStealers

	var out []models.OsintFinding
	headline := strings.TrimSpace(r.Message)
	if headline == "" {
		headline = fmt.Sprintf("employees %d - customers %d - third-parties %d",
			d.Employees, d.Users, d.ThirdParties)
	}
	summary := newFinding("stealer_intel", "breach", "Info-stealer exposure (Hudson Rock)", headline)
	if exposed > 0 {
		summary.Severity = "critical"
	} else {
		summary.Severity = "info"
	}
	out = append(out, summary)

	addCount := func(label string, n int, sev string) {
		if n <= 0 {
			return
		}
		f := newFinding("stealer_intel", "breach", label, fmt.Sprintf("%d", n))
		f.Severity = sev
		out = append(out, f)
	}
	addCount("Compromised employees (in stealer logs)", d.Employees, "high")
	addCount("Compromised customers/users (in stealer logs)", d.Users, "critical")
	addCount("Compromised third parties", d.ThirdParties, "medium")

	if exposed > 0 {
		env.emit(fmt.Sprintf("[+] stealer_intel: %s", headline))
	} else {
		env.emit("[*] stealer_intel: no info-stealer exposure found for this domain")
	}
	return stampSource(out, "https://www.hudsonrock.com/threat-intelligence-cybercrime-tools?domain="+url.QueryEscape(domain)), nil
}

// hudsonRockPost sends a rate-limited JSON POST and returns the (capped) body.
func hudsonRockPost(ctx context.Context, target string, payload map[string]string) ([]byte, int, error) {
	if err := rlHudsonRock.wait(ctx); err != nil {
		return nil, 0, err
	}
	buf, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(buf))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := osintHTTPClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return b, resp.StatusCode, err
}

// collectExposureSearch builds ready-to-open searches that surface a brand's
// leaked / for-sale data across breach forums, paste sites, Telegram channels
// and stealer-log dumps. It performs no requests - the analyst opens each link
// (these sources are CAPTCHA/login-gated and not safely automatable server-side).
func collectExposureSearch(_ context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	if env.ttype != TargetDomain {
		return nil, nil
	}
	d := strings.ToLower(strings.TrimSpace(env.target))
	d = strings.TrimPrefix(d, "www.")
	q := func(s string) string { return "https://www.google.com/search?q=" + url.QueryEscape(s) }
	quoted := `"` + d + `"`

	var out []models.OsintFinding
	add := func(title, link string) {
		f := newFinding("exposure_search", "breach", title, link)
		f.Severity = "low" // exposure lead - needs human verification
		out = append(out, f)
	}

	add("Breach forums / data-for-sale",
		q(quoted+` (leak OR dump OR "leaked database" OR breach OR "for sale" OR breachforums OR raidforums)`))
	add("Paste sites (Pastebin / Ghostbin / Rentry ...)",
		q(quoted+` (site:pastebin.com OR site:ghostbin.com OR site:throwbin.io OR site:rentry.co OR site:justpaste.it)`))
	add("Telegram leak/dump channels",
		q(quoted+` (site:t.me OR site:telegram.me) (leak OR dump OR database OR base OR cards)`))
	add("Info-stealer log dumps (ULP / RedLine ...)",
		q(quoted+` (stealer OR "stealer logs" OR redline OR raccoon OR ULP OR "logs cloud")`))
	add("Combolists / credential dumps",
		q(quoted+` (combolist OR "email:pass" OR "credentials leak" OR antipublic)`))

	env.emit(fmt.Sprintf("[+] exposure_search: %d brand-exposure search(es) ready", len(out)))
	return out, nil
}

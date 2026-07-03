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

	"github.com/analysishub/backend/internal/models"
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
	switch env.ttype {
	case TargetDomain:
		// handled by the domain sweep below
	case TargetEmail, TargetUsername:
		return stealerByIdentifier(ctx, env)
	default:
		return nil, nil
	}
	domain := strings.ToLower(strings.TrimSpace(env.target))

	body, status, err := hudsonRockPost(ctx,
		"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain",
		map[string]string{"domain": domain})
	if err != nil {
		return nil, err
	}
	if status == 404 {
		// Hudson Rock returns 404 when the domain has no records in its stealer-log
		// dataset - that is a clean "no exposure" result, not a collector failure.
		env.emit("[*] stealer_intel: domain not found in Hudson Rock stealer logs")
		return nil, nil
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

// stealerByIdentifier queries Hudson Rock's free Cavalier API for an individual
// e-mail or username appearing in info-stealer logs - the strongest single
// signal that an account's live credentials and session cookies are already in
// criminal hands. Free, no API key. Surfaces only metadata (date, OS, machine),
// never leaked secrets.
func stealerByIdentifier(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	id := strings.ToLower(strings.TrimSpace(env.target))
	if id == "" {
		return nil, nil
	}
	endpoint := "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"
	payload := map[string]string{"email": id}
	viewer := "https://www.hudsonrock.com/threat-intelligence-cybercrime-tools?email=" + url.QueryEscape(id)
	if env.ttype == TargetUsername {
		endpoint = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username"
		payload = map[string]string{"username": id}
		viewer = "https://www.hudsonrock.com/threat-intelligence-cybercrime-tools?username=" + url.QueryEscape(id)
	}

	body, status, err := hudsonRockPost(ctx, endpoint, payload)
	if err != nil {
		return nil, err
	}
	if status == 404 {
		env.emit("[*] stealer_intel: identifier not found in Hudson Rock stealer logs")
		return nil, nil
	}
	if status == 429 {
		return nil, fmt.Errorf("Hudson Rock rate-limited (HTTP 429)")
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("Hudson Rock returned HTTP %d", status)
	}

	var r struct {
		Message  string `json:"message"`
		Stealers []struct {
			DateCompromised string `json:"date_compromised"`
			ComputerName    string `json:"computer_name"`
			OperatingSystem string `json:"operating_system"`
			MalwarePath     string `json:"malware_path"`
			IP              string `json:"ip"`
		} `json:"stealers"`
	}
	// Best-effort decode: the free endpoint's nested shape varies, so a type
	// mismatch on an inner field must not fail the collector.
	_ = json.Unmarshal(body, &r)

	if len(r.Stealers) == 0 {
		env.emit("[*] stealer_intel: identifier not found in Hudson Rock stealer logs")
		return nil, nil
	}

	out := make([]models.OsintFinding, 0, len(r.Stealers)+1)
	summary := newFinding("stealer_intel", "breach", "Info-stealer exposure (Hudson Rock)",
		fmt.Sprintf("identifier found in %d info-stealer log(s)", len(r.Stealers)))
	summary.Severity = "critical" // a stealer-infected host means live credentials/cookies
	out = append(out, summary)

	const maxEntries = 10
	for i := range r.Stealers {
		if i >= maxEntries {
			break
		}
		s := r.Stealers[i]
		detail := joinNonEmpty(" - ", s.DateCompromised, s.OperatingSystem, s.ComputerName)
		if detail == "" {
			detail = "stealer log entry"
		}
		f := newFinding("stealer_intel", "breach", "Info-stealer log entry", detail)
		f.Severity = "high"
		f.Data = toJSON(map[string]string{
			"date_compromised": s.DateCompromised,
			"operating_system": s.OperatingSystem,
			"computer_name":    s.ComputerName,
			"malware_path":     s.MalwarePath,
		})
		out = append(out, f)
	}
	env.emit(fmt.Sprintf("[+] stealer_intel: %s found in %d stealer log(s)", id, len(r.Stealers)))
	return stampSource(out, viewer), nil
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

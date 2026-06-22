package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/forensichub/backend/internal/models"
)

// crtShCap limits how many individual subdomain findings crt.sh contributes,
// so a domain with thousands of CT entries cannot flood the report.
const crtShCap = 120

// waybackCap limits how many sample archived URLs are recorded.
const waybackCap = 40

// -- RDAP / WHOIS --------------------------------------------------------------

// collectDomainRDAP retrieves registration data (registrar, key dates, status,
// nameservers, contacts) for a domain via RDAP.
func collectDomainRDAP(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	u := "https://rdap.org/domain/" + url.PathEscape(env.target)
	r, status, err := fetchRDAP(ctx, u)
	if err != nil {
		return nil, err
	}
	if status == 404 {
		env.emit("[*] rdap: no registration record found")
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("rdap.org returned HTTP %d", status)
	}

	var out []models.OsintFinding

	if ev := fmtEvents(r.Events); ev != "" {
		out = append(out, newFinding("rdap", "registration", "Registration timeline", ev))
	}
	if len(r.Status) > 0 {
		out = append(out, newFinding("rdap", "registration", "Domain status",
			strings.Join(r.Status, ", ")))
	}
	for _, ns := range r.Nameservers {
		host := strings.TrimRight(strings.ToLower(ns.LdhName), ".")
		if host == "" {
			continue
		}
		out = append(out, newFinding("rdap", "registration", "Nameserver", host))
	}

	// Walk entities for registrar + contact e-mails (pivotable).
	seenEmail := map[string]bool{}
	walkEntities(r.Entities, func(roles []string, name, email, org string) {
		if hasRole(roles, "registrar") {
			label := joinNonEmpty(" - ", org, name)
			if label != "" {
				out = append(out, newFinding("rdap", "registration", "Registrar", label))
			}
		}
		email = strings.ToLower(strings.TrimSpace(email))
		if email != "" && !seenEmail[email] {
			seenEmail[email] = true
			role := "contact"
			if len(roles) > 0 {
				role = strings.Join(roles, "/")
			}
			f := newFinding("rdap", "registration",
				fmt.Sprintf("Registration contact (%s)", role), email)
			// Only offer a pivot for a well-formed address that isn't a
			// registrar/abuse infrastructure contact (those are out of scope for
			// the target org). Malformed WHOIS values stay as findings only.
			if emailRe.MatchString(email) && !hasRole(roles, "registrar") && !hasRole(roles, "abuse") {
				f = withRelated(f, RelatedEntity{Type: TargetEmail, Value: email})
			}
			out = append(out, f)
		}
	})

	if len(out) == 0 {
		env.emit("[*] rdap: record found but no extractable fields")
	}
	return out, nil
}

// -- DNS records ---------------------------------------------------------------

// collectDNS resolves the common DNS record types for a domain.
func collectDNS(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	r := &net.Resolver{}
	host := env.target
	var out []models.OsintFinding

	// A / AAAA
	if ips, err := r.LookupIPAddr(ctx, host); err == nil {
		for _, ip := range ips {
			s := ip.IP.String()
			kind := "A record"
			if ip.IP.To4() == nil {
				kind = "AAAA record"
			}
			f := newFinding("dns", "dns", kind, s)
			out = append(out, withRelated(f, RelatedEntity{Type: TargetIP, Value: s}))
		}
	}

	// MX
	if mxs, err := r.LookupMX(ctx, host); err == nil {
		for _, mx := range mxs {
			mh := strings.TrimRight(strings.ToLower(mx.Host), ".")
			if mh == "" {
				continue
			}
			f := newFinding("dns", "dns", "MX record",
				fmt.Sprintf("%s (priority %d)", mh, mx.Pref))
			out = append(out, withRelated(f, RelatedEntity{Type: TargetDomain, Value: mh}))
		}
	}

	// NS
	if nss, err := r.LookupNS(ctx, host); err == nil {
		for _, ns := range nss {
			nh := strings.TrimRight(strings.ToLower(ns.Host), ".")
			if nh != "" {
				out = append(out, newFinding("dns", "dns", "NS record", nh))
			}
		}
	}

	// CNAME (only report when it actually aliases elsewhere)
	if cname, err := r.LookupCNAME(ctx, host); err == nil {
		cn := strings.TrimRight(strings.ToLower(cname), ".")
		if cn != "" && cn != strings.ToLower(host) {
			f := newFinding("dns", "dns", "CNAME record", cn)
			out = append(out, withRelated(f, RelatedEntity{Type: TargetDomain, Value: cn}))
		}
	}

	// TXT (apex) - surfaces SPF, verification tokens, etc.
	if txts, err := r.LookupTXT(ctx, host); err == nil {
		for _, t := range txts {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			title := "TXT record"
			if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
				title = "SPF policy"
			}
			out = append(out, newFinding("dns", "dns", title, t))
		}
	}

	// DMARC lives on the _dmarc subdomain.
	if dmarc, err := r.LookupTXT(ctx, "_dmarc."+host); err == nil {
		for _, t := range dmarc {
			if strings.Contains(strings.ToLower(t), "v=dmarc1") {
				out = append(out, newFinding("dns", "dns", "DMARC policy", strings.TrimSpace(t)))
			}
		}
	}

	if len(out) == 0 {
		env.emit("[*] dns: domain did not resolve any records")
	}
	return out, nil
}

// -- Certificate Transparency (crt.sh) -----------------------------------------

type crtShRow struct {
	NameValue string `json:"name_value"`
}

// collectCrtSh enumerates subdomains from Certificate Transparency logs.
func collectCrtSh(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	q := url.Values{}
	q.Set("q", "%."+env.target)
	q.Set("output", "json")
	u := "https://crt.sh/?" + q.Encode()

	body, status, err := httpGetBody(ctx, rlCrtSh, u, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("crt.sh returned HTTP %d", status)
	}

	var rows []crtShRow
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("crt.sh decode: %w", err)
	}

	target := strings.ToLower(env.target)
	seen := map[string]bool{}
	var subs []string
	for _, row := range rows {
		for _, name := range strings.Split(row.NameValue, "\n") {
			h := strings.ToLower(strings.TrimSpace(name))
			if h == "" || strings.HasPrefix(h, "*.") {
				continue
			}
			if h != target && !strings.HasSuffix(h, "."+target) {
				continue
			}
			if seen[h] {
				continue
			}
			seen[h] = true
			subs = append(subs, h)
		}
	}
	sort.Strings(subs)

	var out []models.OsintFinding
	out = append(out, newFinding("crtsh", "certificate", "Subdomains in CT logs",
		fmt.Sprintf("%d unique hostname(s) seen in Certificate Transparency", len(subs))))

	capped := subs
	if len(capped) > crtShCap {
		capped = capped[:crtShCap]
		env.emit(fmt.Sprintf("[*] crtsh: %d subdomains found, recording first %d", len(subs), crtShCap))
	}
	for _, h := range capped {
		if h == target {
			continue
		}
		f := newFinding("crtsh", "certificate", "Subdomain", h)
		out = append(out, withRelated(f, RelatedEntity{Type: TargetDomain, Value: h}))
	}
	return out, nil
}

// -- Wayback Machine -----------------------------------------------------------

// collectWayback samples historical URLs the Internet Archive holds for the
// domain - useful to surface old endpoints, paths and parameters.
func collectWayback(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	q := url.Values{}
	q.Set("url", env.target+"/*")
	q.Set("output", "json")
	q.Set("collapse", "urlkey")
	q.Set("limit", "300")
	q.Set("fl", "original,timestamp,statuscode")
	u := env.cfg.APIWebArchiveURL + "?" + q.Encode()

	body, status, err := httpGetBody(ctx, nil, u, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("wayback returned HTTP %d", status)
	}

	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("wayback decode: %w", err)
	}
	// First row is the column header - drop it.
	if len(rows) > 0 {
		rows = rows[1:]
	}
	if len(rows) == 0 {
		env.emit("[*] wayback: no archived snapshots")
		return nil, nil
	}

	var out []models.OsintFinding
	out = append(out, newFinding("wayback", "historical", "Archived snapshots",
		fmt.Sprintf("%d unique URL(s) archived by the Wayback Machine", len(rows))))

	limit := len(rows)
	if limit > waybackCap {
		limit = waybackCap
	}
	for _, row := range rows[:limit] {
		if len(row) == 0 {
			continue
		}
		val := row[0]
		if len(row) >= 2 && row[1] != "" {
			val = fmt.Sprintf("%s (snapshot %s)", row[0], row[1])
		}
		out = append(out, newFinding("wayback", "historical", "Archived URL", val))
	}
	return out, nil
}

// -- VirusTotal (optional key) -------------------------------------------------

type vtDomainResponse struct {
	Data struct {
		Attributes struct {
			Reputation       int `json:"reputation"`
			LastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
}

// collectDomainVirusTotal queries VirusTotal for a domain's reputation. Needs
// OSINT_VIRUSTOTAL_API_KEY; skipped (not failed) when unset.
func collectDomainVirusTotal(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	if env.keys.VirusTotal == "" {
		return nil, errNoAPIKey
	}
	u := "https://www.virustotal.com/api/v3/domains/" + url.PathEscape(env.target)
	var r vtDomainResponse
	status, err := httpGetJSON(ctx, rlVT, u, map[string]string{"x-apikey": env.keys.VirusTotal}, &r)
	if err != nil {
		return nil, err
	}
	if status == 401 {
		return nil, fmt.Errorf("VirusTotal rejected the API key (HTTP 401)")
	}
	if status == 404 {
		env.emit("[*] virustotal: domain not present in VT dataset")
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("VirusTotal returned HTTP %d", status)
	}

	st := r.Data.Attributes.LastAnalysisStats
	f := newFinding("virustotal", "reputation", "VirusTotal verdict",
		fmt.Sprintf("malicious %d - suspicious %d - harmless %d - reputation %d",
			st.Malicious, st.Suspicious, st.Harmless, r.Data.Attributes.Reputation))
	switch {
	case st.Malicious > 0:
		f.Severity = "high"
	case st.Suspicious > 0:
		f.Severity = "medium"
	}
	return []models.OsintFinding{f}, nil
}

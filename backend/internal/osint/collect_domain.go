package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

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
	srcURL := u // the RDAP record itself is the verifiable source
	r, status, err := fetchRDAPCached(ctx, env, "rdap:domain:"+env.target, u)
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
	return stampSource(out, srcURL), nil
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
			// A public domain resolving to an internal address is a finding worth
			// flagging, but never a public-OSINT pivot target - record it without a
			// related entity so auto-pivot can't reach into private space.
			if !isPublicIP(ip.IP) {
				f := newFinding("dns", "dns", kind+" (non-public)", s)
				f.Severity = "low"
				f.VerifyNote = "resolves to a private/reserved address - not pivoted"
				out = append(out, f)
				continue
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
	hasSPF := false
	if txts, err := r.LookupTXT(ctx, host); err == nil {
		for _, t := range txts {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			title := "TXT record"
			if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
				title = "SPF policy"
				hasSPF = true
			}
			out = append(out, newFinding("dns", "dns", title, t))
		}
	}

	// DMARC lives on the _dmarc subdomain.
	hasDMARC := false
	dmarcPolicy := ""
	if dmarc, err := r.LookupTXT(ctx, "_dmarc."+host); err == nil {
		for _, t := range dmarc {
			if strings.Contains(strings.ToLower(t), "v=dmarc1") {
				hasDMARC = true
				dmarcPolicy = dmarcPolicyOf(t)
				out = append(out, newFinding("dns", "dns", "DMARC policy", strings.TrimSpace(t)))
			}
		}
	}

	// Grade how easily mail can be spoofed from this domain. Missing/weak SPF and
	// DMARC are a phishing-impersonation risk the analyst should see at a glance.
	out = append(out, emailSpoofPosture(hasSPF, hasDMARC, dmarcPolicy))

	if len(out) == 0 {
		env.emit("[*] dns: domain did not resolve any records")
	}
	// Every DNS record is independently verifiable through a public DoH resolver.
	return stampSource(out, "https://dns.google/query?name="+url.QueryEscape(host)), nil
}

// dmarcPolicyOf extracts the p= policy token (none|quarantine|reject) from a
// DMARC record, or "" if absent.
func dmarcPolicyOf(record string) string {
	for _, tag := range strings.Split(record, ";") {
		tag = strings.TrimSpace(strings.ToLower(tag))
		if strings.HasPrefix(tag, "p=") {
			return strings.TrimSpace(strings.TrimPrefix(tag, "p="))
		}
	}
	return ""
}

// emailSpoofPosture turns the SPF/DMARC state into a single graded finding.
func emailSpoofPosture(hasSPF, hasDMARC bool, policy string) models.OsintFinding {
	switch {
	case !hasSPF && !hasDMARC:
		f := newFinding("dns", "dns", "Email spoofing posture",
			"no SPF and no DMARC - the domain can be trivially spoofed in phishing")
		f.Severity = "high"
		return f
	case !hasDMARC || policy == "none" || policy == "":
		detail := "SPF present but DMARC missing"
		if hasDMARC {
			detail = "DMARC policy is p=none (monitor only) - spoofed mail is not rejected"
		}
		f := newFinding("dns", "dns", "Email spoofing posture", detail+" - impersonation possible")
		f.Severity = "medium"
		return f
	case policy == "quarantine":
		f := newFinding("dns", "dns", "Email spoofing posture",
			"SPF + DMARC p=quarantine - spoofed mail is quarantined")
		f.Severity = "low"
		return f
	default: // reject
		f := newFinding("dns", "dns", "Email spoofing posture",
			"SPF + DMARC p=reject - strong anti-spoofing posture")
		f.Severity = "info"
		return f
	}
}

// -- Certificate Transparency (crt.sh) -----------------------------------------

type crtShRow struct {
	NameValue string `json:"name_value"`
}

// rlCertSpotter paces the certspotter fallback CT source.
var rlCertSpotter = newRateLimiter(2 * time.Second)

// collectCrtSh enumerates subdomains from Certificate Transparency logs (crt.sh,
// with a certspotter fallback when crt.sh is down or empty), then resolves each
// discovered hostname so the report distinguishes live infrastructure from stale
// CT entries and feeds resolved IPs into the investigation graph.
func collectCrtSh(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	target := strings.ToLower(env.target)
	subs, src, err := ctSubdomains(ctx, env, target)
	if len(subs) == 0 {
		// CT enumeration is best-effort: crt.sh is frequently slow or unreachable
		// and certspotter (its fallback) can also be empty. A transient failure
		// here must not fail the collector - subdomains still come from subbrute
		// and host_search - so degrade to a clean "no data" result.
		if err != nil {
			env.emit("[*] crtsh: CT lookup unavailable (" + err.Error() + ") - skipping")
		} else {
			env.emit("[*] crtsh: no subdomains in CT logs")
		}
		return nil, nil
	}
	sort.Strings(subs)

	capped := subs
	truncated := false
	if len(capped) > crtShCap {
		capped = capped[:crtShCap]
		truncated = true
		env.emit(fmt.Sprintf("[*] crtsh: %d subdomains found (%s), resolving first %d", len(subs), src, crtShCap))
	}

	// Resolve the discovered hostnames concurrently so live ones are marked and
	// their public IPs become pivots.
	live := resolveHosts(ctx, capped)

	liveCount := 0
	for _, ips := range live {
		if len(ips) > 0 {
			liveCount++
		}
	}

	var out []models.OsintFinding
	summary := fmt.Sprintf("%d unique hostname(s) in Certificate Transparency (%s); %d resolve live",
		len(subs), src, liveCount)
	if truncated {
		summary += fmt.Sprintf(" — first %d resolved", crtShCap)
	}
	out = append(out, newFinding("crtsh", "certificate", "Subdomains in CT logs", summary))

	for _, h := range capped {
		if h == target {
			continue
		}
		ips := live[h]
		rels := []RelatedEntity{{Type: TargetDomain, Value: h}}
		val := h
		if len(ips) > 0 {
			val = h + " -> " + strings.Join(ips, ", ")
			for _, ip := range ips {
				rels = append(rels, RelatedEntity{Type: TargetIP, Value: ip})
			}
		} else {
			val = h + " (no DNS / not live)"
		}
		f := newFinding("crtsh", "certificate", "Subdomain", val)
		out = append(out, withRelated(f, rels...))
	}
	return stampSource(out, crtShURL(env.target)), nil
}

// ctSubdomains returns the in-scope subdomains for target from Certificate
// Transparency: crt.sh first, falling back to certspotter when crt.sh errors or
// yields nothing. The returned label names which source(s) produced the data.
func ctSubdomains(ctx context.Context, env *collectorEnv, target string) (subs []string, source string, err error) {
	seen := map[string]bool{}
	add := func(name string) {
		h := strings.ToLower(strings.TrimSpace(name))
		h = strings.TrimPrefix(h, "*.")
		if h == "" || (h != target && !strings.HasSuffix(h, "."+target)) || seen[h] {
			return
		}
		seen[h] = true
		subs = append(subs, h)
	}

	// crt.sh
	q := url.Values{}
	q.Set("q", "%."+target)
	q.Set("output", "json")
	body, status, cerr := cachedGetBody(ctx, env.cache, "crtsh:"+target, rlCrtSh, "https://crt.sh/?"+q.Encode(), nil, ttlCrtSh)
	if cerr == nil && status == 200 {
		var rows []crtShRow
		if json.Unmarshal(body, &rows) == nil {
			for _, row := range rows {
				for _, name := range strings.Split(row.NameValue, "\n") {
					add(name)
				}
			}
			if len(subs) > 0 {
				return subs, "crt.sh", nil
			}
		}
	} else if cerr != nil {
		err = cerr
	}

	// Fallback: certspotter (free, no key).
	cs := "https://api.certspotter.com/v1/issuances?domain=" + url.QueryEscape(target) +
		"&include_subdomains=true&expand=dns_names"
	var issuances []struct {
		DNSNames []string `json:"dns_names"`
	}
	if st, ferr := cachedGetJSON(ctx, env.cache, "certspotter:"+target, rlCertSpotter, cs, nil, &issuances, ttlCrtSh); ferr == nil && st == 200 {
		for _, is := range issuances {
			for _, name := range is.DNSNames {
				add(name)
			}
		}
		if len(subs) > 0 {
			return subs, "certspotter", nil
		}
	}
	return subs, "crt.sh+certspotter", err
}

// resolveHosts concurrently resolves hostnames to their public A/AAAA addresses,
// returning a map of host -> []ip (only globally-routable IPs). Bounded so a
// large CT result set can't fan out unboundedly.
func resolveHosts(ctx context.Context, hosts []string) map[string][]string {
	out := make(map[string][]string, len(hosts))
	var mu sync.Mutex
	sem := make(chan struct{}, 25)
	var wg sync.WaitGroup
	resolver := &net.Resolver{}
	for _, h := range hosts {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			// Per-lookup deadline so one slow DNS answer can't dominate the budget.
			lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			addrs, err := resolver.LookupIPAddr(lctx, host)
			cancel()
			if err != nil || len(addrs) == 0 {
				return
			}
			var ips []string
			for _, a := range addrs {
				if isPublicIP(a.IP) {
					ips = append(ips, a.IP.String())
				}
			}
			if len(ips) > 0 {
				mu.Lock()
				out[host] = ips
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
	return out
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

	body, status, err := cachedGetBody(ctx, env.cache, "wayback:"+strings.ToLower(env.target), nil, u, nil, ttlWayback)
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
	return stampSource(out, "https://web.archive.org/web/*/"+url.PathEscape(env.target)+"/*"), nil
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
	status, err := cachedGetJSON(ctx, env.cache, "vt:domain:"+env.target, rlVT, u,
		map[string]string{"x-apikey": env.keys.VirusTotal}, &r, ttlVirusTotal)
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
	return []models.OsintFinding{withSource(f, vtGUIURL(env.target, TargetDomain))}, nil
}

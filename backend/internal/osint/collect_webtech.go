package osint

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"

	"github.com/forensichub/backend/internal/egress"
	"github.com/forensichub/backend/internal/models"
)

// wappaClient is the shared Wappalyzer fingerprint engine (3000+ technologies).
// New() parses an embedded fingerprint DB, so it is built once and reused.
var (
	wappaClient *wappalyzer.Wappalyze
	wappaOnce   sync.Once
)

// wappaFingerprint runs the Wappalyzer engine over a response's headers + body,
// returning each detected technology (key may be "Name:version") with its
// metadata (CPE, categories). Returns nil if the engine failed to initialise.
func wappaFingerprint(h http.Header, body []byte) map[string]wappalyzer.AppInfo {
	wappaOnce.Do(func() {
		if c, err := wappalyzer.New(); err == nil {
			wappaClient = c
		}
	})
	if wappaClient == nil {
		return nil
	}
	return wappaClient.FingerprintWithInfo(h, body)
}

// splitTechVersion splits a Wappalyzer "Name:version" key into its name and
// version parts ("Nginx:1.18.0" -> "Nginx","1.18.0"; "MySQL" -> "MySQL","").
func splitTechVersion(name string) (base, version string) {
	if i := strings.LastIndex(name, ":"); i > 0 {
		return name[:i], name[i+1:]
	}
	return name, ""
}

// webtechClient fetches the target's web root for fingerprinting. It skips TLS
// verification (an IP target or staging host often serves a mismatched cert, and
// we only read headers/markup - we never trust the content) and follows a few
// redirects so an http->https hop is resolved. It still honours the egress proxy.
var webtechClient = &http.Client{
	Timeout: 12 * time.Second,
	CheckRedirect: func(_ *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		return nil
	},
	Transport: &http.Transport{
		Proxy:           egress.Proxy,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, //nolint:gosec // fingerprint-only, content is not trusted
		MaxIdleConns:    8,
		IdleConnTimeout: 30 * time.Second,
	},
}

// detectedTech is one identified technology. cpeKey, when non-empty, keys into
// productCPE so a version-specific CVE lookup can follow.
type detectedTech struct {
	name    string // display label, e.g. "nginx", "WordPress", "PHP"
	version string
	cpeKey  string // productCPE key, e.g. "nginx", "wordpress" ("" = no CVE lookup)
}

var metaGeneratorRe = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)

// collectWebTech fingerprints the technology stack of a web target (domain or
// IP): web server, backend language/framework, and CMS, with versions where the
// server discloses them. Each versioned, well-known product is then matched
// against NVD so the collector also answers "does the running stack have known
// CVEs?". It also grades the response's security-header posture.
func collectWebTech(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	resp, body, finalURL := webtechFetch(ctx, env.target, env.ttype)
	if resp == nil {
		env.emit("[*] webtech: target did not serve a reachable web root")
		return nil, nil
	}
	defer resp.Body.Close()

	var out []models.OsintFinding
	out = append(out, newFinding("webtech", "techstack", "Web root reachable", finalURL))

	// TLS certificate SANs are the subject's own additional hostnames (an
	// in-scope, high-signal way to discover more of its infrastructure). Each
	// SAN becomes a domain pivot; out-of-namespace SANs on a shared cert are
	// filtered later by the pivot scope check.
	out = append(out, certSANFindings(resp)...)

	techCount := 0
	cveDone := 0
	if infos := wappaFingerprint(resp.Header, []byte(body)); len(infos) > 0 {
		// Wappalyzer (3000+ fingerprints) is the primary, high-coverage detector.
		// Each detection may carry a version ("Name:version") and a CPE we can use
		// to drive accurate, version-specific CVE matching.
		names := make([]string, 0, len(infos))
		for name := range infos {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			info := infos[name]
			base, version := splitTechVersion(name)
			label := base
			if version != "" {
				label = base + " " + version
			}
			f := newFinding("webtech", "techstack", "Technology", label)
			if len(info.Categories) > 0 {
				f.Data = toJSON(map[string]string{"category": strings.Join(info.Categories, ", ")})
			}
			out = append(out, f)
			techCount++

			if version != "" && cveDone < 5 {
				if vendor, product, ok := parseCPEVendorProduct(info.CPE); ok {
					if cves := lookupCVEs(ctx, env, "webtech", vendor+" "+product, version); len(cves) > 0 {
						out = append(out, cves...)
						cveDone++
					}
				} else {
					if cves := lookupCVEs(ctx, env, "webtech", base, version); len(cves) > 0 {
						out = append(out, cves...)
						cveDone++
					}
				}
			}
		}
	} else {
		// Fallback: the lightweight built-in fingerprinter (when Wappalyzer's DB
		// failed to load or matched nothing).
		seen := map[string]bool{}
		for _, t := range fingerprint(resp.Header, body) {
			key := strings.ToLower(t.name + "|" + t.version)
			if seen[key] {
				continue
			}
			seen[key] = true
			label := t.name
			if t.version != "" {
				label = t.name + " " + t.version
			}
			out = append(out, newFinding("webtech", "techstack", "Technology", label))
			techCount++
			if t.cpeKey != "" && t.version != "" && cveDone < 4 {
				if cves := lookupCVEs(ctx, env, "webtech", t.cpeKey, t.version); len(cves) > 0 {
					out = append(out, cves...)
					cveDone++
				}
			}
		}
	}

	out = append(out, securityHeaderPosture(resp.Header))

	env.emit(fmt.Sprintf("[+] webtech: %d technolog(y/ies) fingerprinted", techCount))
	// The fetched web root is the evidence for every fingerprint (CVE findings
	// keep their own NVD link, which stampSource leaves intact).
	return stampSource(out, finalURL), nil
}

// certSANFindings extracts the Subject Alternative Names from the served TLS
// certificate and emits each distinct hostname as a finding + domain pivot. SANs
// are the subject's own declared hostnames, so this widens the in-scope
// infrastructure footprint without guessing.
func certSANFindings(resp *http.Response) []models.OsintFinding {
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil
	}
	leaf := resp.TLS.PeerCertificates[0]
	var out []models.OsintFinding
	seen := map[string]bool{}
	for _, name := range leaf.DNSNames {
		h := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(name)), "*.")
		if h == "" || seen[h] || !domainRe.MatchString(h) {
			continue
		}
		seen[h] = true
		f := newFinding("webtech", "certificate", "TLS certificate SAN", h)
		out = append(out, withRelated(f, RelatedEntity{Type: TargetDomain, Value: h}))
		if len(out) >= 50 {
			break
		}
	}
	if issuer := strings.TrimSpace(leaf.Issuer.CommonName); issuer != "" {
		out = append(out, newFinding("webtech", "certificate", "TLS certificate issuer", issuer))
	}
	return out
}

// webtechFetch tries https then http for a domain, or both schemes for an IP, and
// returns the first response together with a capped body and the final URL.
func webtechFetch(ctx context.Context, target, ttype string) (*http.Response, string, string) {
	host := strings.TrimSpace(target)
	var candidates []string
	switch ttype {
	case TargetIP:
		candidates = []string{"https://" + host, "http://" + host}
	default:
		candidates = []string{"https://" + host, "http://" + host}
	}
	for _, u := range candidates {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", browserUA)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		resp, err := webtechClient.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		fin := u
		if resp.Request != nil && resp.Request.URL != nil {
			fin = resp.Request.URL.String()
		}
		return resp, string(body), fin
	}
	return nil, "", ""
}

// fingerprint derives the technology list from response headers and body markup.
func fingerprint(h http.Header, body string) []detectedTech {
	var techs []detectedTech
	add := func(name, version, cpeKey string) {
		techs = append(techs, detectedTech{name: name, version: version, cpeKey: cpeKey})
	}

	// Server header: "nginx/1.18.0", "Apache/2.4.49 (Unix)", "Microsoft-IIS/10.0".
	if s := h.Get("Server"); s != "" {
		name, ver := splitServerToken(s)
		add(name, ver, cpeKeyFor(name))
	}
	// X-Powered-By: "PHP/7.4.3", "Express", "ASP.NET".
	if p := h.Get("X-Powered-By"); p != "" {
		name, ver := splitServerToken(p)
		add(name, ver, cpeKeyFor(name))
	}
	if v := h.Get("X-AspNet-Version"); v != "" {
		add("ASP.NET", extractVersion(v), "")
	}
	// Drupal advertises itself through these response headers.
	if h.Get("X-Drupal-Cache") != "" || h.Get("X-Drupal-Dynamic-Cache") != "" || strings.Contains(h.Get("X-Generator"), "Drupal") {
		add("Drupal", extractVersion(h.Get("X-Generator")), "drupal")
	}

	// Set-Cookie session-name signatures.
	cookies := strings.ToLower(strings.Join(h.Values("Set-Cookie"), " "))
	switch {
	case strings.Contains(cookies, "wordpress_") || strings.Contains(cookies, "wp-settings"):
		add("WordPress", "", "wordpress")
	}
	if strings.Contains(cookies, "laravel_session") {
		add("Laravel", "", "")
	}
	if strings.Contains(cookies, "ci_session") {
		add("CodeIgniter", "", "")
	}
	if strings.Contains(cookies, "jsessionid") {
		add("Java (JSP/Servlet)", "", "")
	}
	if strings.Contains(cookies, "phpsessid") {
		add("PHP", "", "php")
	}

	// HTML <meta name="generator">: "WordPress 6.2", "Joomla! - Open Source ...".
	if m := metaGeneratorRe.FindStringSubmatch(body); len(m) == 2 {
		gen := m[1]
		lg := strings.ToLower(gen)
		switch {
		case strings.Contains(lg, "wordpress"):
			add("WordPress", extractVersion(gen), "wordpress")
		case strings.Contains(lg, "joomla"):
			add("Joomla", extractVersion(gen), "joomla")
		case strings.Contains(lg, "drupal"):
			add("Drupal", extractVersion(gen), "drupal")
		default:
			add(strings.TrimSpace(gen), extractVersion(gen), "")
		}
	}

	// Body markers for CMS / JS frameworks (version-less, but valuable context).
	lb := strings.ToLower(body)
	if strings.Contains(lb, "/wp-content/") || strings.Contains(lb, "/wp-includes/") {
		add("WordPress", "", "wordpress")
	}
	if strings.Contains(lb, "sites/default/files") || strings.Contains(lb, "drupal.settings") {
		add("Drupal", "", "drupal")
	}
	if strings.Contains(lb, "/media/jui/") || strings.Contains(lb, "joomla") {
		add("Joomla", "", "joomla")
	}
	if strings.Contains(lb, "data-reactroot") || strings.Contains(lb, "__react") {
		add("React", "", "")
	}
	if strings.Contains(lb, "window.__nuxt__") {
		add("Nuxt.js", "", "")
	}
	if ng := regexp.MustCompile(`ng-version="([0-9.]+)"`).FindStringSubmatch(body); len(ng) == 2 {
		add("Angular", ng[1], "")
	}
	return techs
}

// splitServerToken splits a "Product/Version (extra)" token into name + version.
func splitServerToken(s string) (name, version string) {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " ("); i > 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "/"); i > 0 {
		return strings.TrimSpace(s[:i]), extractVersion(s[i+1:])
	}
	return s, ""
}

// cpeKeyFor maps a server/header product name to a productCPE key, or "".
// Now just returns the lowercased name since productCPE is removed and we use Fuzzy Matching.
func cpeKeyFor(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// securityHeaderPosture grades the presence of the key browser-security headers.
func securityHeaderPosture(h http.Header) models.OsintFinding {
	type sh struct{ header, label string }
	checks := []sh{
		{"Strict-Transport-Security", "HSTS"},
		{"Content-Security-Policy", "CSP"},
		{"X-Frame-Options", "X-Frame-Options"},
		{"X-Content-Type-Options", "X-Content-Type-Options"},
	}
	var missing []string
	for _, c := range checks {
		if h.Get(c.header) == "" {
			missing = append(missing, c.label)
		}
	}
	if len(missing) == 0 {
		f := newFinding("webtech", "techstack", "Security headers", "all key security headers present")
		f.Severity = "info"
		return f
	}
	f := newFinding("webtech", "techstack", "Security headers",
		"missing: "+strings.Join(missing, ", "))
	if len(missing) >= 3 {
		f.Severity = "medium"
	} else {
		f.Severity = "low"
	}
	return f
}

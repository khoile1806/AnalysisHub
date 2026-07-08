package osint

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// TechStackResult is the standalone "paste a URL → tech stack" lookup payload.
// It is intentionally decoupled from the OsintFinding model: this is a one-shot,
// synchronous tool, not a persisted scan.
type TechStackResult struct {
	InputURL        string           `json:"input_url"`
	FinalURL        string           `json:"final_url"`
	Host            string           `json:"host"`
	StatusCode      int              `json:"status_code"`
	Title           string           `json:"title,omitempty"`
	Server          string           `json:"server,omitempty"`
	PoweredBy       string           `json:"powered_by,omitempty"`
	Technologies    []Technology     `json:"technologies"`
	EdgeServices    []EdgeService    `json:"edge_services,omitempty"`
	SecurityHeaders []SecurityHeader `json:"security_headers"`
	MissingHeaders  []string         `json:"missing_security_headers"`
	Cookies         []CookieInfo     `json:"cookies,omitempty"`
	CORS            *CORSInfo        `json:"cors,omitempty"`
	TLS             *TLSInfo         `json:"tls,omitempty"`
	Exposures       []ExposedPath    `json:"exposures,omitempty"`
	ProbedPaths     []string         `json:"probed_paths,omitempty"`
}

// FingerprintOptions controls how intrusive the lookup is.
//   - Active: probe well-known CMS version files (mild — reads public version markers).
//   - Deep:   probe for exposed sensitive files / panels (.git, .env, actuator, phpMyAdmin…)
//     — aggressive, authorized targets only. Both are force-disabled by a
//     passive-only scope decision (enforced in the handler).
type FingerprintOptions struct {
	Active bool
	Deep   bool
}

// EdgeService is a detected CDN or Web Application Firewall sitting in front of
// the origin. It is surfaced prominently because it changes exploitability: a WAF
// may block payloads and a CDN masks/caches the real origin.
type EdgeService struct {
	Name     string `json:"name"`
	Type     string `json:"type"` // CDN | WAF
	Evidence string `json:"evidence"`
}

// ExposedPath is a sensitive file or panel found reachable during deep probing.
type ExposedPath struct {
	Path     string `json:"path"`
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Severity string `json:"severity"` // critical | high | medium | low | info
	Title    string `json:"title"`
	Evidence string `json:"evidence,omitempty"`
}

// Technology is one detected component of the stack. Version drives CVE matching;
// Confidence == "confirmed" means a version was observed, "detected" means the
// component was seen without a version (CVE matching is skipped for the latter to
// avoid flooding the result with version-agnostic false positives).
type Technology struct {
	Name        string   `json:"name"`
	Version     string   `json:"version,omitempty"`
	Categories  []string `json:"categories,omitempty"`
	CPE         string   `json:"cpe,omitempty"`
	Source      string   `json:"source"`     // wappalyzer | headers | active-probe | js-library
	Confidence  string   `json:"confidence"` // confirmed | detected
	Outdated    bool     `json:"outdated,omitempty"`
	EOL         bool     `json:"eol,omitempty"`
	LatestKnown string   `json:"latest_known,omitempty"` // indicative latest release
	// KnownVulns is set for JS libraries detected via the retire.js database: the
	// precise per-version-range vulnerabilities, used directly instead of a fuzzy
	// NVD keyword search.
	KnownVulns []LibVuln `json:"known_vulns,omitempty"`
}

// LibVuln is one vulnerability affecting a detected library version, sourced from
// the retire.js vulnerability database.
type LibVuln struct {
	CVE      string `json:"cve,omitempty"`
	Severity string `json:"severity"`
	Summary  string `json:"summary,omitempty"`
	Info     string `json:"info,omitempty"`
}

// CookieInfo records the security flags on one Set-Cookie, with any weaknesses.
type CookieInfo struct {
	Name     string   `json:"name"`
	Secure   bool     `json:"secure"`
	HttpOnly bool     `json:"http_only"`
	SameSite string   `json:"same_site,omitempty"`
	Issues   []string `json:"issues,omitempty"`
}

// CORSInfo summarises the Cross-Origin Resource Sharing posture observed when the
// page is requested with an attacker-style Origin header.
type CORSInfo struct {
	AllowOrigin      string `json:"allow_origin,omitempty"`
	AllowCredentials bool   `json:"allow_credentials"`
	Reflected        bool   `json:"reflected"` // ACAO echoes an arbitrary Origin
	Severity         string `json:"severity"`  // high | medium | low | info
	Note             string `json:"note"`
}

// SecurityHeader records the presence/value of one browser-security header.
type SecurityHeader struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
	Value   string `json:"value,omitempty"`
}

// TLSInfo summarises the served certificate for quick posture review.
type TLSInfo struct {
	Version       string   `json:"version,omitempty"`
	Issuer        string   `json:"issuer,omitempty"`
	Subject       string   `json:"subject,omitempty"`
	SANs          []string `json:"sans,omitempty"`
	NotAfter      string   `json:"not_after,omitempty"`
	ExpiresInDays int      `json:"expires_in_days"`
}

var (
	titleRe      = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	wpVersionRe  = regexp.MustCompile(`(?i)\bversion\s+([0-9]+(?:\.[0-9]+){1,2})`)
	drupalVerRe  = regexp.MustCompile(`(?i)Drupal\s+([0-9]+(?:\.[0-9]+){1,2})`)
	joomlaVerRe  = regexp.MustCompile(`(?i)<version>\s*([0-9]+(?:\.[0-9]+){1,2})`)
	securityHdrs = []struct{ header, label string }{
		{"Strict-Transport-Security", "HSTS"},
		{"Content-Security-Policy", "Content-Security-Policy"},
		{"X-Frame-Options", "X-Frame-Options"},
		{"X-Content-Type-Options", "X-Content-Type-Options"},
		{"Referrer-Policy", "Referrer-Policy"},
		{"Permissions-Policy", "Permissions-Policy"},
	}
)

// FingerprintURL fetches a web target and identifies its technology stack. When
// active is true it additionally probes a few well-known CMS version endpoints to
// resolve concrete versions (which sharpen CVE matching); passive mode does a
// single GET only. It is SSRF-safe (private/loopback hosts are rejected up-front
// and blocked again at dial time by the shared osint transport).
func FingerprintURL(ctx context.Context, rawURL string, opts FingerprintOptions) (*TechStackResult, error) {
	active := opts.Active
	raw := strings.TrimSpace(rawURL)
	if raw == "" {
		return nil, errors.New("url is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, errors.New("invalid url")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("only http(s) URLs are supported")
	}
	host := u.Hostname()
	ttype, err := DetectTargetType(host)
	if err != nil {
		return nil, fmt.Errorf("invalid host: %w", err)
	}
	if ttype != TargetDomain && ttype != TargetIP {
		return nil, errors.New("the URL host must be a domain or IP address")
	}
	// Rejects private/loopback/link-local + malformed targets before any request.
	if verr := ValidateTarget(host, ttype); verr != nil {
		return nil, verr
	}

	resp, body, finalURL := techFetch(ctx, u.String())
	if resp == nil {
		// Retry once over http when https was assumed and failed.
		if u.Scheme == "https" && !strings.Contains(rawURL, "://") {
			u.Scheme = "http"
			resp, body, finalURL = techFetch(ctx, u.String())
		}
		if resp == nil {
			return nil, errors.New("target did not serve a reachable web page")
		}
	}

	res := &TechStackResult{
		InputURL:   rawURL,
		FinalURL:   finalURL,
		Host:       host,
		StatusCode: resp.StatusCode,
		Server:     strings.TrimSpace(resp.Header.Get("Server")),
		PoweredBy:  strings.TrimSpace(resp.Header.Get("X-Powered-By")),
	}
	if m := titleRe.FindStringSubmatch(body); len(m) == 2 {
		res.Title = truncate(strings.TrimSpace(htmlUnescapeLite(m[1])), 160)
	}

	// techByKey accumulates detections keyed by lowercased name so multiple sources
	// (Wappalyzer, headers, active probes) merge into one entry, preferring the one
	// that carries a version.
	techByKey := map[string]*Technology{}
	upsert := func(t Technology) {
		key := strings.ToLower(strings.TrimSpace(t.Name))
		if key == "" {
			return
		}
		if t.Version != "" {
			t.Confidence = "confirmed"
		} else {
			t.Confidence = "detected"
		}
		cur, ok := techByKey[key]
		if !ok {
			cp := t
			techByKey[key] = &cp
			return
		}
		// Merge: keep a concrete version and CPE, union categories.
		if cur.Version == "" && t.Version != "" {
			cur.Version = t.Version
			cur.Confidence = "confirmed"
			cur.Source = t.Source
		}
		if cur.CPE == "" && t.CPE != "" {
			cur.CPE = t.CPE
		}
		cur.Categories = unionStrings(cur.Categories, t.Categories)
	}

	// Primary detector: Wappalyzer (3000+ fingerprints, carries CPE + categories).
	if infos := wappaFingerprint(resp.Header, []byte(body)); len(infos) > 0 {
		for name, info := range infos {
			base, version := splitTechVersion(name)
			upsert(Technology{
				Name:       base,
				Version:    version,
				Categories: info.Categories,
				CPE:        info.CPE,
				Source:     "wappalyzer",
			})
		}
	}
	// Header/markup fallback fingerprints (also fills versions Wappalyzer misses).
	for _, t := range fingerprint(resp.Header, body) {
		upsert(Technology{Name: t.name, Version: t.version, Source: "headers"})
	}

	// JS libraries parsed from <script src> (retire.js-style): versioned client-side
	// libraries (jQuery, Bootstrap, Angular…) that the CVE matcher then looks up.
	// Passive — this only reads the already-fetched HTML.
	for _, t := range detectJSLibraries(body) {
		upsert(t)
	}

	// Active version probing: only for CMSs actually detected, and only host-root
	// version files (bounded, short). This is the "more accurate" mode the user opts
	// into for authorized targets.
	if active && ttype == TargetDomain {
		baseURL := u.Scheme + "://" + u.Host
		probeCMSVersions(ctx, baseURL, techByKey, &res.ProbedPaths, upsert)
	}

	// Flatten + sort: versioned first, then by name.
	res.Technologies = make([]Technology, 0, len(techByKey))
	for _, t := range techByKey {
		res.Technologies = append(res.Technologies, *t)
	}
	sort.SliceStable(res.Technologies, func(i, j int) bool {
		vi, vj := res.Technologies[i].Version != "", res.Technologies[j].Version != ""
		if vi != vj {
			return vi
		}
		return strings.ToLower(res.Technologies[i].Name) < strings.ToLower(res.Technologies[j].Name)
	})

	// Edge protection (WAF / CDN) from response headers + fingerprint categories —
	// surfaced separately because it materially changes exploitability.
	res.EdgeServices = detectEdgeServices(resp.Header, res.Technologies)

	// Security header posture.
	for _, h := range securityHdrs {
		v := resp.Header.Get(h.header)
		res.SecurityHeaders = append(res.SecurityHeaders, SecurityHeader{
			Name: h.label, Present: v != "", Value: truncate(v, 120),
		})
		if v == "" {
			res.MissingHeaders = append(res.MissingHeaders, h.label)
		}
	}

	// Flag outdated / end-of-life components (best-effort, indicative).
	for i := range res.Technologies {
		annotateLifecycle(&res.Technologies[i])
	}

	// Cookie security flags + CORS posture from the response headers.
	res.Cookies = parseCookies(resp.Header)
	res.CORS = parseCORS(resp.Header)

	// TLS certificate summary.
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		leaf := resp.TLS.PeerCertificates[0]
		info := &TLSInfo{
			Version:  tlsVersionName(resp.TLS.Version),
			Issuer:   strings.TrimSpace(leaf.Issuer.CommonName),
			Subject:  strings.TrimSpace(leaf.Subject.CommonName),
			NotAfter: leaf.NotAfter.UTC().Format("2006-01-02"),
		}
		info.ExpiresInDays = int(time.Until(leaf.NotAfter).Hours() / 24)
		seen := map[string]bool{}
		for _, san := range leaf.DNSNames {
			san = strings.ToLower(strings.TrimSpace(san))
			if san == "" || seen[san] {
				continue
			}
			seen[san] = true
			info.SANs = append(info.SANs, san)
			if len(info.SANs) >= 25 {
				break
			}
		}
		res.TLS = info
	}

	// Deep probing: check for exposed sensitive files / admin panels. Aggressive —
	// gated by opts.Deep (and the handler forces it off for passive-only scope).
	if opts.Deep {
		baseURL := u.Scheme + "://" + u.Host
		res.Exposures = probeExposedPaths(ctx, baseURL, &res.ProbedPaths)
	}

	return res, nil
}

// techFetch does one GET with the shared SSRF-safe osint client and returns the
// response (body already drained + closed), a capped body string, and the final
// URL after redirects.
func techFetch(ctx context.Context, urlStr string) (*http.Response, string, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, "", ""
	}
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	// Send an attacker-style Origin so a reflected-origin CORS misconfig shows up
	// in the response's Access-Control-Allow-Origin header.
	req.Header.Set("Origin", corsProbeOrigin)
	resp, err := webtechClient.Do(req)
	if err != nil {
		return nil, "", ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()
	fin := urlStr
	if resp.Request != nil && resp.Request.URL != nil {
		fin = resp.Request.URL.String()
	}
	return resp, string(body), fin
}

// probeCMSVersions fetches the canonical version file of each detected CMS to
// resolve a concrete version. Each probe is a single host-root GET; nothing is
// requested unless the corresponding CMS was already fingerprinted.
func probeCMSVersions(ctx context.Context, baseURL string, techs map[string]*Technology, probed *[]string, upsert func(Technology)) {
	has := func(name string) *Technology {
		return techs[strings.ToLower(name)]
	}
	type probe struct {
		when *Technology
		path string
		re   *regexp.Regexp
		name string
	}
	probes := []probe{
		{has("WordPress"), "/readme.html", wpVersionRe, "WordPress"},
		{has("Drupal"), "/CHANGELOG.txt", drupalVerRe, "Drupal"},
		{has("Joomla"), "/administrator/manifests/files/joomla.xml", joomlaVerRe, "Joomla"},
	}
	for _, p := range probes {
		if p.when == nil || p.when.Version != "" {
			continue // CMS not present, or version already known
		}
		pctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		resp, body, _ := techFetch(pctx, baseURL+p.path)
		cancel()
		*probed = append(*probed, p.path)
		if resp == nil || resp.StatusCode != http.StatusOK {
			continue
		}
		if m := p.re.FindStringSubmatch(body); len(m) == 2 {
			upsert(Technology{Name: p.name, Version: m[1], Source: "active-probe"})
		}
	}
}

// tlsVersionName maps a crypto/tls version constant to a human label.
func tlsVersionName(v uint16) string {
	switch v {
	case 0x0304:
		return "TLS 1.3"
	case 0x0303:
		return "TLS 1.2"
	case 0x0302:
		return "TLS 1.1"
	case 0x0301:
		return "TLS 1.0"
	}
	return ""
}

// unionStrings appends items from b to a, skipping case-insensitive duplicates.
func unionStrings(a, b []string) []string {
	seen := map[string]bool{}
	for _, s := range a {
		seen[strings.ToLower(s)] = true
	}
	for _, s := range b {
		if s = strings.TrimSpace(s); s != "" && !seen[strings.ToLower(s)] {
			seen[strings.ToLower(s)] = true
			a = append(a, s)
		}
	}
	return a
}

// corsProbeOrigin is the attacker-style Origin sent with each request so a
// reflected-origin CORS misconfiguration is observable in the response.
const corsProbeOrigin = "https://ah-cors-probe.example"

// ───────────────────────── component lifecycle (EOL / outdated) ──────────────

// latestKnownVersions maps a lowercased component name to its indicative latest
// release and the version below which it is effectively end-of-life. This is a
// point-in-time snapshot (early 2026), advisory only — the UI labels it indicative.
var latestKnownVersions = map[string]struct{ latest, eolBelow string }{
	"jquery":        {"3.7", "3.0"},
	"jquery ui":     {"1.13", "1.12"},
	"bootstrap":     {"5.3", "4.0"},
	"angularjs":     {"1.8", "9999"}, // AngularJS as a whole is EOL (since Jan 2022)
	"vue.js":        {"3.5", "3.0"},  // Vue 2 reached EOL Dec 2023
	"react":         {"19.0", "16.0"},
	"lodash":        {"4.17", "4.0"},
	"moment.js":     {"2.30", "9999"}, // project in maintenance mode / discouraged
	"handlebars":    {"4.7", "4.0"},
	"axios":         {"1.7", "1.0"},
	"tinymce":       {"7.0", "5.0"},
	"ckeditor":      {"4.25", "4.0"},
	"underscore.js": {"1.13", "1.10"},
	"backbone.js":   {"1.6", "1.3"},
	"wordpress":     {"6.7", "5.5"},
	"drupal":        {"11.0", "9.0"},
	"joomla":        {"5.1", "3.10"},
	"php":           {"8.4", "8.1"},
	"nginx":         {"1.27", "1.20"},
	"apache":        {"2.4", "2.4"},
}

// annotateLifecycle marks a technology as outdated/EOL relative to the indicative
// latest version, when both a version and a reference entry are known.
func annotateLifecycle(t *Technology) {
	if t.Version == "" {
		return
	}
	ref, ok := latestKnownVersions[strings.ToLower(t.Name)]
	if !ok {
		return
	}
	t.LatestKnown = ref.latest
	if ref.eolBelow != "" && verLess(t.Version, ref.eolBelow) {
		t.EOL = true
		t.Outdated = true
		return
	}
	if verMajor(t.Version) < verMajor(ref.latest) {
		t.Outdated = true
	}
}

// verLess reports whether version a is strictly lower than b, comparing dotted
// numeric components left to right.
func verLess(a, b string) bool {
	pa, pb := verParts(a), verParts(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		va, vb := 0, 0
		if i < len(pa) {
			va = pa[i]
		}
		if i < len(pb) {
			vb = pb[i]
		}
		if va != vb {
			return va < vb
		}
	}
	return false
}

func verMajor(v string) int {
	if p := verParts(v); len(p) > 0 {
		return p[0]
	}
	return 0
}

func verParts(v string) []int {
	fields := strings.FieldsFunc(v, func(r rune) bool { return r == '.' })
	out := make([]int, 0, len(fields))
	for _, f := range fields {
		n := 0
		for _, r := range f {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int(r-'0')
		}
		out = append(out, n)
	}
	return out
}

// ───────────────────────── cookie + CORS posture ─────────────────────────────

// parseCookies extracts each Set-Cookie's security flags and notes weaknesses.
func parseCookies(h http.Header) []CookieInfo {
	raw := h.Values("Set-Cookie")
	if len(raw) == 0 {
		return nil
	}
	out := make([]CookieInfo, 0, len(raw))
	for _, sc := range raw {
		parts := strings.Split(sc, ";")
		nv := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
		name := strings.TrimSpace(nv[0])
		if name == "" {
			continue
		}
		ci := CookieInfo{Name: name}
		for _, attr := range parts[1:] {
			trimmed := strings.TrimSpace(attr)
			switch {
			case strings.EqualFold(trimmed, "secure"):
				ci.Secure = true
			case strings.EqualFold(trimmed, "httponly"):
				ci.HttpOnly = true
			case strings.HasPrefix(strings.ToLower(trimmed), "samesite="):
				ci.SameSite = strings.TrimSpace(trimmed[strings.Index(trimmed, "=")+1:])
			}
		}
		if !ci.Secure {
			ci.Issues = append(ci.Issues, "no Secure")
		}
		if !ci.HttpOnly {
			ci.Issues = append(ci.Issues, "no HttpOnly")
		}
		if ci.SameSite == "" || strings.EqualFold(ci.SameSite, "none") {
			ci.Issues = append(ci.Issues, "weak SameSite")
		}
		out = append(out, ci)
		if len(out) >= 20 {
			break
		}
	}
	return out
}

// parseCORS grades the Access-Control-Allow-Origin/-Credentials posture given that
// the request carried an attacker-style Origin (corsProbeOrigin).
func parseCORS(h http.Header) *CORSInfo {
	acao := strings.TrimSpace(h.Get("Access-Control-Allow-Origin"))
	if acao == "" {
		return nil
	}
	acac := strings.EqualFold(strings.TrimSpace(h.Get("Access-Control-Allow-Credentials")), "true")
	info := &CORSInfo{AllowOrigin: acao, AllowCredentials: acac}
	switch {
	case acao == corsProbeOrigin:
		info.Reflected = true
		if acac {
			info.Severity = "high"
			info.Note = "Reflects an arbitrary Origin AND allows credentials — cross-origin data theft is possible."
		} else {
			info.Severity = "medium"
			info.Note = "Reflects an arbitrary Origin — overly permissive CORS; review whether responses expose sensitive data."
		}
	case acao == "*":
		if acac {
			info.Severity = "high"
			info.Note = "Wildcard origin combined with credentials — misconfigured CORS."
		} else {
			info.Severity = "low"
			info.Note = "Wildcard CORS (*): acceptable for public data, risky if the endpoint returns anything sensitive."
		}
	default:
		info.Severity = "info"
		info.Note = "Scoped CORS origin."
	}
	return info
}

// htmlUnescapeLite resolves the handful of entities common in <title> text without
// pulling in a full HTML parser.
func htmlUnescapeLite(s string) string {
	r := strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", "\"", "&#39;", "'", "&#039;", "'")
	return r.Replace(s)
}

// ───────────────────────── JS library detection (retire.js-style) ─────────────

var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)

// jsVerParamRe captures a version from a cache-buster query param, e.g.
// "jquery.min.js?ver=3.7.1" — the way WordPress and many CMSs load libraries.
var jsVerParamRe = regexp.MustCompile(`(?i)[?&](?:ver|v|version)=v?(\d+\.\d+(?:\.\d+)?)`)

// jsLibSignatures maps a client-side library to (a) a version regex over a
// <script src> URL that carries the version inline ("jquery-3.4.1.min.js" or the
// CDN path "/ajax/libs/jquery/3.4.1/jquery.min.js"), and (b) a name regex that
// merely confirms the library file is present so a ?ver= cache-buster can supply
// the version. Where a reliable NVD CPE exists it is attached for version-range
// accurate CVE matching.
var jsLibSignatures = []struct {
	name   string
	cpe    string
	verRe  *regexp.Regexp // name + inline version
	nameRe *regexp.Regexp // presence only (pair with ?ver=)
}{
	{"jQuery UI", "cpe:2.3:a:jquery:jquery_ui", regexp.MustCompile(`(?i)jquery[-.]ui[-./@](\d+\.\d+(?:\.\d+)?)`), regexp.MustCompile(`(?i)jquery[-.]ui(?:\.min)?\.js`)},
	{"jQuery", "cpe:2.3:a:jquery:jquery", regexp.MustCompile(`(?i)jquery[-./@](\d+\.\d+(?:\.\d+)?)`), regexp.MustCompile(`(?i)jquery(?:\.slim)?(?:\.min)?\.js`)},
	{"Bootstrap", "cpe:2.3:a:getbootstrap:bootstrap", regexp.MustCompile(`(?i)bootstrap[-./@](\d+\.\d+(?:\.\d+)?)`), regexp.MustCompile(`(?i)bootstrap(?:\.bundle)?(?:\.min)?\.js`)},
	{"AngularJS", "cpe:2.3:a:angularjs:angular.js", regexp.MustCompile(`(?i)angular[-./@](\d+\.\d+(?:\.\d+)?)`), regexp.MustCompile(`(?i)angular(?:\.min)?\.js`)},
	{"Vue.js", "cpe:2.3:a:vuejs:vue", regexp.MustCompile(`(?i)vue[-./@](\d+\.\d+(?:\.\d+)?)`), regexp.MustCompile(`(?i)vue(?:\.runtime|\.global|\.common)?(?:\.min|\.prod)?\.js`)},
	{"React", "cpe:2.3:a:facebook:react", regexp.MustCompile(`(?i)react[-./@](\d+\.\d+(?:\.\d+)?)`), regexp.MustCompile(`(?i)react(?:\.production|\.development)?(?:\.min)?\.js`)},
	{"Lodash", "cpe:2.3:a:lodash:lodash", regexp.MustCompile(`(?i)lodash[-./@](\d+\.\d+(?:\.\d+)?)`), regexp.MustCompile(`(?i)lodash(?:\.min)?\.js`)},
	{"Moment.js", "cpe:2.3:a:momentjs:moment", regexp.MustCompile(`(?i)moment[-./@](\d+\.\d+(?:\.\d+)?)`), regexp.MustCompile(`(?i)moment(?:\.min)?\.js`)},
	{"Dojo", "cpe:2.3:a:dojotoolkit:dojo", regexp.MustCompile(`(?i)dojo[-./@](\d+\.\d+(?:\.\d+)?)`), regexp.MustCompile(`(?i)dojo(?:\.min)?\.js`)},
	{"Handlebars", "cpe:2.3:a:handlebarsjs:handlebars", regexp.MustCompile(`(?i)handlebars[-./@](\d+\.\d+(?:\.\d+)?)`), regexp.MustCompile(`(?i)handlebars(?:\.runtime)?(?:\.min)?\.js`)},
	{"Axios", "cpe:2.3:a:axios:axios", regexp.MustCompile(`(?i)axios[-./@](\d+\.\d+(?:\.\d+)?)`), regexp.MustCompile(`(?i)axios(?:\.min)?\.js`)},
	{"TinyMCE", "cpe:2.3:a:tiny:tinymce", regexp.MustCompile(`(?i)tinymce[-./@](\d+\.\d+(?:\.\d+)?)`), regexp.MustCompile(`(?i)tinymce(?:\.min)?\.js`)},
	{"CKEditor", "cpe:2.3:a:ckeditor:ckeditor", regexp.MustCompile(`(?i)ckeditor[-./@](\d+\.\d+(?:\.\d+)?)`), regexp.MustCompile(`(?i)ckeditor(?:\.min)?\.js`)},
	{"Ember.js", "cpe:2.3:a:emberjs:ember.js", regexp.MustCompile(`(?i)ember[-./@](\d+\.\d+(?:\.\d+)?)`), regexp.MustCompile(`(?i)ember(?:\.min|\.prod|\.debug)?\.js`)},
	{"Underscore.js", "", regexp.MustCompile(`(?i)underscore[-./@](\d+\.\d+(?:\.\d+)?)`), regexp.MustCompile(`(?i)underscore(?:\.min)?\.js`)},
	{"D3.js", "", regexp.MustCompile(`(?i)d3[-./@]v?(\d+\.\d+(?:\.\d+)?)`), regexp.MustCompile(`(?i)d3(?:\.min)?\.js`)},
	{"Backbone.js", "", regexp.MustCompile(`(?i)backbone[-./@](\d+\.\d+(?:\.\d+)?)`), regexp.MustCompile(`(?i)backbone(?:\.min)?\.js`)},
}

// detectJSLibraries scans the page's <script src> URLs for known client-side
// libraries and their versions. The retire.js database is the primary source (76
// libraries + per-version known vulnerabilities); the small manual table then
// supplements it for versions carried in a ?ver=/?v= cache-buster (WordPress-style)
// that retire.js's path/filename regexes miss.
func detectJSLibraries(body string) []Technology {
	matches := scriptSrcRe.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return nil
	}
	srcs := make([]string, 0, len(matches))
	for _, m := range matches {
		srcs = append(srcs, m[1])
	}

	out := detectRetireJS(srcs)
	seen := make(map[string]bool, len(out))
	for _, t := range out {
		seen[strings.ToLower(t.Name)] = true
	}

	for _, src := range srcs {
		verParam := jsVerParamRe.FindStringSubmatch(src)
		for _, lib := range jsLibSignatures {
			key := strings.ToLower(lib.name)
			if seen[key] {
				continue
			}
			var version string
			if vm := lib.verRe.FindStringSubmatch(src); len(vm) == 2 {
				version = vm[1]
			} else if len(verParam) == 2 && lib.nameRe.MatchString(src) {
				version = verParam[1]
			}
			if version == "" {
				continue
			}
			seen[key] = true
			out = append(out, Technology{
				Name:       lib.name,
				Version:    version,
				CPE:        lib.cpe,
				Categories: []string{"JavaScript library"},
				Source:     "js-library",
			})
		}
	}
	return out
}

// ───────────────────────── WAF / CDN edge detection ──────────────────────────

// detectEdgeServices identifies CDN/WAF layers from response headers, cookies, and
// the fingerprint categories. These are surfaced separately because a WAF can
// block payloads and a CDN masks the origin — both change how a target is attacked.
func detectEdgeServices(h http.Header, techs []Technology) []EdgeService {
	var out []EdgeService
	seen := map[string]bool{}
	add := func(name, typ, ev string) {
		key := strings.ToLower(name)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, EdgeService{Name: name, Type: typ, Evidence: ev})
	}
	server := strings.ToLower(h.Get("Server"))
	via := strings.ToLower(h.Get("Via"))
	xServedBy := strings.ToLower(h.Get("X-Served-By"))
	cookies := strings.ToLower(strings.Join(h.Values("Set-Cookie"), " "))

	if strings.Contains(server, "cloudflare") || h.Get("CF-RAY") != "" || h.Get("CF-Cache-Status") != "" {
		add("Cloudflare", "CDN/WAF", "Server / CF-RAY header")
	}
	if h.Get("X-Sucuri-ID") != "" || h.Get("X-Sucuri-Cache") != "" || strings.Contains(server, "sucuri") {
		add("Sucuri", "WAF", "X-Sucuri header")
	}
	if h.Get("X-Iinfo") != "" || strings.Contains(cookies, "incap_ses") || strings.Contains(cookies, "visid_incap") || strings.EqualFold(h.Get("X-CDN"), "Incapsula") {
		add("Imperva Incapsula", "WAF", "X-Iinfo / incap cookie")
	}
	if strings.Contains(server, "akamai") || h.Get("X-Akamai-Transformed") != "" || strings.Contains(via, "akamai") {
		add("Akamai", "CDN", "Akamai header")
	}
	if h.Get("X-Fastly-Request-ID") != "" || h.Get("Fastly-Debug-Digest") != "" || strings.Contains(xServedBy, "cache-") {
		add("Fastly", "CDN", "X-Served-By / Fastly header")
	}
	if h.Get("X-Amz-Cf-Id") != "" || strings.Contains(via, "cloudfront") {
		add("Amazon CloudFront", "CDN", "X-Amz-Cf-Id / Via")
	}
	if strings.Contains(cookies, "awsalb") || strings.Contains(cookies, "aws-waf") {
		add("AWS ALB / WAF", "WAF", "AWSALB cookie")
	}
	if strings.Contains(cookies, "bigipserver") {
		add("F5 BIG-IP", "WAF", "BIGIP cookie")
	}
	if strings.Contains(server, "keycdn") {
		add("KeyCDN", "CDN", "Server header")
	}

	// Augment from fingerprint categories (Wappalyzer tags WAFs/CDNs by category).
	for _, t := range techs {
		for _, cat := range t.Categories {
			lc := strings.ToLower(cat)
			switch {
			case strings.Contains(lc, "waf"):
				add(t.Name, "WAF", "fingerprint category")
			case lc == "cdn" || strings.Contains(lc, "content delivery"):
				add(t.Name, "CDN", "fingerprint category")
			}
		}
	}
	return out
}

// ───────────────────────── Deep exposure probing ─────────────────────────────

var (
	gitHeadRe    = regexp.MustCompile(`(?m)^(ref: refs/|[0-9a-f]{40}\b)`)
	envKeyRe     = regexp.MustCompile(`(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*=`)
	envKeyLineRe = regexp.MustCompile(`^\s*([A-Z][A-Z0-9_]{2,})\s*=`)
)

type exposureProbe struct {
	path     string
	severity string
	title    string
	// match validates the response body so a catch-all 200 (SPA index.html) is not
	// mistaken for a real exposure. Returns whether it matched + short evidence.
	match func(resp *http.Response, body string) (bool, string)
}

// probeExposedPaths checks a bounded set of high-signal sensitive paths and admin
// panels concurrently. Each hit is validated by content (not just status) to avoid
// false positives from single-page-app catch-all routes. Aggressive — callers gate
// it behind an explicit opt-in and the scope policy.
func probeExposedPaths(ctx context.Context, baseURL string, probed *[]string) []ExposedPath {
	notHTML := func(r *http.Response) bool {
		return !strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "text/html")
	}
	probes := []exposureProbe{
		{"/.git/HEAD", "critical", "Exposed Git repository (.git)", func(r *http.Response, b string) (bool, string) {
			if notHTML(r) && gitHeadRe.MatchString(b) {
				return true, firstLine(b)
			}
			return false, ""
		}},
		{"/.git/config", "critical", "Exposed Git config", func(r *http.Response, b string) (bool, string) {
			if strings.Contains(b, "[core]") {
				return true, "[core] repository config readable"
			}
			return false, ""
		}},
		{"/.env", "critical", "Exposed environment file (.env)", func(r *http.Response, b string) (bool, string) {
			if notHTML(r) && envKeyRe.MatchString(b) {
				return true, redactEnv(b)
			}
			return false, ""
		}},
		{"/.env.bak", "high", "Exposed .env backup", func(r *http.Response, b string) (bool, string) {
			if notHTML(r) && envKeyRe.MatchString(b) {
				return true, redactEnv(b)
			}
			return false, ""
		}},
		{"/.svn/entries", "high", "Exposed SVN metadata (.svn)", func(r *http.Response, b string) (bool, string) {
			if notHTML(r) && (strings.Contains(b, "svn:") || strings.HasPrefix(strings.TrimSpace(b), "12")) {
				return true, ""
			}
			return false, ""
		}},
		{"/server-status", "medium", "Apache server-status exposed", func(r *http.Response, b string) (bool, string) {
			if strings.Contains(b, "Apache Server Status") {
				return true, ""
			}
			return false, ""
		}},
		{"/phpinfo.php", "high", "phpinfo() exposed", func(r *http.Response, b string) (bool, string) {
			if strings.Contains(b, "phpinfo()") || (strings.Contains(b, "PHP Version") && strings.Contains(b, "php.ini")) {
				return true, ""
			}
			return false, ""
		}},
		{"/actuator/env", "high", "Spring Boot Actuator exposed", func(r *http.Response, b string) (bool, string) {
			if strings.Contains(b, "propertySources") || strings.Contains(b, "activeProfiles") {
				return true, ""
			}
			return false, ""
		}},
		{"/.DS_Store", "low", "Exposed .DS_Store", func(r *http.Response, b string) (bool, string) {
			if strings.HasPrefix(b, "\x00\x00\x00\x01Bud1") {
				return true, ""
			}
			return false, ""
		}},
		{"/phpmyadmin/", "medium", "phpMyAdmin reachable", func(r *http.Response, b string) (bool, string) {
			if strings.Contains(b, "phpMyAdmin") {
				return true, ""
			}
			return false, ""
		}},
		{"/.well-known/security.txt", "info", "security.txt present (good practice)", func(r *http.Response, b string) (bool, string) {
			if strings.Contains(strings.ToLower(b), "contact:") {
				return true, ""
			}
			return false, ""
		}},
	}

	var (
		results []ExposedPath
		mu      sync.Mutex
		wg      sync.WaitGroup
		sem     = make(chan struct{}, 6)
	)
	for _, p := range probes {
		*probed = append(*probed, p.path)
		wg.Add(1)
		go func(p exposureProbe) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			pctx, cancel := context.WithTimeout(ctx, 6*time.Second)
			defer cancel()
			resp, body, finalURL := techFetch(pctx, baseURL+p.path)
			if resp == nil || resp.StatusCode != http.StatusOK {
				return
			}
			ok, ev := p.match(resp, body)
			if !ok {
				return
			}
			mu.Lock()
			results = append(results, ExposedPath{
				Path: p.path, URL: finalURL, Status: resp.StatusCode,
				Severity: p.severity, Title: p.title, Evidence: ev,
			})
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	sort.SliceStable(results, func(i, j int) bool {
		return sevRank(results[i].Severity) < sevRank(results[j].Severity)
	})
	return results
}

// redactEnv returns the KEY NAMES from a leaked .env (never the values) so the
// finding is actionable without this tool itself exfiltrating the secrets.
func redactEnv(b string) string {
	var keys []string
	for _, line := range strings.Split(b, "\n") {
		if m := envKeyLineRe.FindStringSubmatch(line); len(m) == 2 {
			keys = append(keys, m[1])
			if len(keys) >= 6 {
				break
			}
		}
	}
	if len(keys) == 0 {
		return ""
	}
	return "keys: " + strings.Join(keys, ", ")
}

// firstLine returns the first non-empty line of s, trimmed and capped.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if l := strings.TrimSpace(line); l != "" {
			return truncate(l, 80)
		}
	}
	return ""
}

// sevRank orders severities most-serious first for stable finding sort.
func sevRank(sev string) int {
	switch sev {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

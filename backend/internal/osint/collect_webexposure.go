package osint

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/analysishub/backend/internal/models"
)

// collect_webexposure.go — targeted, content-confirmed probes for the high-signal
// web exposures a pentester checks first: source/secret files left on the web
// root (.git, .env, backups), exposed admin panels, and security.txt / robots /
// sitemap. Every hit is CONFIRMED by content (not just a 200), so noise is low.
// Active + scope-gated like webgrade; pure Go.

// exposedFile is a sensitive path plus a content confirmation predicate.
type exposedFile struct {
	path     string
	title    string
	severity string
	confirm  func(status int, body string) bool
}

var reEnvLine = regexp.MustCompile(`(?m)^[A-Z][A-Z0-9_]{2,}=`)

var exposedFiles = []exposedFile{
	{".git/HEAD", "Exposed .git repository", "high", func(s int, b string) bool { return s == 200 && strings.HasPrefix(strings.TrimSpace(b), "ref:") }},
	{".git/config", "Exposed .git config", "high", func(s int, b string) bool { return s == 200 && strings.Contains(b, "[core]") }},
	{".env", "Exposed .env file", "critical", func(s int, b string) bool { return s == 200 && reEnvLine.MatchString(b) }},
	{".svn/entries", "Exposed .svn directory", "high", func(s int, b string) bool { return s == 200 && strings.TrimSpace(strings.SplitN(b, "\n", 2)[0]) != "" && !strings.Contains(b, "<html") }},
	{".DS_Store", "Exposed .DS_Store", "medium", func(s int, b string) bool { return s == 200 && strings.Contains(b, "Bud1") }},
	{"server-status", "Exposed Apache server-status", "medium", func(s int, b string) bool { return s == 200 && strings.Contains(b, "Apache Server Status") }},
	{"phpinfo.php", "Exposed phpinfo()", "high", func(s int, b string) bool { return s == 200 && strings.Contains(b, "phpinfo()") }},
	{"config.php.bak", "Exposed PHP config backup", "critical", func(s int, b string) bool { return s == 200 && strings.Contains(b, "<?php") }},
	{".env.bak", "Exposed .env backup", "critical", func(s int, b string) bool { return s == 200 && reEnvLine.MatchString(b) }},
	{"backup.zip", "Exposed backup archive", "high", func(s int, b string) bool { return s == 200 && strings.HasPrefix(b, "PK\x03\x04") }},
	{"backup.sql", "Exposed SQL dump", "critical", func(s int, b string) bool { return s == 200 && (strings.Contains(b, "CREATE TABLE") || strings.Contains(b, "INSERT INTO")) }},
	{".well-known/security.txt", "Published security.txt (good posture)", "info", func(s int, b string) bool { return s == 200 && (strings.Contains(strings.ToLower(b), "contact:")) }},
}

// panelSig fingerprints an exposed management panel from the web root.
type panelSig struct {
	name   string
	header string // response header that, if present, confirms
	marker string // body substring (case-insensitive)
}

var panelSigs = []panelSig{
	{"Jenkins", "X-Jenkins", "jenkins"},
	{"phpMyAdmin", "", "phpmyadmin"},
	{"Grafana", "", "grafana"},
	{"Kibana", "kbn-name", "kbn-injected-metadata"},
	{"Adminer", "", "adminer"},
	{"GitLab", "", "gitlab"},
	{"Portainer", "", "portainer"},
	{"pfSense", "", "pfsense"},
	{"Webmin", "", "webmin"},
	{"Cockpit", "", "cockpit"},
}

// collectWebExposure probes for exposed secrets, panels, and security.txt/robots.
func collectWebExposure(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	host := strings.ToLower(strings.TrimSpace(env.target))
	if host == "" {
		return nil, nil
	}
	// Root must be reachable, else there's nothing to probe (avoids noise on
	// non-web targets).
	root, _, err := fetchRoot(ctx, host)
	if err != nil {
		return nil, nil
	}
	rootBody := readCapped(root.Body, 256*1024)
	rootHdr := root.Header
	root.Body.Close()

	var (
		mu  sync.Mutex
		out []models.OsintFinding
		wg  sync.WaitGroup
	)
	sem := make(chan struct{}, 6)

	// Exposed files (content-confirmed).
	for _, ef := range exposedFiles {
		wg.Add(1)
		go func(ef exposedFile) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			status, body := probePath(ctx, host, ef.path)
			if !ef.confirm(status, body) {
				return
			}
			f := newFinding("web_exposure", "exposure", ef.title, host+"/"+ef.path)
			f.Severity = ef.severity
			f.Confidence = "verified"
			mu.Lock()
			out = append(out, f)
			mu.Unlock()
		}(ef)
	}
	wg.Wait()

	// Panels from the root response.
	low := strings.ToLower(rootBody)
	for _, p := range panelSigs {
		hit := (p.header != "" && rootHdr.Get(p.header) != "") || (p.marker != "" && strings.Contains(low, p.marker))
		if hit {
			f := newFinding("web_exposure", "exposure", "Exposed management panel", p.name+" at "+host)
			f.Severity = "medium"
			f.Confidence = "verified"
			out = append(out, f)
		}
	}

	// robots.txt — disallowed paths often point at sensitive areas.
	if status, body := probePath(ctx, host, "robots.txt"); status == 200 && strings.Contains(strings.ToLower(body), "disallow") {
		var paths, sitemaps []string
		for _, line := range strings.Split(body, "\n") {
			l := strings.TrimSpace(line)
			ll := strings.ToLower(l)
			if strings.HasPrefix(ll, "disallow:") {
				if p := strings.TrimSpace(l[len("disallow:"):]); p != "" && p != "/" {
					paths = appendUniqCap(paths, p, 30)
				}
			} else if strings.HasPrefix(ll, "sitemap:") {
				sitemaps = appendUniqCap(sitemaps, strings.TrimSpace(l[len("sitemap:"):]), 10)
			}
		}
		if len(paths) > 0 {
			out = append(out, newFinding("web_exposure", "recon", "robots.txt disallowed paths", strings.Join(paths, ", ")))
		}
		for _, sm := range sitemaps {
			f := newFinding("web_exposure", "recon", "Sitemap declared", sm)
			out = append(out, f)
		}
	}

	if len(out) > 0 {
		env.emit("[+] web_exposure: " + strconv.Itoa(len(out)) + " exposure/recon finding(s)")
	}
	return out, nil
}

// probePath GETs host/path (HTTPS then HTTP) and returns status + a capped body.
func probePath(ctx context.Context, host, path string) (int, string) {
	for _, scheme := range []string{"https://", "http://"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+host+"/"+path, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := osintHTTPClient.Do(req)
		if err != nil {
			continue
		}
		body := readCapped(resp.Body, 128*1024)
		resp.Body.Close()
		return resp.StatusCode, body
	}
	return 0, ""
}

func readCapped(r io.Reader, n int64) string {
	b, _ := io.ReadAll(io.LimitReader(r, n))
	return string(b)
}

func appendUniqCap(s []string, v string, cap int) []string {
	if len(s) >= cap {
		return s
	}
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

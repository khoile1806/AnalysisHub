package osint

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/forensichub/backend/internal/models"
)

// browserUA is sent on social-media checks - many platforms 403 a non-browser
// User-Agent outright.
const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"

// socialHTTPClient does NOT follow redirects: a profile page that 30x-redirects
// to a login/landing page must not be mistaken for an existing account.
var socialHTTPClient = &http.Client{
	Timeout: 12 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConns:      32,
		IdleConnTimeout:   30 * time.Second,
		DisableKeepAlives: true,
	},
}

// socialSite describes one platform whose profile page is HTTP-checked.
type socialSite struct {
	name    string
	urlTmpl string // exactly one %s - the username
	// existsMarker, when set, must appear in a 200 body to count as a hit
	// (for platforms that return 200 for non-existent users).
	existsMarker string
}

// socialSitesChecked are platforms whose 404 / profile detection is reliable
// enough to verify automatically from a server. A blocked or ambiguous
// response is reported as "unverifiable", never as a hit - so the failure
// mode is a false negative, not a false positive.
var socialSitesChecked = []socialSite{
	{"GitHub", "https://github.com/%s", ""},
	{"GitLab", "https://gitlab.com/%s", ""},
	{"Bitbucket", "https://bitbucket.org/%s/", ""},
	{"Keybase", "https://keybase.io/%s", ""},
	{"Reddit", "https://www.reddit.com/user/%s", ""},
	{"npm", "https://www.npmjs.com/~%s", ""},
	{"PyPI", "https://pypi.org/user/%s/", ""},
	{"Docker Hub", "https://hub.docker.com/u/%s", ""},
	{"Dev.to", "https://dev.to/%s", ""},
	{"Medium", "https://medium.com/@%s", ""},
	{"HackerOne", "https://hackerone.com/%s", ""},
	{"TryHackMe", "https://tryhackme.com/p/%s", ""},
	{"about.me", "https://about.me/%s", ""},
	{"Gravatar", "https://gravatar.com/%s", ""},
	{"CodePen", "https://codepen.io/%s", ""},
	{"Telegram", "https://t.me/%s", "tgme_page_title"},
	{"Hacker News", "https://news.ycombinator.com/user?id=%s", "created:"},
}

// socialSitesManual are JS-walled platforms that cannot be checked reliably
// from a server (they return 200 + a login wall for everyone). They are
// emitted as direct candidate URLs for the analyst to open and confirm.
var socialSitesManual = []socialSite{
	{"X (Twitter)", "https://x.com/%s", ""},
	{"Instagram", "https://www.instagram.com/%s/", ""},
	{"Facebook", "https://www.facebook.com/%s", ""},
	{"TikTok", "https://www.tiktok.com/@%s", ""},
	{"YouTube", "https://www.youtube.com/@%s", ""},
	{"LinkedIn", "https://www.linkedin.com/in/%s", ""},
	{"Pinterest", "https://www.pinterest.com/%s/", ""},
	{"Threads", "https://www.threads.net/@%s", ""},
	{"Snapchat", "https://www.snapchat.com/add/%s", ""},
}

// checkSite probes one platform for a username. It returns (found, conclusive):
// conclusive is false when the platform blocked us or replied ambiguously, in
// which case the result must be ignored rather than reported.
func checkSite(ctx context.Context, site socialSite, username string) (found, conclusive bool) {
	u := fmt.Sprintf(site.urlTmpl, url.PathEscape(username))
	cctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
	if err != nil {
		return false, false
	}
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := socialHTTPClient.Do(req)
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == 404 || resp.StatusCode == 410:
		return false, true // definitively absent
	case resp.StatusCode != 200:
		return false, false // 3xx redirect / 403 / 429 / 5xx - unverifiable
	}
	if site.existsMarker == "" {
		return true, true
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return strings.Contains(string(body), site.existsMarker), true
}

// collectSocialMedia checks a username across many platforms. Reliable
// platforms are probed concurrently; JS-walled platforms are emitted as
// candidate links to verify by hand.
func collectSocialMedia(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	username := strings.TrimSpace(env.target)
	if username == "" {
		return nil, fmt.Errorf("empty username")
	}

	var (
		mu        sync.Mutex
		confirmed []models.OsintFinding
		blocked   int
	)
	sem := make(chan struct{}, 10) // cap concurrent outbound requests
	var wg sync.WaitGroup

	for _, site := range socialSitesChecked {
		wg.Add(1)
		go func(s socialSite) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			found, conclusive := checkSite(ctx, s, username)
			mu.Lock()
			defer mu.Unlock()
			if !conclusive {
				blocked++
				return
			}
			if found {
				confirmed = append(confirmed, newFinding("social_search", "social",
					"Profile found - "+s.name, fmt.Sprintf(s.urlTmpl, username)))
			}
		}(site)
	}
	wg.Wait()

	out := confirmed
	for _, s := range socialSitesManual {
		f := newFinding("social_search", "social",
			"Candidate - "+s.name+" (open the link to verify)", fmt.Sprintf(s.urlTmpl, username))
		f.Severity = "low"
		out = append(out, f)
	}
	env.emit(fmt.Sprintf("[*] social_search: %d confirmed profile(s), %d site(s) unverifiable/blocked",
		len(confirmed), blocked))
	return out, nil
}

// collectSearchLinks builds ready-to-open search and assisted-lookup pivots for
// the target. It performs no requests itself - the analyst opens each link in a
// real browser. This is the honest way to cover Facebook / Instagram: their
// account-recovery flow does reveal whether an e-mail / phone is registered
// (Facebook even shows the profile name + photo), but it is CAPTCHA-gated and
// blocks datacenter IPs - so a human completes the final step, not the server.
func collectSearchLinks(_ context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	t := strings.TrimSpace(env.target)
	quoted := url.QueryEscape(`"` + t + `"`)

	var out []models.OsintFinding
	add := func(title, link string) {
		out = append(out, newFinding("search_links", "search", title, link))
	}
	// addAssisted emits a manual social-lookup link - grouped under Social
	// Media Presence and marked low severity (needs human verification).
	addAssisted := func(title, link string) {
		f := newFinding("search_links", "social", title, link)
		f.Severity = "low"
		out = append(out, f)
	}

	add("Google", "https://www.google.com/search?q="+quoted)
	add("Bing", "https://www.bing.com/search?q="+quoted)
	add("DuckDuckGo", "https://duckduckgo.com/?q="+quoted)

	socialDork := func(value string) string {
		return url.QueryEscape(`"` + value + `" (site:facebook.com OR site:twitter.com OR ` +
			`site:instagram.com OR site:linkedin.com OR site:tiktok.com)`)
	}

	// fbRecover builds Facebook's "Find your account" recovery URL pre-filled
	// with the identifier - opening it in a browser shows the matching profile
	// (name + photo) when the e-mail / phone is registered.
	fbRecover := func(identifier string) string {
		return "https://www.facebook.com/login/identify/?ctx=recover&email=" + url.QueryEscape(identifier)
	}
	const igRecover = "https://www.instagram.com/accounts/password/reset/"

	switch env.ttype {
	case TargetEmail:
		add("Google - social profiles", "https://www.google.com/search?q="+socialDork(t))
		addAssisted("Facebook - Find Account by e-mail (open in browser)", fbRecover(t))
		addAssisted("Instagram - Account Recovery, enter this e-mail (open in browser)", igRecover)
	case TargetUsername:
		add("Google - social profiles", "https://www.google.com/search?q="+socialDork(t))
	case TargetName:
		add("Google - social profiles", "https://www.google.com/search?q="+socialDork(t))
		add("LinkedIn - people search",
			"https://www.google.com/search?q="+url.QueryEscape(`"`+t+`" site:linkedin.com/in`))
	case TargetPhone:
		digits := onlyDigits(t)
		add("Google - number variants",
			"https://www.google.com/search?q="+url.QueryEscape(`"+`+digits+`" OR "`+digits+`"`))
		add("Google - social profiles", "https://www.google.com/search?q="+socialDork("+"+digits))
		addAssisted("Facebook - Find Account by phone (open in browser)", fbRecover("+"+digits))
		addAssisted("Instagram - Account Recovery, enter this number (open in browser)", igRecover)
	}
	return out, nil
}

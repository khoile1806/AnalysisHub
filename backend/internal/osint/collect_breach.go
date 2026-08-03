package osint

import (
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

// B2 - identity-leak collectors. These close the de-anonymisation gap: they turn
// an opaque handle or address into the real person/infrastructure behind it by
// mining the two places identities leak in the open: code-hosting metadata
// (GitHub commits expose an author's e-mail even when the profile hides it) and
// credential dumps / paste leaks (a combolist line ties an e-mail to other
// breached identifiers). Every discovered identifier is emitted as a pivot, so
// it feeds straight into the investigation graph (A1) and shared-indicator
// correlation (A2).

var (
	rlGitHub    = newRateLimiter(2 * time.Second)         // GitHub unauth search ~ 10/min
	rlProxyNova = newRateLimiter(1500 * time.Millisecond) // ProxyNova comb is generous but be polite
)

// githubAPIGet performs an authenticated-if-possible GitHub API GET with a
// browser UA and the requested Accept header, and returns the (capped) body.
func githubAPIGet(ctx context.Context, rl *rateLimiter, token, target, accept string) ([]byte, int, error) {
	if rl != nil {
		if err := rl.wait(ctx); err != nil {
			return nil, 0, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept", accept)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := osintHTTPClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return body, resp.StatusCode, err
}

// noreplyGitHub reports whether an e-mail is GitHub's commit-anonymising address
// (e.g. "12345+login@users.noreply.github.com") - useful as a username hint but
// not a real, reachable address.
func noreplyGitHub(email string) bool {
	return strings.HasSuffix(strings.ToLower(email), "@users.noreply.github.com")
}

// collectGitHubIntel mines GitHub for the identity behind the target.
//
//   - username target -> resolve the public profile (name, company, location,
//     blog, linked Twitter, *public e-mail*), then scan recent public push
//     events for commit-author e-mails. A commit e-mail is the classic leak:
//     it reveals a real address the user never put on their profile.
//   - email target -> search commits authored by that address to surface the
//     repos and the GitHub login(s) behind it.
//
// Discovered e-mails and logins are emitted as pivots (de-anonymisation links).
func collectGitHubIntel(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	switch env.ttype {
	case TargetUsername:
		return githubByUsername(ctx, env)
	case TargetEmail:
		return githubByEmail(ctx, env)
	case TargetName:
		return githubByName(ctx, env)
	}
	return nil, nil
}

// githubByName searches GitHub for accounts whose profile name matches a person's
// full name, turning a bare name into resolvable developer identities the graph
// can pivot on (each login → a full username investigation). Uses GITHUB_TOKEN to
// raise the (otherwise very low) search rate limit; still runs unauthenticated.
func githubByName(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	name := strings.TrimSpace(env.target)
	if name == "" {
		return nil, nil
	}
	q := url.QueryEscape(`"` + name + `" in:name`)
	body, status, err := githubAPIGet(ctx, rlGitHub, env.keys.GitHub,
		"https://api.github.com/search/users?per_page=5&q="+q, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	if status == 403 {
		return nil, fmt.Errorf("GitHub search rate-limited (set GITHUB_TOKEN to raise the limit)")
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("GitHub search returned HTTP %d", status)
	}
	var res struct {
		Items []struct {
			Login   string `json:"login"`
			HTMLURL string `json:"html_url"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &res) != nil {
		return nil, fmt.Errorf("could not decode GitHub search results")
	}
	if len(res.Items) == 0 {
		env.emit("[*] github_intel: no GitHub account matches this name")
		return nil, nil
	}

	var out []models.OsintFinding
	for _, it := range res.Items {
		if strings.TrimSpace(it.Login) == "" {
			continue
		}
		f := newFinding("github_intel", "identity", "GitHub account matching name", "@"+it.Login)
		f.Severity = "low"
		f.Confidence = "unverified"
		f.VerifyNote = "Name-based GitHub match; open the profile to confirm it is the same person."
		f = withRelated(withSource(f, it.HTMLURL), RelatedEntity{Type: TargetUsername, Value: it.Login})
		out = append(out, f)
	}
	env.emit(fmt.Sprintf("[*] github_intel: %d GitHub account(s) match this name", len(out)))
	return out, nil
}

type githubUser struct {
	Login     string `json:"login"`
	Name      string `json:"name"`
	Company   string `json:"company"`
	Blog      string `json:"blog"`
	Location  string `json:"location"`
	Email     string `json:"email"`
	Bio       string `json:"bio"`
	Twitter   string `json:"twitter_username"`
	HTMLURL   string `json:"html_url"`
	AvatarURL string `json:"avatar_url"`
	CreatedAt string `json:"created_at"`
	PublicRpo int    `json:"public_repos"`
}

func githubByUsername(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	user := strings.TrimSpace(env.target)
	body, status, err := githubAPIGet(ctx, rlGitHub, env.keys.GitHub,
		"https://api.github.com/users/"+url.PathEscape(user), "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	if status == 404 {
		env.emit("[*] github_intel: no GitHub account with this handle")
		return nil, nil
	}
	if status == 403 {
		return nil, fmt.Errorf("GitHub rate-limited (set GITHUB_TOKEN to raise the limit)")
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("GitHub returned HTTP %d", status)
	}
	var u githubUser
	if json.Unmarshal(body, &u) != nil {
		return nil, fmt.Errorf("could not decode GitHub profile")
	}

	var out []models.OsintFinding
	if prof := joinNonEmpty(" - ", u.Name, u.Company, u.Location); prof != "" {
		out = append(out, newFinding("github_intel", "identity", "GitHub profile", prof))
	}
	if u.HTMLURL != "" {
		out = append(out, newFinding("github_intel", "identity", "GitHub profile URL", u.HTMLURL))
	}
	if u.CreatedAt != "" {
		out = append(out, accountCreatedFinding("github_intel", u.CreatedAt, u.HTMLURL))
	}
	// Avatar → perceptual fingerprint (cross-platform linking) + reverse search.
	if u.AvatarURL != "" {
		if h, ok := fetchAvatarHash(ctx, u.AvatarURL); ok {
			out = append(out, avatarFinding("github_intel", u.AvatarURL, h))
			out = append(out, avatarReverseFindings("github_intel", u.AvatarURL)...)
		}
	}
	if u.Bio != "" {
		out = append(out, newFinding("github_intel", "identity", "Bio", u.Bio))
	}
	if u.Blog != "" {
		f := newFinding("github_intel", "identity", "Linked website", u.Blog)
		if d := hostFromURL(u.Blog); d != "" {
			f = withRelated(f, RelatedEntity{Type: TargetDomain, Value: d})
		}
		out = append(out, f)
	}
	if u.Twitter != "" {
		f := newFinding("github_intel", "identity", "Linked Twitter/X handle", u.Twitter)
		out = append(out, withRelated(f, RelatedEntity{Type: TargetUsername, Value: u.Twitter}))
	}
	// Public profile e-mail - a direct, high-value de-anonymisation link.
	if u.Email != "" {
		f := newFinding("github_intel", "identity", "Public profile e-mail", u.Email)
		f.Severity = "medium"
		out = append(out, withRelated(f, RelatedEntity{Type: TargetEmail, Value: u.Email}))
		env.emit("[+] github_intel: public profile e-mail - " + u.Email)
	}

	// Commit-author e-mails leaked through recent public push events.
	emails := githubCommitEmails(ctx, env, user)
	for _, em := range emails {
		if noreplyGitHub(em) {
			out = append(out, newFinding("github_intel", "identity",
				"Commit identity (GitHub no-reply)", em))
			continue
		}
		f := newFinding("github_intel", "identity", "Commit-author e-mail (leaked via git history)", em)
		f.Severity = "high" // a real address the user never put on the profile
		out = append(out, withRelated(f, RelatedEntity{Type: TargetEmail, Value: em}))
		env.emit("[+] github_intel: commit-author e-mail - " + em)
	}

	if len(out) == 0 {
		env.emit("[*] github_intel: account exists but exposed no extra identity data")
	}
	return out, nil
}

// githubCommitEmails reads a user's recent public push events and returns the
// distinct commit-author e-mails found (capped).
func githubCommitEmails(ctx context.Context, env *collectorEnv, user string) []string {
	body, status, err := githubAPIGet(ctx, rlGitHub, env.keys.GitHub,
		"https://api.github.com/users/"+url.PathEscape(user)+"/events/public?per_page=100",
		"application/vnd.github+json")
	if err != nil || status != 200 {
		return nil
	}
	var events []struct {
		Type    string `json:"type"`
		Payload struct {
			Commits []struct {
				Author struct {
					Email string `json:"email"`
					Name  string `json:"name"`
				} `json:"author"`
			} `json:"commits"`
		} `json:"payload"`
	}
	if json.Unmarshal(body, &events) != nil {
		return nil
	}
	seen := make(map[string]bool)
	var emails []string
	for _, ev := range events {
		for _, cm := range ev.Payload.Commits {
			em := strings.ToLower(strings.TrimSpace(cm.Author.Email))
			if em == "" || seen[em] || !emailRe.MatchString(em) {
				continue
			}
			seen[em] = true
			emails = append(emails, em)
			if len(emails) >= 10 {
				return emails
			}
		}
	}
	return emails
}

func githubByEmail(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	email := strings.ToLower(strings.TrimSpace(env.target))
	api := "https://api.github.com/search/commits?per_page=20&q=" +
		url.QueryEscape("author-email:"+email)
	body, status, err := githubAPIGet(ctx, rlGitHub, env.keys.GitHub, api,
		"application/vnd.github.cloak-preview+json")
	if err != nil {
		return nil, err
	}
	if status == 403 {
		return nil, fmt.Errorf("GitHub commit-search rate-limited (set GITHUB_TOKEN to raise the limit)")
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("GitHub commit-search returned HTTP %d", status)
	}
	var r struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			Author struct {
				Login   string `json:"login"`
				HTMLURL string `json:"html_url"`
			} `json:"author"`
			Repository struct {
				FullName string `json:"full_name"`
				HTMLURL  string `json:"html_url"`
			} `json:"repository"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &r) != nil {
		return nil, fmt.Errorf("could not decode GitHub commit-search response")
	}
	if r.TotalCount == 0 {
		env.emit("[*] github_intel: no public commits authored by this e-mail")
		return nil, nil
	}

	var out []models.OsintFinding
	seenLogin := make(map[string]bool)
	seenRepo := make(map[string]bool)
	for _, it := range r.Items {
		if login := it.Author.Login; login != "" && !seenLogin[login] {
			seenLogin[login] = true
			f := newFinding("github_intel", "identity",
				"GitHub login behind this e-mail - "+login, it.Author.HTMLURL)
			f.Severity = "high"
			out = append(out, withRelated(f, RelatedEntity{Type: TargetUsername, Value: login}))
			env.emit("[+] github_intel: e-mail maps to GitHub login - " + login)
		}
		if repo := it.Repository.FullName; repo != "" && !seenRepo[repo] {
			seenRepo[repo] = true
			out = append(out, newFinding("github_intel", "identity",
				"Authored commits in repo", repo))
		}
		if len(out) >= 30 {
			break
		}
	}
	return out, nil
}

// -- Breach / paste leak (ProxyNova combolist, no API key) --------------------

// collectBreachLeak checks the target against ProxyNova's "comb" combolist -
// an aggregate of historical credential dumps and pastes. A hit means the
// identifier appeared next to a password in a public dump: strong exposure
// evidence for incident response. Passwords are masked before storage; for a
// username target the matched e-mail addresses are emitted as pivots.
func collectBreachLeak(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	q := strings.TrimSpace(env.target)
	if q == "" {
		return nil, nil
	}
	// Domain target -> org-wide sweep: match every leaked "*@domain" credential
	// so a single investigation surfaces all exposed corporate/customer accounts.
	if env.ttype == TargetDomain {
		q = "@" + strings.ToLower(q)
	}
	api := "https://api.proxynova.com/comb?start=0&limit=25&query=" + url.QueryEscape(q)
	// sourceURL is the addressable origin of the leak data, attached to every
	// credential finding so the analyst can open exactly where it was discovered.
	sourceURL := "https://api.proxynova.com/comb?query=" + url.QueryEscape(q)
	var r struct {
		Count int      `json:"count"`
		Lines []string `json:"lines"`
	}
	status, err := httpGetJSON(ctx, rlProxyNova, api, nil, &r)
	if err != nil {
		return nil, err
	}
	if status == 429 {
		return nil, fmt.Errorf("breach-leak source rate-limited (HTTP 429)")
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("breach-leak source returned HTTP %d", status)
	}
	if r.Count == 0 || len(r.Lines) == 0 {
		f := newFinding("breach_leak", "breach", "Credential-dump exposure",
			"identifier not found in the public combolist")
		return []models.OsintFinding{f}, nil
	}

	out := []models.OsintFinding{}
	summary := newFinding("breach_leak", "breach", "Credential-dump exposure",
		fmt.Sprintf("identifier appears in %d leaked credential line(s)", r.Count))
	summary.Severity = "critical"
	summary.SourceURL = sourceURL
	out = append(out, summary)

	seenEmail := make(map[string]bool)
	for _, line := range r.Lines {
		ident, masked, pwMeta := splitLeakLine(line)
		if ident == "" {
			continue
		}
		f := newFinding("breach_leak", "breach", "Leaked credential", ident+" : "+masked)
		f.Severity = "high"
		f.VerifyNote = pwMeta   // password length + character classes (no plaintext)
		f.SourceURL = sourceURL // where this credential was discovered
		// When the leaked identifier is an e-mail (e.g. a username query that hit
		// "alice@corp.com:..."), that address de-anonymises the target.
		if emailRe.MatchString(ident) && !strings.EqualFold(ident, q) && !seenEmail[ident] {
			seenEmail[ident] = true
			f = withRelated(f, RelatedEntity{Type: TargetEmail, Value: ident})
		}
		out = append(out, f)
		if len(out) >= 26 {
			break
		}
	}
	env.emit(fmt.Sprintf("[+] breach_leak: %d leaked line(s) - credentials masked", r.Count))
	return out, nil
}

// splitLeakLine breaks a "identifier:password" combolist line into the
// identifier, a masked password (length-preserving, plaintext never stored),
// and a metadata note describing the password's length + character classes so
// an analyst can sanity-check it without the plaintext ever being kept.
func splitLeakLine(line string) (ident, masked, meta string) {
	line = strings.TrimSpace(line)
	i := strings.LastIndexByte(line, ':')
	if i <= 0 {
		return line, "", ""
	}
	ident = strings.TrimSpace(line[:i])
	pw := strings.TrimSpace(line[i+1:])
	if pw == "" {
		return ident, "", ""
	}
	rs := []rune(pw)
	n := len(rs)
	var lower, upper, digit, sym bool
	for _, r := range rs {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			sym = true
		}
	}
	classes := []string{}
	if lower {
		classes = append(classes, "lower")
	}
	if upper {
		classes = append(classes, "upper")
	}
	if digit {
		classes = append(classes, "digit")
	}
	if sym {
		classes = append(classes, "symbol")
	}
	masked = fmt.Sprintf("%s**** (%d chars)", string(rs[:1]), n)
	meta = fmt.Sprintf("password: %d chars, %s", n, strings.Join(classes, "+"))
	return ident, masked, meta
}

// hostFromURL extracts the host from a URL-ish blog string, or "" if it has no
// usable host. Accepts bare "example.com" too.
func hostFromURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if domainRe.MatchString(host) {
		return host
	}
	return ""
}

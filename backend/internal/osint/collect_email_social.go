package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/analysishub/backend/internal/models"
)

// collectEmailSocialMedia discovers accounts tied to an e-mail address. Two
// honest, API-based techniques are used - no password-reset enumeration, which
// modern platforms intentionally defeat with non-distinguishing responses:
//
//  1. GitHub e-mail search - a *direct* email->account lookup (only finds users
//     who made their e-mail public, but a hit is a true positive).
//  2. Handle probing - the e-mail local part is tried as a username on
//     platforms with a reliable existence API. These are *probable* matches
//     because the local part is only a guess at the person's real handle.
func collectEmailSocialMedia(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	email := strings.ToLower(strings.TrimSpace(env.target))
	if email == "" || !strings.Contains(email, "@") {
		return nil, fmt.Errorf("invalid email target")
	}

	var (
		out []models.OsintFinding
		mu  sync.Mutex
	)
	add := func(f models.OsintFinding) {
		mu.Lock()
		out = append(out, f)
		mu.Unlock()
	}

	// 1. GitHub e-mail search - direct, not a guess.
	if found, login, profileURL, err := githubEmailSearch(ctx, env.keys.GitHub, email); err != nil {
		env.emit("[!] email_social: GitHub e-mail search - " + err.Error())
	} else if found {
		f := newFinding("email_social", "social",
			"GitHub account (public e-mail match) - "+login, profileURL)
		add(withRelated(f, RelatedEntity{Type: TargetUsername, Value: login}))
		env.emit("[+] email_social: GitHub account found via e-mail search - " + login)
	} else {
		env.emit("[*] email_social: no GitHub account exposes this e-mail")
	}

	// 2. Handle probing across reliable existence APIs.
	handle := extractUsernameFromEmail(email)
	if handle != "" {
		env.emit(fmt.Sprintf("[*] email_social: probing local part %q as a handle", handle))

		checkers := []struct {
			name string
			fn   func(context.Context, string) (bool, float64, string, error)
		}{
			{"GitHub", checkGitHubUsername},
			{"Reddit", checkRedditUsername},
			{"Hacker News", checkHackerNewsUsername},
			{"Keybase", checkKeybaseUsername},
		}

		var wg sync.WaitGroup
		for _, c := range checkers {
			wg.Add(1)
			go func(name string, fn func(context.Context, string) (bool, float64, string, error)) {
				defer wg.Done()
				exists, conf, profileURL, err := fn(ctx, handle)
				if err != nil {
					env.emit(fmt.Sprintf("[*] email_social: %s check failed - %v", name, err))
					return
				}
				if exists && conf >= 0.6 {
					f := newFinding("email_social", "social",
						fmt.Sprintf("Probable %s account (handle %q from e-mail)", name, handle),
						profileURL)
					f.Severity = "low" // probable, not confirmed - handle is a guess
					add(withRelated(f, RelatedEntity{Type: TargetUsername, Value: handle}))
					env.emit(fmt.Sprintf("[+] email_social: probable %s account - %s", name, profileURL))
				}
			}(c.name, c.fn)
		}
		wg.Wait()
	}

	if len(out) == 0 {
		env.emit("[*] email_social: no linked accounts discovered")
	}
	return out, nil
}

// githubEmailSearch queries the GitHub user-search API for an account whose
// public profile e-mail matches. Uses GITHUB_TOKEN when available to raise the
// search rate limit (10 -> 30 req/min).
func githubEmailSearch(ctx context.Context, token, email string) (found bool, login, profileURL string, err error) {
	api := "https://api.github.com/search/users?q=" + url.QueryEscape(email+" in:email")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api, nil)
	if err != nil {
		return false, "", "", err
	}
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := osintHTTPClient.Do(req)
	if err != nil {
		return false, "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))

	if resp.StatusCode == 403 {
		return false, "", "", fmt.Errorf("GitHub search rate-limited (set GITHUB_TOKEN to raise the limit)")
	}
	if resp.StatusCode != 200 {
		return false, "", "", fmt.Errorf("GitHub search returned HTTP %d", resp.StatusCode)
	}

	var r struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			Login   string `json:"login"`
			HTMLURL string `json:"html_url"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &r) != nil {
		return false, "", "", fmt.Errorf("could not decode GitHub search response")
	}
	if r.TotalCount == 0 || len(r.Items) == 0 {
		return false, "", "", nil
	}
	return true, r.Items[0].Login, r.Items[0].HTMLURL, nil
}

// -- handle existence checks (reliable public APIs) ----------------------------

// checkGitHubUsername checks whether a username exists on GitHub.
func checkGitHubUsername(ctx context.Context, username string) (bool, float64, string, error) {
	resp, err := emailSocialGet(ctx, "https://api.github.com/users/"+url.PathEscape(username))
	if err != nil {
		return false, 0, "", err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 200:
		return true, 0.95, "https://github.com/" + username, nil
	case 404:
		return false, 0.95, "", nil
	}
	return false, 0, "", nil
}

// checkRedditUsername uses Reddit's username-availability API.
func checkRedditUsername(ctx context.Context, username string) (bool, float64, string, error) {
	resp, err := emailSocialGet(ctx,
		"https://www.reddit.com/api/v1/username_available.json?user="+url.QueryEscape(username))
	if err != nil {
		return false, 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, 0, "", nil // 429/403 from a datacenter IP - inconclusive
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
	if err != nil {
		return false, 0, "", err
	}
	var available bool
	if json.Unmarshal(body, &available) != nil {
		return false, 0, "", fmt.Errorf("unexpected Reddit response")
	}
	if !available { // taken -> the account exists
		return true, 0.9, "https://www.reddit.com/user/" + username, nil
	}
	return false, 0.9, "", nil
}

// checkHackerNewsUsername uses the Hacker News Firebase API.
func checkHackerNewsUsername(ctx context.Context, username string) (bool, float64, string, error) {
	resp, err := emailSocialGet(ctx,
		"https://hacker-news.firebaseio.com/v0/user/"+url.PathEscape(username)+".json")
	if err != nil {
		return false, 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, 0, "", nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
	if err != nil {
		return false, 0, "", err
	}
	// The API returns the literal "null" for a non-existent user.
	if strings.TrimSpace(string(body)) == "null" || len(body) == 0 {
		return false, 0.85, "", nil
	}
	return true, 0.85, "https://news.ycombinator.com/user?id=" + username, nil
}

// checkKeybaseUsername uses the Keybase user-lookup API.
func checkKeybaseUsername(ctx context.Context, username string) (bool, float64, string, error) {
	resp, err := emailSocialGet(ctx,
		"https://keybase.io/_/api/1.0/user/lookup.json?username="+url.QueryEscape(username))
	if err != nil {
		return false, 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, 0, "", nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return false, 0, "", err
	}
	var r struct {
		Status struct {
			Code int `json:"code"`
		} `json:"status"`
	}
	if json.Unmarshal(body, &r) != nil {
		return false, 0, "", fmt.Errorf("unexpected Keybase response")
	}
	if r.Status.Code == 0 { // 0 = OK, user found
		return true, 0.85, "https://keybase.io/" + username, nil
	}
	return false, 0.85, "", nil
}

// emailSocialGet performs a GET with the shared OSINT HTTP client and a
// browser User-Agent. The caller closes the body.
func emailSocialGet(ctx context.Context, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept", "application/json")
	return osintHTTPClient.Do(req)
}

// extractUsernameFromEmail returns the e-mail's local part as a candidate
// handle: lowercased, with any "+tag" plus-addressing suffix removed.
func extractUsernameFromEmail(email string) string {
	at := strings.IndexByte(email, '@')
	if at <= 0 {
		return ""
	}
	local := strings.ToLower(strings.TrimSpace(email[:at]))
	if plus := strings.IndexByte(local, '+'); plus > 0 {
		local = local[:plus]
	}
	return local
}

package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/analysishub/backend/internal/models"
)

// collect_codeleak.go — public source-code exposure. One of the highest-impact
// leaks for an organisation is a developer pushing a secret (an .env, a private
// key, a hard-coded credential) into a PUBLIC repository. This collector queries
// GitHub's code-search index for the target and flags hits whose file path looks
// like it carries secrets, surfacing the repository + exact file so the owner
// can rotate the credential. It never fetches or stores the file contents — only
// names the location (deliberate, mirrors the cloud-bucket collector).
//
// GitHub code search REQUIRES authentication, so this collector is key-gated:
// without GITHUB_TOKEN it reports skipped rather than failing.

// secretFileMarkers are path/filename fragments that strongly suggest a hit
// contains credentials or keys. A hit on one of these is escalated.
var secretFileMarkers = []string{
	".env", "id_rsa", "id_dsa", ".pem", ".pfx", ".p12", ".keystore",
	"credentials", "secrets", "secret.", ".npmrc", ".pypirc", ".dockercfg",
	"config.json", "settings.py", "application.properties", "wp-config.php",
	".aws/credentials", ".ssh/", "private_key", "serviceaccount", ".kdbx",
}

// codeLeakCap bounds how many code hits are reported.
const codeLeakCap = 30

// collectCodeLeak searches public GitHub code for the target (a domain or
// e-mail) and reports exposed files, escalating likely-secret paths.
func collectCodeLeak(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	if env.ttype != TargetDomain && env.ttype != TargetEmail {
		return nil, nil
	}
	q := strings.TrimSpace(env.target)
	if q == "" {
		return nil, nil
	}
	if env.keys.GitHub == "" {
		// Code search is auth-only; without a token there is nothing we can do.
		env.emit("[*] codeleak: requires GITHUB_TOKEN — skipping public-code exposure scan")
		f := newFinding("codeleak", "exposure", "Public-code exposure (GitHub)",
			"skipped: set GITHUB_TOKEN to scan public repositories for this target")
		f.Data = `{"skipped_no_key":true}`
		return []models.OsintFinding{f}, nil
	}

	api := "https://api.github.com/search/code?per_page=" + fmt.Sprint(codeLeakCap) +
		"&q=" + url.QueryEscape("\""+q+"\"")
	body, status, err := githubAPIGet(ctx, rlGitHub, env.keys.GitHub, api, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	if status == 403 || status == 429 {
		env.emit("[*] codeleak: GitHub code-search rate-limited — skipping")
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("GitHub code-search returned HTTP %d", status)
	}

	var r struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			Name       string `json:"name"`
			Path       string `json:"path"`
			HTMLURL    string `json:"html_url"`
			Repository struct {
				FullName string `json:"full_name"`
				HTMLURL  string `json:"html_url"`
				Private  bool   `json:"private"`
			} `json:"repository"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &r) != nil {
		return nil, fmt.Errorf("could not decode GitHub code-search response")
	}
	if r.TotalCount == 0 || len(r.Items) == 0 {
		env.emit("[*] codeleak: no public code references found")
		f := newFinding("codeleak", "exposure", "Public-code exposure (GitHub)",
			"no references found in public repositories")
		return []models.OsintFinding{f}, nil
	}

	out := make([]models.OsintFinding, 0, len(r.Items)+1)
	summary := newFinding("codeleak", "exposure", "Public-code exposure (GitHub)",
		fmt.Sprintf("%d public-code reference(s) mention this target", r.TotalCount))
	summary.Severity = "medium"
	summary.SourceURL = "https://github.com/search?type=code&q=" + url.QueryEscape("\""+q+"\"")
	out = append(out, summary)

	secretHits := 0
	for i, it := range r.Items {
		if i >= codeLeakCap {
			break
		}
		lowerPath := strings.ToLower(it.Path + "/" + it.Name)
		isSecret := false
		for _, m := range secretFileMarkers {
			if strings.Contains(lowerPath, m) {
				isSecret = true
				break
			}
		}
		title := "Code reference in " + it.Repository.FullName
		sev := "low"
		detail := "file: " + it.Path
		if isSecret {
			secretHits++
			title = "Possible SECRET in public repo: " + path.Base(it.Path)
			sev = "critical"
			detail = "sensitive-looking file '" + it.Path + "' in " + it.Repository.FullName +
				" mentions this target — review and rotate any exposed credential"
		}
		f := newFinding("codeleak", "exposure", title, detail)
		f.Severity = sev
		f.SourceURL = it.HTMLURL
		if b, err := json.Marshal(map[string]string{
			"repo": it.Repository.FullName, "path": it.Path, "file": it.Name,
		}); err == nil {
			f.Data = string(b)
		}
		out = append(out, f)
	}

	if secretHits > 0 {
		env.emit(fmt.Sprintf("[!] codeleak: %d likely-secret file(s) found in public repos", secretHits))
	} else {
		env.emit(fmt.Sprintf("[+] codeleak: %d public-code reference(s)", r.TotalCount))
	}
	return out, nil
}

package osint

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/forensichub/backend/internal/models"
)

// collect_keybase.go — Keybase is a high-value de-anonymisation source: a user
// cryptographically PROVES ownership of their other accounts (Twitter, GitHub,
// Reddit, Hacker News, websites) and publishes a PGP key. One Keybase lookup can
// therefore tie a handle to a whole cluster of confirmed identities. Free,
// key-less public API. Every proven account is emitted as a pivot.

var rlKeybase = newRateLimiter(1500 * time.Millisecond)

// keybaseResp is the subset of keybase user/lookup we consume.
type keybaseResp struct {
	Status struct {
		Code int    `json:"code"`
		Name string `json:"name"`
	} `json:"status"`
	Them []struct {
		Basics struct {
			Username string `json:"username"`
		} `json:"basics"`
		Profile struct {
			FullName string `json:"full_name"`
			Location string `json:"location"`
			Bio      string `json:"bio"`
		} `json:"profile"`
		ProofsSummary struct {
			All []struct {
				ProofType         string `json:"proof_type"`
				Nametag           string `json:"nametag"`
				ServiceURL        string `json:"service_url"`
				HumanURL          string `json:"human_url"`
				PresentationGroup string `json:"presentation_group"`
			} `json:"all"`
		} `json:"proofs_summary"`
		Pictures struct {
			Primary struct {
				URL string `json:"url"`
			} `json:"primary"`
		} `json:"pictures"`
	} `json:"them"`
}

// collectKeybase resolves a username (or social-profile handle) on Keybase and
// emits the proven linked accounts + profile facts as findings/pivots.
func collectKeybase(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	if env.ttype != TargetUsername && env.ttype != TargetSocial {
		return nil, nil
	}
	handle := strings.TrimSpace(env.target)
	if env.ttype == TargetSocial {
		if p, ok := ParseSocialProfile(env.target); ok {
			handle = handleForUsernamePivot(p)
		}
	}
	if handle == "" {
		return nil, nil
	}

	api := "https://keybase.io/_/api/1.0/user/lookup.json?usernames=" + url.QueryEscape(handle) +
		"&fields=basics,profile,proofs_summary,pictures"
	var r keybaseResp
	status, err := cachedGetJSON(ctx, env.cache, "keybase:"+strings.ToLower(handle), rlKeybase, api, nil, &r, ttlReputation)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 || len(r.Them) == 0 {
		env.emit("[*] keybase: no Keybase account for this handle")
		return nil, nil
	}

	them := r.Them[0]
	profileURL := "https://keybase.io/" + them.Basics.Username
	var out []models.OsintFinding

	summary := newFinding("keybase", "identity", "Keybase account - "+them.Basics.Username, profileURL)
	summary.Severity = "high"
	summary.SourceURL = profileURL
	out = append(out, summary)

	if name := strings.TrimSpace(them.Profile.FullName); name != "" {
		f := newFinding("keybase", "identity", "Real name (Keybase)", name)
		f.SourceURL = profileURL
		// A full name is itself a pivot for people-search.
		out = append(out, withRelated(f, RelatedEntity{Type: TargetName, Value: name}))
	}
	if loc := strings.TrimSpace(them.Profile.Location); loc != "" {
		out = append(out, withSource(newFinding("keybase", "identity", "Location (Keybase)", loc), profileURL))
	}

	// Proven linked accounts — the de-anonymisation payload.
	for _, p := range them.ProofsSummary.All {
		svc := strings.ToLower(strings.TrimSpace(p.ProofType))
		tag := strings.TrimSpace(p.Nametag)
		if tag == "" {
			continue
		}
		link := firstNonEmptyStr(p.ServiceURL, p.HumanURL)
		f := newFinding("keybase", "identity",
			fmt.Sprintf("Proven %s account - %s", svc, tag), link)
		f.Severity = "high"
		f.SourceURL = link
		f.VerifyNote = "cryptographically proven on Keybase - strong identity link"

		// Emit a pivot for the linked identity.
		switch svc {
		case "twitter", "github", "reddit", "hackernews", "gitlab", "mastodon":
			out = append(out, withRelated(f, RelatedEntity{Type: TargetUsername, Value: tag}))
		case "dns", "https", "http", "web":
			if d := hostFromAny(tag); d != "" {
				out = append(out, withRelated(f, RelatedEntity{Type: TargetDomain, Value: d}))
			} else {
				out = append(out, f)
			}
		default:
			out = append(out, f)
		}
	}

	// Avatar fingerprint for cross-platform correlation + reverse-image lookups.
	if av := strings.TrimSpace(them.Pictures.Primary.URL); av != "" {
		if h, ok := fetchAvatarHash(ctx, av); ok {
			out = append(out, avatarFinding("keybase", av, h))
			out = append(out, avatarReverseFindings("keybase", av)...)
		}
	}

	env.emit(fmt.Sprintf("[+] keybase: %s - %d proven linked account(s)", them.Basics.Username, len(them.ProofsSummary.All)))
	return out, nil
}

// firstNonEmptyStr returns the first non-empty trimmed string.
func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// hostFromAny extracts a bare host from a domain or URL string.
func hostFromAny(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if domainRe.MatchString(s) {
		return s
	}
	return ""
}

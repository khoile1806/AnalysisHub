package osint

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/forensichub/backend/internal/models"
)

// collect_social_profile.go — investigate a pasted profile LINK. It identifies
// the platform + handle, enriches the profile where a free API exists
// (Reddit, Mastodon, Telegram), fingerprints the avatar for cross-platform
// correlation, and ALWAYS pivots the handle into a full username investigation
// (maigret / github / keybase / leak sources) so one profile link fans out into
// the person's whole footprint.

var (
	rlReddit   = newRateLimiter(1500 * time.Millisecond)
	rlMastodon = newRateLimiter(1200 * time.Millisecond)
)

func collectSocialProfile(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	prof, ok := ParseSocialProfile(env.target)
	if !ok {
		return nil, fmt.Errorf("not a recognisable social-media profile URL")
	}
	handle := handleForUsernamePivot(prof)

	out := []models.OsintFinding{}
	// The anchor finding: which platform + handle this link resolves to, and the
	// pivot that launches the full username investigation.
	anchor := newFinding("social_profile", "social",
		fmt.Sprintf("%s profile - @%s", strings.Title(prof.Platform), prof.Handle), prof.URL)
	anchor.Severity = "info"
	anchor.SourceURL = prof.URL
	out = append(out, withRelated(anchor, RelatedEntity{Type: TargetUsername, Value: handle}))

	switch prof.Platform {
	case "reddit":
		out = append(out, enrichReddit(ctx, env, handle)...)
	case "mastodon":
		out = append(out, enrichMastodon(ctx, env, prof.Handle)...)
	case "telegram":
		out = append(out, enrichTelegram(ctx, env, handle)...)
	}

	env.emit(fmt.Sprintf("[+] social_profile: %s/@%s - pivoting handle into full username investigation", prof.Platform, handle))
	return out, nil
}

// accountCreatedFinding emits a standardised "Account created" finding. The
// title is matched by the identity-confidence scorer to enable timeline/age
// correlation across platforms (close sign-up times ⇒ same person).
func accountCreatedFinding(source, isoDate, profileURL string) models.OsintFinding {
	f := newFinding(source, "identity", "Account created", isoDate)
	f.SourceURL = profileURL
	f.Data = toJSON(map[string]string{"created": isoDate})
	return f
}

// enrichReddit pulls public account facts from Reddit's about.json.
func enrichReddit(ctx context.Context, env *collectorEnv, handle string) []models.OsintFinding {
	api := "https://www.reddit.com/user/" + url.PathEscape(handle) + "/about.json"
	var r struct {
		Data struct {
			Name         string  `json:"name"`
			CreatedUTC   float64 `json:"created_utc"`
			CommentKarma int     `json:"comment_karma"`
			LinkKarma    int     `json:"link_karma"`
			IconImg      string  `json:"icon_img"`
			Subreddit    struct {
				PublicDescription string `json:"public_description"`
				Title             string `json:"title"`
			} `json:"subreddit"`
		} `json:"data"`
	}
	st, err := cachedGetJSON(ctx, env.cache, "reddit:"+strings.ToLower(handle), rlReddit, api, map[string]string{"User-Agent": browserUA}, &r, ttlReputation)
	if err != nil || st != 200 || r.Data.Name == "" {
		return nil
	}
	profURL := "https://www.reddit.com/user/" + r.Data.Name
	var out []models.OsintFinding
	f := newFinding("social_profile", "social",
		fmt.Sprintf("Reddit u/%s - %d karma", r.Data.Name, r.Data.CommentKarma+r.Data.LinkKarma),
		profURL)
	f.SourceURL = profURL
	out = append(out, f)
	if r.Data.CreatedUTC > 0 {
		created := time.Unix(int64(r.Data.CreatedUTC), 0).UTC().Format(time.RFC3339)
		out = append(out, accountCreatedFinding("social_profile", created, profURL))
	}
	if d := strings.TrimSpace(r.Data.Subreddit.PublicDescription); d != "" {
		out = append(out, withSource(newFinding("social_profile", "social", "Reddit bio", d), profURL))
	}
	if h, ok := fetchAvatarHash(ctx, cleanRedditIcon(r.Data.IconImg)); ok {
		out = append(out, avatarFinding("social_profile", cleanRedditIcon(r.Data.IconImg), h))
		out = append(out, avatarReverseFindings("social_profile", cleanRedditIcon(r.Data.IconImg))...)
	}
	return out
}

// enrichMastodon resolves a fediverse account via the instance's public API.
func enrichMastodon(ctx context.Context, env *collectorEnv, acct string) []models.OsintFinding {
	user, host, found := strings.Cut(acct, "@")
	if !found || host == "" {
		return nil
	}
	api := "https://" + host + "/api/v1/accounts/lookup?acct=" + url.QueryEscape(user)
	var r struct {
		Username       string `json:"username"`
		Acct           string `json:"acct"`
		DisplayName    string `json:"display_name"`
		Note           string `json:"note"`
		URL            string `json:"url"`
		Avatar         string `json:"avatar"`
		FollowersCount int    `json:"followers_count"`
		StatusesCount  int    `json:"statuses_count"`
		CreatedAt      string `json:"created_at"`
	}
	st, err := cachedGetJSON(ctx, env.cache, "mastodon:"+strings.ToLower(acct), rlMastodon, api, map[string]string{"User-Agent": browserUA}, &r, ttlReputation)
	if err != nil || st != 200 || r.Username == "" {
		return nil
	}
	profURL := firstNonEmptyStr(r.URL, "https://"+host+"/@"+user)
	var out []models.OsintFinding
	f := newFinding("social_profile", "social",
		fmt.Sprintf("Mastodon %s - %d posts, %d followers", r.Acct, r.StatusesCount, r.FollowersCount),
		profURL)
	f.SourceURL = profURL
	out = append(out, f)
	if ca := strings.TrimSpace(r.CreatedAt); ca != "" {
		out = append(out, accountCreatedFinding("social_profile", ca, profURL))
	}
	if dn := strings.TrimSpace(r.DisplayName); dn != "" {
		out = append(out, withSource(newFinding("social_profile", "social", "Display name (Mastodon)", dn), profURL))
	}
	if note := stripHTMLTags(r.Note); note != "" {
		out = append(out, withSource(newFinding("social_profile", "social", "Mastodon bio", note), profURL))
	}
	if h, ok := fetchAvatarHash(ctx, r.Avatar); ok {
		out = append(out, avatarFinding("social_profile", r.Avatar, h))
		out = append(out, avatarReverseFindings("social_profile", r.Avatar)...)
	}
	return out
}

// enrichTelegram reads the public t.me preview page (title + bio) for a handle.
func enrichTelegram(ctx context.Context, env *collectorEnv, handle string) []models.OsintFinding {
	body, status, err := httpGetBody(ctx, rlReddit, "https://t.me/"+url.PathEscape(handle), map[string]string{"User-Agent": browserUA})
	if err != nil || status != 200 {
		return nil
	}
	html := string(body)
	if !strings.Contains(html, "tgme_page_title") {
		return nil // no public preview / not a user
	}
	profURL := "https://t.me/" + handle
	var out []models.OsintFinding
	if title := extractBetween(html, `tgme_page_title" dir="auto"><span dir="auto">`, "</span>"); title != "" {
		out = append(out, withSource(newFinding("social_profile", "social", "Telegram title", title), profURL))
	}
	if desc := extractBetween(html, `tgme_page_description" dir="auto">`, "</div>"); desc != "" {
		out = append(out, withSource(newFinding("social_profile", "social", "Telegram bio", stripHTMLTags(desc)), profURL))
	}
	return out
}

// cleanRedditIcon strips the HTML-escaped query params Reddit appends to avatars.
func cleanRedditIcon(s string) string {
	s = strings.ReplaceAll(s, "&amp;", "&")
	if i := strings.IndexByte(s, '?'); i >= 0 {
		return s[:i]
	}
	return s
}

// stripHTMLTags removes tags and collapses whitespace from a small HTML snippet.
func stripHTMLTags(s string) string {
	var b strings.Builder
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
		case !inTag:
			b.WriteRune(r)
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if len(out) > 500 {
		out = out[:500] + "…"
	}
	return out
}

// extractBetween returns the substring between the first occurrence of pre and
// the next occurrence of post, or "".
func extractBetween(s, pre, post string) string {
	i := strings.Index(s, pre)
	if i < 0 {
		return ""
	}
	rest := s[i+len(pre):]
	j := strings.Index(rest, post)
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}

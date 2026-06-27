package osint

import (
	"net/url"
	"regexp"
	"strings"
)

// social_profile.go — turn a pasted social-media profile LINK into a real
// investigation. Previously a URL like "https://twitter.com/johndoe" was cut
// down to its host ("twitter.com") and scanned as a domain — investigating the
// platform, not the person, and throwing the handle away. ParseSocialProfile
// instead recognises the platform and extracts the handle, so the engine can
// enrich the profile and pivot the handle into a full username investigation.

// SocialProfile is a parsed social-media profile reference.
type SocialProfile struct {
	Platform string // e.g. "twitter", "github", "mastodon"
	Handle   string // the account handle (for mastodon: user@host)
	URL      string // canonical profile URL
}

// reservedSeg are first-path segments that are site sections, never handles.
var reservedSeg = map[string]bool{
	"home": true, "search": true, "explore": true, "settings": true, "about": true,
	"login": true, "signup": true, "signin": true, "help": true, "tos": true,
	"privacy": true, "i": true, "messages": true, "notifications": true,
	"hashtag": true, "share": true, "intent": true, "discover": true,
	"watch": true, "marketplace": true, "groups": true, "pages": true,
	"events": true, "stories": true, "reels": true, "p": true, "tv": true,
}

var fediverseRe = regexp.MustCompile(`^/@([A-Za-z0-9_.]+)/?$`)

// firstSeg returns the first non-empty path segment.
func firstSeg(p string) string {
	for _, s := range strings.Split(strings.Trim(p, "/"), "/") {
		if s != "" {
			return s
		}
	}
	return ""
}

// stripAt removes a leading '@' from a handle.
func stripAt(s string) string { return strings.TrimPrefix(s, "@") }

// ParseSocialProfile recognises a profile URL and returns the platform + handle.
// It accepts URLs with or without a scheme. ok is false when the input is not a
// recognisable social-media profile link.
func ParseSocialProfile(raw string) (SocialProfile, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return SocialProfile{}, false
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return SocialProfile{}, false
	}
	host := strings.ToLower(strings.TrimPrefix(u.Hostname(), "www."))
	path := u.Path
	seg := firstSeg(path)

	mk := func(platform, handle string) (SocialProfile, bool) {
		handle = stripAt(strings.TrimSpace(handle))
		if handle == "" || reservedSeg[strings.ToLower(handle)] {
			return SocialProfile{}, false
		}
		return SocialProfile{Platform: platform, Handle: handle, URL: u.String()}, true
	}

	switch host {
	case "twitter.com", "x.com":
		return mk("twitter", seg)
	case "github.com":
		return mk("github", seg)
	case "gitlab.com":
		return mk("gitlab", seg)
	case "instagram.com":
		return mk("instagram", seg)
	case "facebook.com", "fb.com", "m.facebook.com":
		if strings.HasPrefix(strings.ToLower(path), "/profile.php") {
			if id := u.Query().Get("id"); id != "" {
				return mk("facebook", id)
			}
		}
		return mk("facebook", seg)
	case "t.me", "telegram.me", "telegram.dog":
		if seg == "s" || seg == "joinchat" || strings.HasPrefix(seg, "+") {
			return SocialProfile{}, false // channel/invite, not a user handle
		}
		return mk("telegram", seg)
	case "reddit.com", "old.reddit.com":
		segs := strings.Split(strings.Trim(path, "/"), "/")
		if len(segs) >= 2 && (segs[0] == "user" || segs[0] == "u") {
			return mk("reddit", segs[1])
		}
		return SocialProfile{}, false
	case "linkedin.com":
		segs := strings.Split(strings.Trim(path, "/"), "/")
		if len(segs) >= 2 && segs[0] == "in" {
			return mk("linkedin", segs[1])
		}
		return SocialProfile{}, false
	case "tiktok.com":
		return mk("tiktok", seg)
	case "youtube.com", "m.youtube.com":
		if strings.HasPrefix(seg, "@") {
			return mk("youtube", seg)
		}
		segs := strings.Split(strings.Trim(path, "/"), "/")
		if len(segs) >= 2 && (segs[0] == "user" || segs[0] == "c") {
			return mk("youtube", segs[1])
		}
		return SocialProfile{}, false
	case "medium.com":
		return mk("medium", seg)
	case "threads.net":
		return mk("threads", seg)
	case "keybase.io":
		return mk("keybase", seg)
	case "dev.to":
		return mk("devto", seg)
	case "about.me":
		return mk("aboutme", seg)
	case "pinterest.com":
		return mk("pinterest", seg)
	case "bitbucket.org":
		return mk("bitbucket", seg)
	case "mastodon.social", "mas.to", "fosstodon.org", "infosec.exchange", "hachyderm.io", "mstdn.social":
		if m := fediverseRe.FindStringSubmatch(path); m != nil {
			return mk("mastodon", m[1]+"@"+host)
		}
		return SocialProfile{}, false
	}

	// Generic fediverse fallback: any host serving a /@user profile path.
	if m := fediverseRe.FindStringSubmatch(path); m != nil {
		return mk("mastodon", m[1]+"@"+host)
	}
	return SocialProfile{}, false
}

// handleForUsernamePivot returns the bare handle suitable for a username-target
// pivot (mastodon "user@host" reduces to "user").
func handleForUsernamePivot(p SocialProfile) string {
	if i := strings.IndexByte(p.Handle, '@'); i > 0 {
		return p.Handle[:i]
	}
	return p.Handle
}

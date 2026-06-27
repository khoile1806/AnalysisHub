package osint

import (
	"sort"
	"strconv"
	"strings"

	"github.com/forensichub/backend/internal/models"
)

// identity.go — a single OSINT scan produces dozens of scattered findings; what
// an analyst actually wants is "how sure are we this is all ONE person, and how
// strong is the identity picture?". ComputeIdentityConfidence reduces the graph
// to a small set of INDEPENDENT identity signals and scores them, returning a
// 0-100 confidence with a human-readable breakdown. Independence is the point:
// ten findings from one collector prove little; an e-mail, a proven Keybase
// link, and a matching avatar from three different sources prove a lot.

// IdentitySignal is one scored corroboration signal.
type IdentitySignal struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Weight int    `json:"weight"`
	Detail string `json:"detail,omitempty"`
}

// IdentityConfidence is the aggregated identity assessment for a graph.
type IdentityConfidence struct {
	Score   int              `json:"score"` // 0-100
	Grade   string           `json:"grade"` // strong | moderate | weak | minimal
	Signals []IdentitySignal `json:"signals"`
	Summary string           `json:"summary"`
}

// ComputeIdentityConfidence scores the identity picture from all graph findings.
func ComputeIdentityConfidence(findings []models.OsintFinding) IdentityConfidence {
	// Collect independent signal weights (each key counts once, no matter how
	// many findings back it, so a chatty collector can't inflate the score).
	weights := map[string]IdentitySignal{}
	avatarHashes := map[string]bool{}
	provenCount := 0
	// tzSources maps a timezone token -> the set of distinct sources that report
	// it; agreement across independent sources is a real corroboration signal.
	tzSources := map[string]map[string]bool{}
	creationDates := 0

	for i := range findings {
		f := &findings[i]
		title := strings.ToLower(f.Title)
		val := strings.ToLower(f.Value)

		if strings.Contains(title, "timezone") {
			for _, tz := range splitTZ(f.Value) {
				if tzSources[tz] == nil {
					tzSources[tz] = map[string]bool{}
				}
				tzSources[tz][f.Source] = true
			}
		}
		if strings.Contains(strings.ToLower(f.Data), `"created"`) || strings.Contains(title, "account created") {
			creationDates++
		}

		switch {
		case f.Source == "keybase" && strings.Contains(title, "proven"):
			provenCount++
		case strings.HasPrefix(val, "avatar_phash:"):
			avatarHashes[val] = true
		case f.Source == "github_intel" && strings.Contains(title, "login behind this e-mail"):
			set(weights, "email_to_github", "E-mail ↔ GitHub login linked", 20, f.Value)
		case f.Source == "gravatar":
			set(weights, "gravatar", "Gravatar profile bound to the e-mail", 12, "")
		case f.Source == "email_validate" && f.Confidence == "verified":
			set(weights, "email_deliverable", "E-mail confirmed deliverable (not catch-all)", 10, "")
		case (f.Source == "hibp" || f.Source == "xposed" || f.Source == "leakcheck") && f.Category == "breach":
			set(weights, "breach_named", "Identifier found in named breach corpus", 8, "")
		case f.Source == "stealer_intel":
			set(weights, "stealer", "Appears in info-stealer logs (live credentials)", 14, "")
		case f.Source == "social_search" && f.Confidence == "high" && strings.Contains(title, "profile found"):
			set(weights, "social_confirmed", "Confirmed social-media profile(s)", 8, "")
		case f.Source == "social_profile":
			set(weights, "profile_link", "Resolved from a social-profile link", 6, "")
		}
	}

	if provenCount > 0 {
		// Cryptographically proven linked accounts are the strongest signal.
		w := 25
		if provenCount > 1 {
			w = 35
		}
		set(weights, "keybase_proven", "Cryptographically-proven linked accounts (Keybase)", w,
			pluralCount(provenCount, "proven account"))
	}
	if len(avatarHashes) > 0 {
		// A shared avatar across ≥2 distinct findings links accounts visually.
		set(weights, "avatar_match", "Shared avatar fingerprint across accounts", 15,
			pluralCount(len(avatarHashes), "avatar"))
	}
	// Timezone corroboration: the same timezone reported by ≥2 independent
	// sources (e.g. IP geolocation + phone numbering plan) reinforces one locale.
	for tz, srcs := range tzSources {
		if len(srcs) >= 2 {
			set(weights, "timezone_consistent", "Consistent timezone across independent sources", 10, tz)
			break
		}
	}
	if creationDates >= 2 {
		// Known account-creation dates on multiple profiles let an analyst
		// timeline-correlate the identity (close sign-up times = same person).
		set(weights, "account_age", "Account-creation dates available for timeline correlation", 6,
			pluralCount(creationDates, "dated account"))
	}

	signals := make([]IdentitySignal, 0, len(weights))
	total := 0
	for _, s := range weights {
		signals = append(signals, s)
		total += s.Weight
	}
	sort.Slice(signals, func(i, j int) bool { return signals[i].Weight > signals[j].Weight })

	if total > 100 {
		total = 100
	}
	return IdentityConfidence{
		Score:   total,
		Grade:   identityGrade(total),
		Signals: signals,
		Summary: identitySummary(total, len(signals)),
	}
}

func set(m map[string]IdentitySignal, key, label string, weight int, detail string) {
	if cur, ok := m[key]; ok && cur.Weight >= weight {
		return // keep the strongest instance of a signal
	}
	m[key] = IdentitySignal{Key: key, Label: label, Weight: weight, Detail: detail}
}

func identityGrade(score int) string {
	switch {
	case score >= 70:
		return "strong"
	case score >= 40:
		return "moderate"
	case score >= 15:
		return "weak"
	default:
		return "minimal"
	}
}

func identitySummary(score, n int) string {
	switch {
	case n == 0:
		return "No corroborating identity signals were found — treat any single trace as unconfirmed."
	case score >= 70:
		return "Multiple independent sources corroborate one identity — high confidence the traces belong to the same person."
	case score >= 40:
		return "Several signals point to one identity, but more corroboration would strengthen the link."
	default:
		return "Only weak/limited identity signals — verify manually before drawing conclusions."
	}
}

// splitTZ normalises a timezone finding value into individual TZ tokens
// (handles "America/New_York" and comma-separated "Europe/London, Europe/Paris").
func splitTZ(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if t := strings.TrimSpace(strings.ToLower(part)); strings.Contains(t, "/") {
			out = append(out, t)
		}
	}
	return out
}

func pluralCount(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

package osint

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/forensichub/backend/internal/models"
)

// handle_variants.go — people reuse the same name across platforms but with
// different separators/forms (john.doe ↔ johndoe ↔ jdoe ↔ john_doe). Checking
// only the exact input handle misses those accounts. GenerateHandleVariants
// derives the plausible alternative spellings; the username_variants collector
// surfaces them as ready-to-check candidates (search + social links) WITHOUT
// auto-spawning a scan per variant, so coverage rises without a request blow-up.

// GenerateHandleVariants returns up to a small ordered set of plausible
// alternative spellings of a handle, excluding the input itself.
func GenerateHandleVariants(handle string) []string {
	h := strings.ToLower(strings.TrimSpace(handle))
	if h == "" {
		return nil
	}
	// Split on common separators to recover name parts.
	parts := strings.FieldsFunc(h, func(r rune) bool {
		return r == '.' || r == '_' || r == '-' || r == ' '
	})

	seen := map[string]bool{h: true}
	var out []string
	add := func(v string) {
		v = strings.Trim(v, "._-")
		if v == "" || seen[v] || !usernameRe.MatchString(v) {
			return
		}
		seen[v] = true
		out = append(out, v)
	}

	if len(parts) >= 2 {
		first, last := parts[0], parts[len(parts)-1]
		fi := first[:1]
		add(first + last)       // johndoe
		add(first + "." + last) // john.doe
		add(first + "_" + last) // john_doe
		add(first + "-" + last) // john-doe
		add(fi + last)          // jdoe
		add(first + last[:1])   // johnd
		add(fi + "." + last)    // j.doe
		add(last + first)       // doejohn
		add(first)              // john
	} else {
		// Single token: try inserting a separator is impossible without a split,
		// so just offer a couple of common decorations seen on social handles.
		add(h + "1")
		add(h + "_")
		add("the" + h)
		add(h + "official")
	}

	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

// collectUsernameVariants emits alternative handle spellings as candidate
// findings (with a search link) for the analyst to confirm — raising coverage of
// accounts registered under a different spelling. It deliberately does NOT mark
// them as pivots: an unverified spelling guess must not auto-spawn a scan (that
// would add noise and false positives); the analyst launches one on demand.
func collectUsernameVariants(_ context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	variants := GenerateHandleVariants(env.target)
	if len(variants) == 0 {
		env.emit("[*] username_variants: no alternative spellings to suggest")
		return nil, nil
	}
	var out []models.OsintFinding
	for _, v := range variants {
		f := newFinding("username_variants", "social",
			"Alternative handle to check - "+v,
			"https://www.google.com/search?q="+url.QueryEscape("\""+v+"\""))
		f.Severity = "low"
		f.Confidence = "low"
		f.VerifyNote = "auto-generated spelling variant of the target handle - verify before trusting"
		out = append(out, f)
	}
	env.emit(fmt.Sprintf("[+] username_variants: %d alternative spelling(s) suggested", len(variants)))
	return out, nil
}

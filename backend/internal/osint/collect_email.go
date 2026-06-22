package osint

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/forensichub/backend/internal/models"
)

// emailParts splits an address into local part and domain (lowercased).
func emailParts(email string) (local, domain string) {
	e := strings.ToLower(strings.TrimSpace(email))
	if i := strings.LastIndex(e, "@"); i > 0 {
		return e[:i], e[i+1:]
	}
	return e, ""
}

// -- Syntax + MX validity ------------------------------------------------------

// collectEmailValidate confirms the address is deliverable-shaped and that its
// domain publishes MX records, and emits pivots to the domain and to the
// probable username (the local part).
func collectEmailValidate(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	local, domain := emailParts(env.target)
	if domain == "" {
		return nil, fmt.Errorf("address has no domain part")
	}

	var out []models.OsintFinding

	domainFinding := newFinding("email_validate", "identity", "Mail domain", domain)
	out = append(out, withRelated(domainFinding, RelatedEntity{Type: TargetDomain, Value: domain}))

	// The local part is frequently reused as a social-media handle. Strip any
	// "+tag" plus-addressing suffix, and only offer the pivot when the result
	// is a valid handle shape so the pivot scan cannot 400.
	handle := local
	if i := strings.IndexByte(handle, '+'); i > 0 {
		handle = handle[:i]
	}
	if usernameRe.MatchString(handle) {
		uf := newFinding("email_validate", "identity", "Probable username (email local part)", handle)
		out = append(out, withRelated(uf, RelatedEntity{Type: TargetUsername, Value: handle}))
	}

	r := &net.Resolver{}
	mxs, err := r.LookupMX(ctx, domain)
	if err != nil || len(mxs) == 0 {
		f := newFinding("email_validate", "identity", "Mail exchanger",
			"no MX record - the domain likely cannot receive e-mail")
		f.Severity = "low"
		out = append(out, f)
		return out, nil
	}
	hosts := make([]string, 0, len(mxs))
	for _, mx := range mxs {
		hosts = append(hosts, strings.TrimRight(strings.ToLower(mx.Host), "."))
	}
	out = append(out, newFinding("email_validate", "identity", "Mail exchanger",
		strings.Join(hosts, ", ")))
	return out, nil
}

// -- Gravatar ------------------------------------------------------------------

type gravatarProfile struct {
	Entry []struct {
		ProfileURL        string `json:"profileUrl"`
		PreferredUsername string `json:"preferredUsername"`
		DisplayName       string `json:"displayName"`
		Location          string `json:"currentLocation"`
		AboutMe           string `json:"aboutMe"`
		Accounts          []struct {
			Domain   string `json:"domain"`
			Display  string `json:"display"`
			URL      string `json:"url"`
			Username string `json:"username"`
		} `json:"accounts"`
		URLs []struct {
			Title string `json:"title"`
			Value string `json:"value"`
		} `json:"urls"`
	} `json:"entry"`
}

// collectGravatar looks up the public Gravatar profile bound to the e-mail's
// MD5 hash. A Gravatar profile often links social-media accounts.
func collectGravatar(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	norm := strings.ToLower(strings.TrimSpace(env.target))
	sum := md5.Sum([]byte(norm))
	hash := hex.EncodeToString(sum[:])

	u := "https://www.gravatar.com/" + hash + ".json"
	var p gravatarProfile
	status, err := httpGetJSON(ctx, nil, u, nil, &p)
	if err != nil {
		return nil, err
	}
	if status == 404 {
		env.emit("[*] gravatar: no public profile for this address")
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("gravatar returned HTTP %d", status)
	}
	if len(p.Entry) == 0 {
		return nil, nil
	}
	e := p.Entry[0]

	var out []models.OsintFinding
	if e.DisplayName != "" || e.PreferredUsername != "" {
		out = append(out, newFinding("gravatar", "identity", "Gravatar profile",
			joinNonEmpty(" - ", e.DisplayName, e.PreferredUsername)))
	}
	if e.ProfileURL != "" {
		out = append(out, newFinding("gravatar", "identity", "Gravatar profile URL", e.ProfileURL))
	}
	if e.Location != "" {
		out = append(out, newFinding("gravatar", "identity", "Stated location", e.Location))
	}
	for _, acc := range e.Accounts {
		label := joinNonEmpty(" ", acc.Domain, acc.Display)
		val := acc.URL
		if val == "" {
			val = acc.Username
		}
		out = append(out, newFinding("gravatar", "identity",
			"Linked account: "+label, val))
	}
	for _, link := range e.URLs {
		if link.Value == "" {
			continue
		}
		title := link.Title
		if title == "" {
			title = "Linked website"
		}
		out = append(out, newFinding("gravatar", "identity", title, link.Value))
	}
	return out, nil
}

// -- Have I Been Pwned (optional key) ------------------------------------------

type hibpBreach struct {
	Name        string   `json:"Name"`
	Title       string   `json:"Title"`
	Domain      string   `json:"Domain"`
	BreachDate  string   `json:"BreachDate"`
	PwnCount    int64    `json:"PwnCount"`
	DataClasses []string `json:"DataClasses"`
}

// collectHIBP checks the e-mail against Have I Been Pwned breach data. Needs
// OSINT_HIBP_API_KEY.
func collectHIBP(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	if env.keys.HIBP == "" {
		return nil, errNoAPIKey
	}
	u := "https://haveibeenpwned.com/api/v3/breachedaccount/" +
		url.PathEscape(env.target) + "?truncateResponse=false"
	var breaches []hibpBreach
	status, err := httpGetJSON(ctx, nil, u, map[string]string{
		"hibp-api-key": env.keys.HIBP,
	}, &breaches)
	if err != nil {
		return nil, err
	}
	if status == 401 {
		return nil, fmt.Errorf("HIBP rejected the API key (HTTP 401)")
	}
	if status == 404 {
		f := newFinding("hibp", "breach", "Breach exposure",
			"address not found in any known breach")
		return []models.OsintFinding{f}, nil
	}
	if status == 429 {
		return nil, fmt.Errorf("HIBP rate limit hit (HTTP 429)")
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("HIBP returned HTTP %d", status)
	}

	var out []models.OsintFinding
	summary := newFinding("hibp", "breach", "Breach exposure",
		fmt.Sprintf("address appears in %d known breach(es)", len(breaches)))
	if len(breaches) > 0 {
		summary.Severity = "high"
	}
	out = append(out, summary)
	for _, b := range breaches {
		title := b.Title
		if title == "" {
			title = b.Name
		}
		f := newFinding("hibp", "breach", "Breach: "+title,
			fmt.Sprintf("%s - exposed: %s", b.BreachDate, strings.Join(b.DataClasses, ", ")))
		f.Severity = "high"
		out = append(out, f)
	}
	return out, nil
}

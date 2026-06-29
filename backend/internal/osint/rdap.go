package osint

import (
	"context"
	"fmt"
	"strings"
)

// RDAP (RFC 7483) replaces legacy WHOIS with structured JSON. rdap.org is a
// free redirector that forwards each query to the authoritative registry's
// RDAP server; the shared HTTP client follows those redirects automatically.

type rdapEvent struct {
	EventAction string `json:"eventAction"`
	EventDate   string `json:"eventDate"`
}

type rdapEntity struct {
	Roles      []string      `json:"roles"`
	Handle     string        `json:"handle"`
	VcardArray []interface{} `json:"vcardArray"`
	Entities   []rdapEntity  `json:"entities"`
}

type rdapResponse struct {
	LdhName     string       `json:"ldhName"`
	Handle      string       `json:"handle"`
	Status      []string     `json:"status"`
	Events      []rdapEvent  `json:"events"`
	Entities    []rdapEntity `json:"entities"`
	Nameservers []struct {
		LdhName string `json:"ldhName"`
	} `json:"nameservers"`

	// IP-network object fields (rdap.org/ip/<ip>).
	StartAddress string `json:"startAddress"`
	EndAddress   string `json:"endAddress"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	Country      string `json:"country"`
}

// fetchRDAPCached retrieves and decodes an RDAP object through a Redis
// read-through cache. Registration data changes on the order of days, so caching
// it cuts repeated rdap.org round-trips for re-runs, watches and auto-pivots.
// The HTTP status is returned so the caller can treat 404 ("no record")
// differently from a hard error.
func fetchRDAPCached(ctx context.Context, env *collectorEnv, key, url string) (*rdapResponse, int, error) {
	var r rdapResponse
	status, err := cachedGetJSON(ctx, env.cache, key, rlRDAP, url, nil, &r, ttlRDAP)
	if err != nil {
		return nil, status, err
	}
	return &r, status, nil
}

// parseVCard extracts the formatted name, e-mail and organisation from a
// jCard (RFC 7095) array as embedded in an RDAP entity.
func parseVCard(vcard []interface{}) (fn, email, org string) {
	if len(vcard) < 2 {
		return
	}
	props, ok := vcard[1].([]interface{})
	if !ok {
		return
	}
	for _, p := range props {
		arr, ok := p.([]interface{})
		if !ok || len(arr) < 4 {
			continue
		}
		name, _ := arr[0].(string)
		val, _ := arr[3].(string)
		if val == "" {
			// Some properties (e.g. "org", "adr") carry an array value.
			if a, ok := arr[3].([]interface{}); ok && len(a) > 0 {
				val, _ = a[0].(string)
			}
		}
		switch strings.ToLower(name) {
		case "fn":
			fn = val
		case "email":
			email = val
		case "org":
			org = val
		}
	}
	return
}

// walkEntities visits every entity (recursing into nested entities) and calls
// fn with the role list and the parsed jCard fields.
func walkEntities(ents []rdapEntity, fn func(roles []string, name, email, org string)) {
	for _, e := range ents {
		var n, em, og string
		if len(e.VcardArray) > 0 {
			n, em, og = parseVCard(e.VcardArray)
		}
		fn(e.Roles, n, em, og)
		if len(e.Entities) > 0 {
			walkEntities(e.Entities, fn)
		}
	}
}

// hasRole reports whether role appears (case-insensitively) in roles.
func hasRole(roles []string, role string) bool {
	for _, r := range roles {
		if strings.EqualFold(r, role) {
			return true
		}
	}
	return false
}

// joinNonEmpty joins the non-empty parts with sep.
func joinNonEmpty(sep string, parts ...string) string {
	out := parts[:0]
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}

// fmtEvents turns RDAP events into a single "registration: ..., expiration: ..."
// summary string.
func fmtEvents(events []rdapEvent) string {
	var parts []string
	for _, ev := range events {
		if ev.EventAction == "" || ev.EventDate == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s: %s", ev.EventAction, ev.EventDate))
	}
	return strings.Join(parts, " - ")
}

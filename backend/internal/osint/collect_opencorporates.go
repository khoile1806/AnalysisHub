package osint

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/analysishub/backend/internal/models"
)

// collect_opencorporates.go — resolve a person's name to their corporate roles.
//
// A full name has no single API to "resolve", so name investigations were
// previously search-links only. OpenCorporates is the exception: its officer
// search maps a name to the companies where that person is (or was) a director/
// officer, across ~140 jurisdictions — a real, structured lead for due-diligence.
// Optional: needs a free API token (OSINT_OPENCORPORATES_API_KEY); the collector
// is skipped (not failed) when the key is unset.

var rlOpenCorp = newRateLimiter(1500 * time.Millisecond)

// collectOpenCorporates emits corporate-officer records matching a person's name.
func collectOpenCorporates(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	if env.ttype != TargetName {
		return nil, nil
	}
	key := strings.TrimSpace(env.keys.OpenCorp)
	if key == "" {
		return nil, errNoAPIKey
	}

	u := "https://api.opencorporates.com/v0.4/officers/search?per_page=10" +
		"&q=" + url.QueryEscape(env.target) +
		"&api_token=" + url.QueryEscape(key)

	var r struct {
		Results struct {
			Officers []struct {
				Officer struct {
					Name     string `json:"name"`
					Position string `json:"position"`
					OCURL    string `json:"opencorporates_url"`
					Company  struct {
						Name         string `json:"name"`
						Jurisdiction string `json:"jurisdiction_code"`
						OCURL        string `json:"opencorporates_url"`
					} `json:"company"`
				} `json:"officer"`
			} `json:"officers"`
		} `json:"results"`
	}
	status, err := httpGetJSON(ctx, rlOpenCorp, u, nil, &r)
	if err != nil {
		return nil, err
	}
	if status == 401 || status == 403 {
		return nil, fmt.Errorf("OpenCorporates rejected the API token (HTTP %d)", status)
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("OpenCorporates returned HTTP %d", status)
	}
	if len(r.Results.Officers) == 0 {
		env.emit("[*] opencorporates: no corporate-officer records for this name")
		return nil, nil
	}

	var out []models.OsintFinding
	for _, o := range r.Results.Officers {
		of := o.Officer
		if strings.TrimSpace(of.Name) == "" {
			continue
		}
		detail := of.Name
		if role := strings.TrimSpace(of.Position); role != "" {
			detail += " — " + role
		}
		if c := strings.TrimSpace(of.Company.Name); c != "" {
			detail += " @ " + c
			if j := strings.TrimSpace(of.Company.Jurisdiction); j != "" {
				detail += " (" + strings.ToUpper(j) + ")"
			}
		}
		link := of.OCURL
		if link == "" {
			link = of.Company.OCURL
		}
		f := newFinding("opencorporates", "identity", "Corporate officer record", detail)
		f.Severity = "low"
		f.Confidence = "unverified"
		f.VerifyNote = "Name-based officer match from OpenCorporates; confirm it is the same person before relying on it."
		f = withSource(f, link)
		out = append(out, f)
	}
	env.emit(fmt.Sprintf("[*] opencorporates: %d officer record(s)", len(out)))
	return out, nil
}

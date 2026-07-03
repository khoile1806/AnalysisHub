package osint

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/analysishub/backend/internal/models"
)

// hashAlgo returns the CIRCL hashlookup path segment for a hex digest based on
// its length (md5=32, sha1=40, sha256=64), or "" if unrecognised.
func hashAlgo(h string) string {
	switch len(strings.TrimSpace(h)) {
	case 32:
		return "md5"
	case 40:
		return "sha1"
	case 64:
		return "sha256"
	}
	return ""
}

// collectHashLookup queries CIRCL's hashlookup — a free, key-less reputation
// service backed by NSRL and other known-file datasets. A hit means the file is
// already catalogued: usually a benign, known-good OS/application file (which
// helps an analyst rule a hash out), but the service also flags entries marked
// known-malicious. This complements VirusTotal/MalwareBazaar: it answers "is
// this a known file at all?" without burning a VT quota.
func collectHashLookup(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	h := strings.ToLower(strings.TrimSpace(env.target))
	algo := hashAlgo(h)
	if algo == "" {
		return nil, nil // not a recognised digest length; other collectors handle it
	}

	u := "https://hashlookup.circl.lu/lookup/" + algo + "/" + url.PathEscape(h)
	var r map[string]interface{}
	status, err := cachedGetJSON(ctx, env.cache, "hashlookup:"+algo+":"+h, nil, u,
		map[string]string{"Accept": "application/json"}, &r, ttlHashLookup)
	if err != nil {
		return nil, err
	}
	if status == 404 {
		f := newFinding("hashlookup", "reputation", "CIRCL hashlookup: unknown file",
			"hash not present in NSRL / known-file datasets")
		return []models.OsintFinding{withSource(f, u)}, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("CIRCL hashlookup returned HTTP %d", status)
	}
	// A "message" field (e.g. "Non existing SHA256") means not found.
	if msg, ok := r["message"].(string); ok && msg != "" {
		f := newFinding("hashlookup", "reputation", "CIRCL hashlookup: unknown file",
			"hash not present in NSRL / known-file datasets")
		return []models.OsintFinding{withSource(f, u)}, nil
	}

	var out []models.OsintFinding
	label := str(r["FileName"])
	if pc, ok := r["ProductCode"].(map[string]interface{}); ok {
		if pn := str(pc["ProductName"]); pn != "" {
			label = joinNonEmpty(" - ", label, pn)
		}
	}
	if label == "" {
		label = "known file present in CIRCL hashlookup datasets"
	}
	known := newFinding("hashlookup", "reputation", "CIRCL hashlookup: known file", label)

	// known-malicious flag (present on flagged entries) overrides the benign read.
	if mal := str(r["KnownMalicious"]); mal != "" {
		known.Title = "CIRCL hashlookup: KNOWN MALICIOUS file"
		known.Value = joinNonEmpty(" - ", label, "flagged: "+mal)
		known.Severity = "high"
		env.emit("[+] hashlookup: hash flagged KNOWN MALICIOUS - " + mal)
	} else {
		// A known good file lowers suspicion - record it as informational context.
		known.Severity = "info"
		if trust := str(r["hashlookup:trust"]); trust != "" {
			known.Value = joinNonEmpty(" - ", label, "trust "+trust+"/100")
		}
		env.emit("[*] hashlookup: hash matches a known (likely benign) file")
	}
	out = append(out, withSource(known, u))
	return out, nil
}

// str coerces an interface{} JSON value to a trimmed string ("" when absent or
// not a string/number).
func str(v interface{}) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		return strings.TrimSpace(fmt.Sprintf("%v", t))
	default:
		return ""
	}
}

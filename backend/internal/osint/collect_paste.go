package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/forensichub/backend/internal/models"
)

// collect_paste.go — paste-site monitoring. Leaked data (combolists, config
// dumps, defacement notes) is routinely posted to paste sites. This collector
// queries psbdmp.ws — a free, key-less index of historical Pastebin dumps — for
// the target and reports each dump it appears in, linking to the archived paste
// so an analyst can assess the exposure. It surfaces only paste metadata + a
// link, never bulk-downloads the dump contents.

var rlPsbdmp = newRateLimiter(2 * time.Second)

// psbdmpSearch is the psbdmp.ws v3 search response shape.
type psbdmpSearch struct {
	Count int `json:"count"`
	Data  []struct {
		ID   string `json:"id"`
		Tags string `json:"tags"`
		Date string `json:"date"`
	} `json:"data"`
}

const pasteCap = 40

// collectPaste searches paste-site archives for the target (domain, e-mail, or
// username) and reports the dumps it was found in.
func collectPaste(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	switch env.ttype {
	case TargetDomain, TargetEmail, TargetUsername:
	default:
		return nil, nil
	}
	q := strings.TrimSpace(env.target)
	if q == "" {
		return nil, nil
	}

	api := "https://psbdmp.ws/api/v3/search/" + url.PathEscape(q)
	var r psbdmpSearch
	status, err := cachedGetJSON(ctx, env.cache, "psbdmp:"+strings.ToLower(q), rlPsbdmp, api, nil, &r, ttlReputation)
	if err != nil {
		return nil, err
	}
	if status == 429 {
		env.emit("[*] paste: psbdmp.ws rate-limited — skipping")
		return nil, nil
	}
	if status == 404 || r.Count == 0 || len(r.Data) == 0 {
		env.emit("[*] paste: no paste-site dumps reference this target")
		return []models.OsintFinding{
			newFinding("paste", "exposure", "Paste-site exposure", "no dumps found referencing this target"),
		}, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("psbdmp.ws returned HTTP %d", status)
	}

	out := make([]models.OsintFinding, 0, len(r.Data)+1)
	summary := newFinding("paste", "exposure", "Paste-site exposure",
		fmt.Sprintf("target appears in %d archived paste dump(s)", r.Count))
	summary.Severity = "high"
	summary.SourceURL = "https://psbdmp.ws/search/" + url.PathEscape(q)
	out = append(out, summary)

	for i, d := range r.Data {
		if i >= pasteCap {
			break
		}
		id := strings.TrimSpace(d.ID)
		if id == "" {
			continue
		}
		detail := "archived paste dump"
		if d.Date != "" {
			detail = "dump dated " + d.Date
		}
		if tags := strings.TrimSpace(d.Tags); tags != "" {
			detail += " (tags: " + tags + ")"
		}
		f := newFinding("paste", "exposure", "Paste dump "+id, detail)
		f.Severity = "high"
		f.SourceURL = "https://psbdmp.ws/api/v3/dump/" + url.PathEscape(id)
		if b, err := json.Marshal(map[string]string{"id": id, "date": d.Date, "tags": d.Tags}); err == nil {
			f.Data = string(b)
		}
		out = append(out, f)
	}
	env.emit(fmt.Sprintf("[+] paste: target found in %d paste dump(s)", r.Count))
	return out, nil
}

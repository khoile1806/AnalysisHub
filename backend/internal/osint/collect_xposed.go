package osint

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/analysishub/backend/internal/models"
)

// rlXposed paces XposedOrNot — a free, key-less breach-search API. Be polite.
var rlXposed = newRateLimiter(1500 * time.Millisecond)

// xposedResponse is the XposedOrNot check-email shape. A hit returns the breach
// names nested one level deep (`breaches: [[name, name, ...]]`); a clean address
// returns `{"Error":"Not found"}`.
type xposedResponse struct {
	Breaches [][]string `json:"breaches"`
	Error    string     `json:"Error"`
}

// collectXposedOrNot checks an e-mail against XposedOrNot's breach database. It
// is the key-less, independent corroborator for HIBP: when both name the same
// account, a leaked-credential finding can be upgraded to "verified" without any
// paid API. Each breach is emitted as a named finding (same shape as HIBP) so
// the corroboration pass can fold it in.
func collectXposedOrNot(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	if env.ttype != TargetEmail {
		return nil, nil
	}
	email := strings.ToLower(strings.TrimSpace(env.target))
	if email == "" {
		return nil, nil
	}

	u := "https://api.xposedornot.com/v1/check-email/" + url.PathEscape(email)
	var r xposedResponse
	status, err := cachedGetJSON(ctx, env.cache, "xposed:email:"+email, rlXposed, u, nil, &r, ttlXposed)
	if err != nil {
		return nil, err
	}
	if status == 404 {
		// XposedOrNot answers 404 for an unbreached address.
		f := newFinding("xposed", "breach", "Breach exposure (XposedOrNot)",
			"address not found in any known breach")
		return []models.OsintFinding{f}, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("XposedOrNot returned HTTP %d", status)
	}

	var names []string
	if len(r.Breaches) > 0 {
		names = r.Breaches[0]
	}
	if r.Error != "" || len(names) == 0 {
		f := newFinding("xposed", "breach", "Breach exposure (XposedOrNot)",
			"address not found in any known breach")
		return []models.OsintFinding{f}, nil
	}

	out := make([]models.OsintFinding, 0, len(names)+1)
	xposedSource := "https://xposedornot.com/email/" + url.PathEscape(email)
	summary := newFinding("xposed", "breach", "Breach exposure (XposedOrNot)",
		fmt.Sprintf("address appears in %d known breach(es)", len(names)))
	summary.Severity = "high"
	summary.SourceURL = xposedSource
	out = append(out, summary)

	const xposedCap = 60
	for i, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if i >= xposedCap {
			break
		}
		f := newFinding("xposed", "breach", "Breach: "+name,
			"listed by XposedOrNot breach database")
		f.Severity = "high"
		f.SourceURL = xposedSource
		out = append(out, f)
	}
	env.emit(fmt.Sprintf("[+] xposed: address appears in %d breach(es)", len(names)))
	return out, nil
}

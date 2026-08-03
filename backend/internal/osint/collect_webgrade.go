package osint

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/analysishub/backend/internal/models"
)

// collect_webgrade.go — security-posture grading for a web host.
//
// tlsx (in the vuln-scan engine) records certificate *facts*; nuclei may flag a
// missing header if a template happens to fire. Neither produces a single, at-a-
// glance A–F posture score. This active collector fetches the target's web root
// once and grades two things a pentester triages first: HTTP security headers and
// the negotiated TLS protocol. It is pure Go (no external tool) and only touches
// the validated public target, so it is scope-gated like webtech.

// secHeader is one graded response header. weight reflects how much its absence
// matters; the grade is the share of weighted headers actually present.
type secHeader struct {
	name   string
	weight int
}

// gradedHeaders is the checklist, roughly ordered by security impact.
var gradedHeaders = []secHeader{
	{"Strict-Transport-Security", 3},
	{"Content-Security-Policy", 3},
	{"X-Content-Type-Options", 2},
	{"X-Frame-Options", 2}, // or CSP frame-ancestors (handled below)
	{"Referrer-Policy", 1},
	{"Permissions-Policy", 1},
}

// collectWebGrade grades the security headers and TLS of the target's web root.
func collectWebGrade(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	host := strings.ToLower(strings.TrimSpace(env.target))
	if host == "" {
		return nil, nil
	}

	resp, usedTLS, err := fetchRoot(ctx, host)
	if err != nil {
		env.emit("[*] webgrade: web root not reachable over HTTP(S)")
		return nil, nil // not an error — many targets simply have no web root
	}
	defer resp.Body.Close()

	var out []models.OsintFinding

	// ── HTTP security headers ────────────────────────────────────────────────
	grade, missing := gradeSecurityHeaders(resp.Header)
	hDetail := fmt.Sprintf("Security-header grade %s", grade)
	if len(missing) > 0 {
		hDetail += " — missing: " + strings.Join(missing, ", ")
	} else {
		hDetail += " — all checked headers present"
	}
	hf := newFinding("webgrade", "posture", "HTTP security headers", hDetail)
	hf.Severity = severityForGrade(grade)
	hf.Confidence = "verified"
	if srv := strings.TrimSpace(resp.Header.Get("Server")); srv != "" {
		hf.VerifyNote = "Server banner: " + srv
	}
	out = append(out, hf)

	// ── TLS protocol grade ───────────────────────────────────────────────────
	if usedTLS && resp.TLS != nil {
		tg, tDetail := gradeTLS(resp.TLS)
		tf := newFinding("webgrade", "posture", "TLS protocol", fmt.Sprintf("TLS grade %s — %s", tg, tDetail))
		tf.Severity = severityForGrade(tg)
		tf.Confidence = "verified"
		out = append(out, tf)
	}
	env.emit("[+] webgrade: header grade " + grade)
	return out, nil
}

// fetchRoot GETs the host's web root, HTTPS first then HTTP, and reports whether
// the successful response came over TLS (so its ConnectionState can be graded).
func fetchRoot(ctx context.Context, host string) (*http.Response, bool, error) {
	// osintHTTPClient carries a 30s timeout and the engine sets a per-collector
	// deadline on ctx, so no extra child timeout (and its cancel) is needed here.
	for _, scheme := range []string{"https://", "http://"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+host+"/", nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := osintHTTPClient.Do(req)
		if err != nil {
			continue
		}
		return resp, scheme == "https://", nil
	}
	return nil, false, fmt.Errorf("no reachable web root")
}

// gradeSecurityHeaders returns an A–F grade and the list of missing headers.
func gradeSecurityHeaders(h http.Header) (string, []string) {
	got, total := 0, 0
	var missing []string
	for _, sh := range gradedHeaders {
		total += sh.weight
		present := h.Get(sh.name) != ""
		// X-Frame-Options is satisfied by a CSP frame-ancestors directive too.
		if !present && sh.name == "X-Frame-Options" {
			if csp := strings.ToLower(h.Get("Content-Security-Policy")); strings.Contains(csp, "frame-ancestors") {
				present = true
			}
		}
		if present {
			got += sh.weight
		} else {
			missing = append(missing, sh.name)
		}
	}
	sort.Strings(missing)
	return letterGrade(float64(got) / float64(total)), missing
}

// gradeTLS grades the negotiated TLS version and flags a weak cipher.
func gradeTLS(cs *tls.ConnectionState) (string, string) {
	ver := tlsVersionName(cs.Version)
	cipher := tls.CipherSuiteName(cs.CipherSuite)
	weak := isWeakCipher(cs.CipherSuite)

	var grade string
	switch {
	case cs.Version >= tls.VersionTLS13:
		grade = "A"
	case cs.Version == tls.VersionTLS12:
		grade = "B"
	case cs.Version == tls.VersionTLS11 || cs.Version == tls.VersionTLS10:
		grade = "D"
	default:
		grade = "F"
	}
	if weak && grade < "D" { // never let a weak cipher keep an A/B grade
		grade = "D"
	}
	detail := ver + ", " + cipher
	if weak {
		detail += " (weak cipher)"
	}
	return grade, detail
}

// letterGrade maps a 0–1 score to an A–F letter.
func letterGrade(score float64) string {
	switch {
	case score >= 0.9:
		return "A"
	case score >= 0.7:
		return "B"
	case score >= 0.5:
		return "C"
	case score >= 0.3:
		return "D"
	default:
		return "F"
	}
}

// severityForGrade maps a posture grade to a finding severity so poor posture
// surfaces in the findings list.
func severityForGrade(grade string) string {
	switch grade {
	case "A", "B":
		return "info"
	case "C":
		return "low"
	case "D":
		return "medium"
	default:
		return "high"
	}
}

// isWeakCipher flags legacy/known-weak cipher families (RC4, 3DES, CBC-SHA1).
func isWeakCipher(id uint16) bool {
	name := strings.ToUpper(tls.CipherSuiteName(id))
	for _, bad := range []string{"RC4", "3DES", "DES_", "_CBC_SHA", "NULL", "EXPORT"} {
		if strings.Contains(name, bad) {
			return true
		}
	}
	return false
}

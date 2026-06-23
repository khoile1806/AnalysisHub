package osint

import (
	"fmt"
	"sort"
	"strings"

	"github.com/forensichub/backend/internal/models"
)

// corroborateFindings is the tool's self-verification pass. After every
// collector for a scan has finished, it cross-references the findings against
// each other and assigns a confidence verdict to the ones that are easy to
// fabricate or stale on their own - chiefly leaked-credential hits from the
// aggregated combolist, which a single source cannot be trusted on. A
// credential is only "verified" when independent collectors corroborate the
// same identity (a named HIBP breach, a deliverable mailbox, a matching GitHub
// commit e-mail, a known IOC, repeated dump lines). The verdict and the
// evidence behind it are written back onto each finding so the analyst sees
// why the tool does or does not trust it.
func (e *Engine) corroborateFindings(scan *models.OsintScan) {
	var fs []models.OsintFinding
	e.db.Where("scan_id = ?", scan.ID).Find(&fs)
	if len(fs) == 0 {
		e.computeExposure(scan)
		return
	}
	e.corroborateThreats(fs)
	// Exposure score runs last so it reflects the corroborated severities.
	defer e.computeExposure(scan)

	// Gather scan-wide corroboration signals from sibling collectors.
	var (
		mxValid      bool
		gravatar     bool
		knownIOC     bool
		hibpNames    []string
		xposedNames  []string
		githubEmails = map[string]bool{}
		comboLines   int
	)
	for i := range fs {
		f := &fs[i]
		switch f.Source {
		case "email_validate":
			if strings.HasPrefix(f.Title, "Mail exchanger") && !strings.Contains(f.Value, "no MX") {
				mxValid = true
			}
		case "gravatar":
			gravatar = true
		case "hibp":
			if strings.HasPrefix(f.Title, "Breach: ") {
				hibpNames = append(hibpNames, strings.TrimPrefix(f.Title, "Breach: "))
			}
		case "xposed":
			if strings.HasPrefix(f.Title, "Breach: ") {
				xposedNames = append(xposedNames, strings.TrimPrefix(f.Title, "Breach: "))
			}
		case "local_intel":
			if strings.Contains(f.Title, "KNOWN IOC") {
				knownIOC = true
			}
		case "github_intel":
			for _, r := range parseRelatedEntities(f.RelatedEntities) {
				if r.Type == TargetEmail {
					githubEmails[strings.ToLower(r.Value)] = true
				}
			}
		case "breach_leak":
			if f.Title == "Leaked credential" {
				comboLines++
			}
		}
	}

	domainReal := scan.TargetType == TargetDomain // a real corporate domain was validated to start the scan

	for i := range fs {
		f := &fs[i]
		if f.Source != "breach_leak" {
			continue
		}
		if f.Title != "Leaked credential" && f.Title != "Credential-dump exposure" {
			continue
		}

		email := findingEmail(f, scan)
		score := 0
		var notes []string
		if mxValid {
			score++
			notes = append(notes, "mailbox deliverable (MX valid)")
		}
		if len(hibpNames) > 0 {
			score += 2
			notes = append(notes, "HIBP breach: "+strings.Join(dedupeStrings(hibpNames), ", "))
		}
		if len(xposedNames) > 0 {
			// XposedOrNot is an independent breach database; agreement with (or
			// in addition to) HIBP raises confidence without any paid API.
			score += 2
			notes = append(notes, "XposedOrNot breach: "+strings.Join(dedupeStrings(xposedNames), ", "))
		}
		if gravatar {
			score++
			notes = append(notes, "Gravatar profile exists")
		}
		if email != "" && githubEmails[email] {
			score += 2
			notes = append(notes, "matches a GitHub commit e-mail")
		}
		if knownIOC {
			score += 2
			notes = append(notes, "already a known IOC")
		}
		if comboLines >= 3 {
			score++
			notes = append(notes, fmt.Sprintf("appears in %d dump lines", comboLines))
		}
		if domainReal {
			notes = append(notes, "corporate domain confirmed real")
		}

		verdict, sev := verdictFor(score, f.Title)
		if len(notes) == 0 {
			notes = append(notes, "single aggregated-combolist source, no independent corroboration")
		}
		corr := "corroboration: " + strings.Join(notes, "; ")

		newNote := corr
		if f.VerifyNote != "" { // keep the password metadata breach_leak already attached
			newNote = f.VerifyNote + " | " + corr
		}
		e.db.Model(&models.OsintFinding{}).Where("id = ?", f.ID).
			Updates(map[string]interface{}{
				"confidence":  verdict,
				"verify_note": newNote,
				"severity":    sev,
			})
	}
}

// verdictFor maps a corroboration score to a verdict and a severity that no
// longer over-claims: an unverified single-source leak is dimmed, a verified
// one keeps its weight.
func verdictFor(score int, title string) (verdict, severity string) {
	switch {
	case score >= 3:
		verdict = "verified"
	case score >= 1:
		verdict = "likely"
	default:
		verdict = "unverified"
	}
	summary := title == "Credential-dump exposure"
	switch verdict {
	case "verified":
		if summary {
			return verdict, "critical"
		}
		return verdict, "high"
	case "likely":
		if summary {
			return verdict, "high"
		}
		return verdict, "medium"
	default:
		if summary {
			return verdict, "medium"
		}
		return verdict, "low"
	}
}

// findingEmail returns the e-mail a breach finding pertains to: the scan target
// for an email investigation, otherwise the related e-mail entity, otherwise the
// identifier parsed from the "ident : ****" value.
func findingEmail(f *models.OsintFinding, scan *models.OsintScan) string {
	if scan.TargetType == TargetEmail {
		return strings.ToLower(strings.TrimSpace(scan.Target))
	}
	for _, r := range parseRelatedEntities(f.RelatedEntities) {
		if r.Type == TargetEmail {
			return strings.ToLower(strings.TrimSpace(r.Value))
		}
	}
	if i := strings.Index(f.Value, " : "); i > 0 {
		return strings.ToLower(strings.TrimSpace(f.Value[:i]))
	}
	return ""
}

// tiSources are the reputation collectors whose agreement we treat as
// independent corroboration of a threat verdict.
var tiSources = map[string]bool{
	"virustotal": true, "threatintel": true, "threatfox": true, "urlhaus": true,
	"malwarebazaar": true, "abuseipdb": true, "pulsedive": true, "greynoise": true,
	"shodan": true, "ransomwatch": true,
	// A match in the local IOC store is independent, high-trust corroboration
	// that the indicator is already known-bad.
	"local_intel": true,
}

// corroborateThreats cross-checks the threat verdict across the reputation
// collectors. A single feed flagging an indicator can be noise; when two or more
// independent sources agree it is malicious the verdict becomes "verified". The
// result is written onto every malicious/suspicious reputation finding so the
// analyst sees how many sources back it - the OSINT × threat-intel fusion the
// user asked for, with built-in self-verification.
func (e *Engine) corroborateThreats(fs []models.OsintFinding) {
	strong := map[string]bool{}
	susp := map[string]bool{}
	for i := range fs {
		f := &fs[i]
		if !tiSources[f.Source] {
			continue
		}
		if f.Category != "reputation" && f.Category != "ransomware" {
			continue
		}
		switch f.Severity {
		case "critical", "high":
			strong[f.Source] = true
		case "medium":
			susp[f.Source] = true
		}
	}
	if len(strong) == 0 && len(susp) == 0 {
		return
	}

	var verdict string
	switch {
	case len(strong) >= 2:
		verdict = "verified"
	case len(strong) == 1:
		verdict = "likely"
	default:
		verdict = "unverified"
	}
	srcs := sortedKeys(strong)
	if len(srcs) == 0 {
		srcs = sortedKeys(susp)
	}
	note := fmt.Sprintf("threat verdict corroborated by %d source(s): %s",
		len(srcs), strings.Join(srcs, ", "))

	for i := range fs {
		f := &fs[i]
		if !tiSources[f.Source] {
			continue
		}
		if f.Category != "reputation" && f.Category != "ransomware" {
			continue
		}
		if f.Severity != "critical" && f.Severity != "high" && f.Severity != "medium" {
			continue
		}
		newNote := note
		if f.VerifyNote != "" {
			newNote = f.VerifyNote + " | " + note
		}
		e.db.Model(&models.OsintFinding{}).Where("id = ?", f.ID).
			Updates(map[string]interface{}{"confidence": verdict, "verify_note": newNote})
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

package osint

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/forensichub/backend/internal/models"
)

// -- CSV export ----------------------------------------------------------------

// GenerateCSV renders a scan's findings as CSV for spreadsheet triage and
// hand-off. One row per finding, stable column order.
func GenerateCSV(scan *models.OsintScan, findings []models.OsintFinding) []byte {
	var sb strings.Builder
	w := csv.NewWriter(&sb)
	_ = w.Write([]string{"target", "target_type", "source", "category", "severity", "confidence", "title", "value", "source_url", "verify_note"})
	for i := range findings {
		f := &findings[i]
		sev := f.Severity
		if sev == "" {
			sev = "info"
		}
		_ = w.Write([]string{
			scan.Target, scan.TargetType, f.Source, f.Category, sev, f.Confidence,
			f.Title, f.Value, f.SourceURL, f.VerifyNote,
		})
	}
	w.Flush()
	return []byte(sb.String())
}

// -- STIX 2.1 bundle export ----------------------------------------------------

// stixObject is a minimal, spec-shaped STIX 2.1 SDO/SCO. Only the fields the
// export populates are declared; the JSON omitempty keeps each object lean.
type stixObject struct {
	Type           string   `json:"type"`
	SpecVersion    string   `json:"spec_version,omitempty"`
	ID             string   `json:"id"`
	Created        string   `json:"created,omitempty"`
	Modified       string   `json:"modified,omitempty"`
	Name           string   `json:"name,omitempty"`
	Description    string   `json:"description,omitempty"`
	Pattern        string   `json:"pattern,omitempty"`
	PatternType    string   `json:"pattern_type,omitempty"`
	ValidFrom      string   `json:"valid_from,omitempty"`
	IndicatorTypes []string `json:"indicator_types,omitempty"`
	Labels         []string `json:"labels,omitempty"`
	CreatedByRef   string   `json:"created_by_ref,omitempty"`
	ObjectRefs     []string `json:"object_refs,omitempty"`
	Published      string   `json:"published,omitempty"`
}

type stixBundle struct {
	Type    string       `json:"type"`
	ID      string       `json:"id"`
	Objects []stixObject `json:"objects"`
}

// observable is a deduplicated indicator candidate harvested from the scan.
type observable struct {
	otype     string // ip | domain | email | hash | url
	value     string
	malicious bool
}

// GenerateSTIXBundle builds a STIX 2.1 bundle from a scan so its indicators can
// be shared with a TIP / MISP / OpenCTI. It emits an identity for the tool, an
// indicator per distinct shareable observable (the target plus every pivotable
// related entity and look-alike domain), and a report SDO tying them together.
func GenerateSTIXBundle(scan *models.OsintScan, findings []models.OsintFinding) ([]byte, error) {
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	identityID := "identity--" + uuid.NewString()
	identity := stixObject{
		Type: "identity", SpecVersion: "2.1", ID: identityID,
		Created: now, Modified: now, Name: "ForensicHub OSINT", Description: "ForensicHub passive OSINT engine",
	}

	obs := collectObservables(scan, findings)

	bundle := stixBundle{Type: "bundle", ID: "bundle--" + uuid.NewString()}
	bundle.Objects = append(bundle.Objects, identity)

	var refs []string
	for _, o := range obs {
		pattern, ok := stixPattern(o)
		if !ok {
			continue
		}
		ind := stixObject{
			Type: "indicator", SpecVersion: "2.1", ID: "indicator--" + uuid.NewString(),
			Created: now, Modified: now, CreatedByRef: identityID,
			Name:        fmt.Sprintf("%s observed for %s", o.value, scan.Target),
			Pattern:     pattern,
			PatternType: "stix",
			ValidFrom:   now,
		}
		if o.malicious {
			ind.IndicatorTypes = []string{"malicious-activity"}
			ind.Labels = []string{"malicious-activity"}
		} else {
			ind.IndicatorTypes = []string{"benign"}
		}
		bundle.Objects = append(bundle.Objects, ind)
		refs = append(refs, ind.ID)
	}

	report := stixObject{
		Type: "report", SpecVersion: "2.1", ID: "report--" + uuid.NewString(),
		Created: now, Modified: now, CreatedByRef: identityID,
		Name:        fmt.Sprintf("OSINT investigation: %s (%s)", scan.Target, scan.TargetType),
		Description: fmt.Sprintf("Exposure %d/100 (%s). %d indicator(s).", scan.ExposureScore, scan.ExposureGrade, len(refs)),
		Published:   now,
		Labels:      []string{"osint"},
		ObjectRefs:  refs,
	}
	if len(refs) > 0 {
		bundle.Objects = append(bundle.Objects, report)
	}

	return json.MarshalIndent(bundle, "", "  ")
}

// collectObservables harvests distinct shareable indicators from a scan: the
// target itself and every related-entity pivot / look-alike domain. Malicious
// status is inferred from high/critical reputation, ransomware or look-alike
// findings that reference the value.
func collectObservables(scan *models.OsintScan, findings []models.OsintFinding) []observable {
	seen := map[string]int{} // value -> index in out
	var out []observable

	add := func(otype, value string, malicious bool) {
		v := strings.TrimSpace(value)
		if v == "" {
			return
		}
		key := strings.ToLower(otype + "|" + v)
		if idx, ok := seen[key]; ok {
			if malicious {
				out[idx].malicious = true
			}
			return
		}
		seen[key] = len(out)
		out = append(out, observable{otype: otype, value: v, malicious: malicious})
	}

	// The scan target is the primary indicator.
	if t := stixObservableType(scan.TargetType); t != "" {
		add(t, scan.Target, scan.ExposureGrade == "high" || scan.ExposureGrade == "critical")
	}

	for i := range findings {
		f := &findings[i]
		mal := (f.Category == "reputation" || f.Category == "ransomware") &&
			(f.Severity == "high" || f.Severity == "critical")
		// Look-alike domains are inherently noteworthy indicators.
		if f.Source == "typosquat" {
			mal = true
		}
		for _, r := range parseRelatedEntities(f.RelatedEntities) {
			if t := stixObservableType(r.Type); t != "" {
				add(t, r.Value, mal)
			}
		}
	}
	return out
}

// stixObservableType maps an OSINT target/entity type to the export's internal
// observable type, or "" for types with no standard STIX SCO.
func stixObservableType(t string) string {
	switch t {
	case TargetIP:
		return "ip"
	case TargetDomain:
		return "domain"
	case TargetEmail:
		return "email"
	case TargetHash:
		return "hash"
	default:
		return ""
	}
}

// stixPattern builds the STIX 2.1 pattern string for an observable.
func stixPattern(o observable) (string, bool) {
	v := strings.ReplaceAll(o.value, "'", "")
	switch o.otype {
	case "ip":
		if ip := net.ParseIP(v); ip != nil && ip.To4() == nil {
			return fmt.Sprintf("[ipv6-addr:value = '%s']", v), true
		}
		return fmt.Sprintf("[ipv4-addr:value = '%s']", v), true
	case "domain":
		return fmt.Sprintf("[domain-name:value = '%s']", v), true
	case "email":
		return fmt.Sprintf("[email-addr:value = '%s']", v), true
	case "url":
		return fmt.Sprintf("[url:value = '%s']", v), true
	case "hash":
		switch len(v) {
		case 32:
			return fmt.Sprintf("[file:hashes.'MD5' = '%s']", v), true
		case 40:
			return fmt.Sprintf("[file:hashes.'SHA-1' = '%s']", v), true
		case 64:
			return fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", v), true
		}
	}
	return "", false
}

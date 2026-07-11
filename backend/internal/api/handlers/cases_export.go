package handlers

import (
	"encoding/csv"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/models"
)

// CaseExport emits a machine-readable export of a case for ingestion by other
// tools (SIEM, TIP, spreadsheet). Unlike CaseReport (human HTML/PDF) this returns
// structured data and is NOT capped, so downstream automation gets everything.
//
// GET /api/v1/cases/:id/export?format=json|csv|stix   (default json)
func (h *CasesHandler) CaseExport(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case id"})
		return
	}
	var caseObj models.Case
	if err := h.DB.First(&caseObj, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "case not found"})
		return
	}

	ex := buildCaseExport(h.DB, caseObj)
	slug := safeFileSlug(caseObj.Name)

	switch strings.ToLower(strings.TrimSpace(c.Query("format"))) {
	case "csv":
		c.Header("Content-Disposition", "attachment; filename=\"case-"+slug+"-timeline.csv\"")
		c.Header("Content-Type", "text/csv; charset=utf-8")
		writeCaseCSV(c, ex)
	case "stix":
		c.Header("Content-Disposition", "attachment; filename=\"case-"+slug+"-stix.json\"")
		c.Header("Content-Type", "application/json; charset=utf-8")
		c.JSON(http.StatusOK, buildSTIXBundle(ex))
	default: // json
		c.Header("Content-Disposition", "attachment; filename=\"case-"+slug+".json\"")
		c.JSON(http.StatusOK, gin.H{"success": true, "data": ex})
	}
}

// caseExport is the full, uncapped machine-readable view of a case.
type caseExport struct {
	Case      models.Case            `json:"case"`
	Timeline  []models.TimelineEvent `json:"timeline"`
	Vulns     []caseExportVuln       `json:"vulnerabilities"`
	Evidence  []models.CaseEvidence  `json:"evidence"`
	Agents    []models.Agent         `json:"agents"`
	Osint     []models.OsintScan     `json:"osint_scans"`
	Generated string                 `json:"generated_at"`
}

// caseExportVuln is a trimmed vulnerability finding for export.
type caseExportVuln struct {
	Severity  string  `json:"severity"`
	Name      string  `json:"name"`
	Host      string  `json:"host"`
	CVE       string  `json:"cve,omitempty"`
	EPSS      float64 `json:"epss,omitempty"`
	KEV       bool    `json:"kev"`
	Confirmed bool    `json:"confirmed"`
	MatchedAt string  `json:"matched_at,omitempty"`
}

func buildCaseExport(db *gorm.DB, caseObj models.Case) caseExport {
	ex := caseExport{Case: caseObj, Generated: time.Now().UTC().Format(time.RFC3339)}

	db.Where("case_id = ?", caseObj.ID).Order("event_time asc").Find(&ex.Timeline)
	db.Where("case_id = ?", caseObj.ID).Order("created_at desc").Find(&ex.Evidence)
	db.Where("case_id = ?", caseObj.ID).Find(&ex.Agents)
	db.Where("case_id = ? AND parent_scan_id IS NULL", caseObj.ID).
		Order("created_at desc").Find(&ex.Osint)

	// Vulnerability findings across the case's scans (uncapped).
	var scanIDs []uuid.UUID
	db.Model(&models.VulnScan{}).Where("case_id = ?", caseObj.ID).Pluck("id", &scanIDs)
	if len(scanIDs) > 0 {
		var findings []models.VulnFinding
		db.Where("scan_id IN ? AND tool = ?", scanIDs, "nuclei").
			Order("CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, is_kev DESC, epss_score DESC").
			Find(&findings)
		ex.Vulns = make([]caseExportVuln, 0, len(findings))
		for i := range findings {
			f := &findings[i]
			ex.Vulns = append(ex.Vulns, caseExportVuln{
				Severity:  strings.ToLower(strings.TrimSpace(f.Severity)),
				Name:      f.Name,
				Host:      f.Host,
				CVE:       f.CVEID,
				EPSS:      f.EPSSScore,
				KEV:       f.IsKEV,
				Confirmed: f.Confirmed,
				MatchedAt: f.MatchedAt,
			})
		}
	}
	return ex
}

// writeCaseCSV streams the timeline as CSV — the incident narrative is the most
// naturally tabular part of a case.
func writeCaseCSV(c *gin.Context, ex caseExport) {
	w := csv.NewWriter(c.Writer)
	defer w.Flush()
	_ = w.Write([]string{"event_time", "severity", "tactic", "technique", "source", "host", "title", "detail"})
	for i := range ex.Timeline {
		e := &ex.Timeline[i]
		_ = w.Write([]string{
			e.EventTime.UTC().Format(time.RFC3339),
			e.Severity, e.Tactic, e.Technique, e.Source, e.Host, e.Title,
			strings.ReplaceAll(e.Detail, "\n", " "),
		})
	}
}

// ── STIX 2.1 ────────────────────────────────────────────────────────────────

// stixNS namespaces deterministic STIX IDs so re-exporting a case yields stable
// object IDs (a TIP can then dedupe instead of accumulating duplicates).
var stixNS = uuid.MustParse("6ba7b811-9dad-11d1-80b4-00c04fd430c8")

func stixID(kind, seed string) string {
	return kind + "--" + uuid.NewSHA1(stixNS, []byte(kind+"|"+seed)).String()
}

// buildSTIXBundle assembles a STIX 2.1 bundle: a report SDO tying together
// vulnerability SDOs (distinct CVEs) and host observables (ipv4-addr / domain-name).
func buildSTIXBundle(ex caseExport) map[string]interface{} {
	nowISO := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	var objects []map[string]interface{}
	var refs []string

	// Distinct CVEs → vulnerability SDOs.
	seenCVE := map[string]bool{}
	for _, v := range ex.Vulns {
		cve := strings.ToUpper(strings.TrimSpace(v.CVE))
		if cve == "" || seenCVE[cve] {
			continue
		}
		seenCVE[cve] = true
		id := stixID("vulnerability", cve)
		obj := map[string]interface{}{
			"type": "vulnerability", "spec_version": "2.1", "id": id,
			"created": nowISO, "modified": nowISO, "name": cve,
			"external_references": []map[string]interface{}{
				{"source_name": "cve", "external_id": cve},
			},
		}
		if v.KEV {
			obj["labels"] = []string{"known-exploited"}
		}
		objects = append(objects, obj)
		refs = append(refs, id)
	}

	// Distinct hosts → ipv4-addr / domain-name SCOs.
	seenHost := map[string]bool{}
	addHost := func(raw string) {
		h := cleanExportHost(raw)
		if h == "" || seenHost[h] {
			return
		}
		seenHost[h] = true
		var obj map[string]interface{}
		if ip := net.ParseIP(h); ip != nil {
			kind := "ipv4-addr"
			if ip.To4() == nil {
				kind = "ipv6-addr"
			}
			obj = map[string]interface{}{"type": kind, "spec_version": "2.1", "id": stixID(kind, h), "value": h}
		} else {
			obj = map[string]interface{}{"type": "domain-name", "spec_version": "2.1", "id": stixID("domain-name", h), "value": h}
		}
		objects = append(objects, obj)
		refs = append(refs, obj["id"].(string))
	}
	for _, v := range ex.Vulns {
		addHost(v.Host)
	}
	for i := range ex.Timeline {
		addHost(ex.Timeline[i].Host)
	}

	// Report SDO tying it together (must have >=1 object_ref to be valid; if the
	// case has no CVEs/hosts we still emit a self-referential note-free report).
	reportID := stixID("report", ex.Case.ID.String())
	report := map[string]interface{}{
		"type": "report", "spec_version": "2.1", "id": reportID,
		"created": nowISO, "modified": nowISO,
		"name":         ex.Case.Name,
		"description":  ex.Case.Summary,
		"report_types": []string{"incident"},
		"published":    nowISO,
	}
	if len(refs) > 0 {
		report["object_refs"] = refs
	} else {
		report["object_refs"] = []string{reportID} // self-ref keeps the report valid
	}
	// Report leads the bundle.
	objects = append([]map[string]interface{}{report}, objects...)

	// Stable order for reproducible bundles.
	sort.SliceStable(objects[1:], func(i, j int) bool {
		return objects[i+1]["id"].(string) < objects[j+1]["id"].(string)
	})

	return map[string]interface{}{
		"type":    "bundle",
		"id":      "bundle--" + uuid.NewSHA1(stixNS, []byte("bundle|"+ex.Case.ID.String())).String(),
		"objects": objects,
	}
}

// cleanExportHost strips scheme/port/path from a host string for STIX observables.
func cleanExportHost(raw string) string {
	h := strings.TrimSpace(raw)
	if h == "" {
		return ""
	}
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	// Drop obviously non-host tokens.
	if h == "" || strings.ContainsAny(h, " \t") {
		return ""
	}
	// A bare numeric string isn't a host.
	if _, err := strconv.Atoi(h); err == nil {
		return ""
	}
	return strings.ToLower(h)
}

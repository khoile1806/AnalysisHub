package handlers

import (
	"encoding/json"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/models"
)

// osint_attacksurface.go — the per-host attack-surface roll-up for an OSINT
// investigation. It folds everything the recon + vuln pipelines already produced
// (open services, security posture, subdomain-takeover exposure, and the vuln-
// scan findings linked to the investigation) into one host-keyed table scored by
// risk — the view a pentester opens first to pick the juiciest target.

// SurfaceHost is one row of the attack surface: a host and its aggregated risk.
type SurfaceHost struct {
	Host         string   `json:"host"`
	Kind         string   `json:"kind"` // domain | ip
	Services     []string `json:"services,omitempty"`
	PostureGrade string   `json:"posture_grade,omitempty"`
	Takeover     bool     `json:"takeover"`
	VulnCount    int      `json:"vuln_count"`
	MaxSeverity  string   `json:"max_severity,omitempty"`
	KEVCount     int      `json:"kev_count"`
	PocCount     int      `json:"poc_count"`
	CVEs         []string `json:"cves,omitempty"`
	RiskScore    int      `json:"risk_score"`
	RiskLabel    string   `json:"risk_label"`
}

// AttackSurface is the response: the scored host rows plus roll-up totals.
type AttackSurface struct {
	Hosts       []SurfaceHost `json:"hosts"`
	TotalHosts  int           `json:"total_hosts"`
	TotalVulns  int           `json:"total_vulns"`
	TotalKEV    int           `json:"total_kev"`
	TotalPoC    int           `json:"total_poc"`
	Takeovers   int           `json:"takeovers"`
}

var gradeInValue = regexp.MustCompile(`(?i)grade ([A-F])`)

// GetOsintAttackSurface aggregates the investigation's whole pivot tree into a
// risk-scored, per-host attack-surface table.
//
// GET /api/v1/osint/:id/attack-surface
func GetOsintAttackSurface(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"success": false, "error": "invalid scan id"})
		return
	}
	var scan models.OsintScan
	if err := db.First(&scan, "id = ?", id).Error; err != nil {
		c.JSON(404, gin.H{"success": false, "error": "scan not found"})
		return
	}
	c.JSON(200, gin.H{"success": true, "data": computeAttackSurface(db, &scan)})
}

// computeAttackSurface builds the risk-scored per-host attack-surface for a
// scan's whole investigation tree. Extracted so the scan-diff endpoint can reuse it.
func computeAttackSurface(db *gorm.DB, scan *models.OsintScan) AttackSurface {
	root := scan.ID
	if scan.RootScanID != nil {
		root = *scan.RootScanID
	}

	// All scans in the investigation tree + a scanID → target lookup.
	var scans []models.OsintScan
	db.Where("root_scan_id = ? OR id = ?", root, root).Find(&scans)
	scanIDs := make([]uuid.UUID, 0, len(scans))
	scanTarget := make(map[uuid.UUID]string, len(scans))
	for _, s := range scans {
		scanIDs = append(scanIDs, s.ID)
		scanTarget[s.ID] = strings.ToLower(strings.TrimSpace(s.Target))
	}

	buckets := map[string]*SurfaceHost{}
	host := func(h string) *SurfaceHost {
		h = normHostKey(h)
		if h == "" {
			return nil
		}
		b := buckets[h]
		if b == nil {
			b = &SurfaceHost{Host: h, Kind: hostKind(h)}
			buckets[h] = b
		}
		return b
	}

	// ── OSINT findings: services, posture, takeover ───────────────────────────
	// This handler is polled every few seconds by the UI, so bound the query: only
	// the three categories used here, only the columns read, and a hard row cap —
	// a deep auto-pivot tree can otherwise pull very large result sets each poll.
	var findings []models.OsintFinding
	if len(scanIDs) > 0 {
		db.Select("scan_id", "category", "value", "related_entities").
			Where("scan_id IN ? AND category IN ?", scanIDs, []string{"ports", "posture", "takeover"}).
			Limit(8000).Find(&findings)
	}
	for i := range findings {
		f := &findings[i]
		switch f.Category {
		case "ports":
			if b := host(scanTarget[f.ScanID]); b != nil {
				if v := strings.TrimSpace(f.Value); v != "" && len(b.Services) < 12 {
					b.Services = appendUniq(b.Services, v)
				}
			}
		case "posture":
			if b := host(scanTarget[f.ScanID]); b != nil {
				if g := gradeInValue.FindStringSubmatch(f.Value); g != nil {
					b.PostureGrade = worseGrade(b.PostureGrade, strings.ToUpper(g[1]))
				}
			}
		case "takeover":
			for _, h := range relatedHosts(f.RelatedEntities) {
				if b := host(h); b != nil {
					b.Takeover = true
				}
			}
		}
	}

	// ── Vuln findings linked to this investigation ────────────────────────────
	var vulnScanIDs []uuid.UUID
	db.Model(&models.VulnScan{}).Where("source_scan_id IN ?", scanIDs).Pluck("id", &vulnScanIDs)
	var vulns []models.VulnFinding
	if len(vulnScanIDs) > 0 {
		db.Where("scan_id IN ?", vulnScanIDs).Limit(8000).Find(&vulns)
	}
	for i := range vulns {
		v := &vulns[i]
		b := host(cleanHostStr(v.Host))
		if b == nil {
			continue
		}
		if v.Severity == "info" && v.CVEID == "" {
			continue // a bare "live service" info row isn't a vuln
		}
		b.VulnCount++
		b.MaxSeverity = worseSeverity(b.MaxSeverity, v.Severity)
		if v.IsKEV {
			b.KEVCount++
		}
		if v.PocCount > 0 {
			b.PocCount += v.PocCount
		}
		if v.CVEID != "" {
			b.CVEs = appendUniq(b.CVEs, v.CVEID)
		}
	}

	// ── Score + assemble ──────────────────────────────────────────────────────
	// Initialise Hosts to a non-nil slice so the JSON is [] (not null) — the UI
	// checks .length and would crash on a null.
	out := AttackSurface{Hosts: []SurfaceHost{}}
	for _, b := range buckets {
		b.RiskScore, b.RiskLabel = surfaceRisk(b)
		if len(b.CVEs) > 20 {
			b.CVEs = b.CVEs[:20]
		}
		out.Hosts = append(out.Hosts, *b)
		out.TotalVulns += b.VulnCount
		out.TotalKEV += b.KEVCount
		out.TotalPoC += b.PocCount
		if b.Takeover {
			out.Takeovers++
		}
	}
	out.TotalHosts = len(out.Hosts)
	sort.Slice(out.Hosts, func(i, j int) bool {
		if out.Hosts[i].RiskScore != out.Hosts[j].RiskScore {
			return out.Hosts[i].RiskScore > out.Hosts[j].RiskScore
		}
		return out.Hosts[i].Host < out.Hosts[j].Host
	})

	return out
}

// SurfaceDiff is the change between two attack-surface snapshots of the same target.
type SurfaceDiff struct {
	NewHosts     []SurfaceHost `json:"new_hosts"`     // hosts present in B, absent in A
	RemovedHosts []string      `json:"removed_hosts"` // hosts present in A, absent in B
	Changed      []SurfaceHostChange `json:"changed"` // hosts in both with a material change
	Unchanged    int           `json:"unchanged"`
}

// SurfaceHostChange records what changed on a host between two scans.
type SurfaceHostChange struct {
	Host          string   `json:"host"`
	RiskBefore    int      `json:"risk_before"`
	RiskAfter     int      `json:"risk_after"`
	GradeBefore   string   `json:"grade_before,omitempty"`
	GradeAfter    string   `json:"grade_after,omitempty"`
	NewServices   []string `json:"new_services,omitempty"`
	NewCVEs       []string `json:"new_cves,omitempty"`
	TakeoverNew   bool     `json:"takeover_new,omitempty"`
}

// DiffOsintAttackSurface compares the attack surface of two scans of the same
// target ("what changed since last time") — new hosts, newly-opened services,
// grade regressions, new CVEs, new takeover exposure.
//
// GET /api/v1/osint/:id/attack-surface/diff/:other  (id = newer, other = baseline)
func DiffOsintAttackSurface(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	idNew, err1 := uuid.Parse(c.Param("id"))
	idOld, err2 := uuid.Parse(c.Param("other"))
	if err1 != nil || err2 != nil {
		c.JSON(400, gin.H{"success": false, "error": "invalid scan id"})
		return
	}
	var sNew, sOld models.OsintScan
	if db.First(&sNew, "id = ?", idNew).Error != nil || db.First(&sOld, "id = ?", idOld).Error != nil {
		c.JSON(404, gin.H{"success": false, "error": "scan not found"})
		return
	}
	aNew := computeAttackSurface(db, &sNew)
	aOld := computeAttackSurface(db, &sOld)

	oldByHost := map[string]SurfaceHost{}
	for _, h := range aOld.Hosts {
		oldByHost[h.Host] = h
	}
	newByHost := map[string]SurfaceHost{}
	for _, h := range aNew.Hosts {
		newByHost[h.Host] = h
	}

	diff := SurfaceDiff{NewHosts: []SurfaceHost{}, RemovedHosts: []string{}, Changed: []SurfaceHostChange{}}
	for _, h := range aNew.Hosts {
		prev, existed := oldByHost[h.Host]
		if !existed {
			diff.NewHosts = append(diff.NewHosts, h)
			continue
		}
		ch := SurfaceHostChange{Host: h.Host, RiskBefore: prev.RiskScore, RiskAfter: h.RiskScore,
			GradeBefore: prev.PostureGrade, GradeAfter: h.PostureGrade}
		ch.NewServices = setSub(h.Services, prev.Services)
		ch.NewCVEs = setSub(h.CVEs, prev.CVEs)
		ch.TakeoverNew = h.Takeover && !prev.Takeover
		material := len(ch.NewServices) > 0 || len(ch.NewCVEs) > 0 || ch.TakeoverNew ||
			h.RiskScore != prev.RiskScore || h.PostureGrade != prev.PostureGrade
		if material {
			diff.Changed = append(diff.Changed, ch)
		} else {
			diff.Unchanged++
		}
	}
	for _, h := range aOld.Hosts {
		if _, still := newByHost[h.Host]; !still {
			diff.RemovedHosts = append(diff.RemovedHosts, h.Host)
		}
	}
	c.JSON(200, gin.H{"success": true, "data": gin.H{
		"diff": diff,
		"a":    gin.H{"id": sOld.ID, "name": sOld.Name, "at": sOld.CreatedAt},
		"b":    gin.H{"id": sNew.ID, "name": sNew.Name, "at": sNew.CreatedAt},
	}})
}

// setSub returns items in a not in b.
func setSub(a, b []string) []string {
	inB := make(map[string]bool, len(b))
	for _, x := range b {
		inB[x] = true
	}
	var out []string
	for _, x := range a {
		if !inB[x] {
			out = append(out, x)
		}
	}
	return out
}

// surfaceRisk folds a host's aggregated signals into a 0–100 score + label.
func surfaceRisk(b *SurfaceHost) (int, string) {
	score := map[string]int{"critical": 60, "high": 40, "medium": 20, "low": 8, "info": 2}[b.MaxSeverity]
	if b.KEVCount > 0 {
		score += 25
	}
	if b.PocCount > 0 {
		score += 15
	}
	if b.Takeover {
		score += 30
	}
	switch b.PostureGrade {
	case "F":
		score += 20
	case "D":
		score += 10
	}
	if score > 100 {
		score = 100
	}
	switch {
	case score >= 70:
		return score, "critical"
	case score >= 45:
		return score, "high"
	case score >= 20:
		return score, "medium"
	default:
		return score, "low"
	}
}

// relatedHosts pulls domain/ip values out of a finding's RelatedEntities JSON.
func relatedHosts(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var rels []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	if json.Unmarshal([]byte(raw), &rels) != nil {
		return nil
	}
	var out []string
	for _, r := range rels {
		if r.Type == "domain" || r.Type == "ip" {
			out = append(out, r.Value)
		}
	}
	return out
}

func normHostKey(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return strings.TrimSuffix(h, ".")
}

func hostKind(h string) string {
	if net.ParseIP(h) != nil {
		return "ip"
	}
	return "domain"
}

// cleanHostStr mirrors the vuln engine's host cleanup for cross-referencing.
func cleanHostStr(h string) string { return normHostKey(h) }

func appendUniq(s []string, v string) []string {
	for _, e := range s {
		if e == v {
			return s
		}
	}
	return append(s, v)
}

var severityOrder = map[string]int{"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

func worseSeverity(a, b string) string {
	if severityOrder[b] > severityOrder[a] {
		return b
	}
	return a
}

// worseGrade returns the lower (worse) of two A–F grades.
func worseGrade(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if b > a { // 'F' > 'A' lexically → worse
		return b
	}
	return a
}

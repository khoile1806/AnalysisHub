package handlers

import (
	"bytes"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/models"
	"github.com/forensichub/backend/internal/report"
)

// CaseReport renders a single, self-contained incident report for a case,
// combining everything the system knows about it: metadata, an executive
// summary, the full reconstructed timeline, ATT&CK tactic coverage, evidence,
// endpoint agents and linked OSINT investigations. Print-CSS makes it export to
// PDF directly from the browser.
//
// GET /api/v1/cases/:id/report
func (h *CasesHandler) CaseReport(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.String(http.StatusBadRequest, "invalid case id")
		return
	}
	var caseObj models.Case
	if err := h.DB.First(&caseObj, "id = ?", id).Error; err != nil {
		c.String(http.StatusNotFound, "case not found")
		return
	}

	data := buildCaseReportData(h.DB, caseObj)
	html := report.Page(report.Meta{
		Title:       "Incident Report",
		Subtitle:    caseObj.Name,
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		Badges: []report.Badge{
			{Label: "Status", Value: strings.Title(caseObj.Status), Class: statusBadgeClass(caseObj.Status)},
			{Label: "Opened", Value: caseObj.CreatedAt.UTC().Format("2006-01-02")},
		},
	}, renderCaseReportBody(data))

	// Native PDF when an external renderer is configured (?format=pdf); otherwise
	// HTML (the browser's print-to-PDF still works on the print-CSS).
	if strings.EqualFold(c.Query("format"), "pdf") && report.PDFEnabled() {
		if pdf, perr := report.RenderPDF(c.Request.Context(), html); perr == nil {
			fname := "incident-" + safeFileSlug(caseObj.Name) + ".pdf"
			c.Header("Content-Disposition", "attachment; filename=\""+fname+"\"")
			c.Data(http.StatusOK, "application/pdf", pdf)
			return
		}
		// fall through to HTML on render failure
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, html)
}

// safeFileSlug reduces a case name to a filename-safe slug.
func safeFileSlug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "report"
	}
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

// --- data assembly ---

type caseReportTactic struct {
	Name  string
	Count int
}
type caseReportTLItem struct {
	Time     string
	Severity string
	Title    string
	Host     string
	Source   string
	Detail   string
}
type caseReportData struct {
	Case        models.Case
	Description string
	Summary     string
	// exec summary counts
	Events     int
	High       int
	Medium     int
	Low        int
	Agents     int
	Evidence   int
	OsintScans int
	Tactics    []caseReportTactic
	FirstEvent string
	LastEvent  string
	// sections
	Timeline     []caseReportTLItem
	TimelineMore int
	EvidenceList []models.CaseEvidence
	AgentList    []models.Agent
	OsintList    []models.OsintScan
}

// caseReportTimelineCap bounds how many timeline rows are rendered inline so a
// huge case doesn't produce a 50k-row HTML document.
const caseReportTimelineCap = 500

func buildCaseReportData(db *gorm.DB, caseObj models.Case) caseReportData {
	d := caseReportData{Case: caseObj, Description: caseObj.Description, Summary: caseObj.Summary}

	var events []models.TimelineEvent
	db.Where("case_id = ?", caseObj.ID).Order("event_time asc").Find(&events)
	d.Events = len(events)

	tacticCount := map[string]int{}
	var first, last time.Time
	for i := range events {
		e := &events[i]
		switch strings.ToLower(e.Severity) {
		case "critical", "high":
			d.High++
		case "medium":
			d.Medium++
		case "low":
			d.Low++
		}
		if t := strings.TrimSpace(e.Tactic); t != "" {
			tacticCount[t]++
		}
		if first.IsZero() || e.EventTime.Before(first) {
			first = e.EventTime
		}
		if last.IsZero() || e.EventTime.After(last) {
			last = e.EventTime
		}
		if len(d.Timeline) < caseReportTimelineCap {
			d.Timeline = append(d.Timeline, caseReportTLItem{
				Time:     e.EventTime.UTC().Format("2006-01-02 15:04:05"),
				Severity: strings.ToLower(strings.TrimSpace(e.Severity)),
				Title:    e.Title,
				Host:     e.Host,
				Source:   e.Source,
				Detail:   e.Detail,
			})
		}
	}
	if d.Events > caseReportTimelineCap {
		d.TimelineMore = d.Events - caseReportTimelineCap
	}
	for name, n := range tacticCount {
		d.Tactics = append(d.Tactics, caseReportTactic{Name: name, Count: n})
	}
	sort.Slice(d.Tactics, func(i, j int) bool { return d.Tactics[i].Count > d.Tactics[j].Count })
	if !first.IsZero() {
		d.FirstEvent = first.UTC().Format("2006-01-02 15:04 UTC")
		d.LastEvent = last.UTC().Format("2006-01-02 15:04 UTC")
	}

	db.Where("case_id = ?", caseObj.ID).Order("created_at desc").Find(&d.EvidenceList)
	d.Evidence = len(d.EvidenceList)

	db.Where("case_id = ?", caseObj.ID).Find(&d.AgentList)
	d.Agents = len(d.AgentList)

	// Root OSINT investigations linked to this case (exclude auto-pivot children).
	db.Where("case_id = ? AND parent_scan_id IS NULL", caseObj.ID).
		Order("created_at desc").Find(&d.OsintList)
	d.OsintScans = len(d.OsintList)

	return d
}

func statusBadgeClass(status string) string {
	if strings.EqualFold(status, "closed") {
		return "ok"
	}
	return "warn"
}

var caseReportBodyTmpl = template.Must(template.New("casebody").Funcs(template.FuncMap{
	"upper": strings.ToUpper,
}).Parse(`
<section>
  <h2>Executive Summary</h2>
  <div class="stats">
    <div class="stat"><div class="stat-n c-green">{{.Events}}</div><div class="stat-l">Timeline Events</div></div>
    <div class="stat"><div class="stat-n c-red">{{.High}}</div><div class="stat-l">High / Critical</div></div>
    <div class="stat"><div class="stat-n c-yellow">{{.Medium}}</div><div class="stat-l">Medium</div></div>
    <div class="stat"><div class="stat-n c-cyan">{{.Agents}}</div><div class="stat-l">Endpoints</div></div>
    <div class="stat"><div class="stat-n c-blue">{{.Evidence}}</div><div class="stat-l">Evidence Files</div></div>
    <div class="stat"><div class="stat-n c-purple">{{.OsintScans}}</div><div class="stat-l">OSINT Scans</div></div>
  </div>
  {{if .FirstEvent}}<p class="t-muted" style="margin-top:10px">Activity window: <b>{{.FirstEvent}}</b> → <b>{{.LastEvent}}</b></p>{{end}}
  {{if .Description}}<p style="margin-top:8px">{{.Description}}</p>{{end}}
</section>

{{if .Summary}}
<section>
  <h2>Narrative</h2>
  <div class="narr">{{.Summary}}</div>
</section>
{{end}}

{{if .Tactics}}
<section>
  <h2>ATT&amp;CK Tactics Observed <span class="cnt">{{len .Tactics}}</span></h2>
  <div class="tbl-wrap"><table><thead><tr><th>Tactic</th><th>Events</th></tr></thead><tbody>
  {{range .Tactics}}<tr><td>{{.Name}}</td><td class="mono">{{.Count}}</td></tr>{{end}}
  </tbody></table></div>
</section>
{{end}}

<section>
  <h2>Timeline <span class="cnt">{{.Events}} events</span></h2>
  {{if .Timeline}}
  <div class="tl">
  {{range .Timeline}}
    <div class="tl-item s-{{.Severity}}">
      <div class="tl-time">{{.Time}}{{if .Host}} · {{.Host}}{{end}}{{if .Source}} · {{.Source}}{{end}}</div>
      <div class="tl-title">{{.Title}}</div>
      {{if .Detail}}<div class="t-muted mono">{{.Detail}}</div>{{end}}
    </div>
  {{end}}
  </div>
  {{if .TimelineMore}}<p class="t-muted">…and {{.TimelineMore}} more event(s) not shown (open the case timeline for the full list).</p>{{end}}
  {{else}}<p class="t-muted">No timeline events recorded.</p>{{end}}
</section>

{{if .AgentList}}
<section>
  <h2>Endpoints <span class="cnt">{{len .AgentList}}</span></h2>
  <div class="tbl-wrap"><table><thead><tr><th>Name</th><th>Host</th><th>OS</th><th>Status</th></tr></thead><tbody>
  {{range .AgentList}}<tr><td>{{.Name}}</td><td class="mono">{{.Hostname}}</td><td>{{.OS}}</td><td>{{.Status}}</td></tr>{{end}}
  </tbody></table></div>
</section>
{{end}}

{{if .EvidenceList}}
<section>
  <h2>Evidence <span class="cnt">{{len .EvidenceList}}</span></h2>
  <div class="tbl-wrap"><table><thead><tr><th>File</th><th>Host</th><th>Size</th><th>Notes</th></tr></thead><tbody>
  {{range .EvidenceList}}<tr><td class="mono">{{.FileName}}</td><td class="mono">{{.Host}}</td><td class="mono">{{.Size}}</td><td class="t-muted">{{.Notes}}</td></tr>{{end}}
  </tbody></table></div>
</section>
{{end}}

{{if .OsintList}}
<section>
  <h2>OSINT Investigations <span class="cnt">{{len .OsintList}}</span></h2>
  <div class="tbl-wrap"><table><thead><tr><th>Target</th><th>Type</th><th>Status</th></tr></thead><tbody>
  {{range .OsintList}}<tr><td class="mono">{{.Target}}</td><td>{{.TargetType}}</td><td>{{.Status}}</td></tr>{{end}}
  </tbody></table></div>
</section>
{{end}}
`))

func renderCaseReportBody(d caseReportData) template.HTML {
	var buf bytes.Buffer
	if err := caseReportBodyTmpl.Execute(&buf, d); err != nil {
		return template.HTML("<p>report body error</p>")
	}
	return template.HTML(buf.String())
}

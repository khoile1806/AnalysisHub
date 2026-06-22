package osint

import (
	"bytes"
	"encoding/json"
	"html/template"
	"sort"
	"strings"
	"time"

	"github.com/forensichub/backend/internal/models"
)

// reportCategoryOrder fixes the section order of the HTML report and maps each
// finding category to a human-readable heading. Mirrors the frontend's
// CATEGORY_LABELS so the on-screen view and the downloaded file agree.
var reportCategoryOrder = []struct{ Key, Label string }{
	{"registration", "Registration / WHOIS"},
	{"dns", "DNS Records"},
	{"certificate", "Certificate Transparency"},
	{"historical", "Historical (Web Archive)"},
	{"geolocation", "Geolocation"},
	{"network", "Network / ASN"},
	{"ports", "Exposed Services"},
	{"reputation", "Reputation / Threat Intel"},
	{"ransomware", "Ransomware Leak-Site"},
	{"darkweb", "Dark-Web Exposure"},
	{"breach", "Breach Exposure"},
	{"identity", "Identity"},
	{"social", "Social Media Presence"},
	{"search", "Search Pivots"},
}

type reportFinding struct {
	Source   string
	Title    string
	Value    string
	Severity string
	Related  []RelatedEntity
}

type reportGroup struct {
	Label string
	Items []reportFinding
}

type reportData struct {
	Scan        *models.OsintScan
	GeneratedAt string
	Groups      []reportGroup
	Highlights  []reportFinding
	Collectors  []models.OsintCollector
	Total       int
	High        int
	Medium      int
	Low         int
	Pivots      int
	Confirmed   int // confirmed social-media profiles
}

// severityRank orders findings within a section - most severe first.
func severityRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// GenerateHTMLReport renders a self-contained, styled HTML report for a scan.
func GenerateHTMLReport(scan *models.OsintScan, findings []models.OsintFinding) string {
	data := &reportData{
		Scan:        scan,
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Collectors:  scan.Collectors,
		Total:       len(findings),
	}

	byCat := map[string][]reportFinding{}
	for _, f := range findings {
		rf := reportFinding{
			Source:   f.Source,
			Title:    f.Title,
			Value:    f.Value,
			Severity: strings.ToLower(strings.TrimSpace(f.Severity)),
			Related:  parseRelatedEntities(f.RelatedEntities),
		}
		if rf.Severity == "" {
			rf.Severity = "info"
		}
		byCat[f.Category] = append(byCat[f.Category], rf)
		data.Pivots += len(rf.Related)
		switch rf.Severity {
		case "critical", "high":
			data.High++
		case "medium":
			data.Medium++
		case "low":
			data.Low++
		}
		if f.Category == "social" && strings.HasPrefix(f.Title, "Profile found") {
			data.Confirmed++
		}
		if rf.Severity == "high" || rf.Severity == "critical" || rf.Severity == "medium" {
			data.Highlights = append(data.Highlights, rf)
		}
	}

	// Build ordered groups: known categories first, then any extras.
	seen := map[string]bool{}
	for _, c := range reportCategoryOrder {
		items := byCat[c.Key]
		if len(items) == 0 {
			continue
		}
		seen[c.Key] = true
		sort.SliceStable(items, func(i, j int) bool {
			return severityRank(items[i].Severity) < severityRank(items[j].Severity)
		})
		data.Groups = append(data.Groups, reportGroup{Label: c.Label, Items: items})
	}
	for cat, items := range byCat {
		if seen[cat] {
			continue
		}
		data.Groups = append(data.Groups, reportGroup{Label: cat, Items: items})
	}
	sort.SliceStable(data.Highlights, func(i, j int) bool {
		return severityRank(data.Highlights[i].Severity) < severityRank(data.Highlights[j].Severity)
	})

	funcMap := template.FuncMap{
		"upper": strings.ToUpper,
		"sevClass": func(sev string) string {
			switch sev {
			case "critical":
				return "sev-critical"
			case "high":
				return "sev-high"
			case "medium":
				return "sev-medium"
			case "low":
				return "sev-low"
			default:
				return "sev-info"
			}
		},
		"isURL": func(v string) bool {
			return strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://")
		},
		"fmtTimePtr": func(t *time.Time) string {
			if t == nil {
				return "-"
			}
			return t.UTC().Format("2006-01-02 15:04 UTC")
		},
	}

	tmpl := template.Must(template.New("osint-report").Funcs(funcMap).Parse(osintReportTmpl))
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "<html><body>Report generation error: " + template.HTMLEscapeString(err.Error()) + "</body></html>"
	}
	return buf.String()
}

// parseRelatedEntities decodes a finding's related_entities JSON array.
func parseRelatedEntities(raw string) []RelatedEntity {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var r []RelatedEntity
	if json.Unmarshal([]byte(raw), &r) != nil {
		return nil
	}
	return r
}

const osintReportTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OSINT Report - {{.Scan.Name}}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#070a0f;color:#c9d1d9;line-height:1.6;font-size:14px}
.wrap{max-width:1080px;margin:0 auto;padding:36px 24px}
header{border-bottom:1px solid #1e2937;padding-bottom:24px;margin-bottom:32px}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:18px}
.brand-logo{width:36px;height:36px;background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.3);border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:16px}
.brand-name{font-family:monospace;font-weight:700;color:#10b981;font-size:17px;letter-spacing:2px}
.brand-sub{font-size:9px;color:#4b5563;letter-spacing:4px;text-transform:uppercase;margin-top:1px}
h1{font-size:26px;font-weight:700;color:#f0f6fc;margin-bottom:10px}
.meta{display:flex;flex-wrap:wrap;gap:24px;margin-top:12px}
.meta-item{display:flex;flex-direction:column;gap:3px}
.meta-label{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#4b5563}
.meta-value{font-family:monospace;font-size:13px;color:#e6edf3}
.badge{display:inline-block;font-family:monospace;font-size:10px;text-transform:uppercase;padding:2px 8px;border-radius:100px;font-weight:600}
.b-done{background:rgba(16,185,129,.15);color:#10b981;border:1px solid rgba(16,185,129,.3)}
.b-failed{background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.3)}
.b-stopped{background:rgba(234,179,8,.15);color:#eab308;border:1px solid rgba(234,179,8,.3)}
.b-running{background:rgba(59,130,246,.15);color:#3b82f6;border:1px solid rgba(59,130,246,.3)}
.b-pending{background:rgba(107,114,128,.15);color:#6b7280;border:1px solid rgba(107,114,128,.3)}
.b-skipped{background:rgba(55,65,81,.25);color:#6b7280;border:1px solid rgba(55,65,81,.4)}
section{margin-bottom:40px}
h2{font-size:14px;font-weight:600;color:#f0f6fc;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid #1e2937;display:flex;align-items:center;gap:8px}
.cnt{font-size:11px;background:#161b22;color:#6b7280;padding:1px 8px;border-radius:100px;font-weight:500}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px}
.stat{background:#0d1117;border:1px solid #1e2937;border-radius:8px;padding:16px;text-align:center}
.stat-n{font-size:30px;font-weight:700;font-family:monospace}
.stat-l{font-size:10px;color:#4b5563;text-transform:uppercase;letter-spacing:1px;margin-top:4px}
.c-green{color:#10b981}.c-blue{color:#3b82f6}.c-red{color:#ef4444}
.c-orange{color:#f97316}.c-yellow{color:#eab308}.c-cyan{color:#06b6d4}
.c-purple{color:#a855f7}.c-gray{color:#8b949e}
.tbl-wrap{background:#0d1117;border:1px solid #1e2937;border-radius:8px;overflow:hidden}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#4b5563;padding:9px 12px;background:#0d1117;border-bottom:1px solid #1e2937}
td{padding:10px 12px;border-bottom:1px solid #111827;vertical-align:top}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,.015)}
.mono{font-family:monospace}
.t-muted{color:#6b7280;font-size:12px}.t-dim{color:#4b5563}
a{color:#58a6ff;text-decoration:none;word-break:break-all}
a:hover{text-decoration:underline}
.val{color:#c9d1d9;word-break:break-word}
.src{font-family:monospace;font-size:11px;color:#6b7280;text-transform:lowercase}
.sev-critical{background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.3);padding:2px 7px;border-radius:4px;font-family:monospace;font-size:10px;text-transform:uppercase;font-weight:700;white-space:nowrap}
.sev-high{background:rgba(249,115,22,.15);color:#f97316;border:1px solid rgba(249,115,22,.3);padding:2px 7px;border-radius:4px;font-family:monospace;font-size:10px;text-transform:uppercase;font-weight:700;white-space:nowrap}
.sev-medium{background:rgba(234,179,8,.15);color:#eab308;border:1px solid rgba(234,179,8,.3);padding:2px 7px;border-radius:4px;font-family:monospace;font-size:10px;text-transform:uppercase;font-weight:700;white-space:nowrap}
.sev-low{background:rgba(59,130,246,.15);color:#3b82f6;border:1px solid rgba(59,130,246,.3);padding:2px 7px;border-radius:4px;font-family:monospace;font-size:10px;text-transform:uppercase;font-weight:700;white-space:nowrap}
.sev-info{background:rgba(107,114,128,.15);color:#8b949e;border:1px solid rgba(107,114,128,.3);padding:2px 7px;border-radius:4px;font-family:monospace;font-size:10px;text-transform:uppercase;font-weight:700;white-space:nowrap}
.pivots{margin-top:6px;display:flex;flex-wrap:wrap;gap:5px}
.pivot{font-family:monospace;font-size:10px;background:rgba(16,185,129,.1);color:#34d399;border:1px solid rgba(16,185,129,.25);border-radius:4px;padding:2px 7px}
.hl-card{background:#0d1117;border:1px solid #1e2937;border-left:3px solid #f97316;border-radius:8px;padding:13px 15px;margin-bottom:8px}
.hl-head{display:flex;align-items:center;gap:10px;margin-bottom:5px}
.hl-title{font-weight:600;color:#e6edf3;font-size:13px}
.empty{text-align:center;padding:32px;color:#4b5563;font-size:13px;background:#0d1117;border:1px solid #1e2937;border-radius:8px}
footer{border-top:1px solid #1e2937;padding-top:14px;text-align:center;font-size:11px;color:#374151;font-family:monospace;margin-top:40px}
@media print{body{background:#fff;color:#111}.wrap{padding:16px}header,section{page-break-inside:avoid}a{color:#0a58ca}}
</style>
</head>
<body>
<div class="wrap">

<header>
  <div class="brand">
    <div class="brand-logo">*</div>
    <div>
      <div class="brand-name">OFFSECHUB</div>
      <div class="brand-sub">DFIR Platform - OSINT Report</div>
    </div>
  </div>
  <h1>{{.Scan.Name}}</h1>
  <div class="meta">
    <div class="meta-item"><span class="meta-label">Target</span><span class="meta-value">{{.Scan.Target}}</span></div>
    <div class="meta-item"><span class="meta-label">Type</span><span class="meta-value">{{upper .Scan.TargetType}}</span></div>
    <div class="meta-item"><span class="meta-label">Status</span><span class="badge b-{{.Scan.Status}}">{{.Scan.Status}}</span></div>
    <div class="meta-item"><span class="meta-label">Started</span><span class="meta-value">{{.Scan.CreatedAt.Format "2006-01-02 15:04 UTC"}}</span></div>
    <div class="meta-item"><span class="meta-label">Finished</span><span class="meta-value">{{fmtTimePtr .Scan.FinishedAt}}</span></div>
    <div class="meta-item"><span class="meta-label">Generated</span><span class="meta-value">{{.GeneratedAt}}</span></div>
  </div>
</header>

<section>
  <h2>Executive Summary</h2>
  <div class="stats">
    <div class="stat"><div class="stat-n c-green">{{.Total}}</div><div class="stat-l">Total Findings</div></div>
    <div class="stat"><div class="stat-n c-red">{{.High}}</div><div class="stat-l">High / Critical</div></div>
    <div class="stat"><div class="stat-n c-yellow">{{.Medium}}</div><div class="stat-l">Medium</div></div>
    <div class="stat"><div class="stat-n c-blue">{{.Low}}</div><div class="stat-l">Low</div></div>
    <div class="stat"><div class="stat-n c-cyan">{{.Confirmed}}</div><div class="stat-l">Social Profiles</div></div>
    <div class="stat"><div class="stat-n c-purple">{{.Pivots}}</div><div class="stat-l">Pivots Found</div></div>
  </div>
</section>

{{if .Collectors}}
<section>
  <h2>Collectors <span class="cnt">{{len .Collectors}}</span></h2>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th>Source</th><th>Status</th><th>Findings</th><th>Note</th></tr></thead>
      <tbody>
      {{range .Collectors}}
      <tr>
        <td class="mono">{{.Name}}</td>
        <td><span class="badge b-{{.Status}}">{{.Status}}</span></td>
        <td class="mono">{{.FindingsCount}}</td>
        <td class="t-muted">{{if .Error}}{{.Error}}{{else}}-{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
  </div>
</section>
{{end}}

{{if .Highlights}}
<section>
  <h2>Highlights <span class="cnt">{{len .Highlights}}</span></h2>
  {{range .Highlights}}
  <div class="hl-card">
    <div class="hl-head">
      <span class="{{sevClass .Severity}}">{{upper .Severity}}</span>
      <span class="hl-title">{{.Title}}</span>
      <span class="src">{{.Source}}</span>
    </div>
    <div class="val">{{if isURL .Value}}<a href="{{.Value}}" target="_blank" rel="noreferrer">{{.Value}}</a>{{else}}{{.Value}}{{end}}</div>
  </div>
  {{end}}
</section>
{{end}}

{{range .Groups}}
<section>
  <h2>{{.Label}} <span class="cnt">{{len .Items}}</span></h2>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th style="width:90px">Severity</th><th style="width:120px">Source</th><th>Finding</th></tr></thead>
      <tbody>
      {{range .Items}}
      <tr>
        <td><span class="{{sevClass .Severity}}">{{upper .Severity}}</span></td>
        <td class="src">{{.Source}}</td>
        <td>
          <div class="t-muted" style="margin-bottom:3px">{{.Title}}</div>
          <div class="val mono">{{if isURL .Value}}<a href="{{.Value}}" target="_blank" rel="noreferrer">{{.Value}}</a>{{else}}{{.Value}}{{end}}</div>
          {{if .Related}}<div class="pivots">{{range .Related}}<span class="pivot">{{.Type}}: {{.Value}}</span>{{end}}</div>{{end}}
        </td>
      </tr>
      {{end}}
      </tbody>
    </table>
  </div>
</section>
{{end}}

{{if not .Groups}}
<div class="empty">No findings were recorded for this investigation.</div>
{{end}}

<footer>ForensicHub - OSINT Footprinting - Generated {{.GeneratedAt}}</footer>
</div>
</body>
</html>`

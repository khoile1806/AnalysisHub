// Package report provides a shared, self-contained HTML report shell (styling +
// page chrome + print-CSS) so every report in the system — OSINT, compliance and
// the case incident report — looks consistent and prints cleanly to PDF from the
// browser, without any external dependency.
package report

import (
	"html/template"
	"strings"
)

// Meta is the report header information shown at the top of every report.
type Meta struct {
	Title       string // e.g. "Incident Report"
	Subtitle    string // e.g. the case name / target
	GeneratedAt string // formatted timestamp
	Badges      []Badge
}

// Badge is a small key/value chip in the report header (status, severity, …).
type Badge struct {
	Label string
	Value string
	Class string // "ok" | "warn" | "bad" | "" (neutral)
}

// Page wraps body HTML (already-escaped/templated) in the shared shell. The body
// is trusted template.HTML produced by a caller's own template.
func Page(meta Meta, body template.HTML) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	b.WriteString(`<title>`)
	b.WriteString(template.HTMLEscapeString(meta.Title))
	if meta.Subtitle != "" {
		b.WriteString(" — " + template.HTMLEscapeString(meta.Subtitle))
	}
	b.WriteString(`</title><style>`)
	b.WriteString(baseCSS)
	b.WriteString(`</style></head><body><div class="wrap">`)

	// Header
	b.WriteString(`<header class="rpt-head"><div><h1>`)
	b.WriteString(template.HTMLEscapeString(meta.Title))
	b.WriteString(`</h1>`)
	if meta.Subtitle != "" {
		b.WriteString(`<div class="sub">` + template.HTMLEscapeString(meta.Subtitle) + `</div>`)
	}
	b.WriteString(`</div><div class="rpt-meta">`)
	for _, bd := range meta.Badges {
		cls := "badge"
		if bd.Class != "" {
			cls += " b-" + bd.Class
		}
		b.WriteString(`<span class="` + cls + `">` + template.HTMLEscapeString(bd.Label) + `: ` +
			template.HTMLEscapeString(bd.Value) + `</span>`)
	}
	if meta.GeneratedAt != "" {
		b.WriteString(`<div class="gen">Generated ` + template.HTMLEscapeString(meta.GeneratedAt) + `</div>`)
	}
	b.WriteString(`</div></header>`)

	b.WriteString(string(body))

	b.WriteString(`<footer class="rpt-foot">AnalysisHub-v2 — confidential. Generated automatically; verify findings before acting.</footer>`)
	b.WriteString(`</div></body></html>`)
	return b.String()
}

// baseCSS is the shared stylesheet (screen + print). Kept inline so a report is a
// single self-contained file an analyst can save or e-mail.
const baseCSS = `
:root{--bg:#0b0f17;--card:#121826;--line:#1f2937;--txt:#e5e7eb;--muted:#9ca3af;
--green:#34d399;--red:#f87171;--yellow:#fbbf24;--blue:#60a5fa;--cyan:#22d3ee;--purple:#a78bfa;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:28px}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
.t-muted{color:var(--muted)}
.rpt-head{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;
border-bottom:2px solid var(--line);padding-bottom:14px;margin-bottom:8px}
.rpt-head h1{margin:0;font-size:22px}
.rpt-head .sub{color:var(--muted);margin-top:4px;font-size:13px}
.rpt-meta{text-align:right;font-size:12px}
.rpt-meta .gen{color:var(--muted);margin-top:6px}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid var(--line);
background:#0e1422;color:var(--muted);font-size:11px;margin:0 0 4px 6px}
.badge.b-ok{color:var(--green);border-color:#14532d}
.badge.b-warn{color:var(--yellow);border-color:#713f12}
.badge.b-bad{color:var(--red);border-color:#7f1d1d}
section{margin:22px 0}
h2{font-size:15px;border-left:3px solid var(--green);padding-left:10px;margin:0 0 12px}
h2 .cnt{color:var(--muted);font-weight:400;font-size:12px;margin-left:6px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px;text-align:center}
.stat-n{font-size:22px;font-weight:700}.stat-l{color:var(--muted);font-size:11px;margin-top:2px}
.c-green{color:var(--green)}.c-red{color:var(--red)}.c-yellow{color:var(--yellow)}
.c-blue{color:var(--blue)}.c-cyan{color:var(--cyan)}.c-purple{color:var(--purple)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
.tbl-wrap{background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
.sev-critical{color:#fff;background:#991b1b;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:700}
.sev-high{color:var(--red);font-weight:700}.sev-medium{color:var(--yellow)}.sev-low{color:var(--blue)}.sev-info{color:var(--muted)}
.tl{position:relative;padding-left:18px}
.tl:before{content:"";position:absolute;left:5px;top:4px;bottom:4px;width:1px;background:var(--line)}
.tl-item{position:relative;margin-bottom:12px}
.tl-item:before{content:"";position:absolute;left:-16px;top:5px;width:9px;height:9px;border-radius:50%;background:var(--green);box-shadow:0 0 0 3px var(--bg)}
.tl-item.s-high:before,.tl-item.s-critical:before{background:var(--red)}
.tl-item.s-medium:before{background:var(--yellow)}
.tl-time{font-size:11px;color:var(--muted);font-family:ui-monospace,monospace}
.tl-title{font-weight:600}
.narr{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;white-space:pre-wrap}
.rpt-foot{margin-top:30px;padding-top:12px;border-top:1px solid var(--line);color:var(--muted);font-size:11px;text-align:center}
@media print{
  :root{--bg:#fff;--card:#fff;--line:#d1d5db;--txt:#111;--muted:#555}
  body{background:#fff}.wrap{max-width:none;padding:0}
  a{color:#1d4ed8}section{break-inside:avoid}.tl-item{break-inside:avoid}
  .stat,.tbl-wrap,.narr{box-shadow:none}
}
`

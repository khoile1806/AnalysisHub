package offline

import (
	"encoding/json"
	"fmt"
	"html"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

// Report is the top-level structure serialised to JSON and rendered to HTML.
type Report struct {
	BundleName  string      `json:"bundle_name"`
	CaseID      string      `json:"case_id,omitempty"`
	CaseName    string      `json:"case_name,omitempty"`
	Hostname    string      `json:"hostname"`
	IP          string      `json:"ip"`
	OS          string      `json:"os"`
	Arch        string      `json:"arch"`
	Operator    string      `json:"operator,omitempty"`
	GeneratedAt time.Time   `json:"generated_at"`
	Jobs        []ReportJob `json:"jobs"`
	Findings    []Finding   `json:"findings,omitempty"` // aggregated, most-severe first
	Summary     Summary     `json:"summary"`
}

// ReportJob captures the result of one tool execution.
type ReportJob struct {
	ToolName    string    `json:"tool_name"`
	ToolID      string    `json:"tool_id"`
	Args        string    `json:"args"`
	Status      string    `json:"status"`
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at"`
	DurationSec float64   `json:"duration_seconds"`
	OutputLines int       `json:"output_lines"`
	Output      string    `json:"output"`
	Error       string    `json:"error,omitempty"`
	Findings    []Finding `json:"findings,omitempty"`
}

// Summary holds aggregated counters.
type Summary struct {
	TotalTools int `json:"total_tools"`
	Done       int `json:"done"`
	Failed     int `json:"failed"`
	Stopped    int `json:"stopped"`
	Running    int `json:"running"`
}

// BuildReport assembles a Report from the current runner state.
func BuildReport(manifest *BundleManifest, runner *Runner) Report {
	jobs := runner.ListJobs()

	hostname, _ := os.Hostname()
	ip := localIP()

	rep := Report{
		BundleName:  manifest.Name,
		CaseID:      manifest.CaseID,
		CaseName:    manifest.CaseName,
		Operator:    manifest.Operator,
		Hostname:    hostname,
		IP:          ip,
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		GeneratedAt: time.Now().UTC(),
		Findings:    runner.AllFindings(),
	}

	sum := Summary{TotalTools: len(jobs)}
	for _, j := range jobs {
		var started, finished time.Time
		if j.StartedAt != nil {
			started = *j.StartedAt
		}
		if j.FinishedAt != nil {
			finished = *j.FinishedAt
		}
		dur := 0.0
		if !started.IsZero() && !finished.IsZero() {
			dur = finished.Sub(started).Seconds()
		}
		rj := ReportJob{
			ToolName:    j.ToolName,
			ToolID:      j.ToolID,
			Args:        j.Args,
			Status:      string(j.Status),
			StartedAt:   started,
			FinishedAt:  finished,
			DurationSec: dur,
			OutputLines: len(j.Output),
			Output:      strings.Join(j.Output, "\n"),
			Error:       j.Error,
			Findings:    j.Findings,
		}
		rep.Jobs = append(rep.Jobs, rj)

		switch j.Status {
		case StatusDone:
			sum.Done++
		case StatusFailed:
			sum.Failed++
		case StatusStopped:
			sum.Stopped++
		case StatusRunning:
			sum.Running++
		}
	}
	rep.Summary = sum
	return rep
}

// SaveJSON writes the report as indented JSON to path.
func SaveJSON(rep Report, path string) error {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// SaveHTML writes a self-contained HTML report (no external resources) to path.
func SaveHTML(rep Report, path string) error {
	return os.WriteFile(path, []byte(renderHTML(rep)), 0o644)
}

// renderHTML builds the full HTML string.
func renderHTML(rep Report) string {
	var sb strings.Builder

	statusColor := map[string]string{
		"done":    "#22c55e",
		"failed":  "#ef4444",
		"stopped": "#f59e0b",
		"running": "#3b82f6",
		"pending": "#6b7280",
	}

	sb.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AnalysisHub Offline Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;font-size:14px}
header{background:#1e293b;border-bottom:1px solid #334155;padding:16px 24px;display:flex;align-items:center;gap:12px}
header h1{font-size:18px;font-weight:700;color:#f1f5f9}
header .badge{background:#dc2626;color:#fff;font-size:11px;font-weight:700;padding:2px 8px;border-radius:9999px;letter-spacing:.05em}
.meta{background:#1e293b;border-bottom:1px solid #334155;padding:12px 24px;display:flex;gap:24px;flex-wrap:wrap}
.meta-item{display:flex;flex-direction:column;gap:2px}
.meta-item .label{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.08em}
.meta-item .value{font-size:13px;color:#cbd5e1;font-weight:500}
.summary{display:flex;gap:12px;padding:16px 24px;flex-wrap:wrap}
.stat{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:12px 20px;text-align:center;min-width:90px}
.stat .n{font-size:24px;font-weight:700}
.stat .l{font-size:11px;color:#64748b;margin-top:2px;text-transform:uppercase;letter-spacing:.05em}
.jobs{padding:0 24px 24px}
.job{background:#1e293b;border:1px solid #334155;border-radius:8px;margin-bottom:12px;overflow:hidden}
.job-header{padding:12px 16px;display:flex;align-items:center;gap:10px;cursor:pointer;user-select:none}
.job-header:hover{background:#263248}
.job-title{font-weight:600;color:#f1f5f9;flex:1}
.job-meta{font-size:12px;color:#64748b}
.status-badge{font-size:11px;font-weight:700;padding:2px 10px;border-radius:9999px;color:#fff}
.job-args{font-size:12px;color:#94a3b8;font-family:monospace;background:#0f172a;padding:2px 8px;border-radius:4px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.job-body{display:none;border-top:1px solid #334155}
.job-body.open{display:block}
.output-box{background:#020617;padding:14px 16px;font-family:'Cascadia Code','Fira Code',monospace;font-size:12px;line-height:1.6;white-space:pre-wrap;word-break:break-all;max-height:600px;overflow-y:auto;color:#a3e635}
.error-box{background:#1c0707;border-top:1px solid #7f1d1d;padding:10px 16px;font-family:monospace;font-size:12px;color:#fca5a5}
.toggle-btn{font-size:11px;color:#64748b;transition:transform .2s}
footer{text-align:center;padding:20px;color:#475569;font-size:12px;border-top:1px solid #1e293b}
</style></head><body>
<header>
  <div>
    <h1>AnalysisHub Offline Report</h1>
    <div style="font-size:12px;color:#64748b;margin-top:2px">`)
	sb.WriteString(html.EscapeString(rep.BundleName))
	sb.WriteString(`</div>
  </div>
  <span class="badge">OFFLINE</span>
</header>
<div class="meta">`)
	if rep.CaseName != "" {
		sb.WriteString(`  <div class="meta-item"><span class="label">Case</span><span class="value" style="color:#a78bfa">`)
		sb.WriteString(html.EscapeString(rep.CaseName))
		sb.WriteString(`</span></div>`)
	}
	sb.WriteString(`
  <div class="meta-item"><span class="label">Host</span><span class="value">`)
	sb.WriteString(html.EscapeString(rep.Hostname))
	sb.WriteString(`</span></div>
  <div class="meta-item"><span class="label">IP</span><span class="value">`)
	sb.WriteString(html.EscapeString(rep.IP))
	sb.WriteString(`</span></div>
  <div class="meta-item"><span class="label">OS / Arch</span><span class="value">`)
	sb.WriteString(html.EscapeString(fmt.Sprintf("%s / %s", rep.OS, rep.Arch)))
	sb.WriteString(`</span></div>
  <div class="meta-item"><span class="label">Generated</span><span class="value">`)
	sb.WriteString(html.EscapeString(rep.GeneratedAt.Format("2006-01-02 15:04:05 UTC")))
	sb.WriteString(`</span></div>
</div>
<div class="summary">`)

	colors := map[string]string{"done": "#22c55e", "failed": "#ef4444", "stopped": "#f59e0b", "running": "#3b82f6", "total": "#6366f1"}
	stats := []struct {
		n    int
		l, c string
	}{
		{rep.Summary.TotalTools, "Total", colors["total"]},
		{rep.Summary.Done, "Done", colors["done"]},
		{rep.Summary.Failed, "Failed", colors["failed"]},
		{rep.Summary.Stopped, "Stopped", colors["stopped"]},
		{rep.Summary.Running, "Running", colors["running"]},
	}
	for _, s := range stats {
		sb.WriteString(fmt.Sprintf(`<div class="stat"><div class="n" style="color:%s">%d</div><div class="l">%s</div></div>`, s.c, s.n, s.l))
	}

	sb.WriteString(`</div>`)

	// Findings table at the top — severity-sorted triage before the raw job logs.
	if len(rep.Findings) > 0 {
		sevColor := map[Severity]string{SevCritical: "#ef4444", SevHigh: "#f59e0b", SevMedium: "#fbbf24", SevLow: "#60a5fa", SevInfo: "#94a3b8"}
		sb.WriteString(`<div style="padding:0 24px 8px"><h2 style="font-size:14px;color:#f1f5f9;margin-bottom:10px">⚑ Findings (`)
		sb.WriteString(fmt.Sprintf("%d)</h2>", len(rep.Findings)))
		sb.WriteString(`<table style="width:100%;border-collapse:collapse;font-size:12px"><tbody>`)
		for _, f := range rep.Findings {
			c := sevColor[f.Severity]
			if c == "" {
				c = "#94a3b8"
			}
			sb.WriteString(`<tr style="border-bottom:1px solid #1e293b">`)
			sb.WriteString(fmt.Sprintf(`<td style="padding:5px 8px;color:%s;font-weight:700;text-transform:uppercase;white-space:nowrap">%s</td>`, c, html.EscapeString(string(f.Severity))))
			sb.WriteString(fmt.Sprintf(`<td style="padding:5px 8px;color:#94a3b8;white-space:nowrap">%s</td>`, html.EscapeString(f.Tool)))
			sb.WriteString(fmt.Sprintf(`<td style="padding:5px 8px;color:#e2e8f0;font-family:monospace;word-break:break-all">%s</td>`, html.EscapeString(f.Title)))
			sb.WriteString(`</tr>`)
		}
		sb.WriteString(`</tbody></table></div>`)
	}

	sb.WriteString(`<div class="jobs">`)

	for i, j := range rep.Jobs {
		col := statusColor[j.Status]
		if col == "" {
			col = "#6b7280"
		}
		dur := ""
		if j.DurationSec > 0 {
			if j.DurationSec < 60 {
				dur = fmt.Sprintf("%.1fs", j.DurationSec)
			} else {
				dur = fmt.Sprintf("%.0fm %.0fs", j.DurationSec/60, float64(int(j.DurationSec)%60))
			}
		}

		bodyID := fmt.Sprintf("job-body-%d", i)
		btnID := fmt.Sprintf("btn-%d", i)

		sb.WriteString(fmt.Sprintf(`<div class="job">
  <div class="job-header" onclick="toggle('%s','%s')">
    <span class="status-badge" style="background:%s">%s</span>
    <span class="job-title">%s</span>
    <span class="job-args" title="%s">%s</span>
    <span class="job-meta">%d lines%s</span>
    <span class="toggle-btn" id="%s">▼</span>
  </div>
  <div class="job-body" id="%s">`,
			bodyID, btnID,
			col, html.EscapeString(strings.ToUpper(j.Status)),
			html.EscapeString(j.ToolName),
			html.EscapeString(j.Args),
			html.EscapeString(j.Args),
			j.OutputLines,
			func() string {
				if dur != "" {
					return " · " + dur
				}
				return ""
			}(),
			btnID,
			bodyID,
		))

		if j.Error != "" {
			sb.WriteString(fmt.Sprintf(`<div class="error-box">Error: %s</div>`, html.EscapeString(j.Error)))
		}
		sb.WriteString(fmt.Sprintf(`<div class="output-box">%s</div>`, html.EscapeString(j.Output)))
		sb.WriteString(`</div></div>`)
	}

	sb.WriteString(`</div>
<footer>Generated by AnalysisHub Offline Agent &mdash; ` + rep.GeneratedAt.Format("2006-01-02") + `</footer>
<script>
function toggle(bodyId, btnId) {
  var b = document.getElementById(bodyId);
  var t = document.getElementById(btnId);
  if (b.classList.toggle('open')) { t.style.transform='rotate(180deg)'; }
  else { t.style.transform=''; }
}
// Auto-open failed jobs
document.querySelectorAll('.status-badge').forEach(function(el) {
  if (el.textContent.trim() === 'FAILED') {
    var header = el.closest('.job-header');
    if (header) header.click();
  }
});
</script></body></html>`)

	return sb.String()
}

// localIP returns the first non-loopback IPv4 address, or "unknown".
func localIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "unknown"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				return ip4.String()
			}
		}
	}
	return "unknown"
}

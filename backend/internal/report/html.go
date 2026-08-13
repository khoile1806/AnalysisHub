package report

import (
	"fmt"
	"html"
	"regexp"
	"strings"
)

// Package report renders an analysis as a self-contained HTML document.
//
// It is shared by every analysis feature (malware samples, network captures), so
// a report looks and prints the same wherever it came from, and a fix to the
// renderer reaches all of them at once.
//
// The document is self-contained by design. HTML is the
// default deliverable because it is what a report actually needs to be: readable
// in any browser with no viewer or font dependency, printable to PDF from the
// same file, previewable BEFORE download (the operator sees exactly what they
// will hand over), and attachable to a ticket as one file with no assets.
//
// The Markdown comes from report.go, which this package generates itself, so the
// converter only has to handle the subset that generator emits: headings, GFM
// tables, bullet/ordered lists, fenced code, blockquotes, horizontal rules,
// bold/inline code, and hard line breaks. Everything is HTML-escaped first —
// report content includes attacker-controlled strings (file names, ransom notes,
// e-mail subjects), so no untrusted byte may ever reach the page as markup.

var (
	reBold      = regexp.MustCompile("\\*\\*([^*]+)\\*\\*")
	reCode      = regexp.MustCompile("`([^`]+)`")
	reTableSep  = regexp.MustCompile(`^\s*\|?[\s:|-]+\|[\s:|-]*$`)
	reOrdered   = regexp.MustCompile(`^(\d+)\.\s+(.*)$`)
	reTLPMarker = regexp.MustCompile(`(?i)TLP:([A-Z+]+)`)
)

// inlineHTML renders the inline Markdown subset. Input is already escaped.
func inlineHTML(s string) string {
	s = reCode.ReplaceAllString(s, "<code>$1</code>")
	s = reBold.ReplaceAllString(s, "<strong>$1</strong>")
	return s
}

// splitRow splits a GFM table row into its cells.
func splitRow(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	parts := strings.Split(line, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// MDToHTML converts the report Markdown into the document body.
func MDToHTML(md string) string { return mdToHTMLPrefixed(md, "") }

// mdToHTMLPrefixed is mdToHTML with an anchor-id prefix, so two language
// editions of the same report can live in one document without duplicate ids.
func mdToHTMLPrefixed(md, idPrefix string) string {
	if idPrefix != "" {
		idPrefix += "-"
	}
	return mdRender(md, idPrefix)
}

func mdRender(md, idPrefix string) string {
	lines := strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n")
	var b strings.Builder

	inCode, inList, inOrdered := false, false, false
	closeLists := func() {
		if inList {
			b.WriteString("</ul>\n")
			inList = false
		}
		if inOrdered {
			b.WriteString("</ol>\n")
			inOrdered = false
		}
	}

	for i := 0; i < len(lines); i++ {
		raw := lines[i]
		trimmed := strings.TrimSpace(raw)

		// Fenced code — emitted verbatim (escaped), no inline processing.
		if strings.HasPrefix(trimmed, "```") {
			if inCode {
				b.WriteString("</code></pre>\n")
				inCode = false
				continue
			}
			closeLists()
			lang := strings.TrimSpace(strings.TrimPrefix(trimmed, "```"))
			cls := ""
			if lang != "" {
				cls = ` class="lang-` + html.EscapeString(lang) + `"`
			}
			b.WriteString("<pre><code" + cls + ">")
			inCode = true
			continue
		}
		if inCode {
			b.WriteString(html.EscapeString(raw) + "\n")
			continue
		}

		esc := html.EscapeString(trimmed)

		switch {
		case trimmed == "":
			closeLists()

		case strings.HasPrefix(trimmed, "### "):
			closeLists()
			b.WriteString("<h3>" + inlineHTML(strings.TrimPrefix(esc, "### ")) + "</h3>\n")

		case strings.HasPrefix(trimmed, "## "):
			closeLists()
			// Anchored so the contents list can link to it.
			title := strings.TrimPrefix(trimmed, "## ")
			b.WriteString("<h2 id=\"" + idPrefix + slugify(title) + "\">" + inlineHTML(strings.TrimPrefix(esc, "## ")) + "</h2>\n")

		case strings.HasPrefix(trimmed, "# "):
			closeLists()
			b.WriteString("<h1>" + inlineHTML(strings.TrimPrefix(esc, "# ")) + "</h1>\n")

		case trimmed == "---" || trimmed == "***":
			closeLists()
			b.WriteString("<hr/>\n")

		case strings.HasPrefix(trimmed, "> "):
			closeLists()
			b.WriteString("<blockquote>" + inlineHTML(strings.TrimPrefix(esc, "&gt; ")) + "</blockquote>\n")

		// GFM table: a header row followed by a separator row.
		case strings.HasPrefix(trimmed, "|") && i+1 < len(lines) && reTableSep.MatchString(lines[i+1]):
			closeLists()
			b.WriteString("<table>\n<thead><tr>")
			for _, c := range splitRow(raw) {
				b.WriteString("<th>" + inlineHTML(html.EscapeString(c)) + "</th>")
			}
			b.WriteString("</tr></thead>\n<tbody>\n")
			i++ // consume the separator
			for i+1 < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i+1]), "|") {
				i++
				b.WriteString("<tr>")
				for _, c := range splitRow(lines[i]) {
					b.WriteString("<td>" + inlineHTML(html.EscapeString(c)) + "</td>")
				}
				b.WriteString("</tr>\n")
			}
			b.WriteString("</tbody></table>\n")

		case strings.HasPrefix(trimmed, "- "):
			if inOrdered {
				b.WriteString("</ol>\n")
				inOrdered = false
			}
			if !inList {
				b.WriteString("<ul>\n")
				inList = true
			}
			b.WriteString("<li>" + inlineHTML(strings.TrimPrefix(esc, "- ")) + "</li>\n")

		case reOrdered.MatchString(trimmed):
			if inList {
				b.WriteString("</ul>\n")
				inList = false
			}
			if !inOrdered {
				b.WriteString("<ol>\n")
				inOrdered = true
			}
			m := reOrdered.FindStringSubmatch(esc)
			b.WriteString("<li>" + inlineHTML(m[2]) + "</li>\n")

		default:
			closeLists()
			// A Markdown hard break is two trailing spaces; report.go uses it for the
			// stacked key/value lines on the cover page.
			body := inlineHTML(esc)
			if strings.HasSuffix(raw, "  ") {
				b.WriteString("<p class=\"tight\">" + body + "</p>\n")
			} else {
				b.WriteString("<p>" + body + "</p>\n")
			}
		}
	}
	if inCode {
		b.WriteString("</code></pre>\n")
	}
	closeLists()
	return b.String()
}

// tlpColor maps a TLP level to its official colour, so the marking is recognised
// at a glance instead of being read.
func tlpColor(tlp string) (bg, fg string) {
	switch strings.ToUpper(strings.TrimSpace(tlp)) {
	case "RED":
		return "#000000", "#FF2B2B"
	case "AMBER", "AMBER+STRICT":
		return "#000000", "#FFC000"
	case "GREEN":
		return "#000000", "#33FF00"
	case "CLEAR", "WHITE":
		return "#000000", "#FFFFFF"
	}
	return "#000000", "#FFC000"
}

// reportCSS is print-first (A4 page box, no page break inside a table row, long
// monospace values wrap instead of running off the paper) but reads as a designed
// document on screen too: a cover band carrying the verdict, a numbered contents
// list, and section rules that make a 15-section report navigable.
const reportCSS = `
@page { size: A4; margin: 14mm 13mm 16mm; }
* { box-sizing: border-box; }
:root {
  --ink: #14171c; --muted: #6b7280; --line: #e3e6ea; --line-strong: #cfd4da;
  --bg-soft: #f7f8fa; --accent: #1f4e79;
  --mal: #b3261e; --sus: #b26a00; --ben: #1a7f37; --unk: #5b6472;
}
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
       color: var(--ink); line-height: 1.55; font-size: 12.5px; margin: 0; padding: 0 0 40px;
       background: #eef0f3; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
.wrap { max-width: 940px; margin: 0 auto; background: #fff; padding: 0 34px 34px;
        box-shadow: 0 1px 3px rgba(20,23,28,.09); }

/* ── cover band ─────────────────────────────────────────────────────────── */
.cover { margin: 0 -34px 22px; padding: 20px 34px 18px; background: linear-gradient(180deg,#1f2937 0%,#111827 100%);
         color: #f3f4f6; }
.cover .kicker { font-size: 10px; letter-spacing: 1.6px; text-transform: uppercase; color: #9aa4b2; }
.cover h1 { font-size: 21px; margin: 4px 0 2px; color: #fff; letter-spacing: -0.2px; border: 0; }
.cover .subject { font-family: "SF Mono", Consolas, Menlo, monospace; font-size: 12px; color: #cbd5e1;
                  overflow-wrap: anywhere; }
.cover .row { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-top: 12px; }
.badge { display: inline-block; font-weight: 700; font-size: 11px; letter-spacing: .6px; text-transform: uppercase;
         padding: 4px 10px; border-radius: 3px; }
.badge.mal { background: var(--mal); color: #fff; }
.badge.sus { background: var(--sus); color: #fff; }
.badge.ben { background: var(--ben); color: #fff; }
.badge.unk { background: var(--unk); color: #fff; }
.tlp { display: inline-block; font-weight: 700; letter-spacing: .8px; padding: 4px 10px; border-radius: 3px;
       font-size: 11px; font-family: Consolas, monospace; border: 1px solid rgba(255,255,255,.25); }
.chip { font-size: 11px; padding: 3px 9px; border-radius: 3px; background: rgba(255,255,255,.10);
        color: #e5e7eb; border: 1px solid rgba(255,255,255,.14); }
.meter { flex: 1 1 180px; min-width: 160px; height: 7px; border-radius: 4px; background: rgba(255,255,255,.14);
         overflow: hidden; }
.meter > span { display: block; height: 100%; }
.factgrid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 2px 18px; margin-top: 14px;
            padding-top: 12px; border-top: 1px solid rgba(255,255,255,.14); font-size: 11px; }
.factgrid div { color: #cbd5e1; overflow-wrap: anywhere; }
.factgrid b { color: #9aa4b2; font-weight: 600; display: inline-block; min-width: 96px; }
.factgrid code { background: rgba(255,255,255,.08); color: #e5e7eb; }

/* ── contents ───────────────────────────────────────────────────────────── */
.toc { background: var(--bg-soft); border: 1px solid var(--line); border-radius: 6px; padding: 12px 16px; margin: 0 0 20px; }
.toc h2 { font-size: 11px; letter-spacing: 1.2px; text-transform: uppercase; color: var(--muted);
          margin: 0 0 8px; padding: 0; border: 0; }
.toc ol { columns: 2; column-gap: 26px; margin: 0; padding-left: 18px; font-size: 11.5px; }
.toc li { margin: 2px 0; break-inside: avoid; }
.toc a { color: var(--accent); text-decoration: none; }

/* ── body ───────────────────────────────────────────────────────────────── */
h1 { font-size: 20px; margin: 0 0 10px; }
h2 { font-size: 15px; margin: 26px 0 9px; padding-bottom: 5px; border-bottom: 2px solid var(--accent);
     color: var(--accent); letter-spacing: -0.1px; page-break-after: avoid; }
h3 { font-size: 12.5px; margin: 16px 0 5px; color: #2b3038; page-break-after: avoid; }
p { margin: 6px 0; }
p.tight { margin: 1px 0; }
ul, ol { margin: 6px 0; padding-left: 22px; }
li { margin: 2.5px 0; }
code { font-family: "SF Mono", Consolas, Menlo, monospace; background: #eef1f4; padding: 1px 4px;
       border-radius: 3px; font-size: 11px; overflow-wrap: anywhere; }
pre { background: #1e222a; color: #d7dce4; border: 0; padding: 11px 13px; border-radius: 6px;
      overflow-x: auto; font-size: 10.5px; white-space: pre-wrap; overflow-wrap: anywhere; page-break-inside: avoid; }
pre code { background: none; padding: 0; color: inherit; }
blockquote { margin: 10px 0; padding: 8px 13px; border-left: 4px solid var(--sus); background: #fff8ec;
             color: #5a4a2f; border-radius: 0 4px 4px 0; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; font-size: 11px; }
th, td { border: 1px solid var(--line); padding: 6px 8px; text-align: left; vertical-align: top; overflow-wrap: anywhere; }
th { background: #eaeef2; font-weight: 600; color: #2b3038; border-bottom: 2px solid var(--line-strong); }
tr:nth-child(even) td { background: #fafbfc; }
tr, td, th { page-break-inside: avoid; }
td code { font-size: 10px; }
hr { border: 0; border-top: 1px solid var(--line); margin: 20px 0; }
.footer { margin-top: 30px; padding-top: 10px; border-top: 1px solid var(--line); color: #8b93a1; font-size: 9.5px; }
.v-malicious { color: var(--mal); font-weight: 700; }
.v-suspicious { color: var(--sus); font-weight: 700; }
.v-benign { color: var(--ben); font-weight: 700; }

/* ── language switch (CSS only — the report must stay script-free) ────────── */
.lang-radio { position: absolute; opacity: 0; pointer-events: none; }
.doc { display: none; }
#ah-lang-en:checked ~ #doc-en, #ah-lang-vi:checked ~ #doc-vi, .doc.only { display: block; }
.langbar { position: sticky; top: 0; z-index: 5; max-width: 940px; margin: 0 auto;
           display: flex; align-items: center; gap: 6px; padding: 7px 34px;
           background: #111827; color: #9aa4b2; font-size: 11px; }
.langbar .lbl { letter-spacing: 1.2px; text-transform: uppercase; margin-right: 2px; }
.langbar label { cursor: pointer; padding: 3px 12px; border-radius: 3px; border: 1px solid rgba(255,255,255,.18);
                 color: #cbd5e1; user-select: none; }
.langbar label:hover { background: rgba(255,255,255,.08); }
#ah-lang-en:checked ~ .langbar label[for="ah-lang-en"],
#ah-lang-vi:checked ~ .langbar label[for="ah-lang-vi"] { background: #f3f4f6; color: #111827; border-color: #f3f4f6; font-weight: 600; }

@media print {
  body { background: #fff; padding: 0; }
  .wrap { max-width: none; box-shadow: none; padding: 0; }
  .cover { margin: 0 0 16px; padding: 16px 18px; border-radius: 0; }
  .toc { break-after: page; }
  a { color: inherit; text-decoration: none; }
  .langbar, .noprint { display: none !important; }
}
@media (max-width: 720px) {
  .wrap { padding: 0 14px 20px; } .cover { margin: 0 -14px 16px; padding: 16px 14px; }
  .toc ol { columns: 1; } table { font-size: 10px; }
}
`

// DocMeta is what the cover band needs. It is passed separately from the
// Markdown so the header can be a designed artefact rather than parsed prose.
type DocMeta struct {
	Title       string
	Subject     string // the file (or session) the report is about
	TLP         string
	Generated   string
	Verdict     string
	Confidence  int
	ThreatScore int
	Family      string
	SHA256      string
	FileType    string
	Size        int64
	Analyst     string
	CaseRef     string
	Scope       string // "file" | "session"
	Components  int    // number of analysed components (session reports)
	// Lang is the edition shown first when the document carries several.
	Lang string
}

func verdictClass(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "malicious":
		return "mal"
	case "suspicious":
		return "sus"
	case "benign":
		return "ben"
	}
	return "unk"
}

func meterColor(score int) string {
	switch {
	case score >= 70:
		return "#ef4444"
	case score >= 45:
		return "#f59e0b"
	case score >= 20:
		return "#eab308"
	}
	return "#38bdf8"
}

// reHeading pulls the section titles for the contents list.
var reHeading = regexp.MustCompile(`(?m)^##\s+(.+?)\s*$`)

// slugify makes a stable anchor id from a heading.
func slugify(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// Edition is one language rendering of the same analysis.
type Edition struct {
	Lang     string // "en" | "vi"
	Markdown string
}

// langLabel is what the switch shows for an edition.
func langLabel(code string) string {
	switch code {
	case "vi":
		return "Tiếng Việt"
	case "en":
		return "English"
	}
	return strings.ToUpper(code)
}

// Render renders a single-language report (kept for callers that only
// have one edition).
func Render(markdown string, meta DocMeta) string {
	return RenderMulti([]Edition{{Lang: meta.Lang, Markdown: markdown}}, meta)
}

// RenderMulti puts EVERY language edition into ONE self-contained file
// with a switch at the top. A report is read by more people than the analyst who
// ran it — a Vietnamese responder and an English-speaking customer get the same
// artefact, the same hashes and the same verdict, instead of two files that can
// drift apart. The switch is pure CSS (labelled radio inputs), so it also works
// in a sandboxed preview frame, in an e-mailed copy opened offline, and under a
// strict CSP — the document never needs a script.
//
// meta.Lang selects which edition is shown first; printing outputs whichever
// edition is currently selected.
func RenderMulti(editions []Edition, meta DocMeta) string {
	if len(editions) == 0 {
		editions = []Edition{{Lang: "en"}}
	}
	tlp := strings.ToUpper(strings.TrimSpace(meta.TLP))
	if tlp == "" {
		if m := reTLPMarker.FindStringSubmatch(editions[0].Markdown); len(m) > 1 {
			tlp = strings.ToUpper(m[1])
		} else {
			tlp = "AMBER"
		}
	}
	bg, fg := tlpColor(tlp)
	esc := html.EscapeString
	selected := defaultLang(editions, meta.Lang)

	var b strings.Builder
	b.WriteString("<!doctype html>\n<html lang=\"" + esc(selected) + "\">\n<head>\n<meta charset=\"utf-8\"/>\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>\n")
	fmt.Fprintf(&b, "<title>%s</title>\n", esc(meta.Title))
	b.WriteString("<style>" + reportCSS + "</style>\n</head>\n<body>\n")

	// The radio inputs drive the CSS-only language switch and must precede every
	// element they control (the sibling combinator only looks forward).
	if len(editions) > 1 {
		for _, e := range editions {
			checked := ""
			if e.Lang == selected {
				checked = " checked"
			}
			fmt.Fprintf(&b, "<input class=\"lang-radio\" type=\"radio\" name=\"ah-lang\" id=\"ah-lang-%s\"%s>\n", esc(e.Lang), checked)
		}
		b.WriteString("<div class=\"langbar\"><span class=\"lbl\">Language</span>")
		for _, e := range editions {
			fmt.Fprintf(&b, "<label for=\"ah-lang-%s\">%s</label>", esc(e.Lang), esc(langLabel(e.Lang)))
		}
		b.WriteString("</div>\n")
	}

	for _, e := range editions {
		cls := "wrap doc"
		if len(editions) == 1 {
			cls += " only"
		}
		fmt.Fprintf(&b, "<div class=\"%s\" id=\"doc-%s\" lang=\"%s\">\n", cls, esc(e.Lang), esc(e.Lang))
		writeEdition(&b, e, meta, tlp, bg, fg)
		b.WriteString("</div>\n")
	}
	b.WriteString("</body>\n</html>\n")
	return b.String()
}

// defaultLang picks which edition is shown first: the requested one when present,
// otherwise English (the default deliverable language), otherwise what exists.
func defaultLang(editions []Edition, want string) string {
	for _, e := range editions {
		if want != "" && e.Lang == want {
			return e.Lang
		}
	}
	for _, e := range editions {
		if e.Lang == "en" {
			return "en"
		}
	}
	return editions[0].Lang
}

// writeEdition renders one language: cover band, contents, body, footer.
func writeEdition(b *strings.Builder, e Edition, meta DocMeta, tlp, bg, fg string) {
	esc := html.EscapeString
	vi := e.Lang == "vi"

	// The cover band carries the title and the verdict, so the Markdown's own title
	// line and cover table would only repeat them — lift the title out and drop
	// everything before the first section. Taking the headline from the body keeps
	// the cover in the edition's own language.
	body := e.Markdown
	headline := meta.Title
	if strings.HasPrefix(strings.TrimSpace(body), "# ") {
		if nl := strings.IndexByte(body, '\n'); nl > 2 {
			headline = strings.TrimSpace(body[2:nl])
		}
		if i := strings.Index(body, "\n## "); i > 0 {
			body = body[i+1:]
		}
	}
	if strings.TrimSpace(headline) == "" {
		headline = meta.Title
	}

	// ── cover band ────────────────────────────────────────────────────────────
	// The kicker says what KIND of report this is before the reader parses the
	// title — the same shell serves malware samples, incident sessions and captures.
	kicker := "Malware analysis report"
	switch {
	case meta.Scope == "session" && vi:
		kicker = "Báo cáo sự việc"
	case meta.Scope == "session":
		kicker = "Incident session report"
	case meta.Scope == "network" && vi:
		kicker = "Báo cáo phân tích lưu lượng mạng"
	case meta.Scope == "network":
		kicker = "Network traffic analysis report"
	case vi:
		kicker = "Báo cáo phân tích mã độc"
	}
	b.WriteString("<div class=\"cover\">\n")
	fmt.Fprintf(b, "  <div class=\"kicker\">%s</div>\n", esc(kicker))
	fmt.Fprintf(b, "  <h1>%s</h1>\n", esc(headline))
	if meta.Subject != "" {
		fmt.Fprintf(b, "  <div class=\"subject\">%s</div>\n", esc(meta.Subject))
	}
	b.WriteString("  <div class=\"row\">\n")
	if meta.Verdict != "" {
		fmt.Fprintf(b, "    <span class=\"badge %s\">%s</span>\n", verdictClass(meta.Verdict), esc(strings.ToUpper(meta.Verdict)))
	}
	if meta.Confidence > 0 {
		fmt.Fprintf(b, "    <span class=\"chip\">%s %d%%</span>\n", esc(tr(vi, "độ tin cậy", "confidence")), meta.Confidence)
	}
	if meta.Family != "" {
		fmt.Fprintf(b, "    <span class=\"chip\">%s</span>\n", esc(meta.Family))
	}
	if meta.Components > 0 {
		fmt.Fprintf(b, "    <span class=\"chip\">%d %s</span>\n", meta.Components,
			esc(tr(vi, "thành phần đã phân tích", "components analysed")))
	}
	fmt.Fprintf(b, "    <span class=\"tlp\" style=\"background:%s;color:%s\">TLP:%s</span>\n", bg, fg, esc(tlp))
	fmt.Fprintf(b, "    <span class=\"chip\">%s %d/100</span>\n", esc(tr(vi, "nguy hại", "threat")), meta.ThreatScore)
	fmt.Fprintf(b, "    <span class=\"meter\"><span style=\"width:%d%%;background:%s\"></span></span>\n",
		clampScore(meta.ThreatScore), meterColor(meta.ThreatScore))
	b.WriteString("  </div>\n")

	b.WriteString("  <div class=\"factgrid\">\n")
	fact := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			fmt.Fprintf(b, "    <div><b>%s</b> %s</div>\n", esc(k), v)
		}
	}
	fact("SHA256", "<code>"+esc(meta.SHA256)+"</code>")
	fact(tr(vi, "Định dạng", "File type"), esc(meta.FileType))
	if meta.Size > 0 {
		fact(tr(vi, "Kích thước", "Size"), fmt.Sprintf("%s bytes", humanInt(meta.Size)))
	}
	fact(tr(vi, "Lập lúc", "Generated"), esc(meta.Generated))
	fact(tr(vi, "Người phân tích", "Analyst"), esc(meta.Analyst))
	fact(tr(vi, "Mã vụ việc", "Case"), esc(meta.CaseRef))
	b.WriteString("  </div>\n</div>\n")

	// ── contents ──────────────────────────────────────────────────────────────
	headings := reHeading.FindAllStringSubmatch(body, -1)
	if len(headings) >= 3 {
		fmt.Fprintf(b, "<nav class=\"toc\">\n  <h2>%s</h2>\n  <ol>\n", esc(tr(vi, "Mục lục", "Contents")))
		for _, h := range headings {
			title := strings.TrimSpace(h[1])
			// Section titles already carry their own number ("3. Triage").
			label := title
			if i := strings.Index(title, ". "); i > 0 && i <= 3 {
				label = title[i+2:]
			}
			// Anchors are per-edition, so the two languages cannot collide.
			fmt.Fprintf(b, "    <li><a href=\"#%s-%s\">%s</a></li>\n", esc(e.Lang), slugify(title), esc(label))
		}
		b.WriteString("  </ol>\n</nav>\n")
	}

	b.WriteString(mdToHTMLPrefixed(body, e.Lang))
	if vi {
		fmt.Fprintf(b, "<div class=\"footer\">Lập bởi AnalysisHub · %s · Xử lý theo TLP:%s. "+
			"Các tín hiệu xác định (YARA, uy tín, AV ngoại tuyến, cấu hình trích xuất, hiện vật ransomware) đặt mức sàn cho kết luận; "+
			"phần đọc của AI không thể hạ mức đó.</div>\n", esc(meta.Generated), esc(tlp))
	} else {
		fmt.Fprintf(b, "<div class=\"footer\">Generated by AnalysisHub · %s · Handle according to TLP:%s. "+
			"Deterministic signals (YARA, reputation, offline AV, extracted config, ransomware artifacts) set the verdict floor; "+
			"the AI reading cannot lower it.</div>\n", esc(meta.Generated), esc(tlp))
	}
}

// tr is the two-string localiser for the chrome around the Markdown body.
func tr(vi bool, viText, enText string) string {
	if vi {
		return viText
	}
	return enText
}

// humanInt groups digits so a byte count is readable at a glance.
func humanInt(n int64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ' ')
		}
		out = append(out, c)
	}
	return string(out)
}

// clampScore keeps a 0-100 score inside its range before it becomes a CSS width.
func clampScore(n int) int {
	if n < 0 {
		return 0
	}
	if n > 100 {
		return 100
	}
	return n
}

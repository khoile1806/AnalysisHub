package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/netscan"
	"github.com/analysishub/backend/internal/report"
)

// network_report.go — the capture report, rendered through the SAME document
// shell as the malware reports (cover band with the verdict, contents list,
// bilingual EN/VI switch, print stylesheet). One report shape across the product
// means an analyst learns it once and a fix reaches every feature.
//
// GET /api/v1/network/:id/report
//   (default)         → the HTML document (what the UI opens in a tab)
//   ?format=json      → {html, markdown, …} for a preview dialog
//   ?download=html|md → the same content as a named file attachment
//   ?lang=en|vi       → which edition the document opens on (default English)

// Report renders the standalone report for a completed capture.
func (h *NetworkHandler) Report(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	var scan models.NetworkScan
	if h.DB.First(&scan, "id = ?", id).Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "not found"})
		return
	}
	var res netscan.NetworkResult
	_ = json.Unmarshal([]byte(scan.Result), &res)
	var findings []netscan.NetworkFinding
	_ = json.Unmarshal([]byte(scan.Findings), &findings)

	opt := netscan.ReportOptions{
		TLP:     strings.TrimSpace(c.Query("tlp")),
		Analyst: strings.TrimSpace(c.Query("analyst")),
		CaseRef: strings.TrimSpace(c.Query("case_ref")),
	}
	if opt.Analyst == "" {
		if uid, ok := middleware.GetUserID(c); ok {
			var user models.User
			if h.DB.First(&user, "id = ?", uid).Error == nil {
				opt.Analyst = analystLabel(&user)
			}
		}
	}

	// Both editions go into one file with an in-document switch; `lang` only picks
	// which one it opens on (and which Markdown a Markdown download returns).
	shown := "en"
	if strings.HasPrefix(strings.ToLower(c.Query("lang")), "vi") {
		shown = "vi"
	}
	build := func(lang string) string {
		o := opt
		o.Lang = lang
		return netscan.BuildReport(&scan, &res, findings, o)
	}
	editions := []report.Edition{
		{Lang: "en", Markdown: build("en")},
		{Lang: "vi", Markdown: build("vi")},
	}
	md := editions[0].Markdown
	if shown == "vi" {
		md = editions[1].Markdown
	}

	tlp := opt.TLP
	if tlp == "" {
		tlp = "amber"
	}
	meta := report.DocMeta{
		Title:       fmt.Sprintf("Network capture — %s", baseFileName(scan.FileName)),
		Subject:     captureSubject(&scan, &res),
		TLP:         tlp,
		Generated:   time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		Verdict:     scan.Verdict,
		ThreatScore: scan.ThreatScore,
		SHA256:      scan.Sha256,
		FileType:    "pcap",
		Size:        scan.Size,
		Analyst:     opt.Analyst,
		CaseRef:     opt.CaseRef,
		Scope:       "network",
		Lang:        shown,
	}
	if v := new(netscan.NetVerdict); scan.NetworkAI != "" && json.Unmarshal([]byte(scan.NetworkAI), v) == nil {
		meta.Confidence = v.Confidence
		meta.Family = v.Family
	}
	htmlDoc := report.RenderMulti(editions, meta)

	switch strings.ToLower(c.Query("download")) {
	case "html":
		name := fmt.Sprintf("%s-report.html", sanitizeExportName(scan.FileName))
		c.Header("Content-Disposition", `attachment; filename="`+name+`"`)
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(htmlDoc))
		return
	case "md", "markdown":
		name := fmt.Sprintf("%s-report.md", sanitizeExportName(scan.FileName))
		c.Header("Content-Disposition", `attachment; filename="`+name+`"`)
		c.Data(http.StatusOK, "text/markdown; charset=utf-8", []byte(md))
		return
	}

	if strings.EqualFold(c.Query("format"), "json") {
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
			"html":      htmlDoc,
			"markdown":  md,
			"title":     meta.Title,
			"lang":      shown,
			"languages": []string{"en", "vi"},
		}})
		return
	}
	// Default: the document itself — the UI opens this straight in a tab.
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(htmlDoc))
}

// captureSubject is the one-line "what this capture is" under the cover title.
func captureSubject(scan *models.NetworkScan, res *netscan.NetworkResult) string {
	parts := []string{fmt.Sprintf("%d flows · %d alerts · %d C2", scan.FlowCount, scan.AlertCount, scan.C2Count)}
	if res.Timeline != nil && res.Timeline.StartTS != "" {
		parts = append(parts, fmt.Sprintf("%s (+%ds)", res.Timeline.StartTS, res.Timeline.DurationSec))
	}
	if n := len(res.Files); n > 0 {
		parts = append(parts, fmt.Sprintf("%d file(s) transferred", n))
	}
	return strings.Join(parts, " · ")
}

// IOCs returns the capture's normalised indicator set (block list / hunt input).
//
// GET /api/v1/network/:id/iocs
func (h *NetworkHandler) IOCs(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	var scan models.NetworkScan
	if h.DB.First(&scan, "id = ?", id).Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "not found"})
		return
	}
	var res netscan.NetworkResult
	_ = json.Unmarshal([]byte(scan.Result), &res)
	var findings []netscan.NetworkFinding
	_ = json.Unmarshal([]byte(scan.Findings), &findings)
	iocs := netscan.CollectIOCs(&scan, &res, findings)

	switch strings.ToLower(c.Query("format")) {
	case "csv":
		var b strings.Builder
		b.WriteString("type,value,confidence,context,capture,verdict\n")
		q := func(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }
		for _, i := range iocs {
			fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%s\n", q(i.Type), q(i.Value), q(i.Confidence), q(i.Context),
				q(scan.FileName), q(scan.Verdict))
		}
		c.Header("Content-Disposition", `attachment; filename="`+sanitizeExportName(scan.FileName)+`-iocs.csv"`)
		c.Data(http.StatusOK, "text/csv; charset=utf-8", []byte(b.String()))
	case "suricata":
		c.Header("Content-Disposition", `attachment; filename="`+sanitizeExportName(scan.FileName)+`.rules"`)
		c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(netscan.BuildSuricataRules(&scan, iocs)))
	default:
		c.JSON(http.StatusOK, gin.H{"success": true, "data": iocs})
	}
}

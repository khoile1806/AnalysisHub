package handlers

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/vulnscan"
)

// adHocNucleiReq is the full customisation surface for a single-URL nuclei run —
// close to the CLI. ExtraArgs is a guarded free-form passthrough (dangerous flags
// are rejected in the engine).
type adHocNucleiReq struct {
	URL             string   `json:"url" binding:"required"`
	Name            string   `json:"name"`
	Severities      string   `json:"severities"`
	ExcludeSeverity string   `json:"exclude_severity"`
	Tags            string   `json:"tags"`
	IncludeTags     string   `json:"include_tags"`
	ExcludeTags     string   `json:"exclude_tags"`
	CVEIDs          []string `json:"cve_ids"`
	TemplateIDs     []string `json:"template_ids"`
	ExcludeIDs      []string `json:"exclude_ids"`
	Templates       []string `json:"templates"`
	Authors         string   `json:"authors"`
	Protocols       string   `json:"protocols"`
	Headers         []string `json:"headers"`
	Vars            []string `json:"vars"`
	RateLimit       int      `json:"rate_limit"`
	Concurrency     int      `json:"concurrency"`
	Timeout         int      `json:"timeout"`
	Retries         int      `json:"retries"`
	NewTemplates    bool     `json:"new_templates"`
	DAST            bool     `json:"dast"`
	ExtraArgs       []string `json:"extra_args"`
	ProxyChoice     string   `json:"proxy_choice"`
	AllowPrivate    bool     `json:"allow_private"`
}

func (r adHocNucleiReq) opts() vulnscan.AdHocNucleiOpts {
	ids := make([]string, 0, len(r.CVEIDs)+len(r.TemplateIDs))
	for _, t := range r.TemplateIDs {
		if t = strings.TrimSpace(t); t != "" {
			ids = append(ids, t)
		}
	}
	for _, cve := range r.CVEIDs {
		if cve = strings.ToUpper(strings.TrimSpace(cve)); cve != "" {
			ids = append(ids, cve)
		}
	}
	return vulnscan.AdHocNucleiOpts{
		Severities:      r.Severities,
		ExcludeSeverity: r.ExcludeSeverity,
		Tags:            r.Tags,
		IncludeTags:     r.IncludeTags,
		ExcludeTags:     r.ExcludeTags,
		TemplateIDs:     ids,
		ExcludeIDs:      cleanStrList(r.ExcludeIDs),
		Templates:       cleanStrList(r.Templates),
		Authors:         r.Authors,
		Protocols:       r.Protocols,
		Headers:         cleanStrList(r.Headers),
		Vars:            cleanStrList(r.Vars),
		RateLimit:       r.RateLimit,
		Concurrency:     r.Concurrency,
		Timeout:         r.Timeout,
		Retries:         r.Retries,
		NewTemplates:    r.NewTemplates,
		DAST:            r.DAST,
		ExtraArgs:       cleanStrList(r.ExtraArgs),
	}
}

func cleanStrList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func normalizeAdHocURL(raw string, allowPrivate bool) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return "", "", fmt.Errorf("invalid URL")
	}
	host := parsed.Hostname()
	if ip := net.ParseIP(host); ip != nil && !allowPrivate {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return "", "", fmt.Errorf("target is a private/loopback IP — set allow_private to scan it")
		}
	}
	return raw, host, nil
}

func adHocProxyChoice(choice string) string {
	if choice == "direct" {
		return "direct"
	}
	return "tor"
}

// RunAdHocNuclei launches a customised nuclei run against a single URL. Admin-only.
// POST /api/v1/vulnscan/nuclei
func RunAdHocNuclei(c *gin.Context) {
	if !requireVulnAdmin(c) {
		return
	}
	if !vulnScanEnabled(c) {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "vulnerability scanning is disabled"})
		return
	}
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	engine, ok := mustGetVulnEngine(c)
	if !ok {
		return
	}

	var req adHocNucleiReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	raw, host, err := normalizeAdHocURL(req.URL, req.AllowPrivate)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	opts := req.opts()
	// Validate the assembled command up-front (extra-args guard, templates,
	// protocols) so bad options are a clean 400, not a failed scan.
	if _, err := engine.PreviewAdHocArgs(opts, adHocProxyChoice(req.ProxyChoice)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		if len(opts.TemplateIDs) > 0 {
			name = "Nuclei " + strings.Join(opts.TemplateIDs, ",") + " @ " + host
		} else {
			name = "Ad-hoc nuclei @ " + host
		}
	}

	uid, _ := middleware.GetUserID(c)
	tj, _ := json.Marshal([]string{raw})
	toolsJSON, _ := json.Marshal([]string{"nuclei"})
	scan := models.VulnScan{
		Name:         name,
		Status:       models.VulnPending,
		Targets:      string(tj),
		TargetCount:  1,
		Tools:        string(toolsJSON),
		Severities:   req.Severities,
		Profile:      "adhoc",
		Tags:         req.Tags,
		ProxyChoice:  adHocProxyChoice(req.ProxyChoice),
		AllowPrivate: req.AllowPrivate,
		CreatedBy:    uid,
	}
	if err := db.Create(&scan).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "could not create scan"})
		return
	}
	writeAudit(c, db, &scan.CreatedBy, nil, "vulnscan.adhoc", scan.ID.String(),
		fmt.Sprintf("url=%s ids=%s tags=%s", raw, strings.Join(opts.TemplateIDs, ","), opts.Tags))

	if err := engine.StartAdHocScan(&scan, raw, opts); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": scan})
}

// PreviewAdHocNuclei returns the exact nuclei command a run would execute
// (validated), so the UI can show it like a CLI invocation before launching.
// POST /api/v1/vulnscan/nuclei/preview
func PreviewAdHocNuclei(c *gin.Context) {
	if !requireVulnAdmin(c) {
		return
	}
	engine, ok := mustGetVulnEngine(c)
	if !ok {
		return
	}
	var req adHocNucleiReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	raw, _, err := normalizeAdHocURL(req.URL, req.AllowPrivate)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	args, err := engine.PreviewAdHocArgs(req.opts(), adHocProxyChoice(req.ProxyChoice))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	// Show "-u <url>" instead of the internal "-l targets.txt" for a copy-paste-like
	// command line.
	display := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "-l" && i+1 < len(args) {
			display = append(display, "-u", raw)
			i++
			continue
		}
		display = append(display, args[i])
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"command": "nuclei " + shellJoin(display),
		"args":    display,
	}})
}

// shellJoin quotes argv tokens that contain shell-significant characters so the
// preview reads like a real command line.
func shellJoin(args []string) string {
	parts := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\"'$&|<>();`\\*?") {
			parts[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		} else {
			parts[i] = a
		}
	}
	return strings.Join(parts, " ")
}

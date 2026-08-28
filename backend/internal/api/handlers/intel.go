package handlers

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/analysishub/backend/internal/threatintel"
)

// IntelHandler serves on-demand threat-intelligence lookups (VirusTotal +
// AbuseIPDB / OTX / Shodan when configured) for a single indicator — used by the
// "look this up" buttons next to a suspicious process / IP / file hash.
type IntelHandler struct {
	enrich *threatintel.EnrichClient
}

func NewIntelHandler(enrich *threatintel.EnrichClient) *IntelHandler {
	return &IntelHandler{enrich: enrich}
}

var (
	reHashIntel   = regexp.MustCompile(`^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$`)
	reIPv4Intel   = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}$`)
	reDomainIntel = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
)

// detectIndicatorType classifies a raw indicator. Returns "" when unsupported.
func detectIndicatorType(v string) string {
	v = strings.TrimSpace(v)
	switch {
	case reHashIntel.MatchString(v):
		return "hash"
	case reIPv4Intel.MatchString(v):
		return "ip"
	case strings.HasPrefix(strings.ToLower(v), "http://"), strings.HasPrefix(strings.ToLower(v), "https://"):
		return "url"
	case reDomainIntel.MatchString(v):
		return "domain"
	default:
		return ""
	}
}

// vtGUIURL builds the human-facing VirusTotal page for an indicator so the
// operator can always open the full report even without an API key.
func vtGUIURL(indicator, itype string) string {
	switch itype {
	case "hash":
		return "https://www.virustotal.com/gui/file/" + url.PathEscape(indicator)
	case "ip":
		return "https://www.virustotal.com/gui/ip-address/" + url.PathEscape(indicator)
	case "domain":
		return "https://www.virustotal.com/gui/domain/" + url.PathEscape(indicator)
	default:
		return "https://www.virustotal.com/gui/search/" + url.PathEscape(indicator)
	}
}

// Lookup performs a live threat-intel lookup for one indicator.
//
// GET /api/v1/intel/lookup?indicator=<value>&type=<auto|ip|hash|domain|url>
func (h *IntelHandler) Lookup(c *gin.Context) {
	indicator := strings.TrimSpace(c.Query("indicator"))
	if indicator == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "indicator is required"})
		return
	}

	itype := strings.ToLower(strings.TrimSpace(c.Query("type")))
	if itype == "" || itype == "auto" {
		itype = detectIndicatorType(indicator)
	}
	if itype == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "could not classify indicator (expected hash, IP, domain or URL)"})
		return
	}

	resp := gin.H{
		"success":   true,
		"indicator": indicator,
		"type":      itype,
		"vt_url":    vtGUIURL(indicator, itype),
	}

	// Without keys we still hand back the VT GUI link so the operator can check
	// manually — this endpoint never hard-fails on missing configuration.
	if h.enrich == nil || !h.enrich.Configured() {
		resp["configured"] = false
		resp["message"] = "No threat-intel API keys configured — open the VirusTotal link to check manually."
		c.JSON(http.StatusOK, resp)
		return
	}

	var set threatintel.IOCSet
	switch itype {
	case "ip":
		set.IPs = []string{indicator}
	case "hash":
		set.Hashes = []string{strings.ToLower(indicator)}
	case "domain":
		set.Domains = []string{indicator}
	case "url":
		set.URLs = []string{indicator}
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 25*time.Second)
	defer cancel()
	results := h.enrich.Enrich(ctx, set)

	resp["configured"] = true
	if len(results.Results) > 0 {
		r := results.Results[0]
		resp["threat"] = r.Threat
		resp["max_score"] = r.MaxScore
		resp["findings"] = r.Findings
		// The UI needs these to distinguish a clean verdict from an unanswered one.
		resp["complete"] = r.Complete
		resp["unavailable"] = r.Unavailable
	} else {
		resp["threat"] = false
		resp["max_score"] = 0
		resp["findings"] = []threatintel.Finding{}
	}
	c.JSON(http.StatusOK, resp)
}

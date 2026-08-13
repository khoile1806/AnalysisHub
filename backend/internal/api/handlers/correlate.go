package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/analysishub/backend/internal/malware"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/netscan"
)

// correlate.go — the link between a sample and the wire.
//
// Malware Analysis and Network Analysis each hold half of the same incident and
// neither could see the other's half. The two questions this answers are the ones
// an analyst asks immediately and previously had to answer by hand, by grepping
// their own notes:
//
//   - "This sample calls out to X. Did X ever show up in a capture we took?"
//   - "This capture talks to Y and carried file Z. Do we already have a sample?"
//
// Matching is on the indicator VALUE, so it works across features without either
// side knowing about the other's schema. Hashes match a stored sample outright;
// hosts match what the capture actually resolved, requested or connected to.

// correlationMaxScans bounds how far back each side looks. Correlation is a
// convenience pivot, not an archive search.
const correlationMaxScans = 300

// CorrelationHit is one capture (or sample) that shares an indicator.
type CorrelationHit struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Verdict    string   `json:"verdict,omitempty"`
	When       string   `json:"when,omitempty"`
	Indicators []string `json:"indicators"` // the shared values, not everything either side holds
	Via        string   `json:"via"`        // c2 | url | domain | ip | sha256
}

// MalwareNetworkMatches finds captures whose traffic contains this sample's
// network indicators.
//
// GET /api/v1/malware/:id/network-matches
func (h *MalwareHandler) MalwareNetworkMatches(c *gin.Context) {
	scan, ok := h.loadScan(c)
	if !ok {
		return
	}
	// Only indicators strong enough to justify a pivot. A hostname that merely
	// appeared as a string in a binary would match half the internet's CDNs.
	wanted := map[string]string{} // lowered value -> ioc type
	for _, i := range malware.CollectIOCs(scan) {
		switch i.Type {
		case "url", "domain", "ip":
		default:
			continue
		}
		if strings.EqualFold(i.Confidence, "low") {
			continue
		}
		if v := hostOfIndicator(i.Value); v != "" {
			wanted[v] = i.Type
		}
	}
	if len(wanted) == 0 {
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"matches": []CorrelationHit{},
			"detail": "this analysis produced no medium/high-confidence network indicator to pivot on"}})
		return
	}

	var captures []models.NetworkScan
	h.DB.Where("status = ?", "done").Order("created_at desc").Limit(correlationMaxScans).Find(&captures)

	matches := []CorrelationHit{}
	for i := range captures {
		cap := captures[i]
		shared := sharedWithCapture(&cap, wanted)
		if len(shared) == 0 {
			continue
		}
		matches = append(matches, CorrelationHit{
			ID: cap.ID.String(), Name: cap.FileName, Verdict: cap.Verdict,
			When: cap.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"),
			Indicators: shared, Via: wanted[shared[0]],
		})
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"matches": matches, "searched_captures": len(captures), "indicators_used": len(wanted)}})
}

// NetworkMalwareMatches finds stored samples related to this capture — by a file
// carried over the wire (hash match) or by a C2 address the sample also contacts.
//
// GET /api/v1/network/:id/malware-matches
func (h *NetworkHandler) NetworkMalwareMatches(c *gin.Context) {
	id, perr := uuid.Parse(c.Param("id"))
	if perr != nil {
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
	hashes := map[string]bool{}
	for _, f := range res.Files {
		if f.SHA256 != "" {
			hashes[strings.ToLower(f.SHA256)] = true
		}
	}
	hosts := map[string]bool{}
	for _, i := range netscan.CollectIOCs(&scan, &res, findings) {
		if strings.EqualFold(i.Confidence, "low") {
			continue
		}
		switch i.Type {
		case "ip", "domain", "url":
			if v := hostOfIndicator(i.Value); v != "" {
				hosts[v] = true
			}
		case "sha256":
			hashes[strings.ToLower(i.Value)] = true
		}
	}

	matches := []CorrelationHit{}
	if len(hashes) > 0 {
		list := make([]string, 0, len(hashes))
		for hsh := range hashes {
			list = append(list, hsh)
		}
		var samples []models.MalwareScan
		h.DB.Where("LOWER(sha256) IN ?", list).Limit(correlationMaxScans).Find(&samples)
		for i := range samples {
			s := samples[i]
			matches = append(matches, CorrelationHit{
				ID: s.ID.String(), Name: s.FileName, Verdict: s.Verdict,
				When: s.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"),
				Indicators: []string{s.SHA256}, Via: "sha256",
			})
		}
	}

	if len(hosts) > 0 {
		var samples []models.MalwareScan
		h.DB.Where("status = ? AND iocs <> ''", "done").
			Order("created_at desc").Limit(correlationMaxScans).Find(&samples)
		seen := map[string]bool{}
		for _, m := range matches {
			seen[m.ID] = true
		}
		for i := range samples {
			s := samples[i]
			if seen[s.ID.String()] {
				continue
			}
			var iocs []malware.IOCEntry
			if json.Unmarshal([]byte(s.IOCs), &iocs) != nil {
				continue
			}
			var shared []string
			for _, ioc := range iocs {
				switch ioc.Type {
				case "url", "domain", "ip":
				default:
					continue
				}
				if strings.EqualFold(ioc.Confidence, "low") {
					continue
				}
				if v := hostOfIndicator(ioc.Value); v != "" && hosts[v] && !contains(shared, v) {
					shared = append(shared, v)
				}
			}
			if len(shared) == 0 {
				continue
			}
			matches = append(matches, CorrelationHit{
				ID: s.ID.String(), Name: s.FileName, Verdict: s.Verdict,
				When: s.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"),
				Indicators: shared, Via: "c2",
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"matches": matches, "hashes_seen": len(hashes), "hosts_seen": len(hosts)}})
}

// sharedWithCapture returns the wanted indicators this capture actually contains.
func sharedWithCapture(cap *models.NetworkScan, wanted map[string]string) []string {
	var res netscan.NetworkResult
	if strings.TrimSpace(cap.Result) == "" || json.Unmarshal([]byte(cap.Result), &res) != nil {
		return nil
	}
	seen := map[string]bool{}
	var shared []string
	hit := func(v string) {
		v = hostOfIndicator(v)
		if v == "" || seen[v] {
			return
		}
		if _, want := wanted[v]; !want {
			return
		}
		seen[v] = true
		shared = append(shared, v)
	}
	for _, d := range res.DNS {
		hit(d.Query)
		for _, a := range d.Answers {
			hit(a)
		}
	}
	for _, t := range res.TLS {
		hit(t.SNI)
	}
	for _, hreq := range res.HTTP {
		hit(hreq.Host)
	}
	for _, f := range res.Flows {
		hit(f.Dst)
	}
	return shared
}

// hostOfIndicator normalises a URL/domain/IP to the bare host, so the same C2
// matches whether one side saw a full URL and the other only the hostname.
func hostOfIndicator(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return ""
	}
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i]
	}
	if i := strings.Index(v, "@"); i >= 0 { // user:pass@host
		v = v[i+1:]
	}
	// Strip a port, but leave a bare IPv6 literal alone.
	if !strings.Contains(v, "]") {
		if i := strings.LastIndex(v, ":"); i > 0 && strings.Count(v, ":") == 1 {
			v = v[:i]
		}
	}
	return strings.Trim(v, ".")
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

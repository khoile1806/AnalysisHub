package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const vtBase = "https://www.virustotal.com/api/v3"

func (c *EnrichClient) lookupVT(ctx context.Context, ioc, itype, key string) (Finding, bool) {
	if key == "" {
		return Finding{}, false
	}

	var endpoint string
	switch itype {
	case "ip":
		endpoint = vtBase + "/ip_addresses/" + ioc
	case "hash":
		endpoint = vtBase + "/files/" + ioc
	case "domain":
		endpoint = vtBase + "/domains/" + ioc
	default:
		return Finding{}, false
	}

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return Finding{}, false
	}
	req.Header.Set("x-apikey", key)

	resp, err := c.hc.Do(req)
	if err != nil {
		return Finding{}, false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return Finding{
			Source:  "VirusTotal",
			Summary: "Not found in the VT database",
			Score:   0,
		}, true
	}
	if resp.StatusCode != 200 {
		return Finding{}, false
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))

	var result struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
				PopularThreatClassification struct {
					SuggestedThreatLabel  string `json:"suggested_threat_label"`
					PopularThreatCategory []struct {
						Value string `json:"value"`
					} `json:"popular_threat_category"`
				} `json:"popular_threat_classification"`
				Tags        []string `json:"tags"`
				Country     string   `json:"country"`
				ASOwner     string   `json:"as_owner"`
				Reputation  int      `json:"reputation"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return Finding{}, false
	}

	stats := result.Data.Attributes.LastAnalysisStats
	total := stats.Malicious + stats.Suspicious + stats.Harmless + stats.Undetected
	if total == 0 {
		return Finding{Source: "VirusTotal", Summary: "No analysis data in VT yet", Score: 0}, true
	}

	flagged := stats.Malicious + stats.Suspicious
	score := (flagged * 100) / total
	malicious := stats.Malicious > 2

	summary := fmt.Sprintf("%d/%d engines flagged it malicious", stats.Malicious, total)
	if stats.Suspicious > 0 {
		summary += fmt.Sprintf(" (%d suspicious)", stats.Suspicious)
	}

	// Collect labels: suggested label + popular categories + tags
	seen := make(map[string]bool)
	var labels []string
	addLabel := func(l string) {
		if l != "" && !seen[l] && len(labels) < 5 {
			seen[l] = true
			labels = append(labels, l)
		}
	}
	addLabel(result.Data.Attributes.PopularThreatClassification.SuggestedThreatLabel)
	for _, cat := range result.Data.Attributes.PopularThreatClassification.PopularThreatCategory {
		addLabel(cat.Value)
	}
	for _, tag := range result.Data.Attributes.Tags {
		addLabel(tag)
	}

	extra := make(map[string]string)
	if result.Data.Attributes.Country != "" {
		extra["Country"] = result.Data.Attributes.Country
	}
	if result.Data.Attributes.ASOwner != "" {
		extra["ASN Owner"] = result.Data.Attributes.ASOwner
	}

	return Finding{
		Source:    "VirusTotal",
		Score:     score,
		Malicious: malicious,
		Summary:   summary,
		Labels:    labels,
		Extra:     extra,
	}, true
}

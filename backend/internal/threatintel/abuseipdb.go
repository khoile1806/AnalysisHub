package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const abuseIPDBBase = "https://api.abuseipdb.com/api/v2"

func (c *EnrichClient) lookupAbuseIPDB(ctx context.Context, ip string) (Finding, bool) {
	if c.abuseIPDB == "" {
		return Finding{}, false
	}

	url := abuseIPDBBase + "/check?ipAddress=" + ip + "&maxAgeInDays=90"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return Finding{}, false
	}
	req.Header.Set("Key", c.abuseIPDB)
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return Finding{}, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return Finding{}, false
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	var result struct {
		Data struct {
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			CountryCode          string `json:"countryCode"`
			TotalReports         int    `json:"totalReports"`
			NumDistinctUsers     int    `json:"numDistinctUsers"`
			LastReportedAt       string `json:"lastReportedAt"`
			ISP                  string `json:"isp"`
			UsageType            string `json:"usageType"`
			Domain               string `json:"domain"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return Finding{}, false
	}

	d := result.Data
	score := d.AbuseConfidenceScore
	malicious := score >= 50

	summary := fmt.Sprintf("Confidence score: %d/100 | %d report(s) từ %d user(s)",
		score, d.TotalReports, d.NumDistinctUsers)

	extra := make(map[string]string)
	if d.CountryCode != "" {
		extra["Country"] = d.CountryCode
	}
	if d.ISP != "" {
		extra["ISP"] = d.ISP
	}
	if d.UsageType != "" {
		extra["Usage"] = d.UsageType
	}
	if d.LastReportedAt != "" {
		extra["Last reported"] = d.LastReportedAt
	}

	return Finding{
		Source:    "AbuseIPDB",
		Score:     score,
		Malicious: malicious,
		Summary:   summary,
		Extra:     extra,
	}, true
}

package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const shodanBase = "https://api.shodan.io"

func (c *EnrichClient) lookupShodan(ctx context.Context, ip string) (Finding, error) {
	if c.shodan == "" {
		return Finding{}, errNotApplicable
	}

	url := shodanBase + "/shodan/host/" + ip + "?key=" + c.shodan
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return Finding{}, unavailable("Shodan", err)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return Finding{}, unavailable("Shodan", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return Finding{Source: "Shodan", Summary: "IP not in the Shodan index"}, nil
	}
	if resp.StatusCode != 200 {
		return Finding{}, unavailableStatus("Shodan", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))

	var result struct {
		Ports       []int                  `json:"ports"`
		Tags        []string               `json:"tags"`
		Vulns       map[string]interface{} `json:"vulns"`
		Org         string                 `json:"org"`
		ISP         string                 `json:"isp"`
		CountryName string                 `json:"country_name"`
		Hostnames   []string               `json:"hostnames"`
		OS          string                 `json:"os"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return Finding{}, unavailable("Shodan", err)
	}

	portStrs := make([]string, 0, len(result.Ports))
	for _, p := range result.Ports {
		portStrs = append(portStrs, fmt.Sprintf("%d", p))
	}

	vulnCount := len(result.Vulns)

	summary := fmt.Sprintf("Open ports: [%s]", strings.Join(portStrs, ", "))
	if vulnCount > 0 {
		summary += fmt.Sprintf(" | %d CVE(s)", vulnCount)
	}

	malicious := vulnCount > 0 || tagsContainAny(result.Tags, "tor", "vpn", "proxy", "scanner", "botnet", "malware")

	score := 0
	if vulnCount > 0 {
		score = min(20+vulnCount*10, 60)
	}

	extra := make(map[string]string)
	if result.Org != "" {
		extra["Org"] = result.Org
	}
	if result.CountryName != "" {
		extra["Country"] = result.CountryName
	}
	if result.OS != "" {
		extra["OS"] = result.OS
	}
	if len(result.Hostnames) > 0 && len(result.Hostnames) <= 3 {
		extra["Hostnames"] = strings.Join(result.Hostnames, ", ")
	}
	if vulnCount > 0 {
		vulnList := make([]string, 0, min(vulnCount, 5))
		for cve := range result.Vulns {
			vulnList = append(vulnList, cve)
			if len(vulnList) >= 5 {
				break
			}
		}
		extra["CVEs"] = strings.Join(vulnList, ", ")
	}

	return Finding{
		Source:    "Shodan",
		Score:     score,
		Malicious: malicious,
		Summary:   summary,
		Labels:    result.Tags,
		Extra:     extra,
	}, nil
}

func tagsContainAny(tags []string, keywords ...string) bool {
	for _, t := range tags {
		t = strings.ToLower(t)
		for _, k := range keywords {
			if t == k || strings.Contains(t, k) {
				return true
			}
		}
	}
	return false
}

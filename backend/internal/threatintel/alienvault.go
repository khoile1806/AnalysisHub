package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const ovBase = "https://otx.alienvault.com/api/v1/indicators"

func (c *EnrichClient) lookupAlienVault(ctx context.Context, ioc, itype string) (Finding, bool) {
	if c.alienVault == "" {
		return Finding{}, false
	}

	var endpoint string
	switch itype {
	case "ip":
		endpoint = ovBase + "/IPv4/" + ioc + "/general"
	case "hash":
		endpoint = ovBase + "/file/" + ioc + "/general"
	case "domain":
		endpoint = ovBase + "/domain/" + ioc + "/general"
	default:
		return Finding{}, false
	}

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return Finding{}, false
	}
	req.Header.Set("X-OTX-API-KEY", c.alienVault)

	resp, err := c.hc.Do(req)
	if err != nil {
		return Finding{}, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return Finding{}, false
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))

	var result struct {
		PulseInfo struct {
			Count  int `json:"count"`
			Pulses []struct {
				Name string `json:"name"`
			} `json:"pulses"`
		} `json:"pulse_info"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return Finding{}, false
	}

	count := result.PulseInfo.Count
	malicious := count > 0
	summary := fmt.Sprintf("%d threat pulse(s) liên quan", count)

	// Include up to 3 pulse names as labels
	var labels []string
	for i, p := range result.PulseInfo.Pulses {
		if i >= 3 {
			break
		}
		if p.Name != "" {
			labels = append(labels, p.Name)
		}
	}

	score := 0
	if count > 0 {
		score = min(count*10, 80)
	}

	return Finding{
		Source:    "AlienVault OTX",
		Score:     score,
		Malicious: malicious,
		Summary:   summary,
		Labels:    labels,
	}, true
}

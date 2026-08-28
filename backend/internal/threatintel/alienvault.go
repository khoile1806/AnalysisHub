package threatintel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
)

const ovBase = "https://otx.alienvault.com/api/v1/indicators"

func (c *EnrichClient) lookupAlienVault(ctx context.Context, ioc, itype string) (Finding, error) {
	if c.alienVault == "" {
		return Finding{}, errNotApplicable
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
		return Finding{}, errNotApplicable
	}

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return Finding{}, unavailable("AlienVault OTX", err)
	}
	req.Header.Set("X-OTX-API-KEY", c.alienVault)

	resp, err := c.hc.Do(req)
	if err != nil {
		return Finding{}, unavailable("AlienVault OTX", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return Finding{}, unavailableStatus("AlienVault OTX", resp.StatusCode)
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
		return Finding{}, unavailable("AlienVault OTX", err)
	}

	count := result.PulseInfo.Count
	malicious := otxMalicious(count)
	summary := otxSummary(count)

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

	score := otxScore(count)

	return Finding{
		Source:    "AlienVault OTX",
		Score:     score,
		Malicious: malicious,
		Summary:   summary,
		Labels:    labels,
	}, nil
}

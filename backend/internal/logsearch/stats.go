package logsearch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// ClusterStatus returns the cluster health colour (green/yellow/red) and whether
// Elasticsearch answered at all.
func (c *ESClient) ClusterStatus() (string, bool) {
	resp, err := c.http.Get(c.baseURL + "/_cluster/health")
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", false
	}
	var body struct {
		Status string `json:"status"`
	}
	if json.NewDecoder(resp.Body).Decode(&body) != nil {
		return "", true
	}
	return body.Status, true
}

// Bucket is one aggregation term.
type Bucket struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// Summary is a fast triage view over the ingested logs (optionally one case).
type Summary struct {
	Total        int64    `json:"total"`
	MinTime      string   `json:"min_time"`
	MaxTime      string   `json:"max_time"`
	ByCategory   []Bucket `json:"by_category"`
	ByLogType    []Bucket `json:"by_log_type"`
	TopSourceIP  []Bucket `json:"top_source_ip"`
	TopEventCode []Bucket `json:"top_event_code"`
}

// Summarize aggregates hunt-* (optionally filtered to one case) for triage.
func (c *ESClient) Summarize(caseName string) (*Summary, error) {
	query := map[string]interface{}{"match_all": map[string]interface{}{}}
	if caseName != "" {
		query = map[string]interface{}{"term": map[string]interface{}{"hunt.case": caseName}}
	}
	body, _ := json.Marshal(map[string]interface{}{
		"size":             0,
		"track_total_hits": true,
		"query":            query,
		"aggs": map[string]interface{}{
			"min_ts":         map[string]interface{}{"min": map[string]interface{}{"field": "@timestamp"}},
			"max_ts":         map[string]interface{}{"max": map[string]interface{}{"field": "@timestamp"}},
			"by_category":    termsAgg("hunt.category", 20),
			"by_log_type":    termsAgg("hunt.log_type", 20),
			"top_source_ip":  termsAgg("source.ip", 10),
			"top_event_code": termsAgg("event.code", 10),
		},
	})

	url := fmt.Sprintf("%s/%s-*/_search?ignore_unavailable=true", c.baseURL, IndexPrefix)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return &Summary{}, nil // no indices yet → empty summary, not an error
	}

	var parsed struct {
		Hits struct {
			Total struct {
				Value int64 `json:"value"`
			} `json:"total"`
		} `json:"hits"`
		Aggregations struct {
			MinTS struct {
				ValueAsString string `json:"value_as_string"`
			} `json:"min_ts"`
			MaxTS struct {
				ValueAsString string `json:"value_as_string"`
			} `json:"max_ts"`
			ByCategory   termsResult `json:"by_category"`
			ByLogType    termsResult `json:"by_log_type"`
			TopSourceIP  termsResult `json:"top_source_ip"`
			TopEventCode termsResult `json:"top_event_code"`
		} `json:"aggregations"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}

	return &Summary{
		Total:        parsed.Hits.Total.Value,
		MinTime:      parsed.Aggregations.MinTS.ValueAsString,
		MaxTime:      parsed.Aggregations.MaxTS.ValueAsString,
		ByCategory:   parsed.Aggregations.ByCategory.buckets(),
		ByLogType:    parsed.Aggregations.ByLogType.buckets(),
		TopSourceIP:  parsed.Aggregations.TopSourceIP.buckets(),
		TopEventCode: parsed.Aggregations.TopEventCode.buckets(),
	}, nil
}

func termsAgg(field string, size int) map[string]interface{} {
	return map[string]interface{}{"terms": map[string]interface{}{"field": field, "size": size}}
}

type termsResult struct {
	Buckets []struct {
		Key      interface{} `json:"key"`
		DocCount int64       `json:"doc_count"`
	} `json:"buckets"`
}

func (t termsResult) buckets() []Bucket {
	out := make([]Bucket, 0, len(t.Buckets))
	for _, b := range t.Buckets {
		out = append(out, Bucket{Key: fmt.Sprintf("%v", b.Key), Count: b.DocCount})
	}
	return out
}

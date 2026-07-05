package logsearch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// IndexPrefix is the first segment of every index this module creates. Indices
// are named hunt-<category>-<case>-<logtype> so the hunt UI can filter by
// category (hunt-windows-*), by case, or search everything (hunt-*).
const IndexPrefix = "hunt"

const bulkChunkSize = 2000

// ESClient is a minimal Elasticsearch client for the built-in log store. The
// store runs on the internal network with security disabled, so no auth.
type ESClient struct {
	baseURL  string
	http     *http.Client
	tmplOnce sync.Once
	tmplErr  error
}

// NewESClient returns a client for baseURL (e.g. http://elasticsearch:9200).
func NewESClient(baseURL string) *ESClient {
	return &ESClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 120 * time.Second},
	}
}

// Ping reports whether the cluster answers.
func (c *ESClient) Ping() bool {
	resp, err := c.http.Get(c.baseURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode < 300
}

// IndexInfo is one row of /_cat/indices.
type IndexInfo struct {
	Index string `json:"index"`
	Docs  string `json:"docs"`
	Size  string `json:"size"`
}

// CatIndices lists the hunt-* indices with doc counts and sizes.
func (c *ESClient) CatIndices() ([]IndexInfo, error) {
	url := fmt.Sprintf("%s/_cat/indices/%s-*?format=json&h=index,docs.count,store.size", c.baseURL, IndexPrefix)
	resp, err := c.http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return []IndexInfo{}, nil // no indices yet → empty, not an error
	}
	var rows []map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, err
	}
	out := make([]IndexInfo, 0, len(rows))
	for _, r := range rows {
		out = append(out, IndexInfo{Index: r["index"], Docs: r["docs.count"], Size: r["store.size"]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out, nil
}

// DeleteIndex removes a single hunt index. Refuses non-hunt indices.
func (c *ESClient) DeleteIndex(index string) error {
	if !strings.HasPrefix(index, IndexPrefix+"-") {
		return fmt.Errorf("refusing to delete non-hunt index %q", index)
	}
	req, _ := http.NewRequest(http.MethodDelete, c.baseURL+"/"+index, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("delete %s: status %d", index, resp.StatusCode)
	}
	return nil
}

// EnsureTemplate installs the ECS index template once per client.
func (c *ESClient) EnsureTemplate() error {
	c.tmplOnce.Do(func() {
		body, _ := json.Marshal(indexTemplate())
		req, _ := http.NewRequest(http.MethodPut, c.baseURL+"/_index_template/"+IndexPrefix+"-template", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			c.tmplErr = err
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			b, _ := io.ReadAll(resp.Body)
			c.tmplErr = fmt.Errorf("install template: status %d: %s", resp.StatusCode, string(b))
		}
	})
	return c.tmplErr
}

// IndexName builds hunt-<category>-<case>-<logtype>.
func IndexName(caseName, logType string) string {
	category := LogTypeCategory[logType]
	if category == "" {
		category = "other"
	}
	return fmt.Sprintf("%s-%s-%s-%s", IndexPrefix, category, Sanitize(caseName), Sanitize(logType))
}

// IngestFile parses one file and bulk-indexes it into the store. onProgress is
// called periodically with (indexed, failed). It returns the target index and
// final counts.
func (c *ESClient) IngestFile(path, displayName, caseName, logType string, onProgress func(indexed, failed int)) (index string, indexed, failed int, err error) {
	if logType == TypeAuto {
		logType = DetectLogType(path, displayName)
	}
	if err = c.EnsureTemplate(); err != nil {
		return "", 0, 0, err
	}
	index = IndexName(caseName, logType)
	category := LogTypeCategory[logType]
	if category == "" {
		category = "other"
	}
	ingestTime := time.Now().UTC().Format(time.RFC3339Nano)

	var buf bytes.Buffer
	pending := 0
	flush := func() error {
		if pending == 0 {
			return nil
		}
		ok, bad, ferr := c.bulk(index, &buf)
		indexed += ok
		failed += bad
		buf.Reset()
		pending = 0
		if onProgress != nil {
			onProgress(indexed, failed)
		}
		return ferr
	}

	perr := Parse(path, logType, func(doc Doc) error {
		hunt := Doc{"case": caseName, "log_type": logType, "category": category, "source_file": displayName}
		if _, ok := doc["@timestamp"]; !ok || doc["@timestamp"] == "" {
			doc["@timestamp"] = ingestTime
			hunt["timestamp_missing"] = true
		}
		doc["hunt"] = hunt

		buf.WriteString("{\"index\":{}}\n")
		line, merr := json.Marshal(doc)
		if merr != nil {
			return nil // skip a doc that won't marshal rather than abort the file
		}
		buf.Write(line)
		buf.WriteByte('\n')
		pending++
		if pending >= bulkChunkSize {
			return flush()
		}
		return nil
	})
	if perr != nil {
		return index, indexed, failed, perr
	}
	if ferr := flush(); ferr != nil {
		return index, indexed, failed, ferr
	}
	return index, indexed, failed, nil
}

// bulk posts an NDJSON bulk body and returns (ok, failed).
func (c *ESClient) bulk(index string, body *bytes.Buffer) (int, int, error) {
	url := fmt.Sprintf("%s/%s/_bulk", c.baseURL, index)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body.Bytes()))
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return 0, 0, fmt.Errorf("bulk status %d: %s", resp.StatusCode, truncate(string(respBody), 300))
	}
	var parsed struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Status int `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return 0, 0, err
	}
	ok, failed := 0, 0
	for _, item := range parsed.Items {
		for _, r := range item {
			if r.Status >= 200 && r.Status < 300 {
				ok++
			} else {
				failed++
			}
		}
	}
	return ok, failed, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

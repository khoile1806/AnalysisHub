package logsearch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
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
	baseURL       string
	retentionDays int
	http          *http.Client
	tmplMu        sync.Mutex
	tmplDone      bool // true once the ILM policy + index template are installed
}

// NewESClient returns a client for baseURL (e.g. http://elasticsearch:9200).
// retentionDays > 0 attaches an ILM policy that deletes hunt-* indices after
// that many days; 0 keeps them forever.
func NewESClient(baseURL string, retentionDays int) *ESClient {
	return &ESClient{
		baseURL:       strings.TrimRight(baseURL, "/"),
		retentionDays: retentionDays,
		http:          &http.Client{Timeout: 120 * time.Second},
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

// EnsureTemplate installs the ILM policy (when retention is set) and the ECS
// index template once per client.
func (c *ESClient) EnsureTemplate() error {
	c.tmplMu.Lock()
	defer c.tmplMu.Unlock()
	if c.tmplDone {
		return nil
	}

	// The ILM step is best-effort; only the index template gates ingestion. We
	// deliberately do NOT latch on error (unlike sync.Once) so that ingesting
	// after Elasticsearch was down — e.g. the admin stopped ELK, then started it
	// again — succeeds on the next attempt instead of failing forever.
	ilmPolicy := ""
	if c.retentionDays > 0 {
		if err := c.ensureILM(); err != nil {
			fmt.Printf("logsearch: install ILM policy failed: %v\n", err)
		} else {
			ilmPolicy = IndexPrefix + "-logs"
		}
	}
	body, _ := json.Marshal(indexTemplate(ilmPolicy))
	req, _ := http.NewRequest(http.MethodPut, c.baseURL+"/_index_template/"+IndexPrefix+"-template", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("install template: status %d: %s", resp.StatusCode, string(b))
	}
	c.tmplDone = true
	return nil
}

// ensureILM installs a delete-after-N-days lifecycle policy named hunt-logs.
func (c *ESClient) ensureILM() error {
	policy := map[string]interface{}{
		"policy": map[string]interface{}{
			"phases": map[string]interface{}{
				"delete": map[string]interface{}{
					"min_age": fmt.Sprintf("%dd", c.retentionDays),
					"actions": map[string]interface{}{"delete": map[string]interface{}{}},
				},
			},
		},
	}
	body, _ := json.Marshal(policy)
	req, _ := http.NewRequest(http.MethodPut, c.baseURL+"/_ilm/policy/"+IndexPrefix+"-logs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, truncate(string(b), 200))
	}
	return nil
}

// IndexName builds hunt-<category>-<case>-<logtype>.
func IndexName(caseName, logType string) string {
	return IndexNameHost(caseName, "", logType)
}

// IndexNameHost builds hunt-<category>-<case>-<host>-<logtype>. When host is
// empty it omits the host segment (backward-compatible with manual uploads);
// agent-collected logs pass their source host so each host lands in its own
// indices — the repository can then group and delete by host cleanly.
func IndexNameHost(caseName, host, logType string) string {
	category := LogTypeCategory[logType]
	if category == "" {
		category = "other"
	}
	if strings.TrimSpace(host) != "" {
		return fmt.Sprintf("%s-%s-%s-%s-%s", IndexPrefix, category, Sanitize(caseName), Sanitize(host), Sanitize(logType))
	}
	return fmt.Sprintf("%s-%s-%s-%s", IndexPrefix, category, Sanitize(caseName), Sanitize(logType))
}

// IngestPath ingests an upload: a single log file, or a .zip/.tar(.gz) archive
// whose inner files are each detected and ingested. Returns the distinct target
// indices and aggregate counts. onProgress reports running (indexed, failed).
// host scopes the target indices to a source host ("" for manual uploads).
func (c *ESClient) IngestPath(path, displayName, caseName, host, logType, tz string, onProgress func(indexed, failed int)) (indices []string, indexed, failed int, sampleErr string, err error) {
	if !IsArchive(displayName) {
		idx, ind, fl, samp, e := c.IngestFile(path, displayName, caseName, host, logType, tz, onProgress)
		if idx != "" {
			indices = []string{idx}
		}
		return indices, ind, fl, samp, e
	}

	tmp, err := os.MkdirTemp("", "logingest-")
	if err != nil {
		return nil, 0, 0, "", err
	}
	defer os.RemoveAll(tmp)

	files, err := extractArchive(path, tmp)
	if err != nil {
		return nil, 0, 0, "", fmt.Errorf("extract archive: %w", err)
	}
	if len(files) == 0 {
		return nil, 0, 0, "", fmt.Errorf("archive contained no files")
	}

	seen := map[string]bool{}
	for _, f := range files {
		priorInd, priorFail := indexed, failed
		idx, ind, fl, samp, _ := c.IngestFile(f.Path, f.Name, caseName, host, logType, tz, func(i, fail int) {
			if onProgress != nil {
				onProgress(priorInd+i, priorFail+fail)
			}
		})
		indexed += ind
		failed += fl
		if samp != "" && sampleErr == "" {
			sampleErr = samp
		}
		if idx != "" && !seen[idx] {
			seen[idx] = true
			indices = append(indices, idx)
		}
	}
	sort.Strings(indices)
	return indices, indexed, failed, sampleErr, nil
}

// IngestFile parses one file and bulk-indexes it into the store. onProgress is
// called periodically with (indexed, failed). It returns the target index and
// final counts.
func (c *ESClient) IngestFile(path, displayName, caseName, host, logType, tz string, onProgress func(indexed, failed int)) (index string, indexed, failed int, sampleErr string, err error) {
	if logType == TypeAuto {
		logType = DetectLogType(path, displayName)
	}
	if err = c.EnsureTemplate(); err != nil {
		return "", 0, 0, "", err
	}
	index = IndexNameHost(caseName, host, logType)
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
		ok, bad, samp, ferr := c.bulk(index, &buf)
		indexed += ok
		failed += bad
		if samp != "" && sampleErr == "" {
			sampleErr = samp
		}
		buf.Reset()
		pending = 0
		if onProgress != nil {
			onProgress(indexed, failed)
		}
		return ferr
	}

	perr := ParseTZ(path, logType, tz, func(doc Doc) error {
		hunt := Doc{"case": caseName, "log_type": logType, "category": category, "source_file": displayName}
		if host != "" {
			hunt["host"] = host
		}
		if _, ok := doc["@timestamp"]; !ok || doc["@timestamp"] == "" {
			doc["@timestamp"] = ingestTime
			hunt["timestamp_missing"] = true
		}
		doc["hunt"] = hunt

		// A parser may supply a stable "_docid" (e.g. EVTX record id) so that
		// re-ingesting the same source — such as an agent re-collecting a host —
		// overwrites the existing document instead of creating a duplicate.
		// Without it, ES auto-generates an id and every re-ingest doubles the data.
		action := "{\"index\":{}}\n"
		if id, _ := doc["_docid"].(string); id != "" {
			delete(doc, "_docid")
			action = `{"index":{"_id":` + strconv.Quote(id) + "}}\n"
		}
		buf.WriteString(action)
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
		return index, indexed, failed, sampleErr, perr
	}
	if ferr := flush(); ferr != nil {
		return index, indexed, failed, sampleErr, ferr
	}
	return index, indexed, failed, sampleErr, nil
}

// bulk posts an NDJSON bulk body and returns (ok, failed, sampleError).
func (c *ESClient) bulk(index string, body *bytes.Buffer) (int, int, string, error) {
	url := fmt.Sprintf("%s/%s/_bulk", c.baseURL, index)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body.Bytes()))
	if err != nil {
		return 0, 0, "", err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, 0, "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return 0, 0, "", fmt.Errorf("bulk status %d: %s", resp.StatusCode, truncate(string(respBody), 300))
	}
	var parsed struct {
		Items []map[string]struct {
			Status int             `json:"status"`
			Error  json.RawMessage `json:"error"`
		} `json:"items"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return 0, 0, "", err
	}
	ok, failed, sample := 0, 0, ""
	for _, item := range parsed.Items {
		for _, r := range item {
			if r.Status >= 200 && r.Status < 300 {
				ok++
			} else {
				failed++
				if sample == "" && len(r.Error) > 0 {
					sample = truncate(string(r.Error), 300)
				}
			}
		}
	}
	return ok, failed, sample, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

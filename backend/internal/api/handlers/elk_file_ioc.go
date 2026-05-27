package handlers

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/api/middleware"
	"github.com/forensichub/backend/internal/models"
)

// FileIOC is a single classified entry produced by the line parser.
type FileIOC struct {
	Value    string `json:"value"`
	Type     string `json:"type"`              // IPv4-Addr | IPv6-Addr | File-Hash | Domain-Name | URL | Email-Address | Mac-Addr | Other
	LineNo   int    `json:"line_no"`
	Original string `json:"original,omitempty"`
}

// fileIOCParseResponse is what /elk/iocs/parse returns to the client.
type fileIOCParseResponse struct {
	IOCs       []FileIOC      `json:"iocs"`
	Skipped    []skippedLine  `json:"skipped"`
	Counts     map[string]int `json:"counts"`
	TotalLines int            `json:"total_lines"`
}

type skippedLine struct {
	LineNo int    `json:"line_no"`
	Line   string `json:"line"`
	Reason string `json:"reason"`
}

// Regex set used to classify each line. Order matters — checked top-down,
// first match wins. Hash types are length-based so we don't misclassify a
// 32-hex MD5 as a 40-hex SHA1.
var (
	reIPv4   = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}$`)
	reIPv6   = regexp.MustCompile(`^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$`)
	reMD5    = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	reSHA1   = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	reSHA256 = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	reSHA512 = regexp.MustCompile(`^[a-fA-F0-9]{128}$`)
	reMAC    = regexp.MustCompile(`^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$`)
	reEmail  = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	reURL    = regexp.MustCompile(`^https?://`)
	reDomain = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
)

// classifyIOC normalizes and labels a single token. Returns ("", "") when it
// can't be interpreted as any recognized indicator type.
func classifyIOC(raw string) (value, iocType string) {
	v := strings.TrimSpace(raw)
	// Strip surrounding quotes/brackets often seen in IOC lists.
	v = strings.Trim(v, "\"' []<>")
	// Common defang: replace [.] / (.) with . and hxxp -> http
	v = strings.ReplaceAll(v, "[.]", ".")
	v = strings.ReplaceAll(v, "(.)", ".")
	v = strings.ReplaceAll(v, "[:]", ":")
	v = strings.ReplaceAll(v, "[@]", "@")
	lower := strings.ToLower(v)
	if strings.HasPrefix(lower, "hxxp://") {
		v = "http://" + v[7:]
	} else if strings.HasPrefix(lower, "hxxps://") {
		v = "https://" + v[8:]
	}
	if v == "" {
		return "", ""
	}

	switch {
	case reURL.MatchString(v):
		return v, "URL"
	case reEmail.MatchString(v):
		return strings.ToLower(v), "Email-Address"
	case reIPv4.MatchString(v):
		return v, "IPv4-Addr"
	case reIPv6.MatchString(v) && strings.Contains(v, ":"):
		return strings.ToLower(v), "IPv6-Addr"
	case reMAC.MatchString(v):
		return strings.ToUpper(strings.ReplaceAll(v, "-", ":")), "Mac-Addr"
	case reMD5.MatchString(v), reSHA1.MatchString(v), reSHA256.MatchString(v), reSHA512.MatchString(v):
		return strings.ToLower(v), "File-Hash"
	case reDomain.MatchString(v):
		return strings.ToLower(v), "Domain-Name"
	}
	return "", ""
}

// parseIOCFile reads lines from r, stripping comments (`#` or `//`) and
// empty/whitespace-only lines, then classifies every remaining token.
//
// One IOC per line is the canonical format, but if a line contains
// whitespace-separated tokens (e.g. CSV-ish) each token is parsed independently.
func parseIOCFile(r io.Reader, maxBytes int64) ([]FileIOC, []skippedLine, int) {
	scanner := bufio.NewScanner(io.LimitReader(r, maxBytes))
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	out := make([]FileIOC, 0, 256)
	skipped := make([]skippedLine, 0)
	seen := make(map[string]struct{})

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		// Comment lines (common in MISP / OTX exports).
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Split into tokens to handle CSV-ish or space-separated lines.
		tokens := splitIOCLine(line)
		anyMatch := false
		for _, tok := range tokens {
			val, typ := classifyIOC(tok)
			if val == "" {
				continue
			}
			key := typ + "|" + val
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, FileIOC{Value: val, Type: typ, LineNo: lineNo, Original: tok})
			anyMatch = true
		}
		if !anyMatch {
			snippet := line
			if len(snippet) > 200 {
				snippet = snippet[:200] + "..."
			}
			skipped = append(skipped, skippedLine{LineNo: lineNo, Line: snippet, Reason: "no recognizable IOC"})
		}
	}
	return out, skipped, lineNo
}

// splitIOCLine breaks a raw line into candidate IOC tokens. Splits on common
// CSV/TSV delimiters AND whitespace but preserves URLs / emails since neither
// contains commas/spaces/tabs in their canonical form.
func splitIOCLine(line string) []string {
	// Replace commas/tabs/semicolons with spaces, then fields.
	replaced := strings.NewReplacer(",", " ", ";", " ", "\t", " ").Replace(line)
	return strings.Fields(replaced)
}

// decodeIOCsParam decodes a URL-safe base64 JSON payload that the FE passes
// to the EventSource endpoint. Tries URL encoding first then standard, since
// the FE may use either.
func decodeIOCsParam(raw string) ([]FileIOC, error) {
	decoded, err := base64.URLEncoding.DecodeString(raw)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("base64 decode: %w", err)
		}
	}
	var payload struct {
		IOCs []FileIOC `json:"iocs"`
	}
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}
	return payload.IOCs, nil
}

// ParseIOCFile accepts a multipart file upload (.txt) and returns the parsed
// IOC list grouped by type. Nothing is persisted — the FE may follow up with
// /elk/hunt/file-stream to hunt against these parsed indicators.
//
// POST /api/v1/elk/iocs/parse  (multipart form, field "file")
func ParseIOCFile(c *gin.Context) {
	fileHeader, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file is required (multipart field 'file')"})
		return
	}
	if fileHeader.Size > 5*1024*1024 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file too large (max 5 MB)"})
		return
	}
	f, err := fileHeader.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read upload"})
		return
	}
	defer f.Close()

	iocs, skipped, totalLines := parseIOCFile(f, 5*1024*1024)

	counts := make(map[string]int, 8)
	for _, ioc := range iocs {
		counts[ioc.Type]++
	}

	if uid, ok := middleware.GetUserID(c); ok {
		db := c.MustGet("db").(*gorm.DB)
		writeAudit(c, db, &uid, nil, "elk.ioc.parse", "elk", fmt.Sprintf("parsed %s: %d iocs, %d skipped", fileHeader.Filename, len(iocs), len(skipped)))
	}

	c.JSON(http.StatusOK, fileIOCParseResponse{
		IOCs:       iocs,
		Skipped:    skipped,
		Counts:     counts,
		TotalLines: totalLines,
	})
}

// fileHuntRequest is the JSON body posted by the FE — a list of already
// classified IOCs (typically returned from /elk/iocs/parse, possibly trimmed
// or edited client-side).
type fileHuntRequest struct {
	IOCs []FileIOC `json:"iocs"`
}

// StreamELKFileHunt runs the same bucketed batch-streaming hunt that
// StreamELKAutoHunt uses, but instead of loading every IOC from the database
// it consumes the in-memory IOC list provided in the request body (or, when
// GET is used, decoded from a query parameter). The IOC list is ephemeral —
// nothing is written to the iocs table.
//
// POST /api/v1/elk/hunt/file-stream   (JSON body)
// GET  /api/v1/elk/hunt/file-stream?iocs=<base64-json>&token=<jwt>   (for EventSource)
func StreamELKFileHunt(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	aesKey := c.GetString("aesEncryptionKey")

	config, authHeader, err := loadELKAuth(db, aesKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var req fileHuntRequest

	// EventSource cannot send a request body — accept the IOC list via a
	// base64-encoded JSON query param as well so the FE can stream directly.
	if c.Request.Method == http.MethodGet {
		raw := c.Query("iocs")
		if raw == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "iocs query parameter is required"})
			return
		}
		// raw is URL-safe base64 of the JSON {"iocs":[...]}.
		decoded, derr := decodeIOCsParam(raw)
		if derr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid iocs param: " + derr.Error()})
			return
		}
		req.IOCs = decoded
	} else {
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	if len(req.IOCs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no IOCs supplied"})
		return
	}

	// Convert to []models.IOC so we can reuse groupIOCs() exactly.
	pseudoIOCs := make([]models.IOC, 0, len(req.IOCs))
	for _, fi := range req.IOCs {
		if strings.TrimSpace(fi.Value) == "" {
			continue
		}
		pseudoIOCs = append(pseudoIOCs, models.IOC{Value: fi.Value, Type: fi.Type, Source: "File"})
	}
	if len(pseudoIOCs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "all supplied IOCs are empty"})
		return
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	c.Writer.WriteHeader(http.StatusOK)
	c.Writer.Flush()

	clientGone := c.Request.Context().Done()
	sendEvent := func(event string, data interface{}) bool {
		payload, _ := json.Marshal(data)
		_, werr := fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", event, string(payload))
		if werr != nil {
			return false
		}
		c.Writer.Flush()
		return true
	}

	buckets := groupIOCs(pseudoIOCs)

	type batchPlan struct {
		bucket string
		fields []string
		values []string
	}
	var plans []batchPlan
	for _, b := range bucketOrder {
		vals := buckets[b.name]
		if len(vals) == 0 {
			continue
		}
		for i := 0; i < len(vals); i += elkBatchSize {
			end := i + elkBatchSize
			if end > len(vals) {
				end = len(vals)
			}
			plans = append(plans, batchPlan{bucket: b.name, fields: b.fields, values: vals[i:end]})
		}
	}

	totalBatches := len(plans)
	seen := make(map[string]struct{})
	totalHits := 0
	startedAt := time.Now()

	for idx, plan := range plans {
		select {
		case <-clientGone:
			return
		default:
		}

		var body map[string]interface{}
		if len(plan.fields) == 0 {
			body = luceneBody(luceneOR(plan.values), elkPerBatchHits)
		} else {
			body = termsBatchBody(plan.fields, plan.values, elkPerBatchHits)
		}
		bodyBytes, _ := json.Marshal(body)

		respBody, status, err := elkSearch(config.URL, authHeader, "*", bodyBytes, time.Duration(elkBatchTimeoutSec)*time.Second)
		if err != nil {
			sendEvent("error", gin.H{"batch": idx + 1, "bucket": plan.bucket, "error": err.Error()})
			time.Sleep(elkBetweenBatches)
			continue
		}
		if status != http.StatusOK {
			snippet := string(respBody)
			if len(snippet) > 500 {
				snippet = snippet[:500] + "..."
			}
			sendEvent("error", gin.H{"batch": idx + 1, "bucket": plan.bucket, "error": fmt.Sprintf("status %d: %s", status, snippet)})
			time.Sleep(elkBetweenBatches)
			continue
		}

		var parsed struct {
			Hits struct {
				Hits []map[string]interface{} `json:"hits"`
			} `json:"hits"`
		}
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			sendEvent("error", gin.H{"batch": idx + 1, "bucket": plan.bucket, "error": "parse failed"})
			continue
		}

		fresh := make([]map[string]interface{}, 0, len(parsed.Hits.Hits))
		for _, h := range parsed.Hits.Hits {
			id, _ := h["_id"].(string)
			ix, _ := h["_index"].(string)
			key := ix + "|" + id
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			fresh = append(fresh, h)
		}
		totalHits += len(fresh)

		if len(fresh) > 0 {
			if !sendEvent("hits", gin.H{"batch": idx + 1, "bucket": plan.bucket, "hits": fresh}) {
				return
			}
		}
		if !sendEvent("progress", gin.H{
			"batch":         idx + 1,
			"total_batches": totalBatches,
			"bucket":        plan.bucket,
			"batch_hits":    len(fresh),
			"total_hits":    totalHits,
		}) {
			return
		}

		if idx < len(plans)-1 {
			time.Sleep(elkBetweenBatches)
		}
	}

	sendEvent("done", gin.H{
		"total_hits":    totalHits,
		"total_batches": totalBatches,
		"total_iocs":    len(pseudoIOCs),
		"took_ms":       time.Since(startedAt).Milliseconds(),
	})

	if uid, ok := middleware.GetUserID(c); ok {
		writeAudit(c, db, &uid, nil, "elk.hunt.file", "elk", fmt.Sprintf("file iocs=%d batches=%d hits=%d", len(pseudoIOCs), totalBatches, totalHits))
	}
}

// Package toolproc is the server-side "raw-data processing" layer that runs on a
// tool result file after an agent uploads it, before it lands in the DB / AI.
//
// Each processor classifies the file (kind), extracts a short summary + row
// count, and — where useful — writes a normalized (CSV/JSON) form the AI layer
// can ingest. Processors never fail hard: on any parse error they fall back to
// classify-only so a result is always recorded.
//
// Pure-Go processors (text/csv/json/loki) ship today. redline (goauditparser)
// and kape (Eric Zimmerman tools) are declared here but delegate to an external
// processor that is integrated in a later phase.
package toolproc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Outcome is the result of processing one file.
type Outcome struct {
	Kind         string // report|table|json|text-log|image|archive|other
	Processor    string // the processor actually applied
	ParsedAbs    string // absolute path to normalized output (empty if none)
	RowCount     int
	Summary      string // short human/AI-facing preview (bounded)
	AIWorthy     bool   // whether this result is a good AI-analysis candidate
	NeedsExtern  bool   // true when a not-yet-integrated external processor is required
}

const (
	maxSummaryBytes = 4 << 10  // 4 KB
	maxReadBytes    = 8 << 20  // 8 MB read cap for text/csv/json/loki
	maxSummaryLines = 40
)

// Process runs the named processor on rawAbs. parsedDir is a writable directory
// the processor may drop normalized output into.
func Process(processor, rawAbs, parsedDir string) Outcome {
	proc := strings.ToLower(strings.TrimSpace(processor))
	if proc == "" || proc == "auto" {
		proc = inferProcessor(rawAbs)
	}
	base := strings.ToLower(filepath.Ext(rawAbs))

	switch proc {
	case "text", "log":
		return processText(rawAbs, proc)
	case "csv", "table":
		return processCSV(rawAbs)
	case "json":
		return processJSON(rawAbs)
	case "loki":
		return processLoki(rawAbs, parsedDir)
	case "redline":
		return processRedline(rawAbs, parsedDir)
	case "kape":
		return processKape(rawAbs, parsedDir)
	case "image":
		return Outcome{Kind: "image", Processor: "none", AIWorthy: false,
			Summary: "Binary image (memory/disk) — stored for offline analysis, not sent to AI."}
	default:
		// Unknown / none — classify by extension only.
		return Outcome{Kind: classifyByExt(base), Processor: "none", AIWorthy: isTextExt(base)}
	}
}

// inferProcessor guesses a processor from the file extension when none is set.
func inferProcessor(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".csv":
		return "csv"
	case ".json", ".ndjson":
		return "json"
	case ".txt", ".log":
		return "text"
	case ".mans":
		return "redline"
	case ".raw", ".mem", ".dmp", ".vmem", ".lime":
		return "image"
	default:
		return "text"
	}
}

// QuickKind classifies a file by extension without reading it — used to label a
// result immediately at upload time, before the async processor runs.
func QuickKind(path string) string {
	return classifyByExt(strings.ToLower(filepath.Ext(path)))
}

func classifyByExt(ext string) string {
	switch ext {
	case ".html", ".htm":
		return "report"
	case ".csv":
		return "table"
	case ".json", ".ndjson":
		return "json"
	case ".txt", ".log":
		return "text-log"
	case ".raw", ".mem", ".dmp", ".vmem", ".lime":
		return "image"
	case ".zip", ".mans", ".7z", ".tar", ".gz", ".vhdx":
		return "archive"
	default:
		return "other"
	}
}

func isTextExt(ext string) bool {
	switch ext {
	case ".txt", ".log", ".csv", ".json", ".ndjson", ".html", ".htm", ".xml":
		return true
	}
	return false
}

func processText(rawAbs, proc string) Outcome {
	data := readCapped(rawAbs)
	lines := splitLines(data)
	return Outcome{
		Kind:      "text-log",
		Processor: proc,
		RowCount:  len(lines),
		Summary:   headSummary(lines),
		AIWorthy:  true,
	}
}

func processCSV(rawAbs string) Outcome {
	data := readCapped(rawAbs)
	lines := splitLines(data)
	rows := 0
	header := ""
	if len(lines) > 0 {
		header = lines[0]
		rows = len(lines) - 1
		if rows < 0 {
			rows = 0
		}
	}
	sum := fmt.Sprintf("CSV · %d row(s)\ncolumns: %s", rows, truncate(header, 400))
	return Outcome{Kind: "table", Processor: "csv", RowCount: rows, Summary: truncate(sum, maxSummaryBytes), AIWorthy: true}
}

func processJSON(rawAbs string) Outcome {
	data := readCapped(rawAbs)
	var v interface{}
	rows := 0
	sum := "JSON"
	if err := json.Unmarshal(data, &v); err == nil {
		switch t := v.(type) {
		case []interface{}:
			rows = len(t)
			sum = fmt.Sprintf("JSON array · %d item(s)", rows)
		case map[string]interface{}:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sum = fmt.Sprintf("JSON object · keys: %s", truncate(strings.Join(keys, ", "), 400))
		}
	} else {
		// Maybe NDJSON — count non-empty lines.
		rows = len(splitLines(data))
		sum = fmt.Sprintf("NDJSON · %d line(s)", rows)
	}
	return Outcome{Kind: "json", Processor: "json", RowCount: rows, Summary: truncate(sum, maxSummaryBytes), AIWorthy: true}
}

// lokiDetection is the normalized shape emitted for a Loki result line.
type lokiDetection struct {
	Level   string `json:"level"`   // ALERT|WARNING|NOTICE
	Message string `json:"message"`
}

// processLoki normalizes a Loki scan log (text or --csv) into a compact JSON
// array of detections and writes it next to the raw file.
func processLoki(rawAbs, parsedDir string) Outcome {
	data := readCapped(rawAbs)
	var dets []lokiDetection
	var alerts, warnings int
	for _, ln := range splitLines(data) {
		up := strings.ToUpper(ln)
		lvl := ""
		switch {
		case strings.Contains(up, "ALERT"):
			lvl = "ALERT"
			alerts++
		case strings.Contains(up, "WARNING"):
			lvl = "WARNING"
			warnings++
		default:
			continue
		}
		dets = append(dets, lokiDetection{Level: lvl, Message: truncate(strings.TrimSpace(ln), 1000)})
	}

	out := Outcome{
		Kind:      "table",
		Processor: "loki",
		RowCount:  len(dets),
		Summary:   fmt.Sprintf("Loki · %d ALERT, %d WARNING", alerts, warnings),
		AIWorthy:  true,
	}
	// Write normalized JSON so the AI layer ingests structured detections.
	if len(dets) > 0 && parsedDir != "" {
		if b, err := json.MarshalIndent(dets, "", "  "); err == nil {
			_ = os.MkdirAll(parsedDir, 0o755)
			dst := filepath.Join(parsedDir, baseNoExt(rawAbs)+".detections.json")
			if os.WriteFile(dst, b, 0o644) == nil {
				out.ParsedAbs = dst
			}
		}
	}
	return out
}

// ── helpers ──────────────────────────────────────────────────────────────────

func readCapped(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, maxReadBytes)
	n, _ := f.Read(buf)
	return buf[:n]
}

func splitLines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		ln := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(ln) == "" {
			continue
		}
		out = append(out, ln)
	}
	return out
}

func headSummary(lines []string) string {
	n := len(lines)
	if n > maxSummaryLines {
		n = maxSummaryLines
	}
	return truncate(strings.Join(lines[:n], "\n"), maxSummaryBytes)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func baseNoExt(path string) string {
	b := filepath.Base(path)
	return strings.TrimSuffix(b, filepath.Ext(b))
}

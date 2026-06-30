package offline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Severity ranks a finding for on-the-spot triage.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// sevRank orders severities for sorting (higher = more urgent).
func sevRank(s Severity) int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	default:
		return 0
	}
}

// Finding is a single triage-worthy line surfaced from a tool's output.
type Finding struct {
	Severity Severity `json:"severity"`
	Tool     string   `json:"tool"`
	Title    string   `json:"title"`
	Evidence string   `json:"evidence"`
}

// Centralised severity heuristics so the UI, report and import agree (replaces
// the duplicated substring checks in the old UI/CLI). Conservative: only lines
// with clear signal become findings, so the panel stays meaningful.
var (
	reCritical = regexp.MustCompile(`(?i)\b(malware|webshell|backdoor|trojan|ransomware|c2|cobalt\s?strike|mimikatz|meterpreter|reverse shell|known[- ]bad|matched ioc|ioc match)\b`)
	reHigh     = regexp.MustCompile(`(?i)\b(suspicious|malicious|detected|alert|critical|exploit|injected|persistence|unsigned .* system32|hidden process)\b`)
	reMedium   = regexp.MustCompile(`(?i)\b(warning|anomal|unusual|failed|error|denied|tamper)\b`)
	reMatch    = regexp.MustCompile(`(?i)\b(\d+)\s+(match|hit|detection|threat|finding)s?\b`)
)

// classifyLine returns a severity for a single output line, or "" when the line
// is not noteworthy.
func classifyLine(line string) Severity {
	switch {
	case reCritical.MatchString(line):
		return SevCritical
	case reHigh.MatchString(line):
		return SevHigh
	case reMatch.MatchString(line) && !strings.Contains(line, "0 match"):
		return SevHigh
	case reMedium.MatchString(line):
		return SevMedium
	default:
		return ""
	}
}

// extractFindings scans a finished job's output and returns deduped findings.
// A job that FAILED always yields at least one finding so it isn't missed.
func extractFindings(toolName string, status JobStatus, lines []string) []Finding {
	var out []Finding
	seen := map[string]bool{}
	const maxPerJob = 50

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || len(line) > 2000 {
			continue
		}
		sev := classifyLine(line)
		if sev == "" {
			continue
		}
		key := string(sev) + "|" + line
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Finding{Severity: sev, Tool: toolName, Title: truncateLine(line, 160), Evidence: line})
		if len(out) >= maxPerJob {
			break
		}
	}

	if status == StatusFailed && len(out) == 0 {
		out = append(out, Finding{Severity: SevMedium, Tool: toolName, Title: "Tool failed to complete", Evidence: "see job output"})
	}
	return out
}

func truncateLine(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ── Evidence collection folder + integrity ─────────────────────────────────

// collectionDir returns (and lazily creates) a single clean evidence folder
// next to the launched .exe: FHub-Collection-<host>-<ts>/. All reports and a
// hash manifest land here, instead of being split between %TEMP% and the exe
// dir.
var collectionDirOnce string

func collectionDir() string {
	if collectionDirOnce != "" {
		return collectionDirOnce
	}
	host, _ := os.Hostname()
	ts := time.Now().Format("20060102-150405")
	dir := filepath.Join(outputDir(), "FHub-Collection-"+safeFilename(host)+"-"+ts)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		// Fall back to the exe dir if we can't create the subfolder.
		return outputDir()
	}
	collectionDirOnce = dir
	return dir
}

// writeCollectionManifest writes a SHA-256 manifest of every file in the
// collection folder for chain-of-custody.
func writeCollectionManifest(dir string) {
	type entry struct {
		File   string `json:"file"`
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	}
	var entries []entry
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if info.Name() == "collection-manifest.json" {
			return nil
		}
		sum, sz := fileSHA256(p)
		rel, _ := filepath.Rel(dir, p)
		entries = append(entries, entry{File: filepath.ToSlash(rel), SHA256: sum, Size: sz})
		return nil
	})
	data, _ := json.MarshalIndent(map[string]interface{}{
		"generated_at": time.Now().UTC(),
		"files":        entries,
	}, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "collection-manifest.json"), data, 0o644)
}

func fileSHA256(path string) (string, int64) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0
	}
	defer f.Close()
	h := sha256.New()
	n, _ := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n
}

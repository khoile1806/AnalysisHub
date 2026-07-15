package toolproc

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// externTimeout bounds an external parser run. Redline/.mans collections can be
// large; goauditparser is multi-threaded but a runaway run must not pin a
// request forever.
const externTimeout = 10 * time.Minute

// externMissing degrades gracefully when the required external binary is not on
// PATH: the raw file is still stored, just not parsed/AI-analyzed.
func externMissing(processor, bin string) Outcome {
	return Outcome{
		Kind:        "archive",
		Processor:   processor,
		AIWorthy:    false,
		NeedsExtern: true,
		Summary:     fmt.Sprintf("Requires %q on the server PATH to process %q results — not installed on this build. File stored raw.", bin, processor),
	}
}

// processRedline runs goauditparser over Redline/.mans/audit-XML input, producing
// CSVs, then combines them into one normalized summary the AI layer can ingest.
func processRedline(rawAbs, parsedDir string) Outcome {
	bin, err := exec.LookPath("goauditparser")
	if err != nil {
		return externMissing("redline", "goauditparser")
	}
	csvDir := filepath.Join(parsedDir, "redline-"+baseNoExt(rawAbs))
	_ = os.MkdirAll(csvDir, 0o755)

	ctx, cancel := context.WithTimeout(context.Background(), externTimeout)
	defer cancel()
	// goauditparser -i <mans|zip|xml|dir> -o <csvDir>
	out, runErr := exec.CommandContext(ctx, bin, "-i", rawAbs, "-o", csvDir).CombinedOutput()
	if runErr != nil {
		return Outcome{
			Kind: "archive", Processor: "redline", AIWorthy: false, NeedsExtern: true,
			Summary: truncate("goauditparser failed: "+runErr.Error()+"\n"+string(out), maxSummaryBytes),
		}
	}
	return summarizeCSVDir("redline", csvDir, parsedDir, rawAbs)
}

// processKape maps a single collected artifact to the matching Eric Zimmerman
// tool and runs it (<tool> -f <file> --csv <dir>). For full KAPE triage archives
// point the tool at the specific artifact files; unmapped inputs stay raw.
func processKape(rawAbs, parsedDir string) Outcome {
	tool := ezToolFor(rawAbs)
	if tool == "" {
		return Outcome{
			Kind: "archive", Processor: "kape", AIWorthy: false, NeedsExtern: true,
			Summary: "No Eric Zimmerman tool mapping for this file — stored raw for manual/KAPE processing.",
		}
	}
	bin, err := exec.LookPath(tool)
	if err != nil {
		return externMissing("kape", tool)
	}
	csvDir := filepath.Join(parsedDir, "kape-"+baseNoExt(rawAbs))
	_ = os.MkdirAll(csvDir, 0o755)

	ctx, cancel := context.WithTimeout(context.Background(), externTimeout)
	defer cancel()
	out, runErr := exec.CommandContext(ctx, bin, "-f", rawAbs, "--csv", csvDir).CombinedOutput()
	if runErr != nil {
		return Outcome{
			Kind: "archive", Processor: "kape", AIWorthy: false, NeedsExtern: true,
			Summary: truncate(tool+" failed: "+runErr.Error()+"\n"+string(out), maxSummaryBytes),
		}
	}
	return summarizeCSVDir("kape", csvDir, parsedDir, rawAbs)
}

// ezToolFor picks the Eric Zimmerman tool for a collected artifact by name/ext.
func ezToolFor(path string) string {
	base := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(path))
	switch {
	case base == "$mft" || ext == ".mft":
		return "MFTECmd"
	case ext == ".pf":
		return "PECmd"
	case ext == ".lnk":
		return "LECmd"
	case base == "amcache.hve":
		return "AmcacheParser"
	case ext == ".evtx":
		return "EvtxECmd"
	case base == "srudb.dat":
		return "SrumECmd"
	case strings.Contains(base, "appcompatcache") || strings.Contains(base, "shimcache"):
		return "AppCompatCacheParser"
	case ext == ".db" && strings.Contains(base, "activitiescache"):
		return "WxTCmd"
	default:
		return ""
	}
}

// summarizeCSVDir collects all CSVs produced by an external parser into one
// normalized text file (bounded per CSV) and reports total row count.
func summarizeCSVDir(processor, csvDir, parsedDir, rawAbs string) Outcome {
	var csvs []string
	_ = filepath.Walk(csvDir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.EqualFold(filepath.Ext(p), ".csv") {
			csvs = append(csvs, p)
		}
		return nil
	})
	if len(csvs) == 0 {
		return Outcome{
			Kind: "archive", Processor: processor, AIWorthy: false, NeedsExtern: true,
			Summary: fmt.Sprintf("%s ran but produced no CSV output.", processor),
		}
	}

	var combined strings.Builder
	total := 0
	for _, cf := range csvs {
		lines := splitLines(readCapped(cf))
		rows := 0
		if len(lines) > 0 {
			if rows = len(lines) - 1; rows < 0 {
				rows = 0
			}
		}
		total += rows
		fmt.Fprintf(&combined, "=== %s (%d rows) ===\n", filepath.Base(cf), rows)
		n := len(lines)
		if n > 21 { // header + up to 20 rows
			n = 21
		}
		combined.WriteString(strings.Join(lines[:n], "\n"))
		combined.WriteString("\n\n")
	}

	parsedAbs := filepath.Join(parsedDir, baseNoExt(rawAbs)+".parsed.txt")
	_ = os.WriteFile(parsedAbs, []byte(combined.String()), 0o644)

	return Outcome{
		Kind:      "table",
		Processor: processor,
		ParsedAbs: parsedAbs,
		RowCount:  total,
		Summary:   truncate(fmt.Sprintf("%s → %d CSV file(s), %d total row(s)\n", processor, len(csvs), total)+combined.String(), maxSummaryBytes),
		AIWorthy:  true,
	}
}

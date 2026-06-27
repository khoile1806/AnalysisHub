package parser

import "time"

// TriageArtifact is one collector's output within a triage bundle. Errors are
// captured per-artifact so one failing collector never aborts the whole run.
type TriageArtifact struct {
	Type  string      `json:"type"`
	Count int         `json:"count"`
	Error string      `json:"error,omitempty"`
	Data  interface{} `json:"data,omitempty"`
}

// TriageResult is the combined output of a 1-click triage collection.
type TriageResult struct {
	CollectedAt string           `json:"collected_at"`
	Hostname    string           `json:"hostname,omitempty"`
	Artifacts   []TriageArtifact `json:"artifacts"`
}

// DefaultTriageTypes is the curated set collected when none is specified. MFT is
// intentionally excluded by default (slow + very large); request it explicitly.
var DefaultTriageTypes = []string{
	"processes", "autoruns", "shimcache", "prefetch", "dlls", "netconn", "browser",
}

// CollectTriage runs the requested collectors (or DefaultTriageTypes) in one
// pass and returns a combined bundle. Designed to run inside a single elevated
// context so the operator sees at most one UAC prompt for the whole collection.
func CollectTriage(types []string) TriageResult {
	if len(types) == 0 {
		types = DefaultTriageTypes
	}
	res := TriageResult{CollectedAt: time.Now().UTC().Format(time.RFC3339)}
	for _, t := range types {
		res.Artifacts = append(res.Artifacts, collectOne(t))
	}
	return res
}

func collectOne(t string) TriageArtifact {
	art := TriageArtifact{Type: t}
	switch t {
	case "processes":
		d, err := ScanProcesses()
		set(&art, len(d), d, err)
	case "autoruns":
		d, err := ScanAutoruns()
		set(&art, len(d), d, err)
	case "shimcache":
		d, err := ScanShimcache()
		set(&art, len(d), d, err)
	case "prefetch":
		d, err := ParsePrefetch()
		set(&art, len(d), d, err)
	case "dlls":
		d, err := ScanLoadedDLLs()
		set(&art, len(d), d, err)
	case "netconn":
		d, err := ScanNetwork()
		n := 0
		if d != nil {
			n = len(d.Connections)
		}
		set(&art, n, d, err)
	case "browser":
		d, err := ScanBrowserHistory()
		set(&art, len(d), d, err)
	case "mft":
		d, err := ParseMFT("")
		set(&art, len(d), d, err)
	default:
		art.Error = "unknown artifact type"
	}
	return art
}

func set(art *TriageArtifact, count int, data interface{}, err error) {
	if err != nil {
		art.Error = err.Error()
		return
	}
	art.Count = count
	art.Data = data
}

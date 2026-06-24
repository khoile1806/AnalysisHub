package parser

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type PrefetchResult struct {
	Executable   string    `json:"executable"`
	LastRunTime  time.Time `json:"last_run_time"`
	Hash         string    `json:"hash"`
	PrefetchFile string    `json:"prefetch_file"`
}

func ParsePrefetch() ([]PrefetchResult, error) {
	dir := `C:\Windows\Prefetch`
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read prefetch directory (requires admin): %v", err)
	}

	var results []PrefetchResult
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".pf") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		
		name := entry.Name()
		// E.g., CMD.EXE-087B4001.pf
		parts := strings.Split(name, "-")
		exe := parts[0]
		hash := ""
		if len(parts) > 1 {
			hash = strings.TrimSuffix(parts[len(parts)-1], ".pf")
			hash = strings.TrimSuffix(hash, ".PF")
		}

		results = append(results, PrefetchResult{
			Executable:   exe,
			LastRunTime:  info.ModTime(),
			Hash:         hash,
			PrefetchFile: name,
		})
	}
	return results, nil
}

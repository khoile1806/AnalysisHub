//go:build !windows

package parser

import (
	"fmt"
	"time"
)

// PrefetchResult mirrors the Windows definition so JSON consumers and callers
// compile on every platform. Prefetch only exists on Windows.
type PrefetchResult struct {
	Executable   string      `json:"executable"`
	RunCount     int         `json:"run_count"`
	LastRunTime  time.Time   `json:"last_run_time"`
	LastRunTimes []time.Time `json:"last_run_times,omitempty"`
	PrefetchHash string      `json:"hash"`
	Version      string      `json:"version"`
	Compressed   bool        `json:"compressed"`
	PrefetchFile string      `json:"prefetch_file"`
	Size         int64       `json:"size"`
	MD5          string      `json:"md5"`
	SHA256       string      `json:"sha256"`
	PfModTime    time.Time   `json:"pf_mod_time"`
	Parsed       bool        `json:"parsed"`
	Suspicious   bool        `json:"suspicious"`
	ExePath      string      `json:"exe_path,omitempty"`
	ExeMD5       string      `json:"exe_md5,omitempty"`
	ExeSHA256    string      `json:"exe_sha256,omitempty"`
	ExeHashed    bool        `json:"exe_hashed"`
}

// ParsePrefetch is only implemented on Windows.
func ParsePrefetch() ([]PrefetchResult, error) {
	return nil, fmt.Errorf("prefetch analysis is only supported on Windows agents")
}

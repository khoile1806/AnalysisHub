//go:build !windows

package parser

import "fmt"

// ProcessRec mirrors the Windows definition so JSON consumers / callers compile
// on every platform. Detailed process forensics is Windows-only.
type ProcessRec struct {
	PID        int      `json:"pid"`
	PPID       int      `json:"ppid"`
	Name       string   `json:"name"`
	ParentName string   `json:"parent_name"`
	Path       string   `json:"path"`
	Cmdline    string   `json:"cmdline"`
	User       string   `json:"user"`
	MemKB      int      `json:"mem_kb"`
	Created    string   `json:"created"`
	MD5        string   `json:"md5,omitempty"`
	SHA256     string   `json:"sha256,omitempty"`
	Hashed     bool     `json:"hashed"`
	Suspicious []string `json:"suspicious,omitempty"`
}

// ScanProcesses is only implemented on Windows.
func ScanProcesses() ([]ProcessRec, error) {
	return nil, fmt.Errorf("detailed process forensics is only supported on Windows agents")
}

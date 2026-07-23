//go:build !linux

package parser

import "fmt"

// LinuxArtifact mirrors the Linux type so the agent compiles everywhere.
type LinuxArtifact struct {
	Type       string   `json:"type"`
	Source     string   `json:"source"`
	User       string   `json:"user"`
	Detail     string   `json:"detail"`
	Modified   string   `json:"modified"`
	Suspicious []string `json:"suspicious"`
}

// ScanLinuxTriage is Linux-only.
func ScanLinuxTriage() ([]LinuxArtifact, error) {
	return nil, fmt.Errorf("linux triage is only supported on Linux agents")
}

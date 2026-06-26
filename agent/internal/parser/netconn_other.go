//go:build !windows

package parser

import "fmt"

// ScanNetwork is only implemented on Windows agents.
func ScanNetwork() (*NetworkResult, error) {
	return nil, fmt.Errorf("network connection enumeration is only supported on Windows agents")
}

// CollectConnectionsJSON returns an empty list on non-Windows agents.
func CollectConnectionsJSON() (string, error) {
	return "[]", nil
}

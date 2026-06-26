//go:build !windows

package parser

import "fmt"

// ScanShimcache is only implemented on Windows agents.
func ScanShimcache() ([]ShimEntry, error) {
	return nil, fmt.Errorf("shimcache parsing is only supported on Windows agents")
}

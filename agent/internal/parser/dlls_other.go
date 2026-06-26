//go:build !windows

package parser

import "fmt"

// ScanLoadedDLLs is only implemented on Windows agents.
func ScanLoadedDLLs() ([]DllRec, error) {
	return nil, fmt.Errorf("loaded-DLL enumeration is only supported on Windows agents")
}

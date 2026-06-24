//go:build !windows
// +build !windows

package parser

import "fmt"

// ParseRegistry is a stub for non-Windows platforms
func ParseRegistry(root string, path string) (string, error) {
	return "", fmt.Errorf("registry parsing is only supported on Windows")
}

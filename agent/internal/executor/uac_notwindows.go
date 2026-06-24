//go:build !windows
// +build !windows

package executor

import "fmt"

func RunElevatedAndWait(exe string, args string) error {
	return fmt.Errorf("UAC elevation is only supported on Windows")
}

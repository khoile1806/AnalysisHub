//go:build !windows
// +build !windows

package executor

import (
	"fmt"
	"os"
)

func RunElevatedAndWait(exe string, args string) error {
	return fmt.Errorf("UAC elevation is only supported on Windows")
}

// IsElevated is always false on non-Windows agents.
func IsElevated() bool { return false }

// KillProcess terminates a process by PID (Unix).
func KillProcess(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("invalid pid")
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}

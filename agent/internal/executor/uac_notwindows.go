//go:build !windows
// +build !windows

package executor

import (
	"fmt"
	"os"
)

// RunElevatedAndWait has no equivalent on Unix — privilege comes from running the
// agent as root (systemd service / sudo), not a per-action prompt like UAC.
func RunElevatedAndWait(exe string, args string) error {
	return fmt.Errorf("per-action elevation is not available on this OS; run the agent as root")
}

// IsElevated reports whether the agent is running with full privileges. On Unix
// that means the effective UID is 0 (root) — so a root agent takes the in-process
// fast path just like an elevated Windows agent.
func IsElevated() bool { return os.Geteuid() == 0 }

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

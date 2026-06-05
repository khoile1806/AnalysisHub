//go:build !windows

package ws

import "os/exec"

// setCleanupCmd is a no-op on Linux/macOS — process isolation is handled
// by the OS (fork/exec with no console inheritance issues).
func setCleanupCmd(cmd *exec.Cmd) {}

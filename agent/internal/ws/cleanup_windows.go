//go:build windows

package ws

import (
	"os/exec"
	"syscall"
)

// setCleanupCmd configures cmd to start as a fully detached, hidden process
// so the cleanup script does not inherit the agent's console handle.
// Without CREATE_NEW_CONSOLE the child process keeps our console window alive
// until the cleanup script finishes (several seconds of retries).
func setCleanupCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
		// 0x10 = CREATE_NEW_CONSOLE  — own console (not inherited)
		// 0x200 = CREATE_NEW_PROCESS_GROUP — no Ctrl-C propagation
		CreationFlags: 0x00000010 | 0x00000200,
	}
}

//go:build windows

package offline

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// relaunchElevated starts a NEW elevated instance of this agent via a single UAC
// prompt (Start-Process -Verb RunAs). The caller then exits, so the elevated
// instance takes over and every tool it runs inherits the high-integrity token
// — no per-tool UAC prompts.
func relaunchElevated() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	arg := "Start-Process -FilePath '" + strings.ReplaceAll(exe, "'", "''") + "' -Verb RunAs"
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", arg)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Start()
}

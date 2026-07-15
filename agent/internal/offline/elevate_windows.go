//go:build windows

package offline

import (
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/analysishub/agent/internal/executor"
)

// EnsureElevated relaunches the agent elevated (a single UAC prompt) when it is
// not already running as Administrator, so admin-only tools (DumpIt's kernel
// driver, Redline's audit, …) actually work — otherwise they launch and exit
// instantly. Returns true when a new elevated instance was started and the caller
// should exit and hand over. Returns false to keep running at the current level:
// already elevated, non-Windows, or the user declined the UAC prompt (so the
// agent is still usable for tools that don't need admin).
func EnsureElevated() bool {
	if executor.IsElevated() {
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	ps := "Start-Process -FilePath '" + strings.ReplaceAll(exe, "'", "''") + "' -Verb RunAs"
	if args := os.Args[1:]; len(args) > 0 {
		quoted := make([]string, 0, len(args))
		for _, a := range args {
			quoted = append(quoted, "'"+strings.ReplaceAll(a, "'", "''")+"'")
		}
		ps += " -ArgumentList " + strings.Join(quoted, ",")
	}
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	// Wait so we can tell whether elevation was accepted (exit 0) or declined
	// (non-zero) — on decline we keep running non-elevated instead of quitting.
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

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

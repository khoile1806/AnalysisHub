//go:build !windows

package offline

import "fmt"

// relaunchElevated is Windows-only; elsewhere the agent is run with sudo by the
// operator directly.
func relaunchElevated() error {
	return fmt.Errorf("re-elevation is only supported on Windows; run with sudo")
}

//go:build !linux

package parser

import "fmt"

// LinuxEvent / LinuxEventOptions are declared in the untagged auditd.go, so the
// wire shape is identical on every platform by construction and the record
// parser stays unit-testable on the dev host. Only the collection itself —
// /var/log/audit, journalctl, /proc — is Linux-only.

// ScanLinuxEvents is Linux-only (auditd / journald / auth.log). On other
// platforms it reports that clearly rather than returning misleading empty data.
func ScanLinuxEvents(opts LinuxEventOptions) ([]LinuxEvent, error) {
	_ = opts.normalize()
	return nil, fmt.Errorf("linux event collection is only supported on Linux agents")
}

package osint

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// ValidateTarget rejects malformed or unsafe OSINT targets. Most collectors
// call fixed third-party API hostnames so the SSRF surface is small, but the
// DNS and reverse-DNS collectors resolve the target directly - so private,
// loopback and link-local addresses are refused (they carry no public
// footprint anyway and only invite misuse).
func ValidateTarget(target, targetType string) error {
	t := strings.TrimSpace(target)
	if t == "" {
		return errors.New("target is empty")
	}
	if strings.HasPrefix(t, "-") {
		return errors.New("target cannot start with '-'")
	}
	// A full name is the one type allowed to contain spaces; every other type is
	// a single token, so whitespace there signals a malformed target.
	if targetType == TargetName {
		if strings.ContainsAny(t, "\t\n\r") {
			return errors.New("name contains control whitespace")
		}
	} else if strings.ContainsAny(t, " \t\n\r") {
		return errors.New("target contains whitespace")
	}
	if len(t) > 255 {
		return errors.New("target is too long")
	}

	switch targetType {
	case TargetIP:
		ip := net.ParseIP(t)
		if ip == nil {
			return fmt.Errorf("%q is not a valid IP address", t)
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("IP %s is private/loopback/link-local - not a public OSINT target", ip)
		}
	case TargetDomain:
		h := strings.ToLower(t)
		if h == "localhost" {
			return errors.New("localhost is not a public OSINT target")
		}
		for _, suf := range []string{".local", ".internal", ".localdomain"} {
			if strings.HasSuffix(h, suf) {
				return fmt.Errorf("domain %q uses a private TLD %q", t, suf)
			}
		}
	}
	return nil
}

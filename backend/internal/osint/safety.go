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
	if len(t) > 512 { // profile URLs can be longer than a bare identifier
		return errors.New("target is too long")
	}

	switch targetType {
	case TargetSocial:
		if _, ok := ParseSocialProfile(t); !ok {
			return fmt.Errorf("%q is not a recognisable social-media profile URL", t)
		}
	case TargetIP:
		ip := net.ParseIP(t)
		if ip == nil {
			return fmt.Errorf("%q is not a valid IP address", t)
		}
		if !isPublicIP(ip) {
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

// isPublicIP reports whether ip is a globally-routable public address. It
// rejects loopback, RFC1918 private, link-local, unspecified, multicast and
// the IPv6 unique-local (fc00::/7) range. Collectors that resolve a domain
// directly use it to drop internal addresses from findings — a public domain
// that points at an internal IP (split-horizon DNS, DNS-rebinding, mis-config)
// must not leak that address into the report or spawn an out-of-scope pivot.
func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}
	// IPv4 "this host on this network" (0.0.0.0/8) and 100.64.0.0/10 CGNAT.
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 0 {
			return false
		}
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return false
		}
	}
	return true
}

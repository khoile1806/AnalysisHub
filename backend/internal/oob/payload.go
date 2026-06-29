// Package oob implements the out-of-band ("Catch") interaction server: a
// controlled DNS + HTTP(S) + SMTP endpoint (Interactsh / Burp-Collaborator
// style) that records callbacks from a target to confirm blind vulnerabilities
// on authorised engagements.
package oob

import (
	"crypto/rand"
	"strings"
)

const (
	// CorrelationLen is the length of the per-client prefix shared by every
	// payload hostname a client hands out — the part used to attribute a
	// callback back to its client. Matches Interactsh's 20-char scheme.
	CorrelationLen = 20
	// uniqueLen is the per-payload random suffix appended after the correlation
	// id inside the same leading DNS label.
	uniqueLen = 13
)

// labelAlphabet is the DNS-label-safe character set (lowercase alphanumerics).
const labelAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// randString returns n cryptographically-random characters from the
// DNS-label-safe alphabet.
func randString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("oob: crypto/rand unavailable: " + err.Error())
	}
	for i := range b {
		b[i] = labelAlphabet[int(b[i])%len(labelAlphabet)]
	}
	return string(b)
}

// NewCorrelationID returns a fresh client correlation id whose first character
// is forced to a letter so the resulting DNS label is always valid.
func NewCorrelationID() string {
	s := []byte(randString(CorrelationLen))
	if s[0] >= '0' && s[0] <= '9' {
		s[0] = 'a'
	}
	return string(s)
}

// NewUniqueID returns a fresh per-payload suffix.
func NewUniqueID() string { return randString(uniqueLen) }

// NewSecret returns a random poller secret (longer, hex-ish from the same set).
func NewSecret() string { return randString(32) }

// BuildHost assembles a payload hostname: "<corr><unique>.<domain>".
func BuildHost(corr, unique, domain string) string {
	return corr + unique + "." + strings.TrimSuffix(strings.ToLower(domain), ".")
}

// splitLabel parses the leading label adjacent to the server zone out of a
// queried/Host name and splits it into the correlation prefix + unique suffix.
// ok is false when the name is not under the zone or the adjacent label is too
// short to carry a correlation id.
func splitLabel(name, domain string) (correlation, unique string, ok bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" || name == domain {
		return "", "", false
	}
	suffix := "." + domain
	if !strings.HasSuffix(name, suffix) {
		return "", "", false
	}
	sub := strings.TrimSuffix(name, suffix)
	labels := strings.Split(sub, ".")
	adjacent := labels[len(labels)-1] // label directly left of the zone
	if len(adjacent) < CorrelationLen {
		return "", "", false
	}
	return adjacent[:CorrelationLen], adjacent[CorrelationLen:], true
}

// emailHost extracts the host part of an "<user@host>" / "user@host" address.
func emailHost(addr string) string {
	addr = strings.Trim(addr, "<> \t")
	at := strings.LastIndex(addr, "@")
	if at < 0 || at == len(addr)-1 {
		return ""
	}
	return strings.ToLower(addr[at+1:])
}

// extractAngle pulls the address out of an SMTP "MAIL FROM:<a@b>" command,
// falling back to whatever follows the colon.
func extractAngle(line string) string {
	if i := strings.Index(line, "<"); i >= 0 {
		if j := strings.Index(line[i:], ">"); j >= 0 {
			return line[i+1 : i+j]
		}
	}
	if c := strings.Index(line, ":"); c >= 0 {
		return strings.TrimSpace(line[c+1:])
	}
	return strings.TrimSpace(line)
}

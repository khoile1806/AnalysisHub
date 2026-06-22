package osint

import "strings"

// placeholderDomains are reserved/test domains (RFC 2606 + common throwaways)
// that carry no real footprint — auto-pivoting into them only wastes scans.
var placeholderDomains = map[string]bool{
	"example.com": true, "example.org": true, "example.net": true,
	"example.edu": true, "test.com": true, "domain.com": true,
	"email.com": true, "localhost": true, "invalid": true,
	"mailinator.com": true, "test.test": true,
}

// placeholderTLDs never resolve to a real public host.
var placeholderTLDs = []string{".test", ".example", ".invalid", ".localhost", ".local", ".internal"}

// pivotWorthy decides whether an auto-pivot into a discovered entity is likely
// to yield meaningful results. It rejects reserved/placeholder domains and
// high-entropy gibberish handles (e.g. "alskjdhlakjsdhakjs@example.com") so the
// investigation graph only expands toward investigable, real-looking entities.
// Returns (ok, reason-when-not-ok).
func pivotWorthy(value, ttype string) (bool, string) {
	v := strings.TrimSpace(strings.ToLower(value))
	if v == "" {
		return false, "empty"
	}

	switch ttype {
	case TargetEmail:
		// Reject malformed addresses (e.g. "test@example" with no TLD) that the
		// related-entity path would otherwise pivot into without format checks.
		if !emailRe.MatchString(v) {
			return false, "malformed e-mail"
		}
		local, domain := emailParts(v)
		if !domainWorthy(domain) {
			return false, "placeholder/reserved domain"
		}
		if isGibberish(local) {
			return false, "random/gibberish local part"
		}
	case TargetDomain:
		if !domainRe.MatchString(v) {
			return false, "malformed domain"
		}
		if !domainWorthy(v) {
			return false, "placeholder/reserved domain"
		}
	case TargetUsername:
		if isGibberish(v) {
			return false, "random/gibberish handle"
		}
	}
	return true, ""
}

// inPivotScope keeps an investigation focused on its subject. For a domain
// investigation the auto-pivot must stay within the target's own namespace -
// the domain itself, its subdomains, e-mails at that domain, and the IPs it
// resolves to. Registrar/WHOIS contacts, mail/NS provider domains and
// co-hosted domains (other tenants on a shared IP) are recorded as findings but
// must NOT spawn child scans, or the graph fills with out-of-scope noise.
// Person investigations (email/username/name) are not domain-constrained.
func inPivotScope(rootTarget, rootType, value, ttype string) (bool, string) {
	if rootType != TargetDomain {
		return true, ""
	}
	root := strings.ToLower(strings.TrimSpace(rootTarget))
	v := strings.ToLower(strings.TrimSpace(value))
	switch ttype {
	case TargetDomain:
		if v == root || strings.HasSuffix(v, "."+root) {
			return true, ""
		}
		return false, "outside root domain " + root
	case TargetEmail:
		_, d := emailParts(v)
		if d == root || strings.HasSuffix(d, "."+root) {
			return true, ""
		}
		return false, "e-mail outside root domain " + root
	case TargetIP:
		return true, "" // resolved infrastructure of the target
	default:
		return false, "unrelated to root domain " + root
	}
}

// domainWorthy rejects reserved/placeholder domains.
func domainWorthy(domain string) bool {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" || placeholderDomains[domain] {
		return false
	}
	for _, suf := range placeholderTLDs {
		if strings.HasSuffix(domain, suf) {
			return false
		}
	}
	return true
}

// isGibberish flags a handle/local-part that looks machine-random rather than a
// real name or username: long, vowel-starved, or with a long consonant run.
// It is deliberately conservative so ordinary handles (e.g. "jdoe", "k_smith")
// pass and only obvious noise ("alskjdhlakjsdhakjs") is rejected.
func isGibberish(s string) bool {
	letters, vowels, run, maxRun := 0, 0, 0, 0
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			letters++
			if r == 'a' || r == 'e' || r == 'i' || r == 'o' || r == 'u' || r == 'y' {
				vowels++
				run = 0
			} else {
				run++
				if run > maxRun {
					maxRun = run
				}
			}
		default:
			run = 0
		}
	}
	if letters < 10 {
		return false // too short to judge — keep it
	}
	if maxRun >= 6 {
		return true // 6+ consonants in a row is not a real word/handle
	}
	return float64(vowels)/float64(letters) < 0.22
}

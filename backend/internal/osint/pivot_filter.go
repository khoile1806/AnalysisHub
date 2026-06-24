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

// freeMailDomains are public e-mail providers. An e-mail at one of these maps to
// a person, not to an organisation that owns the domain - so auto-pivoting into
// the domain itself (e.g. "gmail.com") would explode the graph into the
// provider's own infrastructure. They are recorded as findings but never
// spawn a child scan.
var freeMailDomains = map[string]bool{
	"gmail.com": true, "googlemail.com": true, "yahoo.com": true, "ymail.com": true,
	"rocketmail.com": true, "outlook.com": true, "hotmail.com": true, "live.com": true,
	"msn.com": true, "aol.com": true, "icloud.com": true, "me.com": true, "mac.com": true,
	"proton.me": true, "protonmail.com": true, "pm.me": true, "gmx.com": true, "gmx.net": true,
	"mail.com": true, "zoho.com": true, "yandex.com": true, "yandex.ru": true, "qq.com": true,
	"163.com": true, "126.com": true, "naver.com": true, "hey.com": true, "fastmail.com": true,
	"tutanota.com": true, "tuta.io": true, "hushmail.com": true, "mail.ru": true,
}

// providerSuffixes are cloud / CDN / hosting / SaaS / social-platform domains.
// A discovered host under one of these belongs to shared infrastructure or a
// third-party platform - not to the investigation's subject - so it must not
// spawn a child scan when reached from an IP or person root. (A domain-rooted
// investigation is already namespace-constrained, so these only matter there
// when the subject itself is on such a platform, which the namespace check
// handles.)
var providerSuffixes = []string{
	// Cloud / hosting infrastructure
	"amazonaws.com", "cloudfront.net", "elasticbeanstalk.com", "awsglobalaccelerator.com",
	"azurewebsites.net", "azureedge.net", "azure-api.net", "cloudapp.azure.com", "windows.net",
	"trafficmanager.net", "googleusercontent.com", "googlehosted.com", "appspot.com", "1e100.net",
	"run.app", "web.app", "firebaseapp.com", "cloudfunctions.net",
	"digitaloceanspaces.com", "ondigitalocean.app", "render.com", "onrender.com", "fly.dev",
	"herokuapp.com", "herokudns.com", "netlify.app", "vercel.app", "pages.dev", "workers.dev",
	"wpengine.com", "wordpress.com", "blogspot.com", "squarespace.com", "wixsite.com",
	"oraclecloud.com", "linodeusercontent.com", "vultrusercontent.com",
	// CDN / edge
	"cloudflare.net", "cloudflare.com", "fastly.net", "akamai.net", "akamaiedge.net",
	"akamaitechnologies.com", "edgekey.net", "edgesuite.net", "llnwd.net", "stackpathdns.com",
	"cdn77.org", "bunnycdn.com", "b-cdn.net", "jsdelivr.net", "unpkg.com",
	// Code / page hosting
	"github.io", "githubusercontent.com", "gitlab.io", "readthedocs.io", "surge.sh",
	// Social / platforms (pivoting a person into these as a *domain* is noise)
	"facebook.com", "fbcdn.net", "twitter.com", "x.com", "instagram.com", "tiktok.com",
	"linkedin.com", "youtube.com", "reddit.com", "pinterest.com", "tumblr.com", "medium.com",
	"telegram.org", "t.me", "discord.com", "discord.gg", "whatsapp.com",
}

// isProviderDomain reports whether a domain belongs to a public e-mail provider,
// cloud/CDN/hosting infrastructure, or a third-party platform - i.e. something
// that should never be auto-pivoted as the subject's own asset.
func isProviderDomain(domain string) bool {
	d := strings.TrimRight(strings.ToLower(strings.TrimSpace(domain)), ".")
	if d == "" {
		return false
	}
	if freeMailDomains[d] {
		return true
	}
	for _, suf := range providerSuffixes {
		if d == suf || strings.HasSuffix(d, "."+suf) {
			return true
		}
	}
	return false
}

// genericRDNSMarkers are tokens that ISPs and hosting providers embed in
// auto-generated reverse-DNS / PTR hostnames (e.g. "static.5.6.7.8.clients.your-host.de",
// "dynamic-203-0-113-9.dsl.example-isp.net"). Such a hostname names the provider's
// addressing scheme, not the subject's asset, so it must not spawn a child scan.
var genericRDNSMarkers = []string{
	"static", "dynamic", "dyn", "dhcp", "dsl", "pppoe", "ppp", "pool",
	"broadband", "cable", "fibre", "fiber", "wireless", "clients", "client",
	"customer", "cust", "subscriber", "unassigned", "no-reverse", "in-addr",
	"dedicated", "colo", "rdns", "reverse",
}

// isGenericReverseDNS reports whether host looks like an ISP/hosting
// auto-generated reverse-DNS name for ip, rather than a real, investigable asset.
// It fires when the hostname embeds the IP's octets (dotted, dashed, or reversed)
// or carries a strong provider marker alongside a digit group.
func isGenericReverseDNS(host, ip string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	if oct := strings.Split(strings.TrimSpace(ip), "."); len(oct) == 4 {
		dotted := strings.Join(oct, ".")
		dashed := strings.Join(oct, "-")
		revDashed := oct[3] + "-" + oct[2] + "-" + oct[1] + "-" + oct[0]
		for _, p := range []string{dotted, dashed, revDashed} {
			if p != "" && strings.Contains(h, p) {
				return true
			}
		}
	}
	hasDigitRun, run := false, 0
	for _, r := range h {
		if r >= '0' && r <= '9' {
			if run++; run >= 2 {
				hasDigitRun = true
				break
			}
		} else {
			run = 0
		}
	}
	if !hasDigitRun {
		return false
	}
	for _, m := range genericRDNSMarkers {
		if strings.Contains(h, m) {
			return true
		}
	}
	return false
}

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
		// IP and person (email/username/name) roots aren't namespace-constrained,
		// but must still not pivot into shared infrastructure or public providers
		// (a co-hosted CDN tenant, a free-mail domain, a social platform), which is
		// the main way these investigations drift out of scope.
		switch ttype {
		case TargetDomain:
			if isProviderDomain(value) {
				return false, "shared/provider/CDN domain - not the subject's asset"
			}
			if rootType == TargetIP && isGenericReverseDNS(value, rootTarget) {
				return false, "generic ISP/hosting reverse-DNS host - not the subject's asset"
			}
		case TargetEmail:
			if _, d := emailParts(value); isProviderDomain(d) {
				return false, "free-mail/provider domain - maps to a person, not an org"
			}
		}
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

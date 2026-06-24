// Package osint implements entity footprinting: given a single identifier
// (IP, domain, email, phone, username, hash, wallet, or name) it collects the
// traces that identifier left across the internet from many open-source-
// intelligence sources. Most collectors are passive (third-party APIs, DNS,
// certificate transparency). A few are actively probing - the "webtech"
// collector fetches the target's web root to fingerprint its stack, and the
// "portscan" collector runs a TCP-connect scan with banner grabbing - so it
// reflects the host's current state and can match running services to known
// CVEs. Active collectors only ever touch the validated public target (private/
// loopback/link-local targets are rejected up-front by ValidateTarget). It is
// backend-native: collectors are in-process HTTP/DNS/TCP calls, not a forensic
// agent. The only optional external dependency is the Maigret CLI (username
// "maigret" collector, when present on PATH); every other collector is pure Go.
package osint

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"

	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/config"
	"github.com/forensichub/backend/internal/models"
	"github.com/forensichub/backend/internal/threatintel"
)

// Target type identifiers. Stored verbatim in OsintScan.TargetType.
const (
	TargetIP       = "ip"
	TargetDomain   = "domain"
	TargetEmail    = "email"
	TargetPhone    = "phone"
	TargetUsername = "username"
	TargetHash     = "hash"   // file hash (md5/sha1/sha256) - DFIR IOC
	TargetWallet   = "wallet" // crypto wallet (BTC/ETH) - money-trail DFIR
	TargetName     = "name"   // free-text person / full name (allows spaces)
)

// errNoAPIKey is returned by a collector whose optional API key is unset. The
// engine records the collector as "skipped" (not "failed") when it sees this.
var errNoAPIKey = errors.New("optional API key not configured")

// Keys holds the optional third-party API keys. Every field may be empty; an
// empty field just means the matching collector is skipped or runs unauthenticated.
type Keys struct {
	VirusTotal string
	Shodan     string
	AbuseIPDB  string
	AlienVault string // OTX - used by the unified threatintel reputation collector
	HIBP       string
	NumVerify  string
	GitHub     string // optional - raises the GitHub e-mail-search rate limit
	AbuseCh    string // abuse.ch Auth-Key (ThreatFox / URLhaus / MalwareBazaar)
	Pulsedive  string
	GreyNoise  string
}

// collectorEnv is the read-only context handed to every collector run. It is
// shared across the concurrent collector goroutines - do not mutate it.
type collectorEnv struct {
	target string
	ttype  string
	keys   Keys
	cfg    *config.Config
	db     *gorm.DB
	enrich *threatintel.EnrichClient // shared multi-source reputation client (may be nil)
	cache  *osintCache               // shared Redis read-through cache (may be nil)
	emit   func(line string)
}

// collector pairs a stable name (matches OsintCollector.Name) with its impl.
type collector struct {
	name string
	run  func(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error)
}

var (
	emailRe = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,}$`)
	// domainRe is conservative: at least one dot, valid LDH labels, alpha TLD.
	domainRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	// phoneRe accepts an optional leading + then digits/spaces/()-./ separators.
	phoneRe = regexp.MustCompile(`^\+?[0-9][0-9 ().\-]{6,19}$`)
	// usernameRe matches a bare social-media handle (2-32 chars, LDH-ish).
	usernameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{1,31}$`)
	// hashRe matches an MD5 (32), SHA-1 (40), or SHA-256 (64) hex digest.
	hashRe = regexp.MustCompile(`^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$`)
	// btcRe matches a Bitcoin address (legacy 1/3 base58, or bech32 bc1).
	btcRe = regexp.MustCompile(`^(?:bc1[a-zA-HJ-NP-Z0-9]{20,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$`)
	// ethRe matches an Ethereum (0x...) address.
	ethRe = regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`)
	// nameRe matches a person's full name: two or more words of Unicode letters
	// (incl. Vietnamese diacritics via \p{M}) separated by spaces, allowing the
	// usual name punctuation (. ' -). This is the only target type that permits
	// spaces, so people can be searched by name and not just by a single handle.
	nameRe = regexp.MustCompile(`^\p{L}[\p{L}\p{M}.'\-]*( +\p{L}[\p{L}\p{M}.'\-]*)+$`)
)

// DetectTargetType classifies a raw target string. Order matters: IP first
// (unambiguous), then email (has '@'), then phone (digits only), then domain.
func DetectTargetType(raw string) (string, error) {
	t := strings.TrimSpace(raw)
	if t == "" {
		return "", errors.New("target is empty")
	}
	// Strip a pasted URL down to its host so "https://example.com/x" works.
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
		if s := strings.IndexAny(t, "/?#"); s >= 0 {
			t = t[:s]
		}
	}
	if net.ParseIP(t) != nil {
		return TargetIP, nil
	}
	if emailRe.MatchString(t) {
		return TargetEmail, nil
	}
	// Hash before phone: an all-hex digest can otherwise be misread as a phone.
	if hashRe.MatchString(t) {
		return TargetHash, nil
	}
	// Crypto wallet (ETH 0x... is exact; BTC base58/bech32) - before phone/username.
	if ethRe.MatchString(t) || btcRe.MatchString(t) {
		return TargetWallet, nil
	}
	if phoneRe.MatchString(t) && countDigits(t) >= 7 {
		return TargetPhone, nil
	}
	if domainRe.MatchString(strings.ToLower(t)) {
		return TargetDomain, nil
	}
	// A multi-word string of letters is a person's full name (people search).
	if nameRe.MatchString(t) {
		return TargetName, nil
	}
	// Fallback: a bare handle-shaped string is treated as a username.
	if usernameRe.MatchString(t) {
		return TargetUsername, nil
	}
	return "", errors.New("could not detect target type - expected an IP, domain, email, phone, username, or full name")
}

// countDigits returns how many ASCII digits s contains.
func countDigits(s string) int {
	n := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			n++
		}
	}
	return n
}

// buildCollectors returns the ordered collector set for a target type. The
// engine runs them all concurrently; order only affects the UI listing.
func buildCollectors(targetType string) []collector {
	switch targetType {
	case TargetDomain:
		return []collector{
			{"rdap", collectDomainRDAP},
			{"dns", collectDNS},
			{"crtsh", collectCrtSh},
			{"subbrute", collectSubBrute},
			{"host_search", collectHostSearch},
			{"typosquat", collectTyposquat},
			{"cloud", collectCloud},
			{"webtech", collectWebTech},
			{"wayback", collectWayback},
			{"virustotal", collectDomainVirusTotal},
			{"threatintel", collectThreatIntel},
			{"threatfox", collectThreatFox},
			{"urlhaus", collectURLhaus},
			{"urlscan", collectURLScan},
			{"pulsedive", collectPulsedive},
			{"ransomwatch", collectRansomwareWatch},
			{"breach_leak", collectBreachLeak},
			{"stealer_intel", collectStealerIntel},
			{"exposure_search", collectExposureSearch},
			{"darkweb", collectDarkWeb},
			{"local_intel", collectLocalThreatIntel},
		}
	case TargetIP:
		return []collector{
			{"reverse_dns", collectReverseDNS},
			{"reverse_ip", collectReverseIP},
			{"rdap", collectIPRDAP},
			{"geoip", collectGeoIP},
			{"portscan", collectPortScan},
			{"webtech", collectWebTech},
			{"shodan_internetdb", collectShodanInternetDB},
			{"shodan", collectShodan},
			{"virustotal", collectIPVirusTotal},
			{"abuseipdb", collectAbuseIPDB},
			{"threatintel", collectThreatIntel},
			{"threatfox", collectThreatFox},
			{"urlhaus", collectURLhaus},
			{"pulsedive", collectPulsedive},
			{"greynoise", collectGreyNoise},
			{"local_intel", collectLocalThreatIntel},
		}
	case TargetHash:
		return []collector{
			{"virustotal", collectHashVirusTotal},
			{"hashlookup", collectHashLookup},
			{"threatintel", collectThreatIntel},
			{"threatfox", collectThreatFox},
			{"malwarebazaar", collectMalwareBazaar},
			{"local_intel", collectLocalThreatIntel},
		}
	case TargetWallet:
		return []collector{
			{"blockchain", collectBlockchain},
			{"local_intel", collectLocalThreatIntel},
		}
	case TargetEmail:
		return []collector{
			{"email_validate", collectEmailValidate},
			{"gravatar", collectGravatar},
			{"email_social", collectEmailSocialMedia},
			{"github_intel", collectGitHubIntel},
			{"hibp", collectHIBP},
			{"xposed", collectXposedOrNot},
			{"leakcheck", collectLeakCheck},
			{"breach_leak", collectBreachLeak},
			{"stealer_intel", collectStealerIntel},
			{"darkweb", collectDarkWeb},
			{"search_links", collectSearchLinks},
			{"local_intel", collectLocalThreatIntel},
		}
	case TargetPhone:
		return []collector{
			{"phone_meta", collectPhoneMeta},
			{"numverify", collectNumVerify},
			{"search_links", collectSearchLinks},
		}
	case TargetName:
		// A full name has no API-resolvable identifier; it is investigated
		// through assisted searches (web + social dorks) the analyst opens.
		return []collector{
			{"search_links", collectSearchLinks},
			{"darkweb", collectDarkWeb},
		}
	case TargetUsername:
		return []collector{
			{"maigret", collectMaigret},
			{"github_intel", collectGitHubIntel},
			{"social_search", collectSocialMedia},
			{"leakcheck", collectLeakCheck},
			{"breach_leak", collectBreachLeak},
			{"stealer_intel", collectStealerIntel},
			{"search_links", collectSearchLinks},
		}
	}
	return nil
}

// CollectorNamesFor returns the collector names that will run for a target
// type. The handler uses it to pre-create OsintCollector rows.
func CollectorNamesFor(targetType string) []string {
	cs := buildCollectors(targetType)
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.name
	}
	return out
}

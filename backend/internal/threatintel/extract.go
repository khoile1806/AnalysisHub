package threatintel

import (
	"net"
	"regexp"
	"strings"
)

var (
	// reIPv4 matches dotted-quad IPv4 addresses.
	reIPv4 = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)

	// reSHA256 must be checked before reSHA1/reMD5 to avoid short matches on
	// longer strings.
	reSHA256 = regexp.MustCompile(`\b[0-9a-fA-F]{64}\b`)
	reSHA1   = regexp.MustCompile(`\b[0-9a-fA-F]{40}\b`)
	reMD5    = regexp.MustCompile(`\b[0-9a-fA-F]{32}\b`)

	// reDomain matches hostnames with a recognisable public suffix.
	// Deliberately conservative: requires at least two labels and a known TLD.
	reDomain = regexp.MustCompile(
		`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+` +
			`(?:com|net|org|io|co|ru|cn|de|uk|fr|top|xyz|info|biz|site|online|cc|su|` +
			`in|br|jp|au|nl|pl|se|no|dk|fi|ch|at|be|es|pt|it|ro|hu|ua|vn|th|id|ph|my|sg|` +
			`gov|edu|mil|int|mobi|name|pro|tel|travel|museum|coop|aero|` +
			`tk|pw|ga|cf|ml|gq)\b`,
	)
)

// privateRanges lists CIDR blocks that should never be reported as suspicious
// because they are internal or infrastructure addresses.
var privateRanges []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"224.0.0.0/4",
		"240.0.0.0/4",
		"100.64.0.0/10", // RFC6598 shared address space
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			privateRanges = append(privateRanges, network)
		}
	}
}

// isPrivateIP returns true for loopback, RFC1918, link-local, and multicast.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	for _, r := range privateRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// safeDomains lists suffixes that are almost certainly benign and should be
// dropped from extraction to reduce noise.
var safeDomains = []string{
	"microsoft.com", "windows.com", "windowsupdate.com", "live.com",
	"google.com", "googleapis.com", "gstatic.com", "youtube.com",
	"amazon.com", "amazonaws.com",
	"apple.com", "icloud.com",
	"cloudflare.com",
	"github.com", "githubusercontent.com",
	"digicert.com", "verisign.com", "symantec.com",
	"w3.org", "schema.org",
}

func isCommonSafe(d string) bool {
	d = strings.ToLower(d)
	for _, s := range safeDomains {
		if d == s || strings.HasSuffix(d, "."+s) {
			return true
		}
	}
	return false
}

// ExtractIOCs parses raw text and returns distinct, deduplicated indicators.
// Results are capped (10 IPs, 10 hashes, 5 domains) to keep enrichment costs
// within free-tier API rate limits.
func ExtractIOCs(content string) IOCSet {
	ipMap     := make(map[string]struct{})
	hashMap   := make(map[string]struct{})
	domainMap := make(map[string]struct{})

	// IPs — skip private ranges and the unspecified address
	for _, m := range reIPv4.FindAllString(content, -1) {
		if m != "0.0.0.0" && !isPrivateIP(m) {
			ipMap[m] = struct{}{}
		}
	}

	// Hashes — SHA256 first to prevent partial overlap with shorter patterns
	alreadyHashed := make(map[string]struct{})
	for _, m := range reSHA256.FindAllString(content, -1) {
		lower := strings.ToLower(m)
		hashMap[lower] = struct{}{}
		alreadyHashed[lower] = struct{}{}
		// Mark all 40-char and 32-char sub-strings so shorter regexes skip them
		alreadyHashed[lower[:40]] = struct{}{}
		alreadyHashed[lower[:32]] = struct{}{}
	}
	for _, m := range reSHA1.FindAllString(content, -1) {
		lower := strings.ToLower(m)
		if _, seen := alreadyHashed[lower]; !seen {
			hashMap[lower] = struct{}{}
			alreadyHashed[lower] = struct{}{}
			if len(lower) >= 32 {
				alreadyHashed[lower[:32]] = struct{}{}
			}
		}
	}
	for _, m := range reMD5.FindAllString(content, -1) {
		lower := strings.ToLower(m)
		if _, seen := alreadyHashed[lower]; !seen {
			hashMap[lower] = struct{}{}
		}
	}

	// Domains — skip safe/known-good entries
	for _, m := range reDomain.FindAllString(content, -1) {
		d := strings.ToLower(m)
		if !isCommonSafe(d) {
			domainMap[d] = struct{}{}
		}
	}

	// Convert maps → slices with caps
	result := IOCSet{}
	for ip := range ipMap {
		if len(result.IPs) >= 10 {
			break
		}
		result.IPs = append(result.IPs, ip)
	}
	for h := range hashMap {
		if len(result.Hashes) >= 10 {
			break
		}
		result.Hashes = append(result.Hashes, h)
	}
	for d := range domainMap {
		if len(result.Domains) >= 5 {
			break
		}
		result.Domains = append(result.Domains, d)
	}
	return result
}

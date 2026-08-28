package threatintel

import (
	"crypto/sha256"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
)

var (
	// reIPv4 matches dotted-quad IPv4 addresses.
	reIPv4 = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)

	// reIPv6 is loose on purpose — net.ParseIP does the real validation below, so
	// the pattern only has to find candidates. Requiring at least two colons keeps
	// it off timestamps; MAC addresses match the shape but fail ParseIP.
	//
	// Written as "group, then repeated :group" rather than "repeated group:, then
	// tail": Go's alternation is leftmost-FIRST, so a tail of `(?::|hex)` matched
	// the bare colon and stopped, truncating 2606:4700:4700::1111 to
	// 2606:4700:4700:: — a different address entirely.
	reIPv6 = regexp.MustCompile(`\b[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%[0-9A-Za-z]+)?`)

	// reSHA256 must be checked before reSHA1/reMD5 to avoid short matches on
	// longer strings.
	reSHA256 = regexp.MustCompile(`\b[0-9a-fA-F]{64}\b`)
	reSHA1   = regexp.MustCompile(`\b[0-9a-fA-F]{40}\b`)
	reMD5    = regexp.MustCompile(`\b[0-9a-fA-F]{32}\b`)

	// reDomain matches anything host-shaped. It no longer carries its own TLD
	// list: that list was narrower than the one in domains.go and was missing the
	// abuse-heavy TLDs (.app, .dev, .zip, .click, .icu, .shop), so indicators on
	// exactly the infrastructure that matters were being dropped at extraction.
	// PlausibleDomains decides what survives.
	reDomain = regexp.MustCompile(
		`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b`)

	reURL   = regexp.MustCompile(`(?i)\bhttps?://[^\s/$.?#][^\s"'<>]*`)
	reEmail = regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)
	reBTC   = regexp.MustCompile(`\b(?:1|3)[1-9A-HJ-NP-Za-km-z]{25,34}\b|\bbc1[a-zA-HJ-NP-Z0-9]{39,59}\b`)
	reXMR   = regexp.MustCompile(`\b(?:4|8)[0-9a-zA-Z]{94,105}\b`)
)

// ── Defanging ───────────────────────────────────────────────────────────────

var defangReplacer = strings.NewReplacer(
	"[.]", ".", "(.)", ".", "{.}", ".", "[dot]", ".", "(dot)", ".",
	"[:]", ":", "[@]", "@", "(@)", "@", "[at]", "@",
	"hxxp://", "http://", "hxxps://", "https://",
	"hXXp://", "http://", "hXXps://", "https://",
	"hxxp[:]//", "http://", "hxxps[:]//", "https://",
)

// Refang restores a defanged indicator to its real form.
//
// Threat reports, vendor write-ups and analyst notes almost always neuter their
// indicators so nobody clicks them by accident — evil[.]com, hxxps://…,
// 185[.]220[.]101[.]5. The store's importer already understood this; the
// extractor did not, so pasting a report into the analysis pipeline yielded no
// indicators at all from the one source most likely to be full of them.
func Refang(s string) string { return defangReplacer.Replace(s) }

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
		// IPv6 equivalents.
		"::1/128",
		"fe80::/10",     // link-local
		"fc00::/7",      // unique local
		"ff00::/8",      // multicast
		"2001:db8::/32", // documentation
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
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
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
var (
	safeDomainsMu sync.RWMutex
	safeDomains   = []string{
		"microsoft.com", "windows.com", "windowsupdate.com", "live.com",
		"google.com", "googleapis.com", "gstatic.com", "youtube.com",
		"amazon.com", "amazonaws.com",
		"apple.com", "icloud.com",
		"cloudflare.com",
		"github.com", "githubusercontent.com",
		"digicert.com", "verisign.com", "symantec.com",
		"w3.org", "schema.org",
	}
)

func isCommonSafe(d string) bool {
	d = strings.ToLower(d)
	safeDomainsMu.RLock()
	defer safeDomainsMu.RUnlock()
	for _, s := range safeDomains {
		if d == s || strings.HasSuffix(d, "."+s) {
			return true
		}
	}
	return false
}

// ── Bitcoin address validation ──────────────────────────────────────────────

const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// validBTC checks the base58check payload of a legacy (1…/3…) address.
//
// The regex alone matches any base58-looking run of the right length, and a
// binary's string table or a base64 blob produces those constantly. Every false
// match became a "ransom payment address" in the report. The four-byte checksum
// that Bitcoin addresses carry settles it arithmetically instead of by guessing.
// bech32 (bc1…) uses a different checksum and is left to the regex.
func validBTC(addr string) bool {
	if strings.HasPrefix(addr, "bc1") {
		return true
	}
	// base58 decode into a big-endian byte string.
	num := make([]byte, 0, 32)
	for _, ch := range addr {
		idx := strings.IndexRune(b58Alphabet, ch)
		if idx < 0 {
			return false
		}
		carry := idx
		for i := len(num) - 1; i >= 0; i-- {
			carry += int(num[i]) * 58
			num[i] = byte(carry % 256)
			carry /= 256
		}
		for carry > 0 {
			num = append([]byte{byte(carry % 256)}, num...)
			carry /= 256
		}
	}
	// Leading '1's are leading zero bytes.
	for _, ch := range addr {
		if ch != '1' {
			break
		}
		num = append([]byte{0}, num...)
	}
	if len(num) != 25 {
		return false
	}
	payload, want := num[:21], num[21:]
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	for i := 0; i < 4; i++ {
		if second[i] != want[i] {
			return false
		}
	}
	return true
}

// ExtractIOCs parses raw text and returns distinct, deduplicated indicators.
//
// Results are capped (10 IPs, 10 hashes, 5 domains) to keep enrichment costs
// within free-tier API rate limits, and the caps are applied to a SORTED list.
// They used to be applied while ranging over a map, and Go randomises map
// iteration — so the same evidence produced a different set of indicators on
// every run, and which ones an analyst saw was decided by chance. A forensic
// tool has to give the same answer twice.
func ExtractIOCs(content string) IOCSet {
	// Indicators in reports and analyst notes are neutered so nobody clicks them;
	// refang a working copy before matching.
	content = Refang(content)

	ipMap := make(map[string]struct{})
	hashMap := make(map[string]struct{})
	domainMap := make(map[string]struct{})
	urlMap := make(map[string]struct{})
	emailMap := make(map[string]struct{})
	btcMap := make(map[string]struct{})
	xmrMap := make(map[string]struct{})

	// IPs — skip private ranges and the unspecified address
	for _, m := range reIPv4.FindAllString(content, -1) {
		if !isPrivateIP(m) {
			ipMap[m] = struct{}{}
		}
	}
	for _, m := range reIPv6.FindAllString(content, -1) {
		addr := strings.ToLower(strings.SplitN(m, "%", 2)[0])
		// net.ParseIP is the validator; the regex only finds candidates.
		if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil && !isPrivateIP(addr) {
			ipMap[addr] = struct{}{}
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

	// Domains — host-shaped matches, filtered by the shared plausibility rules,
	// then by the known-good suffix list.
	var candidates []string
	for _, m := range reDomain.FindAllString(content, -1) {
		candidates = append(candidates, strings.ToLower(m))
	}
	for _, d := range PlausibleDomains(candidates) {
		if !isCommonSafe(d) {
			domainMap[d] = struct{}{}
		}
	}

	for _, m := range reURL.FindAllString(content, -1) {
		urlMap[strings.TrimRight(m, ".,);]'\"")] = struct{}{}
	}
	for _, m := range reEmail.FindAllString(content, -1) {
		emailMap[strings.ToLower(m)] = struct{}{}
	}
	for _, m := range reBTC.FindAllString(content, -1) {
		if validBTC(m) {
			btcMap[m] = struct{}{}
		}
	}
	for _, m := range reXMR.FindAllString(content, -1) {
		xmrMap[m] = struct{}{}
	}

	return IOCSet{
		IPs:     capSorted(ipMap, 10),
		Hashes:  capSorted(hashMap, 10),
		Domains: capSorted(domainMap, 5),
		URLs:    capSorted(urlMap, 5),
		Emails:  capSorted(emailMap, 5),
		BTCs:    capSorted(btcMap, 5),
		XMRs:    capSorted(xmrMap, 5),
	}
}

// capSorted returns at most n values in a stable order. Sorting before the cut
// is the whole point: it makes the selection reproducible.
func capSorted(set map[string]struct{}, n int) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	if len(out) > n {
		out = out[:n]
	}
	return out
}

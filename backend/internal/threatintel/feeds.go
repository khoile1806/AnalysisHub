package threatintel

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// feeds.go — pulling indicators in, rather than waiting to be asked about one.
//
// Everything else in this package is reactive: something is seen, and a source
// is asked what it knows. That answers "is this bad" but never "what is bad
// right now", so the store only ever held what an operator typed in or what one
// manual OpenCTI sync happened to fetch. Between syncs it aged, and nothing
// aged it out.
//
// The feeds here are the open, no-account ones that carry current attacker
// infrastructure. Each declares how long its indicators stay meaningful, because
// that is a property of the feed and not of the importer: a botnet C2 address is
// stale in a fortnight, a malware distribution URL rather sooner.
//
// Every feed listed here was checked against its live endpoint before being
// included, and two well-known abuse.ch trackers were left OUT as a result:
// Feodo Tracker's recommended blocklist last changed in March and carries a
// single address, and SSLBL's IP blacklist has been empty since January. Both
// parse perfectly and would have contributed nothing while making the store look
// maintained — which is worse than not having them, because an analyst cannot
// tell a feed with no current threats from a feed that stopped.

// FeedIndicator is one parsed row, in the store's vocabulary.
type FeedIndicator struct {
	Value      string
	Type       string // IPv4-Addr | Domain-Name | URL | File-Hash
	Source     string
	Descr      string
	Confidence int
	Expires    time.Time
	Reference  string
	Campaign   string // malware family, where the feed names one
}

// Feed describes one upstream list.
type Feed struct {
	ID   string
	Name string
	URL  string
	// TTL is how long an indicator from this feed stays active. Chosen per feed
	// because the underlying infrastructure has different half-lives.
	TTL time.Duration
	// Confidence reflects how much curation the feed applies before publishing.
	Confidence int
	// Parse turns the response body into indicators.
	Parse func(body io.Reader, f Feed) []FeedIndicator
	// NeedsKey marks feeds that require an abuse.ch Auth-Key.
	NeedsKey bool
}

// DefaultFeeds are the built-in sources. All are open data; the abuse.ch ones
// accept an optional Auth-Key which raises their rate limits.
func DefaultFeeds() []Feed {
	return []Feed{
		{
			ID: "et-compromised", Name: "Emerging Threats compromised hosts",
			URL: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
			// Compromised hosts get cleaned up, and the address then belongs to an
			// innocent party; a short life is the point.
			TTL: 7 * 24 * time.Hour, Confidence: 70,
			Parse: parseLineList("IPv4-Addr", "Emerging Threats compromised host"),
		},
		{
			ID: "urlhaus", Name: "abuse.ch URLhaus (malware distribution URLs)",
			URL: "https://urlhaus.abuse.ch/downloads/text_recent/",
			// Distribution URLs are taken down or abandoned quickly.
			TTL: 7 * 24 * time.Hour, Confidence: 80,
			Parse: parseLineList("URL", "URLhaus malware distribution URL"),
		},
		{
			ID: "threatfox", Name: "abuse.ch ThreatFox (recent IOCs)",
			URL: "https://threatfox.abuse.ch/export/csv/recent/",
			TTL: 30 * 24 * time.Hour, Confidence: 75,
			Parse: parseThreatFox,
		},
	}
}

// parseLineList handles the plain-text feeds: one indicator per line, '#' for
// comments. The same shape covers the ET IP list and URLhaus's URL list.
func parseLineList(iocType, descr string) func(io.Reader, Feed) []FeedIndicator {
	return func(body io.Reader, f Feed) []FeedIndicator {
		var out []FeedIndicator
		expires := time.Now().UTC().Add(f.TTL)
		sc := bufio.NewScanner(body)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if len(out) >= maxFeedIndicators {
				break
			}
			out = append(out, FeedIndicator{
				Value: line, Type: iocType, Source: f.Name, Descr: descr,
				Confidence: f.Confidence, Expires: expires, Reference: f.URL,
			})
		}
		return out
	}
}

// parseThreatFox reads ThreatFox's CSV export. The column layout is documented
// upstream; anything that does not parse is skipped rather than guessed at.
func parseThreatFox(body io.Reader, f Feed) []FeedIndicator {
	var out []FeedIndicator
	expires := time.Now().UTC().Add(f.TTL)

	r := csv.NewReader(stripComments(body))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	for {
		rec, err := r.Read()
		if err != nil {
			break
		}
		if len(rec) < 6 || len(out) >= maxFeedIndicators {
			if len(out) >= maxFeedIndicators {
				break
			}
			continue
		}
		// first_seen, ioc_id, ioc_value, ioc_type, threat_type, malware, …
		value := strings.TrimSpace(strings.Trim(rec[2], `" `))
		kind := strings.TrimSpace(strings.Trim(rec[3], `" `))
		family := ""
		if len(rec) > 5 {
			family = strings.TrimSpace(strings.Trim(rec[5], `" `))
		}
		iocType := threatFoxType(kind)
		if value == "" || iocType == "" {
			continue
		}
		descr := "ThreatFox " + kind
		if family != "" {
			descr += " — " + family
		}
		out = append(out, FeedIndicator{
			Value: value, Type: iocType, Source: f.Name, Descr: descr,
			Confidence: f.Confidence, Expires: expires, Reference: f.URL,
			// The malware family is what turns a bare address into intelligence:
			// "this is a C2" is a blocklist entry, "this is Qakbot's C2" tells a
			// responder what else to look for on the host.
			Campaign: family,
		})
	}
	return out
}

func threatFoxType(kind string) string {
	switch strings.ToLower(kind) {
	case "ip:port", "ip":
		return "IPv4-Addr"
	case "domain":
		return "Domain-Name"
	case "url":
		return "URL"
	case "md5_hash", "sha1_hash", "sha256_hash":
		return "File-Hash"
	default:
		return ""
	}
}

// stripComments drops the '#' preamble abuse.ch puts above its CSV, which the
// csv reader would otherwise choke on.
func stripComments(r io.Reader) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			if _, err := io.WriteString(pw, line+"\n"); err != nil {
				return
			}
		}
	}()
	return pr
}

// maxFeedIndicators bounds one refresh. The feeds are large and the point is
// current infrastructure, not a complete archive.
const maxFeedIndicators = 20000

// maxFeedBody bounds the download itself.
const maxFeedBody = 32 << 20

// FetchFeed downloads and parses one feed. authKey is the optional abuse.ch
// Auth-Key; an empty string still works against the open endpoints.
func FetchFeed(ctx context.Context, hc *http.Client, f Feed, authKey string) ([]FeedIndicator, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", f.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AnalysisHub-IOC-Feed/1")
	if authKey != "" {
		req.Header.Set("Auth-Key", authKey)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, unavailable(f.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, unavailableStatus(f.Name, resp.StatusCode)
	}
	items := f.Parse(io.LimitReader(resp.Body, maxFeedBody), f)
	if len(items) == 0 {
		return nil, fmt.Errorf("%s: response parsed to zero indicators", f.Name)
	}
	return items, nil
}

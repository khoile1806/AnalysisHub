package osint

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/analysishub/backend/internal/models"
)

// collect_pdns.go — passive DNS. Live DNS shows where a domain points NOW;
// passive DNS shows every IP it has historically resolved to, which often
// reveals the real origin behind a CDN, sibling infrastructure, and past hosting
// an attacker has since moved off. Uses mnemonic's free public Passive DNS API
// (no key). Historical IPs become pivots so the graph reaches old infrastructure.

var rlPDNS = newRateLimiter(2 * time.Second)

// pdnsResp is the mnemonic PDNS v3 response shape (subset).
type pdnsResp struct {
	ResponseCode int `json:"responseCode"`
	Data         []struct {
		Query     string `json:"query"`
		Answer    string `json:"answer"`
		RRType    string `json:"rrtype"`
		FirstSeen int64  `json:"firstSeenTimestamp"`
		LastSeen  int64  `json:"lastSeenTimestamp"`
	} `json:"data"`
}

const pdnsCap = 40

// collectPassiveDNS pulls a domain's historical A/AAAA resolutions.
func collectPassiveDNS(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	if env.ttype != TargetDomain {
		return nil, nil
	}
	domain := strings.ToLower(strings.TrimSpace(env.target))
	if domain == "" {
		return nil, nil
	}

	api := "https://api.mnemonic.no/pdns/v3/" + url.PathEscape(domain) + "?limit=200"
	var r pdnsResp
	status, err := cachedGetJSON(ctx, env.cache, "pdns:"+domain, rlPDNS, api, map[string]string{"User-Agent": browserUA}, &r, ttlWayback)
	if err != nil {
		return nil, err
	}
	if status == 402 || status == 403 || status == 429 {
		env.emit("[*] passive_dns: mnemonic API unavailable/rate-limited - skipping")
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("mnemonic PDNS returned HTTP %d", status)
	}

	// Aggregate unique historical IPs with their last-seen time.
	type rec struct {
		ip       string
		lastSeen int64
	}
	seen := map[string]rec{}
	for _, d := range r.Data {
		rt := strings.ToLower(d.RRType)
		if rt != "a" && rt != "aaaa" {
			continue
		}
		ip := strings.TrimSpace(d.Answer)
		if ip == "" || net.ParseIP(ip) == nil {
			continue
		}
		if cur, ok := seen[ip]; !ok || d.LastSeen > cur.lastSeen {
			seen[ip] = rec{ip: ip, lastSeen: d.LastSeen}
		}
	}
	if len(seen) == 0 {
		env.emit("[*] passive_dns: no historical resolutions found")
		return nil, nil
	}

	recs := make([]rec, 0, len(seen))
	for _, v := range seen {
		recs = append(recs, v)
	}
	// Newest first, so the most relevant history leads.
	sort.Slice(recs, func(i, j int) bool { return recs[i].lastSeen > recs[j].lastSeen })

	out := make([]models.OsintFinding, 0, len(recs)+1)
	summary := newFinding("passive_dns", "dns", "Passive DNS history",
		fmt.Sprintf("%d historical IP(s) this domain has resolved to", len(recs)))
	summary.SourceURL = "https://passivedns.mnemonic.no/search/?query=" + url.QueryEscape(domain)
	out = append(out, summary)

	for i, rc := range recs {
		if i >= pdnsCap {
			break
		}
		detail := "historical A/AAAA record"
		if rc.lastSeen > 0 {
			detail = "last seen " + time.UnixMilli(rc.lastSeen).UTC().Format("2006-01-02")
		}
		f := newFinding("passive_dns", "dns", "Historical IP - "+rc.ip, detail)
		f.SourceURL = summary.SourceURL
		// Only public IPs are worth pivoting into.
		if ip := net.ParseIP(rc.ip); ip != nil && isPublicIP(ip) {
			out = append(out, withRelated(f, RelatedEntity{Type: TargetIP, Value: rc.ip}))
		} else {
			out = append(out, f)
		}
	}
	env.emit(fmt.Sprintf("[+] passive_dns: %d historical IP(s)", len(recs)))
	return out, nil
}

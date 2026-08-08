package osint

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/analysishub/backend/internal/models"
)

// collect_asn.go — ASN / BGP netblock enumeration for an IP. Turns a single IP
// into its owning ASN + the announced prefix that covers it + how much address
// space that ASN announces — the "org → all netblocks" pivot that a bare
// geo-ASN string can't give. Key-free via BGPView.

type bgpviewIPResponse struct {
	Status string `json:"status"`
	Data   struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
			IP     string `json:"ip"`
			Cidr   int    `json:"cidr"`
			Name   string `json:"name"`
			ASN    struct {
				ASN         int    `json:"asn"`
				Name        string `json:"name"`
				Description string `json:"description"`
				CountryCode string `json:"country_code"`
			} `json:"asn"`
		} `json:"prefixes"`
	} `json:"data"`
}

type bgpviewASNPrefixes struct {
	Status string `json:"status"`
	Data   struct {
		IPv4Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"ipv4_prefixes"`
	} `json:"data"`
}

// collectASN resolves an IP's ASN + covering prefix and summarises the ASN's
// announced address space. It intentionally does NOT auto-pivot every prefix
// (that would explode the graph); it surfaces the netblock context for the analyst.
func collectASN(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	ip := strings.TrimSpace(env.target)
	u := "https://api.bgpview.io/ip/" + url.PathEscape(ip)
	var r bgpviewIPResponse
	status, err := cachedGetJSON(ctx, env.cache, "bgpview:ip:"+ip, rlBGP, u, nil, &r, ttlASN)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 || r.Status != "ok" || len(r.Data.Prefixes) == 0 {
		return nil, nil
	}
	// The most-specific prefix (largest cidr) is the covering netblock.
	best := r.Data.Prefixes[0]
	for _, p := range r.Data.Prefixes {
		if p.Cidr > best.Cidr {
			best = p
		}
	}
	asn := best.ASN.ASN
	if asn == 0 {
		return nil, nil
	}
	var out []models.OsintFinding
	holder := strings.TrimSpace(best.ASN.Name + " " + best.ASN.Description)
	af := newFinding("asn", "infra", "Autonomous System",
		fmt.Sprintf("AS%d — %s (%s)", asn, holder, best.ASN.CountryCode))
	out = append(out, withSource(af, "https://bgp.tools/as/"+strconv.Itoa(asn)))
	pf := newFinding("asn", "infra", "Announced prefix (netblock)", best.Prefix)
	out = append(out, withSource(pf, "https://bgp.tools/prefix/"+url.PathEscape(best.Prefix)))

	// How much space this ASN announces — a bounded sample + the total count give
	// the analyst the org's footprint without seeding hundreds of pivots.
	var pr bgpviewASNPrefixes
	pu := fmt.Sprintf("https://api.bgpview.io/asn/%d/prefixes", asn)
	if st, perr := cachedGetJSON(ctx, env.cache, fmt.Sprintf("bgpview:asn:%d", asn), rlBGP, pu, nil, &pr, ttlASN); perr == nil && st >= 200 && st < 300 && pr.Status == "ok" {
		total := len(pr.Data.IPv4Prefixes)
		if total > 0 {
			sample := make([]string, 0, 8)
			for i, p := range pr.Data.IPv4Prefixes {
				if i >= 8 {
					break
				}
				sample = append(sample, p.Prefix)
			}
			out = append(out, newFinding("asn", "infra",
				fmt.Sprintf("AS%d announces %d IPv4 prefix(es)", asn, total),
				strings.Join(sample, ", ")+func() string {
					if total > len(sample) {
						return fmt.Sprintf(" … (+%d more)", total-len(sample))
					}
					return ""
				}()))
		}
	}
	env.emit(fmt.Sprintf("[+] asn: AS%d %s, prefix %s", asn, holder, best.Prefix))
	return out, nil
}

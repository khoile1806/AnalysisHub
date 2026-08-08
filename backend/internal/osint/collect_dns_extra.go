package osint

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/analysishub/backend/internal/models"
)

// collect_dns_extra.go — the DNS record types Go's net.Resolver can't fetch:
// CAA (cert-issuance policy), SOA (admin-email pivot), DNSKEY (DNSSEC posture),
// and DKIM selector probing (completes the email-spoofability picture). Uses
// miekg/dns against public resolvers. Key-free.

var dnsExtraServers = []string{"1.1.1.1:53", "8.8.8.8:53"}

// dkimSelectors are the selector names mail providers most commonly use, probed
// at <selector>._domainkey.<domain> to see whether DKIM is published.
var dkimSelectors = []string{
	"default", "google", "selector1", "selector2", "k1", "k2", "dkim",
	"mail", "s1", "s2", "mandrill", "mimecast", "everlytickey1", "smtp",
}

// dnsQuery resolves one record type via public DoH-free resolvers (DO bit set so
// DNSSEC records come back). Returns the answer RRs.
func dnsQuery(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.SetEdns0(4096, true)
	c := &dns.Client{Timeout: 5 * time.Second}
	var lastErr error
	for _, srv := range dnsExtraServers {
		in, _, err := c.ExchangeContext(ctx, m, srv)
		if err == nil && in != nil {
			return in.Answer, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// collectDNSRecords fetches CAA / SOA / DNSSEC / DKIM records for a domain.
func collectDNSRecords(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	host := strings.ToLower(strings.TrimSpace(env.target))
	if host == "" {
		return nil, nil
	}
	var out []models.OsintFinding

	// SOA — the rname field is the zone-admin email, a fresh registrant pivot.
	if ans, err := dnsQuery(ctx, host, dns.TypeSOA); err == nil {
		for _, rr := range ans {
			if soa, ok := rr.(*dns.SOA); ok {
				out = append(out, newFinding("dns_records", "dns", "SOA record",
					fmt.Sprintf("mname=%s serial=%d", strings.TrimRight(soa.Ns, "."), soa.Serial)))
				if em := soaEmail(soa.Mbox); em != "" {
					f := newFinding("dns_records", "dns", "SOA admin email", em)
					out = append(out, withRelated(f, RelatedEntity{Type: TargetEmail, Value: em}))
				}
			}
		}
	}

	// CAA — which CAs may issue certs for this domain (mis-issuance surface).
	if ans, err := dnsQuery(ctx, host, dns.TypeCAA); err == nil {
		for _, rr := range ans {
			if caa, ok := rr.(*dns.CAA); ok {
				out = append(out, newFinding("dns_records", "dns", "CAA record", caa.Tag+" "+caa.Value))
			}
		}
	}

	// DNSSEC — DNSKEY presence.
	if ans, err := dnsQuery(ctx, host, dns.TypeDNSKEY); err == nil {
		n := 0
		for _, rr := range ans {
			if _, ok := rr.(*dns.DNSKEY); ok {
				n++
			}
		}
		if n > 0 {
			out = append(out, newFinding("dns_records", "dns", "DNSSEC enabled", fmt.Sprintf("%d DNSKEY record(s)", n)))
		} else {
			f := newFinding("dns_records", "dns", "DNSSEC not enabled", "no DNSKEY published — zone not cryptographically signed")
			f.Severity = "low"
			out = append(out, f)
		}
	}

	// DKIM — probe common selectors concurrently.
	found := dkimProbe(ctx, host)
	if len(found) > 0 {
		out = append(out, newFinding("dns_records", "dns", "DKIM selectors published", strings.Join(found, ", ")))
	} else {
		f := newFinding("dns_records", "dns", "No DKIM selector found",
			strconv.Itoa(len(dkimSelectors))+" common selectors probed, none published — email is more spoofable")
		f.Severity = "medium"
		out = append(out, f)
	}

	if len(out) > 0 {
		env.emit("[+] dns_records: " + strconv.Itoa(len(out)) + " CAA/SOA/DNSSEC/DKIM record(s)")
	}
	return out, nil
}

// dkimProbe queries each candidate selector's TXT record concurrently and returns
// the selectors that publish a DKIM key.
func dkimProbe(ctx context.Context, host string) []string {
	var (
		mu    sync.Mutex
		found []string
		wg    sync.WaitGroup
	)
	sem := make(chan struct{}, 6)
	for _, sel := range dkimSelectors {
		wg.Add(1)
		go func(sel string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			ans, err := dnsQuery(ctx, sel+"._domainkey."+host, dns.TypeTXT)
			if err != nil {
				return
			}
			for _, rr := range ans {
				if txt, ok := rr.(*dns.TXT); ok {
					joined := strings.ToLower(strings.Join(txt.Txt, ""))
					if strings.Contains(joined, "v=dkim1") || strings.Contains(joined, "p=") {
						mu.Lock()
						found = append(found, sel)
						mu.Unlock()
						return
					}
				}
			}
		}(sel)
	}
	wg.Wait()
	return found
}

// soaEmail converts an SOA rname ("admin.example.com") to an email
// ("admin@example.com"). The first unescaped dot separates local from domain.
func soaEmail(mbox string) string {
	mbox = strings.TrimRight(mbox, ".")
	if mbox == "" {
		return ""
	}
	i := strings.Index(mbox, ".")
	if i <= 0 || i+1 >= len(mbox) {
		return ""
	}
	return mbox[:i] + "@" + mbox[i+1:]
}

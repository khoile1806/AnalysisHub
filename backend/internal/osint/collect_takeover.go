package osint

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/analysishub/backend/internal/models"
)

// collect_takeover.go — dangling-CNAME subdomain-takeover detection.
//
// A subdomain is "takeover-able" when it still points (via CNAME) at a
// third-party service — S3 bucket, GitHub Pages site, Heroku app, Azure resource
// — that has since been deleted. Anyone can then re-register that resource and
// serve content from the victim's subdomain. This collector reuses the same host
// candidates as the subdomain brute-forcer, resolves each host's CNAME, and only
// when the CNAME points at a fingerprinted service does it fetch the host to
// confirm the tell-tale "unclaimed" response. It is an ACTIVE collector: it makes
// a light HTTP request to the target's own hosts, so it is scope-gated like
// webtech/subbrute.

// takeoverCandidateCap bounds how many host candidates are CNAME-checked so the
// collector stays fast on a large wordlist.
const takeoverCandidateCap = 260

// takeoverSig fingerprints one takeover-prone service. A host is flagged when its
// CNAME target contains one of cnames AND either (a) the service page returns one
// of the fps "unclaimed" strings, or (b) nxOnly is set and the CNAME target does
// not resolve at all (a dangling alias).
type takeoverSig struct {
	service string
	cnames  []string
	fps     []string
	nxOnly  bool
}

// takeoverSigs is a curated, high-confidence subset (derived from the public
// "can-i-take-over-xyz" catalogue). Kept deliberately tight to avoid false
// positives on services that merely 404.
var takeoverSigs = []takeoverSig{
	{"GitHub Pages", []string{"github.io"}, []string{"there isn't a github pages site here"}, false},
	{"Heroku", []string{"herokuapp.com", "herokudns.com", "herokussl.com"}, []string{"no such app", "herokucdn.com/error-pages/no-such-app.html"}, false},
	{"AWS S3", []string{"s3.amazonaws.com", "s3-website", "s3.dualstack", ".s3."}, []string{"nosuchbucket", "the specified bucket does not exist"}, false},
	{"Fastly", []string{"fastly.net"}, []string{"fastly error: unknown domain"}, false},
	{"Shopify", []string{"myshopify.com"}, []string{"sorry, this shop is currently unavailable"}, false},
	{"Zendesk", []string{"zendesk.com"}, []string{"help center closed"}, false},
	{"Tumblr", []string{"domains.tumblr.com"}, []string{"whatever you were looking for doesn't currently exist at this address"}, false},
	{"Unbounce", []string{"unbouncepages.com"}, []string{"the requested url was not found on this server"}, false},
	{"Surge.sh", []string{"surge.sh"}, []string{"project not found"}, false},
	{"Bitbucket", []string{"bitbucket.io"}, []string{"repository not found"}, false},
	{"Ghost", []string{"ghost.io"}, []string{"the thing you were looking for is no longer here"}, false},
	{"Pantheon", []string{"pantheonsite.io"}, []string{"the gods are wise, but do not know of the site which you seek"}, false},
	{"Wordpress", []string{"wordpress.com"}, []string{"do you want to register"}, false},
	{"Azure", []string{"azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "blob.core.windows.net", "azureedge.net", "azure-api.net", "azurehdinsight.net"}, nil, true},
}

// collectTakeover checks the domain and its common subdomains for dangling CNAMEs
// pointing at unclaimed third-party services.
func collectTakeover(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	apex := strings.ToLower(strings.TrimSpace(env.target))
	if apex == "" {
		return nil, nil
	}

	// Same candidate space as subbrute (apex + www + wordlist), so takeover
	// coverage tracks the hosts we already enumerate.
	candidates := make([]string, 0, len(subdomainWordlist)+2)
	candidates = append(candidates, apex, "www."+apex)
	for _, label := range subdomainWordlist {
		candidates = append(candidates, label+"."+apex)
	}
	if len(candidates) > takeoverCandidateCap {
		candidates = candidates[:takeoverCandidateCap]
	}

	type hit struct {
		host  string
		cname string
		sig   takeoverSig
	}
	var (
		mu       sync.Mutex
		hits     []hit
		resolver = &net.Resolver{}
		sem      = make(chan struct{}, 25)
		wg       sync.WaitGroup
	)
	for _, h := range candidates {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			cname, err := resolver.LookupCNAME(lctx, host)
			cancel()
			if err != nil || cname == "" {
				return
			}
			cn := strings.TrimSuffix(strings.ToLower(cname), ".")
			if cn == host { // no real alias
				return
			}
			sig, ok := matchTakeoverSig(cn)
			if !ok {
				return
			}
			mu.Lock()
			hits = append(hits, hit{host: host, cname: cn, sig: sig})
			mu.Unlock()
		}(h)
	}
	wg.Wait()

	if len(hits) == 0 {
		env.emit("[*] takeover: no dangling CNAMEs pointing at takeover-prone services")
		return nil, nil
	}

	var out []models.OsintFinding
	for _, h := range hits {
		vulnerable, note := confirmTakeover(ctx, h.host, h.cname, h.sig)
		if !vulnerable {
			continue
		}
		detail := fmt.Sprintf("%s → %s (%s): %s", h.host, h.cname, h.sig.service, note)
		f := newFinding("takeover", "takeover", "Possible subdomain takeover", detail)
		if h.sig.nxOnly {
			// Dangling alias without a body confirmation — strong lead, verify.
			f.Severity = "high"
			f.Confidence = "likely"
			f.VerifyNote = "CNAME points at a " + h.sig.service + " resource that no longer resolves; claim-check the resource to confirm."
		} else {
			f.Severity = "critical"
			f.Confidence = "verified"
			f.VerifyNote = "Host serves the " + h.sig.service + " 'unclaimed resource' page — the alias can be taken over."
		}
		f = withRelated(f, RelatedEntity{Type: TargetDomain, Value: h.host})
		out = append(out, f)
		env.emit("[!] takeover: " + h.host + " (" + h.sig.service + ")")
	}
	if len(out) == 0 {
		env.emit("[*] takeover: dangling CNAMEs seen but none confirmed unclaimed")
		return nil, nil
	}
	return out, nil
}

// matchTakeoverSig returns the signature whose CNAME patterns the target matches.
func matchTakeoverSig(cname string) (takeoverSig, bool) {
	for _, s := range takeoverSigs {
		for _, c := range s.cnames {
			if strings.Contains(cname, c) {
				return s, true
			}
		}
	}
	return takeoverSig{}, false
}

// confirmTakeover verifies a candidate: for body-fingerprint services it fetches
// the host and looks for the "unclaimed" string; for nxOnly services it checks
// that the CNAME target does not resolve. Returns whether it looks vulnerable and
// a short human note.
func confirmTakeover(ctx context.Context, host, cname string, sig takeoverSig) (bool, string) {
	if sig.nxOnly {
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := (&net.Resolver{}).LookupHost(lctx, cname)
		cancel()
		if err != nil || len(addrs) == 0 {
			return true, "alias target does not resolve (NXDOMAIN)"
		}
		return false, ""
	}

	// Try HTTPS then HTTP; a 404-with-fingerprint is exactly the signal, so a
	// non-2xx status is not treated as an error here. Each fetch gets its own short
	// timeout so a single hanging candidate can't consume the whole collector budget.
	for _, scheme := range []string{"https://", "http://"} {
		fctx, fcancel := context.WithTimeout(ctx, 8*time.Second)
		body, _, err := httpGetBody(fctx, nil, scheme+host+"/", nil)
		fcancel()
		if err != nil || len(body) == 0 {
			continue
		}
		low := strings.ToLower(string(body))
		for _, fp := range sig.fps {
			if strings.Contains(low, fp) {
				return true, "matched unclaimed-resource fingerprint"
			}
		}
	}
	return false, ""
}

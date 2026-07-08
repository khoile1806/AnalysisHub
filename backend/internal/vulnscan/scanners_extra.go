package vulnscan

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/analysishub/backend/internal/models"
)

// maxSANTargets bounds how many certificate SAN hostnames tlsx may add as fresh
// scan targets, so a wildcard / multi-domain cert can't blow up the target set.
const maxSANTargets = 200

// tlsxLine is the subset of tlsx -json we consume.
type tlsxLine struct {
	Host       string   `json:"host"`
	Port       string   `json:"port"`
	SubjectCN  string   `json:"subject_cn"`
	SubjectAN  []string `json:"subject_an"`
	IssuerCN   string   `json:"issuer_cn"`
	NotAfter   string   `json:"not_after"`
	JARM       string   `json:"jarm"`
	SelfSigned bool     `json:"self_signed"`
	Expired    bool     `json:"expired"`
}

// runTLSx reads the TLS certificates of the live services: it records issuer /
// expiry / JARM as info findings (expired or self-signed certs as low), and
// harvests in-scope SAN hostnames as additional nuclei targets (a cert often
// reveals sibling hostnames the passive OSINT never saw). Missing binary → the
// live URLs pass through unchanged.
func (e *Engine) runTLSx(ctx context.Context, scan *models.VulnScan, liveURLs []string, proxyURL string) []string {
	scanID := scan.ID.String()
	bin, err := exec.LookPath("tlsx")
	if err != nil {
		return liveURLs
	}
	tool := e.newTool(scan.ID, "tlsx")
	e.startTool(tool)
	e.emit(scanID, fmt.Sprintf("[*] tlsx — reading TLS certificates of %d service(s)...", len(liveURLs)))

	listFile, cleanup, err := writeListFile(liveURLs)
	if err != nil {
		e.markTool(tool, models.VulnToolFailed, 0, err.Error())
		return liveURLs
	}
	defer cleanup()

	cctx, cancel := context.WithTimeout(ctx, e.toolTimeout())
	defer cancel()
	// NOTE: -expired / -self-signed are FILTERS in tlsx (they restrict output to
	// only those certs), not field toggles — including them hid every valid cert.
	// The expired/self_signed booleans come through -json regardless.
	args := []string{"-l", listFile, "-json", "-silent", "-timeout", "10", "-jarm", "-san", "-cn"}
	if proxyURL != "" {
		args = append(args, "-proxy", proxyURL)
	}
	cmd := e.commandFor(tool, cctx, bin, args...)
	cmd.Env = proxyEnv(proxyURL)

	var findings []models.VulnFinding
	sans := map[string]bool{}
	count := 0
	streamLines(cmd, func(line string) {
		var t tlsxLine
		if json.Unmarshal([]byte(line), &t) != nil || t.Host == "" {
			return
		}
		count++
		cn := t.SubjectCN
		if cn == "" {
			cn = t.Host
		}
		var parts []string
		if t.IssuerCN != "" {
			parts = append(parts, "issuer "+t.IssuerCN)
		}
		if t.NotAfter != "" {
			parts = append(parts, "expires "+t.NotAfter)
		}
		if t.Expired {
			parts = append(parts, "EXPIRED")
		}
		if t.SelfSigned {
			parts = append(parts, "self-signed")
		}
		if t.JARM != "" {
			parts = append(parts, "JARM "+t.JARM)
		}
		sev := "info"
		if t.Expired || t.SelfSigned {
			sev = "low"
		}
		hostport := t.Host
		if t.Port != "" {
			hostport = net.JoinHostPort(t.Host, t.Port)
		}
		findings = append(findings, e.buildFinding(scan.ID, tool.ID, "tlsx", "", "TLS: "+cn, sev, t.Host, hostport, "tls", strings.Join(parts, " · "), "", t.SubjectAN, line))
		for _, s := range t.SubjectAN {
			s = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(s, "*.")))
			if s != "" {
				sans[s] = true
			}
		}
	})
	inserted := e.persist(findings)
	e.markTool(tool, models.VulnToolDone, inserted, "")

	// Harvest in-scope SAN hostnames as extra HTTPS targets (scope-filtered, capped).
	fresh := make([]string, 0, len(sans))
	for s := range sans {
		fresh = append(fresh, s)
	}
	keep, _ := scopeFilter(fresh, proxyURL != "", scan.AllowPrivate)
	have := map[string]bool{}
	for _, u := range liveURLs {
		have[u] = true
	}
	out := append([]string{}, liveURLs...)
	added := 0
	for _, h := range keep {
		if added >= maxSANTargets {
			break
		}
		u := "https://" + h
		if !have[u] {
			have[u] = true
			out = append(out, u)
			added++
		}
	}
	e.emit(scanID, fmt.Sprintf("[+] tlsx done — %d cert(s), %d in-scope SAN host(s) added", count, added))
	return out
}

// runGau (deep/aggressive) pulls historically-known URLs for the target
// hostnames from passive archives (Wayback/CommonCrawl/OTX via the gau binary) to
// surface parameterised endpoints for the fuzzers. Bounded by maxGau and routed
// through the egress proxy. Missing binary / pure-IP set → no-op pass-through.
func (e *Engine) runGau(ctx context.Context, scan *models.VulnScan, targets []string, proxyURL string) []string {
	scanID := scan.ID.String()
	bin, err := exec.LookPath("gau")
	if err != nil {
		return targets
	}
	hosts := map[string]bool{}
	for _, t := range targets {
		if h := cleanHost(t); h != "" && net.ParseIP(h) == nil { // gau is for domains, not bare IPs
			hosts[h] = true
		}
	}
	if len(hosts) == 0 {
		return targets
	}
	hostList := make([]string, 0, len(hosts))
	for h := range hosts {
		hostList = append(hostList, h)
	}

	tool := e.newTool(scan.ID, "gau")
	e.startTool(tool)
	e.emit(scanID, fmt.Sprintf("[*] gau — fetching known URLs for %d host(s)...", len(hostList)))

	listFile, cleanup, err := writeListFile(hostList)
	if err != nil {
		e.markTool(tool, models.VulnToolFailed, 0, err.Error())
		return targets
	}
	defer cleanup()
	in, err := os.Open(listFile)
	if err != nil {
		e.markTool(tool, models.VulnToolFailed, 0, err.Error())
		return targets
	}
	defer in.Close()

	cctx, cancel := context.WithTimeout(ctx, e.toolTimeout())
	defer cancel()
	cmd := e.commandFor(tool, cctx, bin, "--threads", "5", "--subs")
	cmd.Stdin = in
	cmd.Env = proxyEnv(proxyURL)

	const maxGau = 1000
	have := map[string]bool{}
	for _, t := range targets {
		have[t] = true
	}
	out := append([]string{}, targets...)
	added := 0
	streamLines(cmd, func(line string) {
		u := strings.TrimSpace(line)
		if u == "" || have[u] || added >= maxGau {
			return
		}
		have[u] = true
		out = append(out, u)
		added++
	})
	e.markTool(tool, models.VulnToolDone, added, "")
	e.emit(scanID, fmt.Sprintf("[+] gau done — %d known URL(s) added (cap %d)", added, maxGau))
	return out
}

// nucleiOOBArgs returns nuclei's out-of-band (interactsh / OAST) flags. With a
// self-hosted server configured, nuclei uses it to catch blind/OOB vulnerabilities
// (SSRF, blind RCE, Log4Shell) via callbacks. With none configured, OOB is
// DISABLED so the scanner never silently calls the public oast.* servers — which
// would also leak target identity and defeat Tor-only egress.
func (e *Engine) nucleiOOBArgs() []string {
	if e.cfg != nil && e.cfg.VulnScanInteractshServer != "" {
		args := []string{"-interactsh-server", e.cfg.VulnScanInteractshServer}
		if e.cfg.VulnScanInteractshToken != "" {
			args = append(args, "-interactsh-token", e.cfg.VulnScanInteractshToken)
		}
		return args
	}
	return []string{"-no-interactsh"}
}

package vulnscan

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm/clause"

	"github.com/forensichub/backend/internal/models"
	"github.com/forensichub/backend/internal/netsafe"
)

// runPipeline is the scan body: scope-filter the assets, probe live HTTP
// services with httpx, then scan them with nuclei — all routed through the
// configured egress proxy. Each stage updates its VulnTool row and streams
// progress to SSE subscribers.
func (e *Engine) runPipeline(ctx context.Context, scan *models.VulnScan, targets []string) {
	scanID := scan.ID.String()
	e.db.Model(scan).Update("status", models.VulnRunning)
	e.emit(scanID, fmt.Sprintf("[*] Vulnerability scan started — %d asset(s) submitted", len(targets)))

	// Resolve egress FIRST: the proxy posture decides whether scope classification
	// may touch the local resolver. anonymous == "all DNS must transit the proxy".
	proxyURL, mode := e.resolveProxy(scan.ProxyChoice)
	anonymous := proxyURL != ""
	e.db.Model(scan).Update("proxy_mode", mode)
	switch mode {
	case "direct":
		e.emit(scanID, "[!] Egress DIRECT — traffic AND DNS leave from this host IP (no proxy).")
	default:
		e.emit(scanID, fmt.Sprintf("[*] Routing scanner traffic through %s proxy (%s)", mode, proxyURL))
		e.emit(scanID, "[*] Anonymous mode — target names are resolved through the proxy; no local DNS lookups.")
	}

	// Scope guard: never let the scanner touch private/loopback/metadata ranges.
	// In anonymous mode hostnames are deferred (resolved via the proxy) so scoping
	// itself never leaks a target name to the local/ISP resolver.
	var scoped []string
	for _, v := range classifyScope(targets, anonymous) {
		if v.Keep {
			scoped = append(scoped, v.Value)
		} else {
			e.emit(scanID, fmt.Sprintf("[!] Out of scope, skipped: %s — %s", v.Value, v.Reason))
		}
	}
	if len(scoped) == 0 {
		e.emit(scanID, "[!] No in-scope public assets to scan.")
		e.finalize(scan, models.VulnDone)
		e.emit(scanID, "__DONE__")
		e.scheduleHistoryCleanup(scanID)
		return
	}

	stopped := func() bool {
		if ctx.Err() != nil {
			e.finalize(scan, models.VulnStopped)
			e.emit(scanID, "[!] Scan stopped by operator")
			e.emit(scanID, "__DONE__")
			e.scheduleHistoryCleanup(scanID)
			return true
		}
		return false
	}

	// Stage 1 — subfinder: expand domain assets with passively-discovered
	// subdomains (skipped for pure-IP target sets / missing binary).
	scoped = e.assetStage(scanID, "subfinder", scoped, func() []string { return e.runSubfinder(ctx, scan, scoped, proxyURL) })
	if stopped() {
		return
	}

	// Stage 2 — dnsx: keep only domains that actually resolve (drops dead /
	// wildcard subdomains). SKIPPED in anonymous mode: dnsx queries public
	// resolvers over UDP directly (it can't transit a SOCKS proxy), which would
	// leak every target name. The proxied scanners drop dead hosts on their own.
	if !anonymous {
		scoped = e.assetStage(scanID, "dnsx", scoped, func() []string { return e.runDNSx(ctx, scan, scoped) })
		if stopped() {
			return
		}
	} else {
		e.emit(scanID, "[*] dnsx skipped (anonymous mode) — liveness handled by the proxied scanners")
	}

	// Stage 3 — cdncheck: drop IP literals that sit behind a CDN/WAF (third-party
	// shared infrastructure), so the scan stays on the operator's own targets.
	scoped = e.assetStage(scanID, "cdncheck", scoped, func() []string { return e.runCDNCheck(ctx, scan, scoped) })
	if stopped() {
		return
	}

	// Stage 4 — naabu: discover open ports (full/aggressive) so httpx/nuclei
	// also probe non-standard service ports, not just 80/443. SKIPPED on Tor: a
	// connect scan of the top-1000 ports per host through a SOCKS circuit is
	// impractically slow and usually yields nothing (it just burns minutes).
	probeTargets := scoped
	if e.profileIn(scan, "full", "deep", "aggressive") {
		if anonymous {
			e.emit(scanID, "[*] naabu skipped (anonymous mode) — port scanning over Tor is impractical")
		} else {
			probeTargets = e.assetStage(scanID, "naabu", scoped, func() []string {
				if ports := e.runNaabu(ctx, scan, scoped, proxyURL); len(ports) > 0 {
					return ports
				}
				return scoped
			})
			if stopped() {
				return
			}
		}
	}

	// Stage 5 — httpx: find live HTTP(S) services among the assets.
	httpxTool := e.newTool(scan.ID, "httpx")
	nucleiTool := e.newTool(scan.ID, "nuclei")
	live := e.assetStage(scanID, "httpx", nil, func() []string { return e.runHTTPx(ctx, scan, httpxTool, probeTargets, proxyURL) })
	if stopped() {
		e.markTool(nucleiTool, models.VulnToolSkipped, 0, "scan stopped")
		return
	}
	if len(live) == 0 {
		e.emit(scanID, "[*] No live HTTP services found; nothing for nuclei to scan.")
		e.markTool(nucleiTool, models.VulnToolSkipped, 0, "no live hosts")
		e.finalize(scan, models.VulnDone)
		e.emit(scanID, "__DONE__")
		e.scheduleHistoryCleanup(scanID)
		return
	}

	// Stage 6 — tlsx: cert issuer/SAN/JARM intel + harvest in-scope SAN hostnames
	// as extra scan bases.
	nucleiBases := e.assetStage(scanID, "tlsx", live, func() []string { return e.runTLSx(ctx, scan, live, proxyURL) })

	// nucleiBases = the BASE URLs nuclei templates run against (live roots + SAN +
	// ffuf-discovered endpoints). nuclei templates define their own paths, so they
	// only ever need these bases — never a crawl of deep URLs.

	// Stage 6b — ffuf (full/deep/aggressive): brute-force hidden dirs/files. Hits
	// are real endpoints → added as nuclei bases.
	if e.profileIn(scan, "full", "deep", "aggressive") {
		nucleiBases = e.assetStage(scanID, "ffuf", nucleiBases, func() []string { return e.runFfuf(ctx, scan, nucleiBases, proxyURL) })
		if stopped() {
			return
		}
	}

	// Stages 7–7b (deep/aggressive): katana crawl + gau archive → parameterised
	// URLs for the fuzzers. These DON'T feed the nuclei template scan (templates
	// define their own paths) — only the parameter-aware engines below.
	var paramURLs []string
	if e.profileIn(scan, "deep", "aggressive") {
		crawled := e.assetStage(scanID, "katana", nil, func() []string { return e.runKatana(ctx, scan, nucleiBases, proxyURL) })
		crawled = e.assetStage(scanID, "gau", crawled, func() []string { return e.runGau(ctx, scan, crawled, proxyURL) })
		paramURLs = filterParamURLs(crawled)
		e.emit(scanID, fmt.Sprintf("[*] %d parameterised URL(s) collected for fuzzing", len(paramURLs)))
		if stopped() {
			return
		}
	}

	// Stage 8 — nuclei TEMPLATE scan over the bases (roots first, capped). Small &
	// reliable: it always finishes, so high-signal services are never missed.
	nucleiBases = e.capNucleiTargets(scanID, live, nucleiBases, anonymous)
	e.voidStage(scanID, "nuclei", func() { e.runNuclei(ctx, scan, nucleiTool, nucleiBases, proxyURL, false) })

	// Stages 8a–8b (deep/aggressive): parameter fuzzing. dalfox tests the crawled
	// params AND self-mines the bases; nuclei -dast fuzzes the crawled params.
	if e.profileIn(scan, "deep", "aggressive") {
		dalfoxURLs := append(append([]string{}, paramURLs...), nucleiBases...)
		e.voidStage(scanID, "dalfox", func() { e.runDalfox(ctx, scan, dalfoxURLs, proxyURL) })
		if len(paramURLs) > 0 {
			dastTool := e.newTool(scan.ID, "nuclei-dast")
			e.voidStage(scanID, "nuclei-dast", func() { e.runNuclei(ctx, scan, dastTool, paramURLs, proxyURL, true) })
		}
		if stopped() {
			return
		}
	}

	// Stage 8c — wpscan (full/deep/aggressive): WordPress core/plugin/theme vulns
	// for hosts httpx fingerprinted as WordPress.
	if e.profileIn(scan, "full", "deep", "aggressive") {
		e.voidStage(scanID, "wpscan", func() { e.runWPScan(ctx, scan, proxyURL) })
		if stopped() {
			return
		}
	}

	// Stage 8d — nmap NSE vuln/vulners (aggressive, DIRECT egress only): non-HTTP
	// service vulnerabilities + version→CVE mapping. Skipped under Tor (NSE can't
	// tunnel reliably), keeping the anonymity guarantee intact.
	if e.profileIn(scan, "aggressive") {
		if anonymous {
			e.emit(scanID, "[*] nmap NSE skipped — incompatible with anonymous/Tor egress (use direct egress to enable)")
		} else {
			e.voidStage(scanID, "nmap", func() { e.runNmapVuln(ctx, scan, probeTargets, proxyURL) })
			if stopped() {
				return
			}
		}
	}

	// Stage 9 — enrich CVEs (EPSS/KEV) + defence loop (timeline / IOC / notify).
	e.voidStage(scanID, "enrich", func() { e.enrichAndReport(ctx, scan) })

	// Stage 10 — verification: independently re-check the high-impact findings to
	// confirm them (cuts false positives).
	e.voidStage(scanID, "verify", func() { e.verifyFindings(ctx, scan, proxyURL) })

	status := models.VulnDone
	if ctx.Err() != nil {
		status = models.VulnStopped
		e.emit(scanID, "[!] Scan stopped by operator")
	}
	e.finalize(scan, status)
	e.emit(scanID, "[+] Scan complete")
	e.emit(scanID, "__DONE__")
	e.scheduleHistoryCleanup(scanID)
}

// assetStage runs one asset-transforming pipeline stage with panic isolation: a
// crash inside a tool wrapper (bad input, library bug, nil deref) is caught,
// logged to the scan's live log, and the stage's INPUT list passed through
// unchanged so every later stage — and the whole scan — still completes. This is
// what stops one bad host or tool from sinking a multi-host scan.
func (e *Engine) assetStage(scanID, name string, in []string, fn func() []string) []string {
	out := in
	func() {
		defer func() {
			if r := recover(); r != nil {
				e.emit(scanID, fmt.Sprintf("[!] %s crashed (%v) — stage skipped, scan continues", name, r))
			}
		}()
		out = fn()
	}()
	return out
}

// voidStage is assetStage for a stage that produces no asset list (nuclei,
// enrich, verify): isolate its panic so the scan still finalizes cleanly.
func (e *Engine) voidStage(scanID, name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			e.emit(scanID, fmt.Sprintf("[!] %s crashed (%v) — stage skipped, scan continues", name, r))
		}
	}()
	fn()
}

// profileOf returns the scan profile, defaulting to "quick".
func (e *Engine) profileOf(scan *models.VulnScan) string {
	switch scan.Profile {
	case "full", "cve-only", "deep", "aggressive":
		return scan.Profile
	default:
		return "quick"
	}
}

// profileIn reports whether the scan's profile is one of the given names.
func (e *Engine) profileIn(scan *models.VulnScan, names ...string) bool {
	p := e.profileOf(scan)
	for _, n := range names {
		if p == n {
			return true
		}
	}
	return false
}

// maxNucleiTargets bounds how many URLs nuclei scans per run.
func (e *Engine) maxNucleiTargets() int {
	if e.cfg != nil && e.cfg.VulnScanMaxNucleiTargets > 0 {
		return e.cfg.VulnScanMaxNucleiTargets
	}
	return 1500
}

// capNucleiTargets returns the scan list with the live roots first (so they are
// always scanned even if the run times out), followed by the remaining crawled /
// archived URLs, de-duped and capped to maxNucleiTargets. On Tor the ceiling is
// lowered hard because circuit throughput is low — a few thousand URLs would time
// nuclei out before it covers the roots. Warns when it truncates.
func (e *Engine) capNucleiTargets(scanID string, roots, all []string, anonymous bool) []string {
	max := e.maxNucleiTargets()
	if anonymous && max > 500 {
		max = 500
	}
	seen := make(map[string]bool, len(all))
	out := make([]string, 0, max)
	add := func(u string) bool {
		if u == "" || seen[u] {
			return true
		}
		seen[u] = true
		out = append(out, u)
		return len(out) < max
	}
	for _, u := range roots {
		if !add(u) {
			break
		}
	}
	dropped := 0
	for _, u := range all {
		if seen[u] || u == "" {
			continue
		}
		if len(out) >= max {
			dropped++
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	if dropped > 0 {
		e.emit(scanID, fmt.Sprintf("[*] nuclei target list capped at %d (roots first) — %d crawled URL(s) dropped to keep the scan within budget", max, dropped))
	}
	return out
}

// nmapTimeout returns the NSE-vuln stage budget.
func (e *Engine) nmapTimeout() time.Duration {
	if e.cfg != nil && e.cfg.VulnScanNmapTimeout > 0 {
		return time.Duration(e.cfg.VulnScanNmapTimeout) * time.Second
	}
	return 15 * time.Minute
}

// resolveProxy returns the egress proxy URL the scanners must use and a label
// for it. Tor is preferred; the operator can opt a single scan out with
// proxyChoice=="direct". When proxy is requested but none is configured it falls
// back to direct (loudly warned by the caller).
func (e *Engine) resolveProxy(proxyChoice string) (string, string) {
	if proxyChoice == "direct" {
		return "", "direct"
	}
	if e.cfg == nil {
		return "", "direct"
	}
	if e.cfg.VulnScanProxy != "" {
		return e.cfg.VulnScanProxy, "configured"
	}
	if e.cfg.TorProxy != "" {
		return e.cfg.TorProxy, "tor"
	}
	if e.cfg.OutboundProxy != "" {
		return e.cfg.OutboundProxy, "outbound"
	}
	return "", "direct"
}

// runSubfinder passively expands the domain assets with discovered subdomains.
// IP-only target sets or a missing binary are no-ops (the original assets pass
// through unchanged). Newly found subdomains are scope-filtered before use.
func (e *Engine) runSubfinder(ctx context.Context, scan *models.VulnScan, assets []string, proxyURL string) []string {
	scanID := scan.ID.String()
	var domains []string
	for _, a := range assets {
		if net.ParseIP(a) == nil {
			domains = append(domains, a)
		}
	}
	if len(domains) == 0 {
		return assets
	}
	bin, err := exec.LookPath("subfinder")
	if err != nil {
		return assets // not installed — skip silently, keep original assets
	}
	tool := e.newTool(scan.ID, "subfinder")
	e.startTool(tool)
	e.emit(scanID, fmt.Sprintf("[*] subfinder — enumerating subdomains of %d domain(s)...", len(domains)))

	listFile, cleanup, err := writeListFile(domains)
	if err != nil {
		e.markTool(tool, models.VulnToolFailed, 0, err.Error())
		return assets
	}
	defer cleanup()

	cctx, cancel := context.WithTimeout(ctx, e.toolTimeout())
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, "-dL", listFile, "-silent", "-all")
	cmd.Env = proxyEnv(proxyURL)

	found := map[string]bool{}
	for _, a := range assets {
		found[a] = true
	}
	var fresh []string
	streamLines(cmd, func(line string) {
		d := strings.TrimSpace(line)
		if d != "" && !found[d] {
			found[d] = true
			fresh = append(fresh, d)
		}
	})
	keep, _ := scopeFilter(fresh, proxyURL != "")
	e.markTool(tool, models.VulnToolDone, len(keep), "")
	e.emit(scanID, fmt.Sprintf("[+] subfinder done — %d new subdomain(s)", len(keep)))
	return append(assets, keep...)
}

// runNaabu discovers open ports and returns host:port probe targets. Uses a
// CONNECT scan (no raw sockets / works through SOCKS-Tor and as non-root).
func (e *Engine) runNaabu(ctx context.Context, scan *models.VulnScan, assets []string, proxyURL string) []string {
	scanID := scan.ID.String()
	bin, err := exec.LookPath("naabu")
	if err != nil {
		return nil // not installed — caller falls back to the asset list
	}
	tool := e.newTool(scan.ID, "naabu")
	e.startTool(tool)
	e.emit(scanID, fmt.Sprintf("[*] naabu — discovering open ports on %d host(s) (top 1000)...", len(assets)))

	listFile, cleanup, err := writeListFile(assets)
	if err != nil {
		e.markTool(tool, models.VulnToolFailed, 0, err.Error())
		return nil
	}
	defer cleanup()

	cctx, cancel := context.WithTimeout(ctx, e.nucleiTimeout())
	defer cancel()
	args := []string{"-list", listFile, "-silent", "-no-color", "-s", "c", "-top-ports", "1000",
		"-rate", fmt.Sprintf("%d", e.rateLimit())}
	if proxyURL != "" {
		args = append(args, "-proxy", proxyURL)
	}
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Env = proxyEnv(proxyURL)

	var out []string
	streamLines(cmd, func(line string) {
		hp := strings.TrimSpace(line) // naabu prints host:port
		if hp != "" {
			out = append(out, hp)
		}
	})
	e.markTool(tool, models.VulnToolDone, len(out), "")
	e.emit(scanID, fmt.Sprintf("[+] naabu done — %d open port(s)", len(out)))
	return dedupeStrings(out)
}

// runDNSx keeps only the domain assets that actually resolve, dropping dead and
// wildcard subdomains so the scan never wastes effort on phantom hosts. IPs pass
// through untouched. DNS resolution is not proxied (it resolves already-public
// names the OSINT layer surfaced).
func (e *Engine) runDNSx(ctx context.Context, scan *models.VulnScan, assets []string) []string {
	scanID := scan.ID.String()
	var domains, ips []string
	for _, a := range assets {
		if net.ParseIP(a) != nil {
			ips = append(ips, a)
		} else {
			domains = append(domains, a)
		}
	}
	if len(domains) == 0 {
		return assets
	}
	bin, err := exec.LookPath("dnsx")
	if err != nil {
		return assets
	}
	tool := e.newTool(scan.ID, "dnsx")
	e.startTool(tool)
	e.emit(scanID, fmt.Sprintf("[*] dnsx — validating %d domain(s) resolve...", len(domains)))

	listFile, cleanup, err := writeListFile(domains)
	if err != nil {
		e.markTool(tool, models.VulnToolFailed, 0, err.Error())
		return assets
	}
	defer cleanup()

	cctx, cancel := context.WithTimeout(ctx, e.toolTimeout())
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, "-l", listFile, "-silent", "-wd", "-r", "1.1.1.1,8.8.8.8")
	var live []string
	streamLines(cmd, func(line string) {
		if h := strings.TrimSpace(line); h != "" {
			live = append(live, h)
		}
	})
	live = dedupeStrings(live)
	e.markTool(tool, models.VulnToolDone, len(live), "")
	e.emit(scanID, fmt.Sprintf("[+] dnsx done — %d/%d domain(s) resolve", len(live), len(domains)))
	return append(ips, live...)
}

// runCDNCheck drops IP literals that sit behind a CDN/WAF (shared third-party
// infrastructure) so the active scan stays on the operator's own targets and
// doesn't generate noise/false-positives against a CDN edge. Domains are kept
// (the app behind the CDN is still in scope by hostname).
func (e *Engine) runCDNCheck(ctx context.Context, scan *models.VulnScan, assets []string) []string {
	scanID := scan.ID.String()
	var ips, others []string
	for _, a := range assets {
		if net.ParseIP(a) != nil {
			ips = append(ips, a)
		} else {
			others = append(others, a)
		}
	}
	if len(ips) == 0 {
		return assets
	}
	bin, err := exec.LookPath("cdncheck")
	if err != nil {
		return assets
	}
	tool := e.newTool(scan.ID, "cdncheck")
	e.startTool(tool)
	e.emit(scanID, fmt.Sprintf("[*] cdncheck — checking %d IP(s) for CDN/WAF...", len(ips)))

	listFile, cleanup, err := writeListFile(ips)
	if err != nil {
		e.markTool(tool, models.VulnToolFailed, 0, err.Error())
		return assets
	}
	defer cleanup()

	cctx, cancel := context.WithTimeout(ctx, e.toolTimeout())
	defer cancel()
	// Default cdncheck output is the inputs that ARE behind a CDN/WAF/cloud edge.
	cmd := exec.CommandContext(cctx, bin, "-l", listFile, "-silent")
	cdn := map[string]bool{}
	streamLines(cmd, func(line string) {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) > 0 && net.ParseIP(f[0]) != nil {
			cdn[f[0]] = true
		}
	})
	keep := others
	for _, ip := range ips {
		if cdn[ip] {
			e.emit(scanID, "[*] cdncheck — skipping CDN/WAF IP: "+ip)
		} else {
			keep = append(keep, ip)
		}
	}
	e.markTool(tool, models.VulnToolDone, len(cdn), "")
	e.emit(scanID, fmt.Sprintf("[+] cdncheck done — %d CDN IP(s) excluded", len(cdn)))
	return keep
}

// runKatana crawls the live HTTP services for real endpoints/URLs — used to
// harvest parameterised URLs for the fuzzers (dalfox / nuclei -dast), NOT to feed
// the nuclei template scan (templates define their own paths). Returns the live
// URLs merged with crawled ones (deduped, capped). Missing binary → no-op.
func (e *Engine) runKatana(ctx context.Context, scan *models.VulnScan, liveURLs []string, proxyURL string) []string {
	scanID := scan.ID.String()
	bin, err := exec.LookPath("katana")
	if err != nil {
		return liveURLs
	}
	tool := e.newTool(scan.ID, "katana")
	e.startTool(tool)
	depth := 2
	e.emit(scanID, fmt.Sprintf("[*] katana — crawling %d service(s) (depth %d)...", len(liveURLs), depth))

	listFile, cleanup, err := writeListFile(liveURLs)
	if err != nil {
		e.markTool(tool, models.VulnToolFailed, 0, err.Error())
		return liveURLs
	}
	defer cleanup()

	cctx, cancel := context.WithTimeout(ctx, e.nucleiTimeout())
	defer cancel()
	args := []string{"-list", listFile, "-silent", "-no-color", "-d", fmt.Sprintf("%d", depth), "-c", "10", "-kf", "all"}
	if proxyURL != "" {
		args = append(args, "-proxy", proxyURL)
	}
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Env = proxyEnv(proxyURL)

	const maxURLs = 3000
	urls := map[string]bool{}
	for _, u := range liveURLs {
		urls[u] = true
	}
	crawled := 0
	streamLines(cmd, func(line string) {
		u := strings.TrimSpace(line)
		if u == "" || urls[u] || len(urls) >= maxURLs {
			return
		}
		urls[u] = true
		crawled++
	})
	out := make([]string, 0, len(urls))
	for u := range urls {
		out = append(out, u)
	}
	e.markTool(tool, models.VulnToolDone, crawled, "")
	e.emit(scanID, fmt.Sprintf("[+] katana done — %d crawled URL(s)", crawled))
	return out
}

// filterParamURLs keeps only URLs carrying a query parameter (?k=v) — the ones
// worth fuzzing with dalfox / nuclei -dast. Deduped.
func filterParamURLs(urls []string) []string {
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		if i := strings.IndexByte(u, '?'); i >= 0 && strings.IndexByte(u[i:], '=') >= 0 {
			out = append(out, u)
		}
	}
	return dedupeStrings(out)
}

// proxyEnv augments the child process environment so HTTP-based tools honor the
// proxy even via libraries that read *_PROXY rather than the -proxy flag.
func proxyEnv(proxyURL string) []string {
	env := os.Environ()
	if proxyURL == "" {
		return env
	}
	return append(env,
		"HTTP_PROXY="+proxyURL, "http_proxy="+proxyURL,
		"HTTPS_PROXY="+proxyURL, "https_proxy="+proxyURL,
		"ALL_PROXY="+proxyURL, "all_proxy="+proxyURL,
		"NO_PROXY=localhost,127.0.0.1,::1", "no_proxy=localhost,127.0.0.1,::1",
	)
}

// httpxLine is the subset of httpx -json we consume.
type httpxLine struct {
	URL        string   `json:"url"`
	Host       string   `json:"host"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	WebServer  string   `json:"webserver"`
	Tech       []string `json:"tech"`
}

// runHTTPx probes the assets for live HTTP(S) services and returns the live URLs
// for nuclei. If httpx isn't installed it degrades to feeding the raw assets
// (both schemes) downstream so nuclei still runs.
func (e *Engine) runHTTPx(ctx context.Context, scan *models.VulnScan, tool *models.VulnTool, targets []string, proxyURL string) []string {
	scanID := scan.ID.String()
	bin, err := exec.LookPath("httpx")
	if err != nil {
		e.markTool(tool, models.VulnToolSkipped, 0, "httpx not installed")
		e.emit(scanID, "[*] httpx not installed — passing raw assets to nuclei")
		out := make([]string, 0, len(targets)*2)
		for _, t := range targets {
			out = append(out, "http://"+t, "https://"+t)
		}
		return out
	}

	listFile, cleanup, err := writeListFile(targets)
	if err != nil {
		e.markTool(tool, models.VulnToolFailed, 0, err.Error())
		return nil
	}
	defer cleanup()

	e.startTool(tool)
	e.emit(scanID, fmt.Sprintf("[*] httpx — probing %d asset(s) for live services...", len(targets)))

	budget := e.toolTimeout()
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	// -td/-title/-server populate the tech/title/webserver fields we parse. The
	// wappalyzer tech fingerprint (-td) is what gates the wpscan stage and feeds
	// nuclei's tech-aware tags, so it must be on.
	args := []string{"-l", listFile, "-json", "-silent", "-no-color", "-timeout", "10", "-retries", "1", "-td", "-title", "-server"}
	// Probe common alternate web ports too, so a service on 8080/8443/8000/… isn't
	// missed when naabu didn't run (quick/cve-only, or Tor). httpx uses a target's
	// explicit port when given (naabu host:port) and otherwise sweeps this set.
	args = append(args, "-ports", "80,443,8080,8443,8000,8888,8081,9000")
	if proxyURL != "" {
		args = append(args, "-proxy", proxyURL)
	}
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Env = proxyEnv(proxyURL)

	var live []string
	var findings []models.VulnFinding
	errTail, err := streamLinesCapture(cmd, func(line string) {
		var h httpxLine
		if json.Unmarshal([]byte(line), &h) != nil || h.URL == "" {
			return
		}
		live = append(live, h.URL)
		title := h.Title
		if title == "" {
			title = h.Host
		}
		desc := fmt.Sprintf("HTTP %d", h.StatusCode)
		if h.WebServer != "" {
			desc += " · " + h.WebServer
		}
		if len(h.Tech) > 0 {
			desc += " · " + strings.Join(h.Tech, ", ")
		}
		findings = append(findings, e.buildFinding(scan.ID, tool.ID, "httpx", "", "Live service: "+title, "info", h.Host, h.URL, "http", desc, "", h.Tech, line))
		e.emit(scanID, fmt.Sprintf("[+] live: %s (%s)", h.URL, desc))
	})

	inserted := e.persist(findings)
	if err != nil && cctx.Err() == nil && ctx.Err() == nil {
		msg := err.Error()
		if errTail != "" {
			msg += ": " + errTail
		}
		e.markTool(tool, models.VulnToolFailed, inserted, msg)
		e.emit(scanID, "[!] httpx error: "+msg)
	} else {
		e.markTool(tool, models.VulnToolDone, inserted, "")
	}
	e.emit(scanID, fmt.Sprintf("[+] httpx done — %d live service(s)", len(live)))
	return dedupeStrings(live)
}

// nucleiLine is the subset of nuclei -jsonl we consume.
type nucleiLine struct {
	TemplateID string `json:"template-id"`
	Type       string `json:"type"`
	Host       string `json:"host"`
	MatchedAt  string `json:"matched-at"`
	Info       struct {
		Name           string   `json:"name"`
		Severity       string   `json:"severity"`
		Description    string   `json:"description"`
		Tags           []string `json:"tags"`
		Reference      []string `json:"reference"`
		Classification struct {
			CVEID []string `json:"cve-id"`
		} `json:"classification"`
	} `json:"info"`
}

// cveIDPattern matches a canonical CVE identifier (used to recover a CVE id from
// a nuclei template-id when info.classification.cve-id is absent).
var cveIDPattern = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)

// nucleiTagsFor maps a scan profile (+ optional extra tags) to nuclei -tags.
// "full" applies no tag filter (all templates). Returns "" for no filter.
func nucleiTagsFor(profile, extra string) string {
	var tags []string
	switch profile {
	case "cve-only":
		tags = []string{"cve"}
	case "full", "deep", "aggressive":
		tags = nil // no tag filter — run every (non-excluded) template
	default: // quick
		// Fast subset, but it MUST still include the high-impact exploit classes —
		// otherwise a critical RCE/injection template (tagged rce/sqli/… but not
		// "cve") is silently filtered out and quick misses real criticals.
		tags = []string{
			"cve", "exposure", "misconfiguration", "default-login", "exposed-panel", "tech",
			"rce", "injection", "sqli", "lfi", "ssrf", "ssti", "xxe", "xss",
			"deserialization", "auth-bypass", "unauth", "takeover", "oast",
		}
	}
	for _, t := range strings.Split(extra, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tags = append(tags, t)
		}
	}
	return strings.Join(tags, ",")
}

// detectedTechToken reduces an httpx technology name to a nuclei tag token:
// lowercase, version stripped (cut at the first space), non-alphanumerics
// dropped. Unknown tokens are harmless — nuclei simply matches no template.
func detectedTechToken(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexAny(s, " :/"); i >= 0 {
		s = s[:i] // drop version / suffix
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// detectedTechTags returns a comma-joined set of nuclei tags derived from the
// technologies httpx fingerprinted on this scan's live hosts (deduped, capped).
func (e *Engine) detectedTechTags(scanID uuid.UUID) string {
	var rows []string
	e.db.Model(&models.VulnFinding{}).
		Where("scan_id = ? AND tool = ? AND tags <> ''", scanID, "httpx").
		Pluck("tags", &rows)
	seen := map[string]bool{}
	var out []string
	for _, r := range rows {
		for _, t := range strings.Split(r, ",") {
			tok := detectedTechToken(t)
			if len(tok) >= 3 && !seen[tok] { // skip 1-2 char noise
				seen[tok] = true
				out = append(out, tok)
				if len(out) >= 25 {
					return strings.Join(out, ",")
				}
			}
		}
	}
	return strings.Join(out, ",")
}

// sanitizeSeverities keeps only valid nuclei severity tokens from an operator-
// supplied CSV, so a malformed value (e.g. "High", "p1") can never make nuclei
// exit with "invalid severity". Falls back to the standard low→critical set.
func sanitizeSeverities(s string) string {
	allowed := map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
	seen := map[string]bool{}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if allowed[p] && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return "low,medium,high,critical"
	}
	return strings.Join(out, ",")
}

// runNuclei runs nuclei over the given URLs. dast=false is the TEMPLATE scan
// (live roots + SAN + ffuf endpoints); dast=true is the parameter-fuzzing pass
// over URLs carrying query parameters (deep/aggressive). Streams + persists live.
func (e *Engine) runNuclei(ctx context.Context, scan *models.VulnScan, tool *models.VulnTool, urls []string, proxyURL string, dast bool) {
	scanID := scan.ID.String()
	bin, err := exec.LookPath("nuclei")
	if err != nil {
		e.markTool(tool, models.VulnToolSkipped, 0, "nuclei not installed")
		e.emit(scanID, "[!] nuclei not installed — cannot run vulnerability templates")
		return
	}

	urls = dedupeStrings(urls)
	if len(urls) == 0 {
		e.markTool(tool, models.VulnToolSkipped, 0, "no live targets for nuclei")
		e.emit(scanID, "[*] nuclei skipped — no live targets to scan")
		return
	}

	listFile, cleanup, err := writeListFile(urls)
	if err != nil {
		e.markTool(tool, models.VulnToolFailed, 0, err.Error())
		return
	}
	defer cleanup()

	e.startTool(tool)
	sev := sanitizeSeverities(scan.Severities)
	mode := "templates"
	if dast {
		mode = "DAST/fuzzing"
	}
	e.emit(scanID, fmt.Sprintf("[*] nuclei (%s) — scanning %d target(s), severities: %s", mode, len(urls), sev))
	if proxyURL != "" {
		e.emit(scanID, "[!] Tor/proxy egress: only HTTP(S) templates are reliable. Network/SSH/TCP checks (e.g. the SSH Terrapin CVE) need DIRECT egress — they may be missed here.")
	}

	budget := e.nucleiTimeout()
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	// Exclude noisy/destructive classes. The "aggressive" profile keeps fuzz/
	// intrusive (the operator opted in) and only drops DoS; other profiles stay
	// conservative (discovery, not destructive fuzzing).
	excludeTags := "dos,fuzz,intrusive"
	if e.profileIn(scan, "aggressive") {
		excludeTags = "dos"
	}
	// Over a proxy/Tor, high concurrency + rate + a short per-request timeout cause
	// dropped circuits and request timeouts → MISSED findings (silently wrong
	// results). Dial these back and lengthen the timeout when egress is proxied.
	// Over a proxy/Tor, high concurrency + rate + a short per-request timeout cause
	// dropped circuits and request timeouts → MISSED findings. Dial back + lengthen
	// the timeout when proxied. -retries 2 recovers transient drops (fewer FNs).
	conc, rate, reqTimeout, retries := e.concurrency(), e.rateLimit(), 10, 2
	if proxyURL != "" {
		if conc > 10 {
			conc = 10
		}
		if rate > 40 {
			rate = 40
		}
		reqTimeout = 30
	}
	args := []string{
		"-l", listFile, "-jsonl", "-silent", "-no-color",
		"-disable-update-check", "-severity", sev,
		"-rate-limit", fmt.Sprintf("%d", rate),
		"-concurrency", fmt.Sprintf("%d", conc),
		"-timeout", fmt.Sprintf("%d", reqTimeout),
		"-retries", fmt.Sprintf("%d", retries),
		// host-spray: finish each host's full template set before moving on, so an
		// early host (the live roots, listed first) is scanned COMPLETELY even if
		// the run later times out — instead of every host left half-scanned.
		"-scan-strategy", "host-spray",
		// follow redirects so a template reaches the real app when a root 301/302s.
		"-follow-redirects", "-max-redirects", "3",
		"-exclude-tags", excludeTags,
	}
	if dast {
		// Pure parameter-fuzzing pass: let -dast pick the fuzzing templates; no tag
		// filter (it would restrict the fuzzing set).
		args = append(args, "-dast")
		if e.cfg == nil || e.cfg.VulnScanInteractshServer == "" {
			e.emit(scanID, "[!] DAST blind/OOB detection limited — no interactsh server set (VULNSCAN_INTERACTSH_SERVER). Reflected injection still works.")
		}
	} else {
		// Template scan: apply the profile tag filter (+ tech-aware tags for quick).
		extraTags := scan.Tags
		if e.profileOf(scan) == "quick" {
			if tech := e.detectedTechTags(scan.ID); tech != "" {
				if extraTags != "" {
					extraTags += ","
				}
				extraTags += tech
				e.emit(scanID, "[*] nuclei tech-aware tags: "+tech)
			}
		}
		if tags := nucleiTagsFor(e.profileOf(scan), extraTags); tags != "" {
			args = append(args, "-tags", tags)
			e.emit(scanID, "[*] nuclei tags: "+tags)
		}
	}
	args = append(args, e.nucleiOOBArgs()...)
	if e.cfg != nil && e.cfg.VulnScanInteractshServer != "" {
		e.emit(scanID, "[*] nuclei OOB/OAST enabled (interactsh) — catching blind/SSRF/RCE callbacks")
	}
	if proxyURL != "" {
		args = append(args, "-proxy", proxyURL)
	}
	if tdir := e.nucleiTemplatesDir(); tdir != "" {
		args = append(args, "-templates", tdir)
	}
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Env = proxyEnv(proxyURL)

	// Micro-batch the streamed findings: keep the live log line per match (for
	// responsiveness) but flush DB inserts in groups so a noisy scan doesn't fire
	// thousands of single-row INSERTs.
	count := 0
	var batch []models.VulnFinding
	flush := func() {
		if len(batch) > 0 {
			count += e.persist(batch)
			batch = batch[:0]
		}
	}
	errTail, err := streamLinesCapture(cmd, func(line string) {
		var n nucleiLine
		if json.Unmarshal([]byte(line), &n) != nil || n.TemplateID == "" {
			return
		}
		sev := strings.ToLower(n.Info.Severity)
		if sev == "" {
			sev = "unknown"
		}
		ref := ""
		if len(n.Info.Reference) > 0 {
			b, _ := json.Marshal(n.Info.Reference)
			ref = string(b)
		}
		f := e.buildFinding(scan.ID, tool.ID, "nuclei", n.TemplateID, n.Info.Name, sev, n.Host, n.MatchedAt, n.Type, n.Info.Description, ref, n.Info.Tags, line)
		// Recover a CVE id from the classification, falling back to the template id.
		if len(n.Info.Classification.CVEID) > 0 {
			f.CVEID = strings.ToUpper(n.Info.Classification.CVEID[0])
		} else if m := cveIDPattern.FindString(n.TemplateID); m != "" {
			f.CVEID = strings.ToUpper(m)
		}
		batch = append(batch, f)
		label := strings.ToUpper(sev)
		if f.CVEID != "" {
			label += " " + f.CVEID
		}
		e.emit(scanID, fmt.Sprintf("[%s] %s — %s", label, n.Info.Name, n.MatchedAt))
		if len(batch) >= 25 {
			flush()
		}
	})
	flush()

	if err != nil && cctx.Err() == nil && ctx.Err() == nil {
		msg := err.Error()
		if errTail != "" {
			msg += ": " + errTail
		}
		e.markTool(tool, models.VulnToolFailed, count, msg)
		e.emit(scanID, "[!] nuclei error: "+msg)
		return
	}
	e.markTool(tool, models.VulnToolDone, count, "")
	e.emit(scanID, fmt.Sprintf("[+] nuclei done — %d finding(s)", count))
}

// ── helpers ───────────────────────────────────────────────────────────────────

func (e *Engine) toolTimeout() time.Duration {
	if e.cfg != nil && e.cfg.VulnScanToolTimeout > 0 {
		return time.Duration(e.cfg.VulnScanToolTimeout) * time.Second
	}
	return 5 * time.Minute
}

// nucleiTemplatesDir returns a non-empty nuclei templates directory to point
// nuclei at, or "" to let nuclei use its own default. It prefers the configured
// dir, then the image's bundled clone (/app/nuclei-templates). Returning a dir
// that ACTUALLY contains templates avoids nuclei's "no templates found → exit 1"
// when the container has no per-user template store and update checks are off.
func (e *Engine) nucleiTemplatesDir() string {
	if e.cfg != nil && e.cfg.VulnScanNucleiTemplates != "" {
		if dirHasFiles(e.cfg.VulnScanNucleiTemplates) {
			return e.cfg.VulnScanNucleiTemplates
		}
		return ""
	}
	for _, p := range []string{"/app/nuclei-templates", "/root/nuclei-templates"} {
		if dirHasFiles(p) {
			return p
		}
	}
	return ""
}

func (e *Engine) nucleiTimeout() time.Duration {
	if e.cfg != nil && e.cfg.VulnScanNucleiTimeout > 0 {
		return time.Duration(e.cfg.VulnScanNucleiTimeout) * time.Second
	}
	return 20 * time.Minute
}

func (e *Engine) rateLimit() int {
	if e.cfg != nil && e.cfg.VulnScanRateLimit > 0 {
		return e.cfg.VulnScanRateLimit
	}
	return 150
}

func (e *Engine) concurrency() int {
	if e.cfg != nil && e.cfg.VulnScanConcurrency > 0 {
		return e.cfg.VulnScanConcurrency
	}
	return 25
}

func (e *Engine) newTool(scanID uuid.UUID, name string) *models.VulnTool {
	t := &models.VulnTool{ScanID: scanID, Name: name, Status: models.VulnToolPending}
	e.db.Create(t)
	return t
}

func (e *Engine) startTool(t *models.VulnTool) {
	now := time.Now()
	e.db.Model(t).Updates(map[string]interface{}{"status": models.VulnToolRunning, "started_at": now})
}

func (e *Engine) markTool(t *models.VulnTool, status models.VulnToolStatus, count int, errMsg string) {
	now := time.Now()
	e.db.Model(t).Updates(map[string]interface{}{
		"status": status, "findings_count": count, "error": errMsg, "finished_at": now,
	})
}

func (e *Engine) buildFinding(scanID, toolID uuid.UUID, tool, templateID, name, severity, host, matchedAt, ftype, desc, ref string, tags []string, raw string) models.VulnFinding {
	sum := sha256.Sum256([]byte(tool + "|" + templateID + "|" + matchedAt + "|" + host))
	tagStr := ""
	if len(tags) > 0 {
		tagStr = strings.Join(tags, ",")
	}
	return models.VulnFinding{
		ScanID: scanID, ToolID: toolID, Tool: tool, TemplateID: templateID,
		Name: name, Severity: severity, Host: host, MatchedAt: matchedAt,
		Type: ftype, Description: desc, Reference: ref, Tags: tagStr,
		Status: "open", Data: raw, DedupeKey: hex.EncodeToString(sum[:]),
	}
}

// persist inserts findings idempotently via the (scan_id, dedupe_key) unique
// index; returns how many new rows landed.
func (e *Engine) persist(findings []models.VulnFinding) int {
	if len(findings) == 0 {
		return 0
	}
	res := e.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "scan_id"}, {Name: "dedupe_key"}},
		DoNothing: true,
	}).Create(&findings)
	if res.Error != nil {
		// Fall back to per-row inserts so one bad row can't drop the batch.
		n := 0
		for i := range findings {
			if e.db.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "scan_id"}, {Name: "dedupe_key"}},
				DoNothing: true,
			}).Create(&findings[i]).Error == nil {
				n++
			}
		}
		return n
	}
	return int(res.RowsAffected)
}

// ScopeVerdict is the in/out-of-scope decision for one asset, with a human reason
// surfaced in the scan log and the asset-preview UI.
type ScopeVerdict struct {
	Value  string `json:"value"`
	Keep   bool   `json:"keep"`
	Scope  string `json:"scope"`            // in | private | mixed | unresolved | deferred
	Reason string `json:"reason,omitempty"` // why it was dropped / how it's handled
}

const (
	scopeResolveTimeout = 4 * time.Second
	scopeResolveWorkers = 16
)

// classifyScope resolves each unique asset and decides whether it is in scope.
//
// anonymous selects the privacy posture:
//
//   - anonymous=false (direct egress): hostnames are resolved on THIS host so we
//     can apply the full public/private/mixed policy (mixed = DNS-rebinding shape
//     → dropped). The operator already accepted exposing this host's IP.
//
//   - anonymous=true (Tor / proxy egress): NO local DNS is performed for
//     hostnames — doing so would leak every target name to the host resolver /
//     ISP / public DNS before any proxied traffic, defeating the anonymity the
//     operator asked for. Hostnames are KEPT as "deferred" and resolved later by
//     the scanners THROUGH the proxy (the SOCKS server resolves at the exit, i.e.
//     remote DNS). Rebinding to *our* internal ranges is moot here because traffic
//     egresses from the proxy/exit, not this host. IP literals are still checked
//     locally (no DNS needed) so private/loopback literals are always refused.
//
// Resolution is bounded (per-host timeout + worker pool) so a large or hostile
// target set can never hang the scan on DNS.
func classifyScope(targets []string, anonymous bool) []ScopeVerdict {
	seen := map[string]bool{}
	var uniq []string
	for _, raw := range targets {
		t := strings.TrimSpace(raw)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		uniq = append(uniq, t)
	}

	out := make([]ScopeVerdict, len(uniq))
	sem := make(chan struct{}, scopeResolveWorkers)
	var wg sync.WaitGroup
	for i, t := range uniq {
		// IP literals need no DNS — decide inline (works in both postures).
		if ip := net.ParseIP(t); ip != nil {
			if netsafe.IsPublicIP(ip) {
				out[i] = ScopeVerdict{Value: t, Keep: true, Scope: "in"}
			} else {
				out[i] = ScopeVerdict{Value: t, Scope: "private", Reason: "private/loopback/link-local IP"}
			}
			continue
		}
		// Anonymous posture: never touch the local resolver — defer to proxied DNS.
		if anonymous {
			out[i] = ScopeVerdict{Value: t, Keep: true, Scope: "deferred", Reason: "resolved anonymously through the proxy at scan time (no local DNS)"}
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, host string) {
			defer wg.Done()
			defer func() {
				<-sem
				if r := recover(); r != nil { // a resolver panic must not sink scoping
					out[i] = ScopeVerdict{Value: host, Keep: true, Scope: "unresolved", Reason: "scope check errored — scanner will try"}
				}
			}()
			out[i] = classifyHost(host)
		}(i, t)
	}
	wg.Wait()
	return out
}

// classifyHost resolves a single hostname under a bounded timeout and applies the
// public/private/mixed policy (direct-egress posture only — see classifyScope).
func classifyHost(host string) ScopeVerdict {
	ctx, cancel := context.WithTimeout(context.Background(), scopeResolveTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return ScopeVerdict{Value: host, Keep: true, Scope: "unresolved", Reason: "does not resolve yet — scanner will try"}
	}
	hasPublic, hasPrivate := false, false
	for _, ip := range ips {
		if netsafe.IsPublicIP(ip.IP) {
			hasPublic = true
		} else {
			hasPrivate = true
		}
	}
	switch {
	case hasPublic && hasPrivate:
		return ScopeVerdict{Value: host, Scope: "mixed", Reason: "resolves to BOTH public and private IPs (DNS-rebinding risk)"}
	case hasPublic:
		return ScopeVerdict{Value: host, Keep: true, Scope: "in"}
	default:
		return ScopeVerdict{Value: host, Scope: "private", Reason: "resolves only to private/internal IPs"}
	}
}

// scopeFilter is the boolean view of classifyScope used where reasons aren't
// needed (e.g. re-filtering subfinder's / tlsx's freshly-discovered subdomains).
// anonymous MUST mirror the scan's egress posture so re-filtering never leaks DNS.
func scopeFilter(targets []string, anonymous bool) (keep, drop []string) {
	for _, v := range classifyScope(targets, anonymous) {
		if v.Keep {
			keep = append(keep, v.Value)
		} else {
			drop = append(drop, v.Value)
		}
	}
	return keep, drop
}

// writeListFile writes items one per line to a temp file for `-l` input.
func writeListFile(items []string) (string, func(), error) {
	f, err := os.CreateTemp("", "vulnscan-*.txt")
	if err != nil {
		return "", func() {}, fmt.Errorf("temp list: %w", err)
	}
	w := bufio.NewWriter(f)
	for _, it := range items {
		fmt.Fprintln(w, it)
	}
	w.Flush()
	f.Close()
	return f.Name(), func() { os.Remove(f.Name()) }, nil
}

// streamLines runs cmd and invokes onLine for each stdout line as it arrives,
// so findings stream live. stderr is drained and discarded (tool progress).
func streamLines(cmd *exec.Cmd, onLine func(string)) error {
	_, err := streamLinesCapture(cmd, onLine)
	return err
}

// streamLinesCapture is streamLines that also returns the TAIL of stderr — the
// few last diagnostic lines a tool prints before exiting. On a non-zero exit
// (e.g. nuclei "no templates found", a proxy connection refused, a bad flag) the
// bare "exit status 1" is useless; this surfaces the actual reason to the
// operator instead of swallowing it.
func streamLinesCapture(cmd *exec.Cmd, onLine func(string)) (string, error) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return "", err
	}
	var mu sync.Mutex
	var errTail []string
	done := make(chan struct{})
	if stderr != nil {
		go func() {
			defer close(done)
			s := bufio.NewScanner(stderr)
			s.Buffer(make([]byte, 8*1024), 256*1024)
			for s.Scan() {
				line := strings.TrimSpace(s.Text())
				if line == "" {
					continue
				}
				mu.Lock()
				errTail = append(errTail, line)
				if len(errTail) > 12 { // keep only the last few lines
					errTail = errTail[len(errTail)-12:]
				}
				mu.Unlock()
			}
		}()
	} else {
		close(done)
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		safeOnLine(onLine, sc.Text())
	}
	<-done // ensure stderr fully drained before Wait closes the pipe
	werr := cmd.Wait()
	mu.Lock()
	tail := strings.Join(errTail, " | ")
	mu.Unlock()
	return tail, werr
}

// dirHasFiles reports whether path is a directory containing at least one entry.
func dirHasFiles(path string) bool {
	if path == "" {
		return false
	}
	entries, err := os.ReadDir(path)
	return err == nil && len(entries) > 0
}

// safeOnLine invokes a per-line parser, swallowing a panic on a single malformed
// tool line so one bad row can't kill the reader goroutine (and with it the scan).
func safeOnLine(onLine func(string), line string) {
	defer func() { _ = recover() }()
	onLine(line)
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

package vulnscan

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/analysishub/backend/internal/models"
)

// runCapture runs cmd to completion and returns its stdout (bounded) plus the
// tail of stderr (for diagnosing a non-zero exit). Used by tools whose useful
// output is an aggregate document (nmap XML, wpscan JSON) rather than a stream of
// independent lines.
func runCapture(cmd *exec.Cmd, maxBytes int64) ([]byte, string, error) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, "", err
	}
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return nil, "", err
	}
	errCh := make(chan string, 1)
	if stderr != nil {
		go func() {
			b, _ := io.ReadAll(io.LimitReader(stderr, 64*1024))
			s := strings.TrimSpace(string(b))
			if len(s) > 600 {
				s = s[len(s)-600:]
			}
			errCh <- s
		}()
	} else {
		errCh <- ""
	}
	buf, _ := io.ReadAll(io.LimitReader(stdout, maxBytes))
	tail := <-errCh
	werr := cmd.Wait()
	return buf, tail, werr
}

// ── nmap NSE-vuln ───────────────────────────────────────────────────────────

// nmapXML is the minimal subset of nmap -oX we parse.
type nmapXML struct {
	Hosts []struct {
		Address []struct {
			Addr     string `xml:"addr,attr"`
			AddrType string `xml:"addrtype,attr"`
		} `xml:"address"`
		Ports struct {
			Port []struct {
				Protocol string `xml:"protocol,attr"`
				PortID   string `xml:"portid,attr"`
				Service  struct {
					Name    string `xml:"name,attr"`
					Product string `xml:"product,attr"`
					Version string `xml:"version,attr"`
				} `xml:"service"`
				Script []struct {
					ID     string `xml:"id,attr"`
					Output string `xml:"output,attr"`
				} `xml:"script"`
			} `xml:"port"`
		} `xml:"ports"`
		HostScript struct {
			Script []struct {
				ID     string `xml:"id,attr"`
				Output string `xml:"output,attr"`
			} `xml:"script"`
		} `xml:"hostscript"`
	} `xml:"host"`
}

// runNmapVuln runs nmap's NSE "vuln" + "vulners" scripts over the discovered
// services to catch NON-HTTP service vulnerabilities and map service versions to
// CVEs — the big coverage gap nuclei (HTTP-centric) leaves. DIRECT egress only:
// NSE scripts + connect scan don't tunnel reliably through Tor, so the caller
// gates this to non-anonymous scans. Missing binary → skipped.
func (e *Engine) runNmapVuln(ctx context.Context, scan *models.VulnScan, probeTargets []string, proxyURL string) {
	scanID := scan.ID.String()
	bin, err := exec.LookPath("nmap")
	if err != nil {
		e.markTool(e.newTool(scan.ID, "nmap"), models.VulnToolSkipped, 0, "nmap not installed")
		return
	}

	hosts := map[string]bool{}
	ports := map[string]bool{}
	for _, t := range probeTargets {
		if h, p, err := net.SplitHostPort(t); err == nil {
			if hh := cleanHost(h); hh != "" {
				hosts[hh] = true
			}
			if p != "" {
				ports[p] = true
			}
		} else if h := cleanHost(t); h != "" {
			hosts[h] = true
		}
	}
	if len(hosts) == 0 {
		return
	}
	hostList := make([]string, 0, len(hosts))
	for h := range hosts {
		hostList = append(hostList, h)
	}

	tool := e.newTool(scan.ID, "nmap")
	e.startTool(tool)
	e.emit(scanID, fmt.Sprintf("[*] nmap — NSE vuln/vulners scan over %d host(s)...", len(hostList)))

	listFile, cleanup, err := writeListFile(hostList)
	if err != nil {
		e.markTool(tool, models.VulnToolFailed, 0, err.Error())
		return
	}
	defer cleanup()

	cctx, cancel := context.WithTimeout(ctx, e.nmapTimeout())
	defer cancel()
	args := []string{"-sT", "-sV", "-Pn", "--script", "vuln,vulners", "--script-timeout", "120s", "-oX", "-", "-iL", listFile}
	if len(ports) > 0 {
		pl := make([]string, 0, len(ports))
		for p := range ports {
			pl = append(pl, p)
		}
		args = append(args, "-p", strings.Join(pl, ","))
	} else {
		args = append(args, "--top-ports", "200")
	}
	cmd := e.commandFor(tool, cctx, bin, args...)
	cmd.Env = proxyEnv(proxyURL)

	out, errTail, werr := runCapture(cmd, 16*1024*1024)
	var parsed nmapXML
	if xml.Unmarshal(out, &parsed) != nil {
		msg := "could not parse nmap output"
		if werr != nil {
			msg = werr.Error()
		}
		if errTail != "" {
			msg += ": " + errTail
		}
		e.markTool(tool, models.VulnToolFailed, 0, msg)
		e.emit(scanID, "[!] nmap error: "+msg)
		return
	}

	var findings []models.VulnFinding
	for _, h := range parsed.Hosts {
		host := ""
		for _, a := range h.Address {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
				host = a.Addr
				break
			}
		}
		emit := func(scriptID, output, portID, svc string) {
			output = strings.TrimSpace(output)
			if output == "" || strings.Contains(output, "ERROR: Script execution failed") {
				return
			}
			sev := "info"
			up := strings.ToUpper(output)
			cve := cveIDPattern.FindString(output)
			switch {
			case strings.Contains(up, "VULNERABLE"):
				sev = "high"
			case cve != "":
				sev = "medium"
			}
			where := host
			if portID != "" {
				where = net.JoinHostPort(host, portID)
			}
			desc := output
			if len(desc) > 1500 {
				desc = desc[:1500] + "…"
			}
			name := "nmap " + scriptID
			if svc != "" {
				name += " (" + svc + ")"
			}
			f := e.buildFinding(scan.ID, tool.ID, "nmap", scriptID, name, sev, host, where, "service", desc, "", []string{"nmap", scriptID}, output)
			if cve != "" {
				f.CVEID = strings.ToUpper(cve)
			}
			findings = append(findings, f)
		}
		for _, p := range h.Ports.Port {
			svc := strings.TrimSpace(p.Service.Name + " " + p.Service.Product + " " + p.Service.Version)
			for _, s := range p.Script {
				emit(s.ID, s.Output, p.PortID, svc)
			}
		}
		for _, s := range h.HostScript.Script {
			emit(s.ID, s.Output, "", "")
		}
	}
	inserted := e.persist(findings)
	e.markTool(tool, models.VulnToolDone, inserted, "")
	e.emit(scanID, fmt.Sprintf("[+] nmap done — %d service finding(s)", inserted))
}

// ── ffuf content discovery ──────────────────────────────────────────────────

// ffufOutput is the subset of ffuf -of json we consume.
type ffufOutput struct {
	Results []struct {
		URL    string `json:"url"`
		Status int    `json:"status"`
		Length int64  `json:"length"`
		Words  int    `json:"words"`
	} `json:"results"`
}

// fileExists reports whether path is a readable regular file.
func fileExists(path string) bool {
	if path == "" {
		return false
	}
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

// maxFfufHosts bounds how many live hosts get brute-forced so a big live set
// can't multiply a whole wordlist across dozens of targets.
const maxFfufHosts = 8

// runFfuf brute-forces hidden directories/files on the live hosts (the content-
// discovery step every recon flow runs) and returns the live URLs plus every
// path it found, so nuclei/dalfox scan real but unlinked endpoints (admin panels,
// backups, .env, API routes). Each hit is also recorded as a finding. Missing
// binary or wordlist → no-op pass-through.
func (e *Engine) runFfuf(ctx context.Context, scan *models.VulnScan, liveURLs []string, proxyURL string) []string {
	scanID := scan.ID.String()
	bin, err := exec.LookPath("ffuf")
	if err != nil {
		e.markTool(e.newTool(scan.ID, "ffuf"), models.VulnToolSkipped, 0, "ffuf not installed")
		return liveURLs
	}
	wordlist := "/app/wordlists/content-discovery.txt"
	if e.cfg != nil && e.cfg.VulnScanFfufWordlist != "" {
		wordlist = e.cfg.VulnScanFfufWordlist
	}
	if !fileExists(wordlist) {
		e.markTool(e.newTool(scan.ID, "ffuf"), models.VulnToolSkipped, 0, "wordlist not found: "+wordlist)
		e.emit(scanID, "[*] ffuf skipped — wordlist not found: "+wordlist)
		return liveURLs
	}

	// Only fuzz site ROOTS (scheme://host[:port]), not every crawled URL.
	roots := map[string]bool{}
	for _, u := range liveURLs {
		if r := rootURL(u); r != "" {
			roots[r] = true
		}
	}
	maxHosts := maxFfufHosts
	if proxyURL != "" {
		maxHosts = 3 // content discovery over Tor is expensive — fuzz fewer hosts
	}
	hosts := make([]string, 0, len(roots))
	for r := range roots {
		hosts = append(hosts, r)
		if len(hosts) >= maxHosts {
			break
		}
	}
	if len(hosts) == 0 {
		return liveURLs
	}

	tool := e.newTool(scan.ID, "ffuf")
	e.startTool(tool)
	threads := 40
	if proxyURL != "" {
		threads = 10 // Tor throughput is low
	}
	e.emit(scanID, fmt.Sprintf("[*] ffuf — content discovery on %d host(s), wordlist %s...", len(hosts), wordlist))

	var found []string
	var findings []models.VulnFinding
	for _, host := range hosts {
		if ctx.Err() != nil {
			break
		}
		target := strings.TrimRight(host, "/") + "/FUZZ"
		cctx, cancel := context.WithTimeout(ctx, e.toolTimeout())
		args := []string{"-w", wordlist + ":FUZZ", "-u", target, "-of", "json", "-o", "-",
			"-mc", "200,204,301,302,307,401,403,405,500", "-t", fmt.Sprintf("%d", threads), "-s", "-noninteractive"}
		if proxyURL != "" {
			args = append(args, "-x", proxyURL)
		}
		cmd := e.commandFor(tool, cctx, bin, args...)
		cmd.Env = proxyEnv(proxyURL)
		out, errTail, _ := runCapture(cmd, 16*1024*1024)
		cancel()

		var parsed ffufOutput
		if json.Unmarshal(out, &parsed) != nil {
			if errTail != "" {
				e.emit(scanID, "[!] ffuf "+host+": "+errTail)
			}
			continue
		}
		for _, r := range parsed.Results {
			if r.URL == "" {
				continue
			}
			found = append(found, r.URL)
			sev := "info"
			if r.Status == 401 || r.Status == 403 {
				sev = "low" // protected resource — worth a look
			}
			desc := fmt.Sprintf("HTTP %d · %d bytes", r.Status, r.Length)
			findings = append(findings, e.buildFinding(scan.ID, tool.ID, "ffuf", "", "Content: "+pathOf(r.URL), sev, cleanHost(r.URL), r.URL, "http", desc, "", []string{"content-discovery"}, ""))
			e.emit(scanID, fmt.Sprintf("[ffuf] %d %s", r.Status, r.URL))
		}
	}
	inserted := e.persist(findings)
	e.markTool(tool, models.VulnToolDone, inserted, "")
	e.emit(scanID, fmt.Sprintf("[+] ffuf done — %d path(s) discovered", inserted))

	// Merge discovered paths into the scan set (deduped).
	have := map[string]bool{}
	for _, u := range liveURLs {
		have[u] = true
	}
	out := append([]string{}, liveURLs...)
	for _, u := range found {
		if !have[u] {
			have[u] = true
			out = append(out, u)
		}
	}
	return out
}

// rootURL reduces a URL to scheme://host[:port].
func rootURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

// pathOf returns the path (+query) of a URL, or the whole string on parse error.
func pathOf(u string) string {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Path == "" {
		return u
	}
	p := parsed.Path
	if parsed.RawQuery != "" {
		p += "?" + parsed.RawQuery
	}
	return p
}

// ── dalfox (XSS) ────────────────────────────────────────────────────────────

// dalfoxLine is the subset of dalfox --format json output we consume.
type dalfoxLine struct {
	Type       string `json:"type"`        // "V" verified, "G" grep, "R" reflected
	InjectType string `json:"inject_type"` // e.g. inHTML-URL
	Method     string `json:"method"`
	Data       string `json:"data"`     // the PoC URL
	Param      string `json:"param"`    // vulnerable parameter
	Payload    string `json:"payload"`  // the payload
	CWE        string `json:"cwe"`      // e.g. CWE-79
	Severity   string `json:"severity"` // Low/Medium/High
	MessageStr string `json:"message_str"`
}

// maxDalfoxURLs bounds how many bases dalfox mines/tests so its parameter mining
// (which probes many param names per URL) can't blow up over a large base set.
const maxDalfoxURLs = 30

// runDalfox runs the dalfox XSS engine over the discovered bases (roots + ffuf
// endpoints). dalfox MINES parameters itself (dictionary + DOM), so it finds
// reflected/DOM XSS WITHOUT a separate crawler/parameter source. Honors the egress
// proxy via env + --proxy (anonymous under Tor). Missing binary → skipped.
func (e *Engine) runDalfox(ctx context.Context, scan *models.VulnScan, urls []string, proxyURL string) {
	scanID := scan.ID.String()
	bin, err := exec.LookPath("dalfox")
	if err != nil {
		e.markTool(e.newTool(scan.ID, "dalfox"), models.VulnToolSkipped, 0, "dalfox not installed")
		return
	}
	targets := dedupeStrings(urls)
	max := maxDalfoxURLs
	worker := 10
	if proxyURL != "" {
		max, worker = 10, 4 // Tor throughput is low
	}
	if len(targets) > max {
		targets = targets[:max]
	}
	if len(targets) == 0 {
		e.markTool(e.newTool(scan.ID, "dalfox"), models.VulnToolSkipped, 0, "no targets")
		return
	}

	tool := e.newTool(scan.ID, "dalfox")
	e.startTool(tool)
	e.emit(scanID, fmt.Sprintf("[*] dalfox — XSS scan with parameter mining on %d URL(s)...", len(targets)))

	listFile, cleanup, err := writeListFile(targets)
	if err != nil {
		e.markTool(tool, models.VulnToolFailed, 0, err.Error())
		return
	}
	defer cleanup()

	cctx, cancel := context.WithTimeout(ctx, e.nucleiTimeout())
	defer cancel()
	args := []string{"file", listFile, "--format", "json", "--silence", "--no-color", "--no-spinner",
		"--skip-bav", "--mining-dict", "--mining-dom", "--worker", fmt.Sprintf("%d", worker)}
	if proxyURL != "" {
		args = append(args, "--proxy", proxyURL)
	}
	cmd := e.commandFor(tool, cctx, bin, args...)
	cmd.Env = proxyEnv(proxyURL)

	var batch []models.VulnFinding
	count := 0
	flush := func() {
		if len(batch) > 0 {
			count += e.persist(batch)
			batch = batch[:0]
		}
	}
	streamLines(cmd, func(line string) {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			return
		}
		var d dalfoxLine
		if json.Unmarshal([]byte(line), &d) != nil || d.Data == "" {
			return
		}
		if d.Type != "V" && d.Type != "R" { // only real/reflected findings
			return
		}
		sev := strings.ToLower(d.Severity)
		if sev == "" {
			sev = "medium"
		}
		name := "XSS"
		if d.InjectType != "" {
			name = "XSS (" + d.InjectType + ")"
		}
		desc := strings.TrimSpace(fmt.Sprintf("param=%s payload=%s %s", d.Param, d.Payload, d.MessageStr))
		f := e.buildFinding(scan.ID, tool.ID, "dalfox", "", name, sev, cleanHost(d.Data), d.Data, "xss", desc, "", []string{"xss", d.CWE}, line)
		batch = append(batch, f)
		e.emit(scanID, fmt.Sprintf("[%s] XSS — %s (param %s)", strings.ToUpper(sev), d.Data, d.Param))
		if len(batch) >= 25 {
			flush()
		}
	})
	flush()
	e.markTool(tool, models.VulnToolDone, count, "")
	e.emit(scanID, fmt.Sprintf("[+] dalfox done — %d XSS finding(s)", count))
}

// ── wpscan (WordPress) ──────────────────────────────────────────────────────

// wpVuln is one vulnerability entry in wpscan's JSON (version/plugin/theme).
type wpVuln struct {
	Title      string `json:"title"`
	References struct {
		CVE []string `json:"cve"`
		URL []string `json:"url"`
	} `json:"references"`
}
type wpComponent struct {
	Vulnerabilities []wpVuln `json:"vulnerabilities"`
}
type wpScanOut struct {
	Version struct {
		Number          string   `json:"number"`
		Vulnerabilities []wpVuln `json:"vulnerabilities"`
	} `json:"version"`
	Plugins map[string]wpComponent `json:"plugins"`
	Themes  map[string]wpComponent `json:"themes"`
}

// runWPScan runs wpscan against the live hosts that httpx fingerprinted as
// WordPress, enumerating vulnerable core/plugins/themes from the WPScan VulnDB
// (needs WPSCAN_API_TOKEN for version-vuln data). CVE ids feed the EPSS/KEV
// enrichment. Honors the proxy. Missing binary / no WP hosts → skipped.
func (e *Engine) runWPScan(ctx context.Context, scan *models.VulnScan, proxyURL string) {
	scanID := scan.ID.String()
	bin, err := exec.LookPath("wpscan")
	if err != nil {
		e.markTool(e.newTool(scan.ID, "wpscan"), models.VulnToolSkipped, 0, "wpscan not installed")
		return
	}

	// WordPress hosts = live services whose httpx wappalyzer TECH fingerprint says
	// WordPress. Detection is fingerprint-only (the httpx `tech` field, populated
	// by -td) — deliberately NOT a substring match on the raw response, so wpscan
	// only ever fires at real WordPress sites and never burns the limited WPScan
	// API quota probing things that merely mention "wordpress" in a title/header.
	var wpHosts []string
	e.db.Model(&models.VulnFinding{}).
		Where("scan_id = ? AND tool = ? AND tags ILIKE ?", scan.ID, "httpx", "%wordpress%").
		Limit(10).Pluck("matched_at", &wpHosts)
	wpHosts = dedupeStrings(wpHosts)
	if len(wpHosts) == 0 {
		e.markTool(e.newTool(scan.ID, "wpscan"), models.VulnToolSkipped, 0, "no WordPress hosts fingerprinted")
		return
	}

	tool := e.newTool(scan.ID, "wpscan")
	e.startTool(tool)
	e.emit(scanID, fmt.Sprintf("[*] wpscan — %d WordPress host(s) fingerprinted: %s", len(wpHosts), strings.Join(wpHosts, ", ")))

	token := ""
	if e.cfg != nil {
		token = e.cfg.WPScanAPIToken
	}

	total := 0
	for _, target := range wpHosts {
		if ctx.Err() != nil {
			break
		}
		findings := e.wpscanOne(ctx, scan, tool, bin, target, token, proxyURL)
		total += e.persist(findings)
	}
	e.markTool(tool, models.VulnToolDone, total, "")
	e.emit(scanID, fmt.Sprintf("[+] wpscan done — %d WordPress finding(s)", total))
}

// wpscanOne scans a single WordPress URL and returns its findings.
func (e *Engine) wpscanOne(ctx context.Context, scan *models.VulnScan, tool *models.VulnTool, bin, target, token, proxyURL string) []models.VulnFinding {
	cctx, cancel := context.WithTimeout(ctx, e.nucleiTimeout())
	defer cancel()
	args := []string{"--url", target, "--format", "json", "--no-banner", "--random-user-agent",
		"--disable-tls-checks", "--enumerate", "vp,vt", "--plugins-detection", "passive"}
	if token != "" {
		args = append(args, "--api-token", token)
	}
	if proxyURL != "" {
		args = append(args, "--proxy", proxyURL)
	}
	cmd := e.commandFor(tool, cctx, bin, args...)
	cmd.Env = proxyEnv(proxyURL)

	out, _, _ := runCapture(cmd, 16*1024*1024)
	var parsed wpScanOut
	if json.Unmarshal(out, &parsed) != nil {
		return nil
	}

	host := cleanHost(target)
	var findings []models.VulnFinding
	add := func(component string, v wpVuln) {
		ref := ""
		if len(v.References.URL) > 0 {
			b, _ := json.Marshal(v.References.URL)
			ref = string(b)
		}
		name := v.Title
		if component != "" {
			name = component + ": " + v.Title
		}
		f := e.buildFinding(scan.ID, tool.ID, "wpscan", "", name, "high", host, target, "wordpress",
			"WordPress vulnerability ("+component+")", ref, []string{"wordpress"}, v.Title)
		if len(v.References.CVE) > 0 {
			f.CVEID = "CVE-" + strings.TrimPrefix(strings.ToUpper(v.References.CVE[0]), "CVE-")
		}
		findings = append(findings, f)
	}
	for _, v := range parsed.Version.Vulnerabilities {
		add("core "+parsed.Version.Number, v)
	}
	for name, p := range parsed.Plugins {
		for _, v := range p.Vulnerabilities {
			add("plugin "+name, v)
		}
	}
	for name, t := range parsed.Themes {
		for _, v := range t.Vulnerabilities {
			add("theme "+name, v)
		}
	}
	return findings
}

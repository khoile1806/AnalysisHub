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

	// Scope guard: never let the scanner touch private/loopback/metadata ranges.
	scoped, dropped := scopeFilter(targets)
	for _, d := range dropped {
		e.emit(scanID, "[!] Out of scope (private/unresolvable), skipped: "+d)
	}
	if len(scoped) == 0 {
		e.emit(scanID, "[!] No in-scope public assets to scan.")
		e.finalize(scan, models.VulnDone)
		e.emit(scanID, "__DONE__")
		e.scheduleHistoryCleanup(scanID)
		return
	}

	proxyURL, mode := e.resolveProxy(scan.ProxyChoice)
	e.db.Model(scan).Update("proxy_mode", mode)
	switch mode {
	case "direct":
		e.emit(scanID, "[!] Egress DIRECT — traffic leaves from this host IP (no proxy).")
	default:
		e.emit(scanID, fmt.Sprintf("[*] Routing scanner traffic through %s proxy (%s)", mode, proxyURL))
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
	scoped = e.runSubfinder(ctx, scan, scoped, proxyURL)
	if stopped() {
		return
	}

	// Stage 2 — naabu: discover open ports (full profile only) so httpx/nuclei
	// also probe non-standard service ports, not just 80/443.
	probeTargets := scoped
	if e.profileOf(scan) == "full" {
		if ports := e.runNaabu(ctx, scan, scoped, proxyURL); len(ports) > 0 {
			probeTargets = ports
		}
		if stopped() {
			return
		}
	}

	// Stage 3 — httpx: find live HTTP(S) services among the assets.
	httpxTool := e.newTool(scan.ID, "httpx")
	nucleiTool := e.newTool(scan.ID, "nuclei")
	live := e.runHTTPx(ctx, scan, httpxTool, probeTargets, proxyURL)
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

	// Stage 4 — nuclei: template-based vulnerability scan of the live services.
	e.runNuclei(ctx, scan, nucleiTool, live, proxyURL)

	// Stage 5 — enrich CVEs (EPSS/KEV) + defence loop (timeline / IOC / notify).
	e.enrichAndReport(ctx, scan)

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

// profileOf returns the scan profile, defaulting to "quick".
func (e *Engine) profileOf(scan *models.VulnScan) string {
	switch scan.Profile {
	case "full", "cve-only":
		return scan.Profile
	default:
		return "quick"
	}
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
	keep, _ := scopeFilter(fresh)
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

	args := []string{"-l", listFile, "-json", "-silent", "-no-color", "-timeout", "10", "-retries", "1"}
	if proxyURL != "" {
		args = append(args, "-proxy", proxyURL)
	}
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Env = proxyEnv(proxyURL)

	var live []string
	var findings []models.VulnFinding
	err = streamLines(cmd, func(line string) {
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
		e.markTool(tool, models.VulnToolFailed, inserted, err.Error())
		e.emit(scanID, "[!] httpx error: "+err.Error())
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
	case "full":
		tags = nil
	default: // quick
		tags = []string{"cve", "exposure", "misconfiguration", "default-login", "exposed-panel", "tech"}
	}
	for _, t := range strings.Split(extra, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tags = append(tags, t)
		}
	}
	return strings.Join(tags, ",")
}

// runNuclei runs the templated vulnerability scan over the live URLs, parsing
// each JSONL finding line as it streams and persisting it live.
func (e *Engine) runNuclei(ctx context.Context, scan *models.VulnScan, tool *models.VulnTool, urls []string, proxyURL string) {
	scanID := scan.ID.String()
	bin, err := exec.LookPath("nuclei")
	if err != nil {
		e.markTool(tool, models.VulnToolSkipped, 0, "nuclei not installed")
		e.emit(scanID, "[!] nuclei not installed — cannot run vulnerability templates")
		return
	}

	listFile, cleanup, err := writeListFile(urls)
	if err != nil {
		e.markTool(tool, models.VulnToolFailed, 0, err.Error())
		return
	}
	defer cleanup()

	e.startTool(tool)
	sev := scan.Severities
	if sev == "" {
		sev = "low,medium,high,critical"
	}
	e.emit(scanID, fmt.Sprintf("[*] nuclei — scanning %d service(s), severities: %s", len(urls), sev))

	budget := e.nucleiTimeout()
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	args := []string{
		"-l", listFile, "-jsonl", "-silent", "-no-color",
		"-disable-update-check", "-severity", sev,
		"-rate-limit", fmt.Sprintf("%d", e.rateLimit()),
		"-concurrency", fmt.Sprintf("%d", e.concurrency()),
		"-timeout", "10",
		// Exclude noisy/aggressive template classes by default — this scanner is
		// for discovery, not denial-of-service or destructive fuzzing.
		"-exclude-tags", "dos,fuzz,intrusive",
	}
	if tags := nucleiTagsFor(e.profileOf(scan), scan.Tags); tags != "" {
		args = append(args, "-tags", tags)
		e.emit(scanID, "[*] nuclei tags: "+tags)
	}
	if proxyURL != "" {
		args = append(args, "-proxy", proxyURL)
	}
	if e.cfg != nil && e.cfg.VulnScanNucleiTemplates != "" {
		// Only point nuclei at the templates dir when it actually exists, so a
		// missing/failed template install degrades to nuclei's own discovery
		// instead of erroring the whole tool.
		if _, statErr := os.Stat(e.cfg.VulnScanNucleiTemplates); statErr == nil {
			args = append(args, "-templates", e.cfg.VulnScanNucleiTemplates)
		}
	}
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Env = proxyEnv(proxyURL)

	count := 0
	err = streamLines(cmd, func(line string) {
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
		if e.persist([]models.VulnFinding{f}) > 0 {
			count++
			label := strings.ToUpper(sev)
			if f.CVEID != "" {
				label += " " + f.CVEID
			}
			e.emit(scanID, fmt.Sprintf("[%s] %s — %s", label, n.Info.Name, n.MatchedAt))
		}
	})

	if err != nil && cctx.Err() == nil && ctx.Err() == nil {
		e.markTool(tool, models.VulnToolFailed, count, err.Error())
		e.emit(scanID, "[!] nuclei error: "+err.Error())
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
		Data: raw, DedupeKey: hex.EncodeToString(sum[:]),
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

// scopeFilter splits assets into in-scope (public) and dropped. IP literals are
// checked directly; hostnames are resolved and dropped only if they resolve
// exclusively to non-public addresses (a resolution failure keeps the host —
// the scanner will simply find nothing rather than us guessing it's internal).
func scopeFilter(targets []string) (keep, drop []string) {
	seen := map[string]bool{}
	for _, raw := range targets {
		t := strings.TrimSpace(raw)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		if ip := net.ParseIP(t); ip != nil {
			if netsafe.IsPublicIP(ip) {
				keep = append(keep, t)
			} else {
				drop = append(drop, t)
			}
			continue
		}
		// Hostname: resolve and require at least one public IP if resolvable.
		ips, err := net.LookupIP(t)
		if err != nil {
			keep = append(keep, t) // unresolvable now; let the scanner try
			continue
		}
		hasPublic := false
		for _, ip := range ips {
			if netsafe.IsPublicIP(ip) {
				hasPublic = true
				break
			}
		}
		if hasPublic {
			keep = append(keep, t)
		} else {
			drop = append(drop, t)
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
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return err
	}
	if stderr != nil {
		go func() {
			s := bufio.NewScanner(stderr)
			for s.Scan() {
			}
		}()
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		onLine(sc.Text())
	}
	return cmd.Wait()
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

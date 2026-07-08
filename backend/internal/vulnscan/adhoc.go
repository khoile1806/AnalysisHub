package vulnscan

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/analysishub/backend/internal/models"
)

// AdHocNucleiOpts configures a targeted, single-URL nuclei run outside the full
// vuln-scan pipeline — from "verify this one CVE" (TemplateIDs) to a fully custom
// invocation. It deliberately skips the subfinder→httpx→…→nuclei stages: nuclei
// runs directly on one URL. ExtraArgs is a guarded free-form passthrough for
// power users (dangerous flags are rejected — see validateExtraArgs).
type AdHocNucleiOpts struct {
	Severities      string   // -severity (ignored when TemplateIDs is set)
	ExcludeSeverity string   // -es
	Tags            string   // -tags
	IncludeTags     string   // -itags
	ExcludeTags     string   // -etags
	TemplateIDs     []string // -id (e.g. CVE ids); most precise
	ExcludeIDs      []string // -eid
	Templates       []string // -t (validated: templates-dir-relative, no traversal)
	Authors         string   // -author
	Protocols       string   // -type (http,dns,ssl,tcp,…)
	Headers         []string // -H  key: value
	Vars            []string // -var key=value
	RateLimit       int      // -rl (bounded)
	Concurrency     int      // -c  (bounded)
	Timeout         int      // -timeout seconds (bounded)
	Retries         int      // -retries (bounded)
	NewTemplates    bool     // -nt (only templates added in the latest release)
	DAST            bool     // -dast
	ExtraArgs       []string // guarded free-form flags
}

// StartAdHocScan runs ONLY nuclei against a single URL with custom options, in a
// goroutine bounded by the same engine semaphore. It reuses the VulnScan record,
// SSE streaming, and findings persistence so the result surfaces like any scan.
func (e *Engine) StartAdHocScan(scan *models.VulnScan, url string, opts AdHocNucleiOpts) error {
	e.mu.Lock()
	if _, exists := e.running[scan.ID.String()]; exists {
		e.mu.Unlock()
		return fmt.Errorf("scan already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.running[scan.ID.String()] = cancel
	e.mu.Unlock()

	go func() {
		defer func() {
			e.mu.Lock()
			delete(e.running, scan.ID.String())
			e.mu.Unlock()
		}()
		defer func() {
			if r := recover(); r != nil {
				e.finalize(scan, models.VulnFailed)
				e.failOpenTools(scan.ID, fmt.Sprintf("scan crashed: %v", r))
				e.emit(scan.ID.String(), fmt.Sprintf("[!] Scan crashed (%v) — finalized as failed", r))
				e.emit(scan.ID.String(), "__DONE__")
				e.scheduleHistoryCleanup(scan.ID.String())
			}
		}()
		select {
		case e.scanSem <- struct{}{}:
			defer func() { <-e.scanSem }()
		default:
			e.emit(scan.ID.String(), "[*] Queued — waiting for a free scan slot...")
			select {
			case e.scanSem <- struct{}{}:
				defer func() { <-e.scanSem }()
			case <-ctx.Done():
				e.finalize(scan, models.VulnStopped)
				e.emit(scan.ID.String(), "[!] Scan stopped before it started (was queued)")
				e.emit(scan.ID.String(), "__DONE__")
				e.scheduleHistoryCleanup(scan.ID.String())
				return
			}
		}
		e.runAdHocNuclei(ctx, scan, url, opts)
	}()
	return nil
}

func (e *Engine) runAdHocNuclei(ctx context.Context, scan *models.VulnScan, url string, opts AdHocNucleiOpts) {
	scanID := scan.ID.String()
	e.db.Model(scan).Update("status", models.VulnRunning)
	if len(opts.TemplateIDs) > 0 {
		e.emit(scanID, fmt.Sprintf("[*] Ad-hoc nuclei — %s (templates: %s)", url, strings.Join(opts.TemplateIDs, ",")))
	} else {
		e.emit(scanID, fmt.Sprintf("[*] Ad-hoc nuclei — %s", url))
	}
	proxyURL, label := e.resolveProxy(scan.ProxyChoice)
	if proxyURL != "" {
		e.emit(scanID, "[*] egress via "+label+" proxy")
	}
	tool := e.newTool(scan.ID, "nuclei")
	e.runNucleiAdHoc(ctx, scan, tool, url, proxyURL, opts)
	if ctx.Err() != nil {
		e.finalize(scan, models.VulnStopped)
		e.emit(scanID, "[!] Scan stopped by user")
	} else {
		e.finalize(scan, models.VulnDone)
		e.emit(scanID, "[*] Ad-hoc scan complete")
	}
	e.emit(scanID, "__DONE__")
	e.scheduleHistoryCleanup(scanID)
}

// runNucleiAdHoc invokes nuclei on a single URL with the ad-hoc option filters. It
// mirrors the pipeline's runNuclei streaming/persistence but builds args from opts
// instead of the scan profile, so it can target a specific template/CVE.
func (e *Engine) runNucleiAdHoc(ctx context.Context, scan *models.VulnScan, tool *models.VulnTool, url, proxyURL string, opts AdHocNucleiOpts) {
	scanID := scan.ID.String()
	bin, err := exec.LookPath("nuclei")
	if err != nil {
		e.markTool(tool, models.VulnToolSkipped, 0, "nuclei not installed")
		e.emit(scanID, "[!] nuclei not installed — cannot run templates")
		return
	}
	listFile, cleanup, err := writeListFile([]string{url})
	if err != nil {
		e.markTool(tool, models.VulnToolFailed, 0, err.Error())
		return
	}
	defer cleanup()
	e.startTool(tool)

	cctx, cancel := context.WithTimeout(ctx, e.nucleiTimeout())
	defer cancel()

	args, err := e.buildAdHocArgs(opts, listFile, proxyURL)
	if err != nil {
		e.markTool(tool, models.VulnToolFailed, 0, err.Error())
		e.emit(scanID, "[!] invalid nuclei options: "+err.Error())
		return
	}
	useID := len(opts.TemplateIDs) > 0
	e.setToolCommand(tool, nucleiDisplayCommand(bin, args, url))
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Env = proxyEnv(proxyURL)

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
	if count == 0 && useID {
		e.emit(scanID, "[*] No match — target does not appear vulnerable to the selected template(s), or no such template exists.")
	}
}

// ───────────────────── ad-hoc arg builder + guards ─────────────────────

// nucleiForbiddenFlags are flags rejected in ExtraArgs: they could override the
// target (scope bypass), write arbitrary files, execute code / launch a browser,
// load arbitrary templates (a `code:` template = RCE), override the egress proxy /
// OAST server, or self-update the binary. Everything else passes through.
var nucleiForbiddenFlags = map[string]bool{
	"u": true, "target": true, "l": true, "list": true, "resume": true,
	"o": true, "output": true, "store-resp": true, "srd": true, "store-resp-dir": true, "or": true, "omit-raw": true,
	"me": true, "markdown-export": true, "se": true, "sarif-export": true,
	"je": true, "json-export": true, "jle": true, "jsonl-export": true, "pe": true, "pdf-export": true,
	"code": true, "headless": true, "sc": true, "system-chrome": true, "lha": true,
	"t": true, "templates": true, "w": true, "workflows": true,
	"tu": true, "template-url": true, "wu": true, "workflow-url": true,
	"et": true, "exclude-templates": true, "config": true, "tlc": true,
	"proxy": true, "pi": true, "proxy-internal": true,
	"iserver": true, "interactsh-server": true, "itoken": true, "interactsh-token": true,
	"update": true, "un": true, "update-templates": true, "ut": true,
	"ldf": true, "lfa": true,
}

var templateRefRe = regexp.MustCompile(`^[a-zA-Z0-9._/-]+$`)

var nucleiAllowedProtocols = map[string]bool{
	"http": true, "dns": true, "ssl": true, "tcp": true, "file": true, "websocket": true, "whois": true,
}

// validateExtraArgs rejects the dangerous flag classes above. Value tokens (not
// starting with "-") pass through as they belong to allowed flags.
func validateExtraArgs(args []string) error {
	if len(args) > 40 {
		return fmt.Errorf("too many extra args (max 40)")
	}
	for _, a := range args {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if len(a) > 256 || strings.ContainsAny(a, "\n\r") {
			return fmt.Errorf("invalid extra arg")
		}
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name := strings.ToLower(strings.TrimLeft(a, "-"))
		if i := strings.IndexAny(name, "= "); i >= 0 {
			name = name[:i]
		}
		if nucleiForbiddenFlags[name] {
			return fmt.Errorf("flag not allowed: -%s (blocked: target override, file output, code/headless, template loading, proxy/OOB override, self-update)", name)
		}
	}
	return nil
}

func validateTemplateRef(t string) error {
	t = strings.TrimSpace(t)
	if t == "" {
		return fmt.Errorf("empty template reference")
	}
	if strings.Contains(t, "..") || strings.HasPrefix(t, "/") || strings.Contains(t, "://") || !templateRefRe.MatchString(t) {
		return fmt.Errorf("template must be a relative path within the templates dir: %q", t)
	}
	return nil
}

func validateProtocols(s string) error {
	for _, p := range strings.Split(s, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if !nucleiAllowedProtocols[p] {
			return fmt.Errorf("protocol %q not allowed", p)
		}
	}
	return nil
}

func boundInt(v, def, lo, hi int) int {
	if v <= 0 {
		return def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// buildAdHocArgs assembles the full nuclei argv from opts. It is the single source
// of truth shared by the runner and the command preview, and validates every
// user-controlled input. listFile is the (already-written) target list path.
func (e *Engine) buildAdHocArgs(opts AdHocNucleiOpts, listFile, proxyURL string) ([]string, error) {
	if err := validateExtraArgs(opts.ExtraArgs); err != nil {
		return nil, err
	}
	for _, t := range opts.Templates {
		if err := validateTemplateRef(t); err != nil {
			return nil, err
		}
	}

	conc := boundInt(opts.Concurrency, e.concurrency(), 1, 100)
	rate := boundInt(opts.RateLimit, e.rateLimit(), 1, 1000)
	reqTimeout := boundInt(opts.Timeout, 10, 1, 60)
	retries := boundInt(opts.Retries, 1, 0, 5)
	if proxyURL != "" {
		if conc > 10 {
			conc = 10
		}
		if rate > 40 {
			rate = 40
		}
		if reqTimeout < 30 {
			reqTimeout = 30
		}
	}

	args := []string{
		"-l", listFile, "-jsonl", "-silent", "-no-color", "-disable-update-check",
		"-rate-limit", strconv.Itoa(rate), "-concurrency", strconv.Itoa(conc),
		"-timeout", strconv.Itoa(reqTimeout), "-retries", strconv.Itoa(retries),
		"-follow-redirects", "-max-redirects", "3",
	}

	useID := len(opts.TemplateIDs) > 0
	if useID {
		// -id is precise; no severity/exclude filter so the target template can't be
		// dropped by a severity mismatch or an "intrusive" tag.
		args = append(args, "-id", strings.Join(opts.TemplateIDs, ","))
	} else {
		if sev := sanitizeSeverities(opts.Severities); sev != "" {
			args = append(args, "-severity", sev)
		}
		// Default safety exclusions only when the operator hasn't taken explicit
		// control of the template selection.
		if strings.TrimSpace(opts.Tags) == "" && strings.TrimSpace(opts.ExcludeTags) == "" && len(opts.Templates) == 0 {
			args = append(args, "-exclude-tags", "dos,intrusive")
		}
	}
	if s := strings.TrimSpace(opts.Tags); s != "" {
		args = append(args, "-tags", s)
	}
	if s := strings.TrimSpace(opts.IncludeTags); s != "" {
		args = append(args, "-itags", s)
	}
	if s := strings.TrimSpace(opts.ExcludeTags); s != "" {
		args = append(args, "-etags", s)
	}
	if len(opts.ExcludeIDs) > 0 {
		args = append(args, "-eid", strings.Join(opts.ExcludeIDs, ","))
	}
	if s := strings.TrimSpace(opts.ExcludeSeverity); s != "" {
		args = append(args, "-es", s)
	}
	if s := strings.TrimSpace(opts.Authors); s != "" {
		args = append(args, "-author", s)
	}
	if s := strings.TrimSpace(opts.Protocols); s != "" {
		if err := validateProtocols(s); err != nil {
			return nil, err
		}
		args = append(args, "-type", s)
	}
	for _, h := range opts.Headers {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if strings.ContainsAny(h, "\n\r") {
			return nil, fmt.Errorf("invalid header")
		}
		args = append(args, "-H", h)
	}
	for _, v := range opts.Vars {
		if v = strings.TrimSpace(v); v != "" {
			args = append(args, "-var", v)
		}
	}
	if opts.NewTemplates {
		args = append(args, "-nt")
	}
	if opts.DAST {
		args = append(args, "-dast")
	}

	args = append(args, e.nucleiOOBArgs()...)
	if proxyURL != "" {
		args = append(args, "-proxy", proxyURL)
	}

	tdir := e.nucleiTemplatesDir()
	if len(opts.Templates) > 0 {
		// Operator-selected templates, resolved within (and confined to) the managed
		// templates dir; the whole-dir source is NOT added so only these run.
		paths := make([]string, 0, len(opts.Templates))
		for _, t := range opts.Templates {
			if tdir != "" {
				paths = append(paths, filepath.Join(tdir, t))
			} else {
				paths = append(paths, t)
			}
		}
		args = append(args, "-t", strings.Join(paths, ","))
	} else if tdir != "" {
		args = append(args, "-templates", tdir)
	}

	// Guarded free-form flags last so an operator can add anything not blocked.
	args = append(args, opts.ExtraArgs...)
	return args, nil
}

// PreviewAdHocArgs validates opts and returns the exact nuclei argv that a run
// would use, with a placeholder target-list path — for the UI command preview.
func (e *Engine) PreviewAdHocArgs(opts AdHocNucleiOpts, proxyChoice string) ([]string, error) {
	proxyURL, _ := e.resolveProxy(proxyChoice)
	return e.buildAdHocArgs(opts, "targets.txt", proxyURL)
}

// ───────────────────── command capture (for session review) ─────────────────

// setToolCommand records the exact command a tool ran, so a saved scan can show
// and reproduce it.
func (e *Engine) setToolCommand(tool *models.VulnTool, cmd string) {
	if tool == nil {
		return
	}
	e.db.Model(tool).Update("command", cmd)
}

// nucleiDisplayCommand renders a readable, reproducible command line: the internal
// "-l <tmpfile>" becomes "-u <url>" (single-URL) or "-l targets.txt" (pipeline),
// and proxy/OAST credentials are redacted.
func nucleiDisplayCommand(bin string, args []string, url string) string {
	out := make([]string, 0, len(args)+1)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-l" && i+1 < len(args):
			if url != "" {
				out = append(out, "-u", url)
			} else {
				out = append(out, "-l", "targets.txt")
			}
			i++
		case a == "-proxy" && i+1 < len(args):
			out = append(out, "-proxy", redactProxyCreds(args[i+1]))
			i++
		case a == "-interactsh-token" && i+1 < len(args):
			out = append(out, "-interactsh-token", "***")
			i++
		default:
			out = append(out, a)
		}
	}
	return bin + " " + shellQuoteJoin(out)
}

// redactProxyCreds masks user:pass in a proxy URL (scheme://user:pass@host → scheme://***@host).
func redactProxyCreds(p string) string {
	if i := strings.Index(p, "://"); i >= 0 {
		rest := p[i+3:]
		if at := strings.Index(rest, "@"); at >= 0 {
			return p[:i+3] + "***@" + rest[at+1:]
		}
	}
	return p
}

func shellQuoteJoin(args []string) string {
	parts := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\"'$&|<>();*?[]{}") {
			parts[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		} else {
			parts[i] = a
		}
	}
	return strings.Join(parts, " ")
}

// commandFor records a tool's exact command (generic display) and returns the
// prepared *exec.Cmd. Used by every pipeline tool runner so a saved scan shows
// each step's command.
func (e *Engine) commandFor(tool *models.VulnTool, ctx context.Context, bin string, args ...string) *exec.Cmd {
	e.setToolCommand(tool, toolDisplayCommand(bin, args))
	return exec.CommandContext(ctx, bin, args...)
}

// toolDisplayCommand renders a readable command for any tool: the internal target
// list file is shown as "targets.txt" and proxy credentials are redacted.
func toolDisplayCommand(bin string, args []string) string {
	out := make([]string, 0, len(args)+1)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case (a == "-l" || a == "-list" || a == "-dL") && i+1 < len(args):
			out = append(out, a, "targets.txt")
			i++
		case (a == "-proxy" || a == "-x") && i+1 < len(args) && strings.Contains(args[i+1], "://"):
			out = append(out, a, redactProxyCreds(args[i+1]))
			i++
		default:
			out = append(out, a)
		}
	}
	return bin + " " + shellQuoteJoin(out)
}

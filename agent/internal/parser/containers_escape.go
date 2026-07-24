package parser

// Container-escape assessment and image-vulnerability types.
//
// This file carries no build tag on purpose: the decision logic is pure (it only
// reads an already-collected Container) and must be testable on the developer's
// host, while the collection around it stays Linux-only.

import (
	"encoding/json"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// ── options ──────────────────────────────────────────────────────────────────

// ContainerScanOptions tunes the optional, slower parts of a container scan.
// The zero value is the forensic-only scan that ScanContainers has always done.
type ContainerScanOptions struct {
	// ScanImageVulns runs the image vulnerability scanner (Trivy) when it is
	// installed. Off by default: a vuln scan costs seconds-to-minutes per image
	// where the rest of the collection costs milliseconds.
	ScanImageVulns bool
	// MaxImageScans caps how many distinct images one run may scan; <= 0 uses
	// the built-in cap.
	MaxImageScans int
}

// vulnScanEnvVar opts the image scan in without a code change. The agent's conf
// file is loaded into the process environment, and the edge-scan entry point
// that reaches ScanContainers takes no parameters today.
const vulnScanEnvVar = "CONTAINER_VULN_SCAN"

func vulnScanEnabledByEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(vulnScanEnvVar))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// ── image vulnerability surface ──────────────────────────────────────────────

// ImageVuln is one HIGH/CRITICAL finding kept for the UI.
type ImageVuln struct {
	ID        string `json:"id"`
	Pkg       string `json:"pkg"`
	Installed string `json:"installed"`
	Fixed     string `json:"fixed"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
}

// ImageVulnSummary is the per-image roll-up of a scanner run.
type ImageVulnSummary struct {
	Critical  int         `json:"critical"`
	High      int         `json:"high"`
	Total     int         `json:"total"`
	Scanner   string      `json:"scanner"`
	ScannedAt string      `json:"scanned_at"`
	Top       []ImageVuln `json:"top"`
}

// Container.ImageScanStatus values. "no vulnerabilities" and "never looked at"
// must never render the same way, which is why the status is always set.
const (
	imageScanOff       = "disabled"      // vuln scanning not enabled for this run
	imageScanNoScanner = "trivy-missing" // enabled, but no scanner on the endpoint
	imageScanOK        = "scanned"
	imageScanFailed    = "failed"
	imageScanCapped    = "capped" // per-run image cap reached
)

const (
	maxTopVulns  = 15 // findings kept per image
	maxVulnTitle = 200
	trivyName    = "trivy"
)

// trivyReport is the subset of `trivy image --format json` that we consume.
type trivyReport struct {
	Results []struct {
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// parseTrivyReport summarises a scanner report: full counts, plus the worst
// maxTopVulns findings (critical before high, then by id) for the UI.
func parseTrivyReport(raw []byte, scannedAt time.Time) (*ImageVulnSummary, error) {
	var rep trivyReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, err
	}
	sum := &ImageVulnSummary{Scanner: trivyName, ScannedAt: scannedAt.UTC().Format(time.RFC3339)}
	seen := map[string]bool{}
	var all []ImageVuln
	for _, res := range rep.Results {
		for _, v := range res.Vulnerabilities {
			sum.Total++
			switch strings.ToUpper(v.Severity) {
			case "CRITICAL":
				sum.Critical++
			case "HIGH":
				sum.High++
			}
			// The same CVE is reported once per affected package; keep one row
			// per (cve, package) so the top list is not one CVE repeated.
			key := v.VulnerabilityID + "|" + v.PkgName
			if seen[key] {
				continue
			}
			seen[key] = true
			title := collapseSpaces(v.Title)
			if len(title) > maxVulnTitle {
				title = title[:maxVulnTitle]
			}
			all = append(all, ImageVuln{
				ID:        v.VulnerabilityID,
				Pkg:       v.PkgName,
				Installed: v.InstalledVersion,
				Fixed:     v.FixedVersion,
				Severity:  strings.ToUpper(v.Severity),
				Title:     title,
			})
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		si, sj := severityRank(all[i].Severity), severityRank(all[j].Severity)
		if si != sj {
			return si > sj
		}
		return all[i].ID < all[j].ID
	})
	if len(all) > maxTopVulns {
		all = all[:maxTopVulns]
	}
	sum.Top = all
	return sum, nil
}

func severityRank(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 3
	case "HIGH":
		return 2
	case "MEDIUM":
		return 1
	}
	return 0
}

// ── image provenance ─────────────────────────────────────────────────────────

// imageStaleDays is the age past which an image has missed a full cycle of
// distro security updates. Plenty of production images are legitimately pinned
// and old, so image-stale is a lead to pivot on, never a finding on its own.
const imageStaleDays = 365

// imageAgeDays converts the image build timestamp into an age in days. Unknown
// or future timestamps yield 0 so the UI can treat 0 as "unknown".
func imageAgeDays(created string, now time.Time) int {
	created = strings.TrimSpace(created)
	if created == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, created)
	if err != nil {
		return 0
	}
	d := int(now.Sub(t).Hours() / 24)
	if d < 0 {
		return 0
	}
	return d
}

// ── escape ids ───────────────────────────────────────────────────────────────

// Escape-class risk ids. They are stable and machine-readable; prior findings
// reference them, so extend the list rather than renaming an entry.
const (
	escapeDockerSock     = "escape:docker-sock"
	escapeCgroupRelease  = "escape:cgroup-release-agent"
	escapeHostRootMount  = "escape:host-root-mount"
	escapeProcWritable   = "escape:proc-writable"
	escapeKernelModule   = "escape:kernel-module-capable"
	escapePtrace         = "escape:ptrace-capable"
	escapeDacReadSearch  = "escape:dac-read-search"
	escapeHostDisk       = "escape:device-host-disk"
	escapeCorePattern    = "escape:core-pattern-writable"
	escapeSuspiciousTool = "escape:suspicious-tooling"
	escapeHostNSTool     = "escape:host-namespace-tool"
)

// ── escape preconditions (configuration evidence) ────────────────────────────

// escapePreconditions returns the escape primitives the container's own
// configuration hands it. Every entry is derived from collected inspect data,
// and the compound ones require both halves (a capability alone is not an escape
// path if the namespace or mount it needs is absent) — an ordinary container
// must come back empty.
//
// Rows without inspect data carry no HostConfig at all, so they are skipped:
// silence is correct there, a guess is not.
func escapePreconditions(c *Container) []string {
	if c == nil || !c.InspectOK {
		return nil
	}

	var rwRoot, rwProc, rwCgroup, sockMount, hostDisk bool
	for _, m := range c.Mounts {
		src := normHostPath(m.Source)
		dst := normHostPath(m.Dest)
		// Same predicate as the docker-socket-mounted risk, so the two can never
		// disagree about what a runtime socket is.
		if isRuntimeSocketMount(src) {
			sockMount = true
			continue
		}
		if isHostDiskNode(src) {
			hostDisk = true
		}
		if !m.RW {
			continue
		}
		switch {
		case src == "/":
			rwRoot = true
		case pathUnder(src, "/proc"):
			// Any writable slice of the host /proc is the same primitive,
			// whether it is /proc, /proc/sys or a single tunable below it.
			rwProc = true
		}
		// A cgroup hierarchy shows up either as the host source or, when the
		// container gets its own cgroup namespace, only at the destination.
		if pathUnder(src, "/sys/fs/cgroup") || pathUnder(dst, "/sys/fs/cgroup") {
			rwCgroup = true
		}
	}
	for _, d := range c.Devices {
		if isHostDiskNode(normHostPath(d.Host)) {
			hostDisk = true
		}
	}

	var out []string
	add := func(id string) { out = append(out, id) }

	if sockMount {
		// Listed as an escape path, but the risk id stays docker-socket-mounted —
		// the caller must not emit both for the same mount.
		add(escapeDockerSock)
	}
	// notify_on_release/release_agent: writing the release agent needs both
	// CAP_SYS_ADMIN and a writable cgroup hierarchy to write it into.
	if rwCgroup && hasEffectiveCap(c, "SYS_ADMIN") {
		add(escapeCgroupRelease)
	}
	if rwRoot {
		add(escapeHostRootMount)
	}
	if rwProc {
		add(escapeProcWritable)
	}
	if hasEffectiveCap(c, "SYS_MODULE") {
		add(escapeKernelModule)
	}
	// Ptrace only reaches host processes when their PIDs are visible.
	if c.HostPID && hasEffectiveCap(c, "SYS_PTRACE") {
		add(escapePtrace)
	}
	// CAP_DAC_READ_SEARCH is the shocker / open_by_handle_at primitive.
	if hasEffectiveCap(c, "DAC_READ_SEARCH") {
		add(escapeDacReadSearch)
	}
	if hostDisk {
		add(escapeHostDisk)
	}
	// core_pattern turns any crash on the host into command execution. It is
	// implied by a writable / or /proc, but named separately because it is the
	// concrete write target an analyst checks first.
	if rwRoot || rwProc {
		add(escapeCorePattern)
	}
	return out
}

// hasEffectiveCap reports whether the container can actually use a capability.
// --privileged grants the whole set while leaving CapAdd empty, and an explicit
// drop of the same capability wins over the add.
func hasEffectiveCap(c *Container, want string) bool {
	if c.Privileged {
		return true
	}
	for _, cp := range c.CapDrop {
		if normCap(cp) == want {
			return false
		}
	}
	for _, cp := range c.CapAdd {
		switch normCap(cp) {
		case want, "ALL":
			return true
		}
	}
	return false
}

func normCap(cap string) string {
	return strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(cap)), "CAP_")
}

// runtimeSocketNames are the control sockets that hand a container the host's
// container runtime — mounting one is a complete escape on its own.
var runtimeSocketNames = []string{"docker.sock", "podman.sock", "containerd.sock", "crio.sock"}

func isRuntimeSocketMount(src string) bool {
	for _, s := range runtimeSocketNames {
		if strings.Contains(src, s) {
			return true
		}
	}
	return false
}

// hostDiskPrefixes are raw block devices. Handing one to a container lets it
// read or write the host filesystem directly, bypassing every namespace.
var hostDiskPrefixes = []string{"/dev/sd", "/dev/nvme", "/dev/mapper/", "/dev/dm-"}

// isHostDiskNode matches a raw disk passed either as a --device or as a bind
// mount of the node itself.
func isHostDiskNode(p string) bool {
	for _, pre := range hostDiskPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// normHostPath normalizes a mount source/destination for prefix matching: no
// trailing slash (except root), lower case, and "" reads as root.
func normHostPath(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	if p == "" {
		return "/"
	}
	if p = strings.TrimRight(p, "/"); p == "" {
		return "/"
	}
	return p
}

// pathUnder reports whether p is base or lives below it.
func pathUnder(p, base string) bool {
	return p == base || strings.HasPrefix(p, base+"/")
}

// ── escape attempt evidence (runtime, best-effort) ───────────────────────────

// escapeAttemptEvidence looks for traces that someone has already gone looking
// for a way out: escape tooling written into the container, or a running process
// reaching for the host's namespaces or runtime.
func escapeAttemptEvidence(c *Container) []string {
	if c == nil {
		return nil
	}
	var out []string
	for _, ch := range c.Changes {
		if ch.Kind == "added" && isEscapeToolFile(ch.Path) {
			out = append(out, escapeSuspiciousTool)
			break
		}
	}
	for _, p := range c.Processes {
		if isHostNamespaceTool(p.Cmd) {
			out = append(out, escapeHostNSTool)
			break
		}
	}
	return out
}

// escapeToolNames are file names that essentially only appear when someone is
// enumerating a container or breaking out of it. The name itself is the
// evidence — "a script under /tmp" is far too weak to flag.
var escapeToolNames = []string{"nsenter", "deepce", "amicontained", "cdk", "linpeas", "pspy"}

// escapeToolSkipDirs are package trees where a same-named binary is legitimate:
// an npm install of the AWS CDK drops a `cdk` executable into node_modules.
var escapeToolSkipDirs = []string{"/node_modules/", "/site-packages/", "/vendor/"}

// isEscapeToolFile matches on the base name minus a script or architecture
// suffix, so /tmp/linpeas.sh, /tmp/pspy64 and /tmp/cdk_linux_amd64 all hit while
// a path that merely contains the word does not.
func isEscapeToolFile(p string) bool {
	lp := strings.ToLower(p)
	for _, d := range escapeToolSkipDirs {
		if strings.Contains(lp, d) {
			return false
		}
	}
	base := path.Base(lp)
	stem := strings.TrimSuffix(base, path.Ext(base))
	for _, t := range escapeToolNames {
		if !strings.HasPrefix(stem, t) {
			continue
		}
		if rest := stem[len(t):]; rest == "" || isToolVariantSuffix(rest) {
			return true
		}
	}
	return false
}

// isToolVariantSuffix accepts the packaging suffixes these tools ship with
// (pspy64, linpeas_fat, cdk-linux) and nothing else, so "nsenterprise" or
// "cdkgen" stay clean.
func isToolVariantSuffix(rest string) bool {
	switch rest[0] {
	case '-', '_', '.':
		return true
	}
	for i := 0; i < len(rest); i++ {
		if rest[i] < '0' || rest[i] > '9' {
			return false
		}
	}
	return true
}

// hostNSTools are executables that only make sense inside a container when
// someone is reaching for the host: entering its namespaces, or driving the
// host runtime / orchestrator from within a workload.
var hostNSTools = map[string]bool{"nsenter": true, "kubectl": true, "crictl": true, "docker": true}

// isHostNamespaceTool matches on argv tokens rather than substrings, so a
// dockerd or docker-proxy process (or a path that mentions docker) is not
// mistaken for a docker client running inside the container.
func isHostNamespaceTool(cmd string) bool {
	fields := strings.Fields(strings.ToLower(cmd))
	for i, f := range fields {
		name := path.Base(strings.Trim(f, `"'`))
		switch {
		case hostNSTools[name]:
			return true
		case name == "unshare":
			// Only the mount-namespace form is an escape primitive.
			for _, a := range fields[i+1:] {
				if a == "-m" || a == "--mount" || strings.HasPrefix(a, "--mount=") {
					return true
				}
			}
		case name == "chroot":
			// chroot into a mounted host filesystem, the second half of most
			// bind-mount escapes.
			if i+1 < len(fields) && pathUnder(normHostPath(fields[i+1]), "/host") {
				return true
			}
		}
	}
	return false
}

// ── small helpers ────────────────────────────────────────────────────────────

// collapseSpaces folds runs of whitespace. It lives here rather than in the
// Linux file because the pure logic above has to build on every platform.
func collapseSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

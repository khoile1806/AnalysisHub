package osint

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/forensichub/backend/internal/models"
)

// portServiceNames labels well-known TCP ports so an open port reads as a named
// service even before a banner is grabbed. Ports not listed are reported as
// "unknown" and identified from their banner if they volunteer one.
var portServiceNames = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
	110: "POP3", 111: "RPCbind", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
	161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
	587: "SMTP submission", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
	1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle DB", 1723: "PPTP", 2049: "NFS",
	2082: "cPanel", 2083: "cPanel SSL", 2375: "Docker API", 2376: "Docker API (TLS)",
	3000: "Dev/Grafana", 3306: "MySQL", 3389: "RDP", 5060: "SIP", 5432: "PostgreSQL",
	5601: "Kibana", 5672: "AMQP", 5900: "VNC", 5984: "CouchDB", 6379: "Redis",
	7001: "WebLogic", 8000: "HTTP-alt", 8008: "HTTP-alt", 8080: "HTTP-proxy",
	8443: "HTTPS-alt", 8888: "HTTP-alt", 9000: "SonarQube/PHP-FPM", 9200: "Elasticsearch",
	9300: "Elasticsearch", 9418: "Git", 10000: "Webmin", 11211: "Memcached",
	15672: "RabbitMQ mgmt", 27017: "MongoDB", 5000: "HTTP-alt/UPnP",
}

// httpProbePorts / tlsProbePorts choose the banner-grab method for well-known
// web ports. Unknown open ports fall back to a generic read, then an HTTP probe.
var httpProbePorts = map[int]bool{80: true, 3000: true, 8000: true, 8008: true, 8080: true, 8888: true, 5000: true, 5601: true, 9000: true, 10000: true}
var tlsProbePorts = map[int]bool{443: true, 8443: true, 2376: true, 2083: true}

// sshBannerRe pulls the product/version from an SSH identification string such
// as "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5".
var sshBannerRe = regexp.MustCompile(`SSH-\d+\.\d+-([A-Za-z0-9_.\-]+)`)

// portscanHostSem bounds how many hosts are full-scanned simultaneously across
// the WHOLE engine. Each host scan opens up to OsintPortScanConcurrency sockets;
// without this cap an auto-pivot graph with several IP nodes could open
// thousands of sockets at once and exhaust ephemeral ports / file descriptors.
// Initialised once from config on first use.
var (
	portscanHostSem  chan struct{}
	portscanSemOnce  sync.Once
)

// acquireHostSlot blocks until a host-scan slot is free or ctx is cancelled. It
// returns a release func (nil when the slot was not acquired).
func acquireHostSlot(ctx context.Context, env *collectorEnv) func() {
	portscanSemOnce.Do(func() {
		n := 2
		if env.cfg != nil && env.cfg.OsintPortScanMaxHosts > 0 {
			n = env.cfg.OsintPortScanMaxHosts
		}
		portscanHostSem = make(chan struct{}, n)
	})
	select {
	case portscanHostSem <- struct{}{}:
		return func() { <-portscanHostSem }
	case <-ctx.Done():
		return nil
	}
}

// portResult is one open port plus whatever banner / product was identified.
type portResult struct {
	port    int
	service string
	banner  string
	product string // CPE-mappable product name when recognised
	version string
}

// collectPortScan performs an ACTIVE TCP-connect scan of the FULL port range
// (1-65535 by default) on the IP so no listening service is missed, grabs
// service banners, identifies product + version where disclosed, and matches
// recognised versions against NVD for known CVEs. Unlike the passive Shodan/
// InternetDB collectors this reflects the host's CURRENT state. Private/loopback
// targets are already rejected by ValidateTarget, so this only touches public
// addresses. Range and concurrency are tunable via OSINT_PORTSCAN_MAX /
// OSINT_PORTSCAN_CONCURRENCY for operators on constrained links.
func collectPortScan(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	if env.ttype != TargetIP {
		return nil, nil
	}
	ip := strings.TrimSpace(env.target)

	// Engine-wide cap: wait for a host-scan slot so concurrent IP scans across an
	// auto-pivot graph can't exhaust sockets. Queued scans simply wait their turn.
	release := acquireHostSlot(ctx, env)
	if release == nil {
		env.emit("[*] portscan: skipped - scan cancelled while queued for a host slot")
		return nil, nil
	}
	defer release()

	// Every target - root or auto-pivoted - gets the FULL TCP sweep so no
	// listening service is ever missed. Operators can still cap the range with
	// OSINT_PORTSCAN_MAX on constrained links.
	maxPort := 65535
	if env.cfg != nil && env.cfg.OsintPortScanMax > 0 && env.cfg.OsintPortScanMax <= 65535 {
		maxPort = env.cfg.OsintPortScanMax
	}
	concurrency := 800
	if env.cfg != nil && env.cfg.OsintPortScanConcurrency > 0 {
		concurrency = env.cfg.OsintPortScanConcurrency
	}
	env.emit(fmt.Sprintf("[*] portscan: full TCP sweep 1-%d (%d concurrent)", maxPort, concurrency))

	var (
		mu      sync.Mutex
		results []portResult
		scanned int64
		open    int64
	)
	ports := make(chan int, 2048)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range ports {
				if ctx.Err() != nil {
					return
				}
				if res, isOpen := probePort(ctx, ip, p); isOpen {
					mu.Lock()
					results = append(results, res)
					mu.Unlock()
					atomic.AddInt64(&open, 1)
				}
				if n := atomic.AddInt64(&scanned, 1); n%8192 == 0 {
					env.emit(fmt.Sprintf("[*] portscan: %d/%d ports probed, %d open so far",
						n, maxPort, atomic.LoadInt64(&open)))
				}
			}
		}()
	}
	// Producer: feed every port, stop early if the scan is cancelled/timed out.
	go func() {
		defer close(ports)
		for p := 1; p <= maxPort; p++ {
			select {
			case ports <- p:
			case <-ctx.Done():
				return
			}
		}
	}()
	wg.Wait()

	if ctx.Err() != nil {
		env.emit(fmt.Sprintf("[!] portscan: time budget reached after %d port(s) - returning partial results",
			atomic.LoadInt64(&scanned)))
	}

	if len(results) == 0 {
		env.emit("[*] portscan: no open TCP ports found")
		return nil, nil
	}
	sort.Slice(results, func(i, j int) bool { return results[i].port < results[j].port })

	var out []models.OsintFinding
	ports2 := make([]string, 0, len(results))
	for _, r := range results {
		ports2 = append(ports2, strconv.Itoa(r.port))
	}
	out = append(out, newFinding("portscan", "ports", "Open ports (active full scan)", strings.Join(ports2, ", ")))

	// OS detection of the scanned host, inferred from service banners + the open-
	// port profile.
	if osf, ok := inferOS(results); ok {
		out = append(out, osf)
		env.emit("[+] portscan: OS guess - " + osf.Value)
	}

	cveDone := 0
	for i := range results {
		r := &results[i]
		val := fmt.Sprintf("%d/tcp - %s", r.port, r.service)
		if r.product != "" {
			val += " - " + strings.TrimSpace(r.product+" "+r.version)
		} else if r.banner != "" {
			val += " - " + truncate(r.banner, 120)
		}
		f := newFinding("portscan", "ports", "Open service", val)
		// Dangerous unauthenticated/admin services on the public internet are
		// flagged so they stand out even without a CVE.
		if riskyPorts[strconv.Itoa(r.port)] >= 4 {
			f.Severity = "medium"
		}
		out = append(out, f)

		if r.product != "" && r.version != "" && cveDone < 6 {
			if key := cpeKeyFor(r.product); key != "" {
				if cves := lookupCVEs(ctx, env, "portscan", key, r.version); len(cves) > 0 {
					out = append(out, cves...)
					cveDone++
				}
			}
		}
	}
	env.emit(fmt.Sprintf("[+] portscan: %d open port(s) found across the full range", len(results)))
	// Cross-verifiable on Shodan's host page (CVE findings keep their NVD link).
	return stampSource(out, shodanHostURL(ip)), nil
}

// osSignature maps a substring found in a service banner to the OS / distro it
// discloses. Order matters: more specific distros are matched before generic
// families.
var osSignatures = []struct{ key, label, family string }{
	{"ubuntu", "Ubuntu Linux", "linux"},
	{"debian", "Debian Linux", "linux"},
	{"raspbian", "Raspbian (Debian)", "linux"},
	{"centos", "CentOS Linux", "linux"},
	{"red hat", "Red Hat Enterprise Linux", "linux"},
	{"redhat", "Red Hat Enterprise Linux", "linux"},
	{"rhel", "Red Hat Enterprise Linux", "linux"},
	{"fedora", "Fedora Linux", "linux"},
	{"amazon", "Amazon Linux", "linux"},
	{"alpine", "Alpine Linux", "linux"},
	{"suse", "SUSE Linux", "linux"},
	{"gentoo", "Gentoo Linux", "linux"},
	{"oracle linux", "Oracle Linux", "linux"},
	{"freebsd", "FreeBSD", "bsd"},
	{"openbsd", "OpenBSD", "bsd"},
	{"netbsd", "NetBSD", "bsd"},
	{"darwin", "macOS / Darwin", "unix"},
	{"microsoft-iis", "Windows Server (IIS)", "windows"},
	{"win64", "Windows", "windows"},
	{"win32", "Windows", "windows"},
	{"windows", "Windows", "windows"},
	{"mikrotik", "MikroTik RouterOS", "network"},
	{"routeros", "MikroTik RouterOS", "network"},
	{"cisco", "Cisco IOS", "network"},
	{"ubnt", "Ubiquiti / EdgeOS", "network"},
	{"unix", "Unix-like", "unix"},
}

// inferOS makes a best-effort OS determination for the scanned host. A TCP
// connect scan can't fingerprint the IP stack (that needs raw sockets), but
// service banners routinely disclose the exact distro and the open-port profile
// distinguishes Windows from Unix. Returns (finding, true) when a guess can be
// made.
func inferOS(results []portResult) (models.OsintFinding, bool) {
	portSet := make(map[int]bool, len(results))
	var blob strings.Builder
	for i := range results {
		portSet[results[i].port] = true
		blob.WriteString(strings.ToLower(results[i].banner + " " + results[i].product + " " + results[i].version))
		blob.WriteByte('\n')
	}
	text := blob.String()

	// 1. Exact distro/OS disclosed in a banner = highest confidence.
	for _, sig := range osSignatures {
		if strings.Contains(text, sig.key) {
			f := newFinding("portscan", "ports", "Operating system (inferred)",
				sig.label+" - disclosed in a service banner")
			f.Severity = "info"
			f.Data = toJSON(map[string]string{"os": sig.label, "family": sig.family, "method": "banner"})
			return f, true
		}
	}

	// 2. Fall back to the open-port profile (Windows vs Unix-like).
	win := 0
	if portSet[3389] { // RDP
		win += 2
	}
	if portSet[445] || portSet[139] || portSet[135] { // SMB / NetBIOS / MSRPC
		win++
	}
	if portSet[5985] || portSet[5986] { // WinRM
		win += 2
	}
	nix := 0
	if portSet[22] { // SSH
		nix++
	}
	switch {
	case win >= 2 && win > nix:
		f := newFinding("portscan", "ports", "Operating system (inferred)",
			"Windows - inferred from the exposed RDP/SMB/WinRM service profile")
		f.Severity = "info"
		f.Data = toJSON(map[string]string{"os": "Windows", "family": "windows", "method": "port-profile"})
		return f, true
	case nix > 0 && win == 0:
		f := newFinding("portscan", "ports", "Operating system (inferred)",
			"Linux/Unix-like - inferred from the exposed service profile (SSH, no Windows services)")
		f.Severity = "info"
		f.Data = toJSON(map[string]string{"os": "Linux/Unix", "family": "unix", "method": "port-profile"})
		return f, true
	}
	return models.OsintFinding{}, false
}

// probePort attempts a TCP connection and, on success, grabs a service banner.
func probePort(ctx context.Context, ip string, port int) (portResult, bool) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return portResult{}, false
	}
	defer conn.Close()

	service := portServiceNames[port]
	if service == "" {
		service = "unknown"
	}
	res := portResult{port: port, service: service}
	res.banner, res.product, res.version = grabBanner(conn, ip, port)
	// A banner that looks like an HTTP Server header upgrades an "unknown" port.
	if res.service == "unknown" && res.product != "" {
		res.service = "HTTP"
	}
	return res, true
}

// grabBanner reads a service banner and tries to extract a product + version. For
// known HTTP(S) ports it sends a minimal request; for unknown ports it first
// reads any volunteered banner (SSH/FTP/SMTP announce themselves) and, failing
// that, falls back to an HTTP probe to catch web servers on non-standard ports.
func grabBanner(conn net.Conn, ip string, port int) (banner, product, version string) {
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if tlsProbePorts[port] {
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: ip}) //nolint:gosec // banner-grab only
		if tc.Handshake() == nil {
			_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
			return httpBanner(tc, ip)
		}
		return "", "", ""
	}
	if httpProbePorts[port] {
		return httpBanner(conn, ip)
	}

	// Generic: many services emit a banner immediately on connect.
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 0 {
		raw := string(buf[:n])
		product, version = parseServiceBanner(port, raw)
		banner = printableBanner(raw)
		if banner != "" || product != "" {
			return banner, product, version
		}
	}
	// Silent port: try an HTTP probe (catches web servers on arbitrary ports).
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	return httpBanner(conn, ip)
}

// httpBanner sends a HEAD request and returns the Server header (and parsed
// product/version).
func httpBanner(conn net.Conn, host string) (banner, product, version string) {
	if _, err := fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n", host, "ForensicHub-OSINT"); err != nil {
		return "", "", ""
	}
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if line == "" && err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			banner = strings.TrimSpace(line[len("server:"):])
			product, version = splitServerToken(banner)
			return banner, product, version
		}
		if err != nil {
			break
		}
	}
	return banner, "", ""
}

// printableBanner keeps only printable ASCII from a raw banner so binary
// protocols (e.g. nping-echo) don't write control bytes into findings. Returns
// "" when nothing printable remains.
func printableBanner(raw string) string {
	var b strings.Builder
	for _, r := range raw {
		if r == '\t' || (r >= 0x20 && r <= 0x7e) {
			b.WriteRune(r)
		} else if r == '\n' || r == '\r' {
			b.WriteByte(' ')
		}
	}
	return strings.TrimSpace(b.String())
}

// parseServiceBanner extracts a product + version from a non-HTTP banner.
func parseServiceBanner(port int, banner string) (product, version string) {
	lb := strings.ToLower(banner)
	// SSH announces on any port it runs on, not just 22.
	if m := sshBannerRe.FindStringSubmatch(banner); len(m) == 2 {
		tok := m[1] // e.g. "OpenSSH_8.2p1"
		if strings.HasPrefix(strings.ToLower(tok), "openssh") {
			return "OpenSSH", extractVersion(tok)
		}
		name := tok
		if i := strings.IndexAny(tok, "_/"); i > 0 {
			name = tok[:i]
		}
		return name, extractVersion(tok)
	}
	switch {
	case strings.Contains(lb, "proftpd"):
		return "ProFTPD", extractVersion(banner)
	case strings.Contains(lb, "pure-ftpd"):
		return "Pure-FTPd", extractVersion(banner)
	case strings.Contains(lb, "vsftpd"):
		return "vsftpd", extractVersion(banner)
	case strings.Contains(lb, "exim"):
		return "Exim", extractVersion(banner)
	case strings.Contains(lb, "postfix"):
		return "Postfix", extractVersion(banner)
	}
	return "", ""
}

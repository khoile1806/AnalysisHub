package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds all application configuration loaded from environment variables.
type Config struct {
	ServerPort    string
	PostgresDSN   string
	RedisAddr     string
	RedisPassword string
	JWTSecret     string
	StoragePath   string
	AdminEmail    string
	AdminPassword string
	AppEnv        string
	// PublicURL is the externally-reachable base URL of this server
	// (e.g. "http://192.168.1.10:8080"). When set, it overrides the
	// Host-header-derived URL used in install scripts and job dispatch.
	PublicURL string
	// CanaryBaseURL is the public base URL used to build canary-token links
	// (e.g. "https://promo-event.io"). It is deliberately decoupled from
	// PublicURL so operators can front canary links with a separate / disposable
	// domain (or reverse proxy / tunnel) and avoid leaking the real ForensicHub
	// host to whoever clicks the link. When empty the per-token override (if any)
	// or the request-derived host is used.
	CanaryBaseURL string

	// ── Outbound alert notifications (canary hits, OSINT watches) ──────────
	// All optional; when a channel's fields are set, alerts are fanned out to it
	// best-effort. NotifyWebhookURL receives a JSON POST; NotifyTelegram* send
	// via the Telegram Bot API. Empty = that channel is disabled.
	NotifyWebhookURL    string
	NotifyTelegramToken string
	NotifyTelegramChat  string

	// UseHTTPS, when true, forces the automatically-derived server URL to
	// use https:// even if the request appears to be plain http.
	UseHTTPS bool
	// AllowedOrigins is the list of browser origins permitted for CORS
	// and WebSocket upgrades (e.g. ["http://localhost:3000"]). When the
	// ALLOWED_ORIGINS env var is unset a dev-friendly default is used.
	AllowedOrigins []string
	// NVDAPIKey is an optional API key for the NVD CVE API. When set it
	// raises the rate limit from 5 to 50 requests per 30s window.
	NVDAPIKey string
	// APINvdURL is the NVD CVE API endpoint (overridable for testing/mirrors).
	APINvdURL string

	// GitHubToken is an optional Personal Access Token used when querying
	// the GitHub Search API for PoC repositories. Without it the unauth
	// rate limit (~10 req/min) applies.
	GitHubToken string
	// AESEncryptionKey is a 32-byte key used for encrypting sensitive data like OpenCTI credentials.
	AESEncryptionKey string

	// ── Threat Intelligence API keys ─────────────────────────────────────
	// Used by the AI analysis pipeline to automatically enrich extracted IOCs
	// (IPs, hashes, domains) before passing context to the AI model.
	//
	// VirusTotalKeys holds up to 4 VT API keys loaded from VIRUSTOTAL_1 …
	// VIRUSTOTAL_4 (or a single VIRUSTOTAL env var). Keys are rotated
	// round-robin so free-tier quota (4 req/min per key) is shared.
	VirusTotalKeys []string
	// AbuseIPDBKey is the API key for https://www.abuseipdb.com (IP reputation).
	AbuseIPDBKey string
	// AlienVaultKey is the OTX API key for https://otx.alienvault.com.
	AlienVaultKey string
	// ShodanKey is the API key for https://www.shodan.io (internet-wide scanning DB).
	ShodanKey string

	// ── OSINT footprinting ───────────────────────────────────────────────
	// The OSINT module's reputation collectors (VirusTotal, Shodan, AbuseIPDB)
	// reuse the Threat Intelligence keys above. These are the extra keys/URLs
	// it needs on top of that. All optional — a missing key skips that collector.
	OsintHIBPKey      string // Have I Been Pwned (email breach exposure)
	OsintDehashedKey  string // Dehashed (data leak exposure)
	OsintNumVerifyKey string // NumVerify (phone metadata)
	// Active port scan (the "portscan" collector) tuning. By default the scanner
	// sweeps the FULL TCP range (1-65535) so nothing is missed; operators on slow
	// links can shrink the range or concurrency to throttle it.
	OsintPortScanMax         int // highest TCP port to scan (default 65535)
	OsintPortScanConcurrency int // simultaneous connect probes per host (default 800)
	OsintPortScanMaxHosts    int // how many hosts may be full-scanned at once engine-wide (default 2)
	// OsintMaxConcurrentScans bounds how many OSINT scans execute at once across
	// the whole engine. Every scan - a root investigation or an auto-pivot child -
	// queues through this limit, so a deep/wide pivot graph can't exhaust sockets,
	// goroutines or third-party rate limits. Queued scans stay "pending" until a
	// slot frees. (default 6)
	OsintMaxConcurrentScans int
	// Cloud-storage exposure ("cloud" collector). The collector permutes bucket
	// names from the target domain and probes public S3/GCS/Azure endpoints. The
	// candidate count is capped so the active probe stays bounded.
	OsintCloudMaxCandidates int // max bucket-name candidates probed (default 120)
	// OsintCohostPivotMax is the most co-hosted domains an IP may have before the
	// IP is treated as shared hosting and its co-hosted domains are recorded as
	// findings but NOT auto-pivoted (they are other tenants, not the subject).
	OsintCohostPivotMax int // default 5

	// OsintMaxPivotChildren bounds how many child scans one scan may auto-spawn.
	// The budget is allocated round-robin across categories (IP / domain /
	// account / other) so each related-entity class is investigated and no class
	// (e.g. e-mails/usernames) is starved by a long list of IPs or domains.
	OsintMaxPivotChildren int // default 12

	// Configurable auto-pivot filter lists. If empty, the engine uses its built-in defaults.
	OsintProviderSuffixes []string
	OsintRDNSMarkers      []string

	// OsintAutoPromote, when true, automatically adds a scanned target to the IOC
	// store once a collector flags it malicious with high confidence — closing the
	// OSINT → defence loop (ELK auto-hunt then searches the logs for it).
	OsintAutoPromote bool

	// Threat-feed / reputation keys (all optional). abuse.ch (ThreatFox/URLhaus/
	// MalwareBazaar) share one Auth-Key; Pulsedive and GreyNoise have their own.
	AbuseChKey   string
	PulsediveKey string
	GreyNoiseKey string

	// ── Dark-web (Phase 3) ───────────────────────────────────────────────
	// Enterprise aggregator API keys (seams — empty unless the org licenses one).
	FlareKey    string
	DarkOwlKey  string
	Intel471Key string
	// DarkWebSources are operator-configured source URLs the generic crawler
	// fetches and scans for the org's own selectors. EMPTY by default — the tool
	// ships with NO targets; pointing it at a source is the operator's
	// responsibility and must be within their legal authority.
	DarkWebSources []string
	// TorProxy is an optional SOCKS5 proxy (e.g. socks5://127.0.0.1:9050) the
	// dark-web crawler dials through to reach .onion / Tor sources. Empty =
	// fall back to the project-wide OutboundProxy (or direct).
	TorProxy string

	// OutboundProxy is a project-wide egress proxy (http/https/socks5 URL) applied
	// automatically to every EXTERNAL fetch (OSINT, threat-intel, CVE, news…).
	// Internal SIEM connectors (ELK/Splunk/QRadar/OpenCTI) bypass it. Empty =
	// direct. OutboundNoProxy is an optional comma-separated NO_PROXY list.
	OutboundProxy   string
	OutboundNoProxy string
	// OutboundProxyFallback: when true, egress automatically falls back to a
	// DIRECT connection if the configured proxy is unhealthy (keeps fetches
	// working at the cost of anonymity). OutboundProxyProbe is the URL the
	// background health checker GETs through the proxy.
	OutboundProxyFallback bool
	OutboundProxyProbe    string
	APINumVerifyURL       string // NumVerify validate endpoint
	APIIpApiURL           string // ip-api.com geolocation endpoint
	APIWebArchiveURL      string // Wayback Machine CDX endpoint

	// LogPath is the directory where date-stamped log files are written.
	// Defaults to "data/logs" (relative to CWD) for local dev.
	// In Docker set LOG_PATH=/app/data/logs via the compose environment block.
	LogPath string

	// ── OOB interaction server (Catch — Interactsh / Burp-Collaborator style) ──
	// A controlled DNS + HTTP(S) + SMTP endpoint that records out-of-band
	// callbacks from a target, used to confirm blind vulns (SSRF, blind XXE/RCE,
	// blind SQLi, email-header injection) on authorised engagements.
	//
	// Requires a real domain whose NS records are DELEGATED to OOBPublicIP (so
	// the internet resolves *.OOBDomain to this server). Disabled by default.
	OOBEnabled    bool   // master switch — start the listeners
	OOBDomain     string // delegated zone, e.g. "oob.example.com" (no trailing dot)
	OOBPublicIP   string // public IPv4 the DNS A answers + payloads advertise
	OOBPublicIPv6 string // optional public IPv6 for AAAA answers
	OOBNSName     string // this server's NS hostname for SOA/NS (default ns1.<domain>)
	OOBDNSPort    string // UDP+TCP DNS listen port (default 53)
	OOBHTTPPort   string // HTTP catch-all port (default 80; empty/0 disables)
	OOBHTTPSPort  string // HTTPS catch-all port (default 443; needs cert/key)
	OOBSMTPPort   string // SMTP catch-all port (default 25; empty/0 disables)
	OOBTLSCert    string // PEM cert path for the HTTPS catch-all (wildcard *.OOBDomain)
	OOBTLSKey     string // PEM key path for the HTTPS catch-all
	OOBLDAPPort   string // JNDI/LDAP callback catcher (Log4Shell) — default 1389 (empty/0 disables)
	OOBRMIPort    string // JNDI/RMI callback catcher — default 1099 (empty/0 disables)

	// Anti-abuse / retention for the public webhook receiver.
	OOBRateLimitPerMin int // max recorded hits per token per minute (default 600)
	OOBMaxPerClient    int // max stored interactions per session (default 10000; 0 = unlimited)
	OOBRetentionDays   int // delete interactions older than this many days (default 30; 0 = keep)

	// TrustedProxies, when set (comma-separated IPs/CIDRs), is passed to gin's
	// SetTrustedProxies so X-Forwarded-For / X-Forwarded-Proto are only honoured
	// from the real front proxy — preventing source-IP/scheme spoofing. Empty
	// keeps gin's default (trust all) for backward compatibility.
	TrustedProxies []string

	// SandboxTerminalURL is the internal address of the volatility/kali ttyd web
	// terminal. The sandbox is NOT published on the host — the backend reverse-
	// proxies to it behind an admin JWT (see handlers/sandbox.go), so this is a
	// container-network address. Defaults to the compose service name.
	SandboxTerminalURL string
}

// Load reads configuration from environment variables, applying defaults where appropriate.
func Load() *Config {
	return &Config{
		ServerPort:          getEnv("SERVER_PORT", "8080"),
		PostgresDSN:         getEnv("POSTGRES_DSN", "host=localhost user=forensichub password=forensichub dbname=forensichub port=5432 sslmode=disable TimeZone=UTC"),
		RedisAddr:           getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword:       getEnv("REDIS_PASSWORD", ""),
		JWTSecret:           getEnv("JWT_SECRET", "change-me-in-production-use-a-long-random-string"),
		StoragePath:         getEnv("STORAGE_PATH", "/app/storage"),
		AdminEmail:          getEnv("ADMIN_EMAIL", "admin@forensichub.local"),
		AdminPassword:       getEnv("ADMIN_PASSWORD", "ChangeMe!2024"),
		AppEnv:              getEnv("APP_ENV", "development"),
		PublicURL:           getEnv("PUBLIC_URL", ""),
		CanaryBaseURL:       getEnv("CANARY_BASE_URL", ""),
		NotifyWebhookURL:    getEnv("NOTIFY_WEBHOOK_URL", ""),
		NotifyTelegramToken: getEnv("NOTIFY_TELEGRAM_TOKEN", ""),
		NotifyTelegramChat:  getEnv("NOTIFY_TELEGRAM_CHAT_ID", ""),
		UseHTTPS:            getEnv("USE_HTTPS", "false") == "true",
		AllowedOrigins:      parseOrigins(getEnv("ALLOWED_ORIGINS", "")),
		NVDAPIKey:           getEnv("NVD_API_KEY", ""),
		APINvdURL:           getEnv("API_NVD_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
		GitHubToken:         getEnv("GITHUB_TOKEN", ""),
		AESEncryptionKey:    getEnv("AES_ENCRYPTION_KEY", "default-insecure-key-exct-32-byt"),

		VirusTotalKeys: loadVirusTotalKeys(),
		AbuseIPDBKey:   getEnv("ABUSEIPDB", ""),
		AlienVaultKey:  getEnv("ALIENVAULT", ""),
		ShodanKey:      getEnv("SHODAN", ""),

		OsintHIBPKey:             getEnv("HIBP_API_KEY", ""),
		OsintDehashedKey:         getEnv("DEHASHED_API_KEY", ""),
		OsintNumVerifyKey:        getEnv("OSINT_NUMVERIFY_API_KEY", ""),
		OsintPortScanMax:         getEnvInt("OSINT_PORTSCAN_MAX", 65535),
		OsintPortScanConcurrency: getEnvInt("OSINT_PORTSCAN_CONCURRENCY", 800),
		OsintPortScanMaxHosts:    getEnvInt("OSINT_PORTSCAN_MAX_HOSTS", 2),
		OsintCloudMaxCandidates:  getEnvInt("OSINT_CLOUD_MAX_CANDIDATES", 120),
		OsintCohostPivotMax:      getEnvInt("OSINT_COHOST_PIVOT_MAX", 5),
		OsintMaxPivotChildren:    getEnvInt("OSINT_MAX_PIVOT_CHILDREN", 12),
		OsintMaxConcurrentScans:  getEnvInt("OSINT_MAX_CONCURRENT_SCANS", 6),
		OsintProviderSuffixes:    parseCSV(getEnv("OSINT_PROVIDER_SUFFIXES", "")),
		OsintRDNSMarkers:         parseCSV(getEnv("OSINT_RDNS_MARKERS", "")),
		OsintAutoPromote:         getEnv("OSINT_AUTO_PROMOTE", "true") != "false",
		AbuseChKey:               getEnv("ABUSE_CH_API_KEY", ""),
		PulsediveKey:             getEnv("PULSEDIVE_API_KEY", ""),
		GreyNoiseKey:             getEnv("GREYNOISE_API_KEY", ""),
		FlareKey:                 getEnv("FLARE_API_KEY", ""),
		DarkOwlKey:               getEnv("DARKOWL_API_KEY", ""),
		Intel471Key:              getEnv("INTEL471_API_KEY", ""),
		DarkWebSources:           parseCSV(getEnv("OSINT_DARKWEB_SOURCES", "")),
		TorProxy:                 getEnv("OSINT_TOR_PROXY", ""),
		SandboxTerminalURL:       getEnv("SANDBOX_TERMINAL_URL", "http://volatility_sandbox:7681"),

		OOBEnabled:    getEnv("OOB_ENABLED", "false") == "true",
		OOBDomain:     strings.ToLower(strings.TrimSuffix(getEnv("OOB_DOMAIN", ""), ".")),
		OOBPublicIP:   getEnv("OOB_PUBLIC_IP", ""),
		OOBPublicIPv6: getEnv("OOB_PUBLIC_IPV6", ""),
		OOBNSName:     getEnv("OOB_NS_NAME", ""),
		OOBDNSPort:    getEnv("OOB_DNS_PORT", "53"),
		OOBHTTPPort:   getEnv("OOB_HTTP_PORT", "80"),
		OOBHTTPSPort:  getEnv("OOB_HTTPS_PORT", "443"),
		OOBSMTPPort:   getEnv("OOB_SMTP_PORT", "25"),
		OOBTLSCert:    getEnv("OOB_TLS_CERT", ""),
		OOBTLSKey:     getEnv("OOB_TLS_KEY", ""),
		OOBLDAPPort:   getEnv("OOB_LDAP_PORT", "1389"),
		OOBRMIPort:    getEnv("OOB_RMI_PORT", "1099"),

		OOBRateLimitPerMin: getEnvInt("OOB_RATE_LIMIT_PER_MIN", 600),
		OOBMaxPerClient:    getEnvInt("OOB_MAX_PER_CLIENT", 10000),
		OOBRetentionDays:   getEnvInt("OOB_RETENTION_DAYS", 30),

		TrustedProxies:        parseCSV(getEnv("TRUSTED_PROXIES", "")),
		OutboundProxy:         getEnv("OUTBOUND_PROXY", ""),
		OutboundNoProxy:       getEnv("OUTBOUND_NO_PROXY", ""),
		OutboundProxyFallback: getEnv("OUTBOUND_PROXY_FALLBACK_DIRECT", "false") == "true",
		OutboundProxyProbe:    getEnv("OUTBOUND_PROXY_PROBE_URL", "https://www.google.com/generate_204"),
		APINumVerifyURL:       getEnv("API_NUMVERIFY_URL", "http://apilayer.net/api/validate"),
		APIIpApiURL:           getEnv("API_IP_API_URL", "http://ip-api.com/json/"),
		APIWebArchiveURL:      getEnv("API_WEB_ARCHIVE_URL", "http://web.archive.org/cdx/search/cdx"),

		LogPath: getEnv("LOG_PATH", "data/logs"),
	}
}

// parseOrigins splits a comma-separated origin list. Falls back to a
// dev-friendly default (localhost:3000) when the value is empty so that
// fresh checkouts keep working without extra configuration.
func parseOrigins(raw string) []string {
	if raw == "" {
		return []string{"http://localhost:3000", "http://127.0.0.1:3000"}
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// BaseNoProxy lists the hosts that must ALWAYS bypass the egress proxy
// (loopback — DB/Redis/SIEM health probes over HTTP).
const BaseNoProxy = "localhost,127.0.0.1,::1"

// EffectiveNoProxy composes the NO_PROXY value: the mandatory loopback bypass
// plus any operator-supplied exceptions. Shared by the startup proxy installer
// and the proxy-validate endpoint so the two never drift.
func EffectiveNoProxy(extra string) string {
	out := BaseNoProxy
	if e := strings.TrimSpace(extra); e != "" {
		out += "," + e
	}
	return out
}

// parseCSV splits a comma-separated env value into trimmed, non-empty items.
func parseCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// loadVirusTotalKeys returns up to 4 VirusTotal API keys.
// Accepts VIRUSTOTAL (single or comma-separated) plus VIRUSTOTAL_1…VIRUSTOTAL_4.
func loadVirusTotalKeys() []string {
	seen := make(map[string]bool)
	out := make([]string, 0, 4)
	add := func(raw string) {
		for _, t := range strings.Split(raw, ",") {
			s := strings.TrimSpace(t)
			if s == "" || seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	add(os.Getenv("VIRUSTOTAL"))
	for i := 1; i <= 4; i++ {
		add(os.Getenv(fmt.Sprintf("VIRUSTOTAL_%d", i)))
	}
	return out
}

// getEnv returns the value of the environment variable named by key,
// or fallback if the variable is not set or empty.
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// getEnvInt reads an integer env var, returning fallback when unset or invalid.
func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return fallback
}

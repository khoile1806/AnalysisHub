package config

import (
	"fmt"
	"os"
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
	// API endpoint configurations for scanners
	APINvdURL           string
	APIWpscanURL        string
	APINumVerifyURL     string
	APIIpApiURL         string
	APIWebArchiveURL    string
	APICrtShURL         string
	APICertSpotterURL   string

	// GitHubToken is an optional Personal Access Token used when querying
	// the GitHub Search API for PoC repositories. Without it the unauth
	// rate limit (~10 req/min) applies.
	GitHubToken string
	// WPScanAPITokens is an ordered list of tokens for the WPScan
	// Vulnerability DB. CVE search tries them in order on each request and
	// rotates to the next when one returns 429 (quota exhausted) — so a
	// pair of free-tier tokens effectively doubles the daily budget. The
	// loader accepts either a single comma-separated env var
	// (WPSCAN_API_TOKEN="a,b") or numbered fallbacks (WPSCAN_API_TOKEN_2,
	// WPSCAN_API_TOKEN_3, …) so docker-compose stays readable.
	WPScanAPITokens []string
	// AESEncryptionKey is a 32-byte key used for encrypting sensitive data like OpenCTI credentials.
	AESEncryptionKey string
	// Osint* are optional API keys for the OSINT footprinting module. The
	// module works without any of them (free no-key sources), and each key
	// simply unlocks one richer collector. Empty → that collector is skipped.
	OsintVirusTotalKey string
	OsintShodanKey     string
	OsintAbuseIPDBKey  string
	OsintHIBPKey       string
	OsintNumVerifyKey  string
}

// Load reads configuration from environment variables, applying defaults where appropriate.
func Load() *Config {
	return &Config{
		ServerPort:    getEnv("SERVER_PORT", "8080"),
		PostgresDSN:   getEnv("POSTGRES_DSN", "host=localhost user=forensichub password=forensichub dbname=forensichub port=5432 sslmode=disable TimeZone=UTC"),
		RedisAddr:     getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),
		JWTSecret:     getEnv("JWT_SECRET", "change-me-in-production-use-a-long-random-string"),
		StoragePath:   getEnv("STORAGE_PATH", "/app/storage"),
		AdminEmail:    getEnv("ADMIN_EMAIL", "admin@forensichub.local"),
		AdminPassword: getEnv("ADMIN_PASSWORD", "ChangeMe!2024"),
		AppEnv:        getEnv("APP_ENV", "development"),
		PublicURL:      getEnv("PUBLIC_URL", ""),
		UseHTTPS:       getEnv("USE_HTTPS", "false") == "true",
		AllowedOrigins: parseOrigins(getEnv("ALLOWED_ORIGINS", "")),
		NVDAPIKey:       getEnv("NVD_API_KEY", ""),
		APINvdURL:         getEnv("API_NVD_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
		APIWpscanURL:      getEnv("API_WPSCAN_URL", "https://wpscan.com/api/v3"),
		APINumVerifyURL:   getEnv("API_NUMVERIFY_URL", "http://apilayer.net/api/validate"),
		APIIpApiURL:       getEnv("API_IP_API_URL", "http://ip-api.com/json/"),
		APIWebArchiveURL:  getEnv("API_WEB_ARCHIVE_URL", "http://web.archive.org/cdx/search/cdx"),
		APICrtShURL:       getEnv("API_CRTSH_URL", "https://crt.sh/"),
		APICertSpotterURL: getEnv("API_CERTSPOTTER_URL", "https://api.certspotter.com/v1/issuances"),
		GitHubToken:     getEnv("GITHUB_TOKEN", ""),
		WPScanAPITokens: loadWPScanTokens(),
		AESEncryptionKey: getEnv("AES_ENCRYPTION_KEY", "default-insecure-key-exct-32-byt"),
		// VirusTotal & Shodan reuse the keys already configured for the recon
		// module (SUBFINDER_*) when no dedicated OSINT_* key is set, so the
		// OSINT collectors work without duplicating credentials.
		OsintVirusTotalKey: pickKey(getEnv("OSINT_VIRUSTOTAL_API_KEY", ""), getEnv("SUBFINDER_VIRUSTOTAL", "")),
		OsintShodanKey:     pickKey(getEnv("OSINT_SHODAN_API_KEY", ""), getEnv("SUBFINDER_SHODAN", "")),
		OsintAbuseIPDBKey:  getEnv("OSINT_ABUSEIPDB_API_KEY", ""),
		OsintHIBPKey:       getEnv("OSINT_HIBP_API_KEY", ""),
		OsintNumVerifyKey:  getEnv("OSINT_NUMVERIFY_API_KEY", ""),
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

// loadWPScanTokens returns the configured WPScan tokens in priority order.
// Sources, merged in order with duplicates dropped:
//  1. WPSCAN_API_TOKEN — single token, or comma-separated list ("a,b,c").
//  2. WPSCAN_API_TOKEN_2 … WPSCAN_API_TOKEN_9 — numbered fallbacks for
//     ops who prefer one-var-per-token in compose files.
func loadWPScanTokens() []string {
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
	add(os.Getenv("WPSCAN_API_TOKEN"))
	for i := 2; i <= 9; i++ {
		add(os.Getenv(fmt.Sprintf("WPSCAN_API_TOKEN_%d", i)))
	}
	return out
}

// pickKey returns primary when set, otherwise the first non-empty entry of
// fallback (which may be a comma-separated list, as subfinder accepts).
func pickKey(primary, fallback string) string {
	if s := strings.TrimSpace(primary); s != "" {
		return s
	}
	for _, p := range strings.Split(fallback, ",") {
		if s := strings.TrimSpace(p); s != "" {
			return s
		}
	}
	return ""
}

// getEnv returns the value of the environment variable named by key,
// or fallback if the variable is not set or empty.
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

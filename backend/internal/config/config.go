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

	// LogPath is the directory where date-stamped log files are written.
	// Defaults to "data/logs" (relative to CWD) for local dev.
	// In Docker set LOG_PATH=/app/data/logs via the compose environment block.
	LogPath string
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
		NVDAPIKey:        getEnv("NVD_API_KEY", ""),
		APINvdURL:        getEnv("API_NVD_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
		GitHubToken:      getEnv("GITHUB_TOKEN", ""),
		AESEncryptionKey: getEnv("AES_ENCRYPTION_KEY", "default-insecure-key-exct-32-byt"),

		VirusTotalKeys: loadVirusTotalKeys(),
		AbuseIPDBKey:   getEnv("ABUSEIPDB", ""),
		AlienVaultKey:  getEnv("ALIENVAULT", ""),
		ShodanKey:      getEnv("SHODAN", ""),

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

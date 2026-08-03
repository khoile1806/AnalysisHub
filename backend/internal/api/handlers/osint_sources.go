package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/analysishub/backend/internal/config"
)

// osintSource describes one OSINT intelligence source and whether its (optional)
// API key is configured — so analysts can tell "no data" from "not configured".
type osintSource struct {
	Name       string `json:"name"`
	Category   string `json:"category"` // reputation | breach | infra | vuln | search
	EnvVar     string `json:"env_var"`
	Configured bool   `json:"configured"`
	Note       string `json:"note"`
}

// OsintSources reports the configuration status of every optional OSINT API-keyed
// source (presence flags only — never the key values). Powers the "Sources &
// Keys" health panel so silently-skipped collectors are visible.
//
// GET /api/v1/osint/sources
func OsintSources(c *gin.Context) {
	var cfg *config.Config
	if v, ok := c.Get("config"); ok {
		cfg, _ = v.(*config.Config)
	}
	if cfg == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "config unavailable"})
		return
	}

	sources := []osintSource{
		{"NVD (CVE lookups)", "vuln", "NVD_API_KEY", cfg.NVDAPIKey != "", "Raises the NVD rate limit 5→50 req/30s — CVE search is slow/throttled without it"},
		{"GitHub (PoC/exploit search)", "vuln", "GITHUB_TOKEN", cfg.GitHubToken != "", "Raises GitHub search rate limit for public PoC discovery"},
		{"VirusTotal", "reputation", "VIRUSTOTAL_1..4", len(cfg.VirusTotalKeys) > 0, "IP/domain/file reputation — collectors skip without a key"},
		{"Shodan", "infra", "SHODAN", cfg.ShodanKey != "", "Full Shodan host data (InternetDB free tier still works keyless)"},
		{"AbuseIPDB", "reputation", "ABUSEIPDB", cfg.AbuseIPDBKey != "", "IP abuse confidence score"},
		{"AlienVault OTX", "reputation", "ALIENVAULT", cfg.AlienVaultKey != "", "Open Threat Exchange pulses"},
		{"Have I Been Pwned", "breach", "HIBP_API_KEY", cfg.OsintHIBPKey != "", "Email breach exposure"},
		{"NumVerify", "search", "OSINT_NUMVERIFY_API_KEY", cfg.OsintNumVerifyKey != "", "Phone-number metadata / carrier"},
		{"abuse.ch (ThreatFox/URLhaus/MalwareBazaar)", "reputation", "ABUSE_CH_API_KEY", cfg.AbuseChKey != "", "Malware/C2 IOC feeds — Auth-Key increases limits"},
		{"Pulsedive", "reputation", "PULSEDIVE_API_KEY", cfg.PulsediveKey != "", "Indicator risk enrichment"},
		{"GreyNoise", "reputation", "GREYNOISE_API_KEY", cfg.GreyNoiseKey != "", "Internet background-noise / scanner classification"},
		{"Dehashed", "breach", "DEHASHED_API_KEY", cfg.OsintDehashedKey != "", "Leaked-credential search — returns matching breach records (email/username)"},
		{"OpenCorporates", "search", "OSINT_OPENCORPORATES_API_KEY", cfg.OsintOpenCorpKey != "", "Person name → corporate-officer / director records across jurisdictions"},
	}

	configured := 0
	for _, s := range sources {
		if s.Configured {
			configured++
		}
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"sources":          sources,
		"configured_count": configured,
		"total":            len(sources),
	}})
}

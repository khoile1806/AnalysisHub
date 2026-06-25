package osint

import (
	"net/url"
	"strings"
)

// This file centralises the canonical "verify it here" viewer URLs for the
// third-party sources the collectors query, so every finding can link back to
// the page where an analyst can independently confirm it.

// vtGUIURL returns the VirusTotal GUI page for a target of the given type.
func vtGUIURL(target, ttype string) string {
	switch ttype {
	case TargetDomain:
		return "https://www.virustotal.com/gui/domain/" + url.PathEscape(target)
	case TargetIP:
		return "https://www.virustotal.com/gui/ip-address/" + url.PathEscape(target)
	case TargetHash:
		return "https://www.virustotal.com/gui/file/" + url.PathEscape(target)
	}
	return ""
}

// shodanHostURL returns the Shodan host page for an IP.
func shodanHostURL(ip string) string {
	return "https://www.shodan.io/host/" + url.PathEscape(ip)
}

// abuseIPDBURL returns the AbuseIPDB check page for an IP.
func abuseIPDBURL(ip string) string {
	return "https://www.abuseipdb.com/check/" + url.PathEscape(ip)
}

// greynoiseURL returns the GreyNoise visualizer page for an IP.
func greynoiseURL(ip string) string {
	return "https://viz.greynoise.io/ip/" + url.PathEscape(ip)
}

// pulsediveURL returns the Pulsedive indicator page for a target.
func pulsediveURL(target string) string {
	return "https://pulsedive.com/indicator/?ioc=" + url.QueryEscape(target)
}

// threatfoxURL returns the ThreatFox browse/search page for an IOC.
func threatfoxURL(target string) string {
	return "https://threatfox.abuse.ch/browse.php?search=ioc%3A" + url.QueryEscape(target)
}

// urlhausHostURL returns the URLhaus host page for a domain/IP.
func urlhausHostURL(host string) string {
	return "https://urlhaus.abuse.ch/host/" + url.PathEscape(host) + "/"
}

// malwareBazaarURL returns the MalwareBazaar browse page for a hash.
func malwareBazaarURL(hash string) string {
	return "https://bazaar.abuse.ch/browse.php?search=" + url.QueryEscape(hash)
}

// crtShURL returns the crt.sh search page for a domain's certificates.
func crtShURL(domain string) string {
	return "https://crt.sh/?q=%25." + url.QueryEscape(domain)
}

// ipAPIViewerURL returns the ip-api.com map/detail page for an IP.
func ipAPIViewerURL(ip string) string {
	return "https://ip-api.com/#" + url.PathEscape(ip)
}

// reputationSourceURL maps an enrichment sub-source name to its verifier page
// for the target, so each consensus row links to the provider that produced it.
func reputationSourceURL(source, target, ttype string) string {
	switch strings.ToLower(source) {
	case "virustotal", "vt":
		return vtGUIURL(target, ttype)
	case "abuseipdb":
		return abuseIPDBURL(target)
	case "shodan":
		return shodanHostURL(target)
	case "greynoise":
		return greynoiseURL(target)
	case "pulsedive":
		return pulsediveURL(target)
	case "alienvault", "otx", "alienvault otx":
		return "https://otx.alienvault.com/indicator/" + otxKind(ttype) + "/" + url.PathEscape(target)
	}
	// Fall back to the VirusTotal page, which covers every indicator type.
	return vtGUIURL(target, ttype)
}

// otxKind maps a target type to AlienVault OTX's indicator path segment.
func otxKind(ttype string) string {
	switch ttype {
	case TargetIP:
		return "ip"
	case TargetDomain:
		return "domain"
	case TargetHash:
		return "file"
	}
	return "domain"
}

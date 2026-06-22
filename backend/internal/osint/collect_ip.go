package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/forensichub/backend/internal/models"
)

// -- Reverse DNS ---------------------------------------------------------------

// collectReverseDNS resolves the PTR records of an IP address.
func collectReverseDNS(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	r := &net.Resolver{}
	names, err := r.LookupAddr(ctx, env.target)
	if err != nil {
		// "no such host" just means no PTR - not a real error.
		env.emit("[*] reverse_dns: no PTR record")
		return nil, nil
	}
	var out []models.OsintFinding
	for _, n := range names {
		h := strings.TrimRight(strings.ToLower(n), ".")
		if h == "" {
			continue
		}
		f := newFinding("reverse_dns", "dns", "PTR record", h)
		out = append(out, withRelated(f, RelatedEntity{Type: TargetDomain, Value: h}))
	}
	return out, nil
}

// -- RDAP (IP network) ---------------------------------------------------------

// collectIPRDAP retrieves the network registration (netblock, owner, country)
// of an IP via RDAP.
func collectIPRDAP(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	u := "https://rdap.org/ip/" + url.PathEscape(env.target)
	r, status, err := fetchRDAP(ctx, u)
	if err != nil {
		return nil, err
	}
	if status == 404 {
		env.emit("[*] rdap: no network record found")
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("rdap.org returned HTTP %d", status)
	}

	var out []models.OsintFinding
	if r.StartAddress != "" || r.EndAddress != "" {
		out = append(out, newFinding("rdap", "network", "Network range",
			joinNonEmpty(" - ", r.StartAddress, r.EndAddress)))
	}
	if r.Name != "" {
		out = append(out, newFinding("rdap", "network", "Network name", r.Name))
	}
	if r.Type != "" {
		out = append(out, newFinding("rdap", "network", "Allocation type", r.Type))
	}
	if r.Country != "" {
		out = append(out, newFinding("rdap", "network", "Registered country", r.Country))
	}
	walkEntities(r.Entities, func(roles []string, name, email, org string) {
		label := joinNonEmpty(" - ", org, name)
		if label == "" {
			return
		}
		role := "contact"
		if len(roles) > 0 {
			role = strings.Join(roles, "/")
		}
		out = append(out, newFinding("rdap", "network",
			fmt.Sprintf("Network %s", role), label))
	})
	return out, nil
}

// -- GeoIP (ip-api.com, free) --------------------------------------------------

type ipAPIResponse struct {
	Status     string  `json:"status"`
	Message    string  `json:"message"`
	Country    string  `json:"country"`
	RegionName string  `json:"regionName"`
	City       string  `json:"city"`
	Lat        float64 `json:"lat"`
	Lon        float64 `json:"lon"`
	Timezone   string  `json:"timezone"`
	ISP        string  `json:"isp"`
	Org        string  `json:"org"`
	AS         string  `json:"as"`
}

// collectGeoIP resolves geolocation and network ownership via ip-api.com.
func collectGeoIP(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	u := env.cfg.APIIpApiURL + url.PathEscape(env.target) +
		"?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
	var r ipAPIResponse
	status, err := httpGetJSON(ctx, rlIPAPI, u, nil, &r)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("ip-api.com returned HTTP %d", status)
	}
	if r.Status != "success" {
		msg := r.Message
		if msg == "" {
			msg = "lookup failed"
		}
		env.emit("[*] geoip: " + msg)
		return nil, nil
	}

	var out []models.OsintFinding
	loc := joinNonEmpty(", ", r.City, r.RegionName, r.Country)
	if loc != "" {
		f := newFinding("geoip", "geolocation", "Location", loc)
		f.Data = toJSON(map[string]float64{"lat": r.Lat, "lon": r.Lon})
		out = append(out, f)
	}
	if r.Timezone != "" {
		out = append(out, newFinding("geoip", "geolocation", "Timezone", r.Timezone))
	}
	if r.ISP != "" {
		out = append(out, newFinding("geoip", "network", "ISP", r.ISP))
	}
	if r.Org != "" && !strings.EqualFold(r.Org, r.ISP) {
		out = append(out, newFinding("geoip", "network", "Organization", r.Org))
	}
	if r.AS != "" {
		out = append(out, newFinding("geoip", "network", "Autonomous System", r.AS))
	}
	return out, nil
}

// -- Shodan InternetDB (free, no key) ------------------------------------------

type internetDBResponse struct {
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	CPEs      []string `json:"cpes"`
	Hostnames []string `json:"hostnames"`
	Tags      []string `json:"tags"`
	Vulns     []string `json:"vulns"`
}

// collectShodanInternetDB queries Shodan's free InternetDB for open ports,
// detected software (CPEs), hostnames and known CVEs of an IP.
func collectShodanInternetDB(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	u := "https://internetdb.shodan.io/" + url.PathEscape(env.target)
	var r internetDBResponse
	status, err := httpGetJSON(ctx, nil, u, nil, &r)
	if err != nil {
		return nil, err
	}
	if status == 404 {
		env.emit("[*] shodan_internetdb: no data for this IP")
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("InternetDB returned HTTP %d", status)
	}

	var out []models.OsintFinding
	if len(r.Ports) > 0 {
		sort.Ints(r.Ports)
		ports := make([]string, len(r.Ports))
		for i, p := range r.Ports {
			ports[i] = strconv.Itoa(p)
		}
		out = append(out, newFinding("shodan_internetdb", "ports", "Open ports",
			strings.Join(ports, ", ")))
	}
	for _, h := range r.Hostnames {
		h = strings.TrimRight(strings.ToLower(h), ".")
		if h == "" {
			continue
		}
		f := newFinding("shodan_internetdb", "dns", "Hostname", h)
		out = append(out, withRelated(f, RelatedEntity{Type: TargetDomain, Value: h}))
	}
	for _, cpe := range r.CPEs {
		if cpe != "" {
			out = append(out, newFinding("shodan_internetdb", "ports", "Detected software (CPE)", cpe))
		}
	}
	if len(r.Tags) > 0 {
		out = append(out, newFinding("shodan_internetdb", "ports", "Shodan tags",
			strings.Join(r.Tags, ", ")))
	}
	for _, v := range r.Vulns {
		if v == "" {
			continue
		}
		f := newFinding("shodan_internetdb", "reputation", "Known vulnerability", v)
		f.Severity = "high"
		out = append(out, f)
	}
	return out, nil
}

// -- Shodan host API (optional key) --------------------------------------------

type shodanHostResponse struct {
	Ports       []int           `json:"ports"`
	Hostnames   []string        `json:"hostnames"`
	Org         string          `json:"org"`
	ISP         string          `json:"isp"`
	OS          string          `json:"os"`
	CountryName string          `json:"country_name"`
	Vulns       json.RawMessage `json:"vulns"`
}

// collectShodan queries the full Shodan host API. Needs OSINT_SHODAN_API_KEY.
func collectShodan(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	if env.keys.Shodan == "" {
		return nil, errNoAPIKey
	}
	u := "https://api.shodan.io/shodan/host/" + url.PathEscape(env.target) +
		"?key=" + url.QueryEscape(env.keys.Shodan)
	var r shodanHostResponse
	status, err := httpGetJSON(ctx, nil, u, nil, &r)
	if err != nil {
		return nil, err
	}
	if status == 401 {
		return nil, fmt.Errorf("Shodan rejected the API key (HTTP 401)")
	}
	if status == 403 {
		// The shared key is a free-tier key; the host API needs a paid
		// membership. Not a failure - InternetDB already covers the basics.
		env.emit("[*] shodan: host API needs a paid membership - Shodan InternetDB used instead")
		return nil, nil
	}
	if status == 404 {
		env.emit("[*] shodan: no host record")
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("Shodan returned HTTP %d", status)
	}

	var out []models.OsintFinding
	if len(r.Ports) > 0 {
		sort.Ints(r.Ports)
		ports := make([]string, len(r.Ports))
		for i, p := range r.Ports {
			ports[i] = strconv.Itoa(p)
		}
		out = append(out, newFinding("shodan", "ports", "Open ports (Shodan)",
			strings.Join(ports, ", ")))
	}
	if r.Org != "" {
		out = append(out, newFinding("shodan", "network", "Organization (Shodan)", r.Org))
	}
	if r.OS != "" {
		out = append(out, newFinding("shodan", "ports", "Operating system", r.OS))
	}
	for _, h := range r.Hostnames {
		h = strings.TrimRight(strings.ToLower(h), ".")
		if h == "" {
			continue
		}
		f := newFinding("shodan", "dns", "Hostname (Shodan)", h)
		out = append(out, withRelated(f, RelatedEntity{Type: TargetDomain, Value: h}))
	}
	for _, v := range parseShodanVulns(r.Vulns) {
		f := newFinding("shodan", "reputation", "Known vulnerability (Shodan)", v)
		f.Severity = "high"
		out = append(out, f)
	}
	return out, nil
}

// parseShodanVulns copes with Shodan returning "vulns" either as a string
// array or as an object keyed by CVE id.
func parseShodanVulns(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var arr []string
	if json.Unmarshal(raw, &arr) == nil {
		return arr
	}
	var obj map[string]interface{}
	if json.Unmarshal(raw, &obj) == nil {
		out := make([]string, 0, len(obj))
		for k := range obj {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	return nil
}

// -- VirusTotal IP reputation (optional key) -----------------------------------

// collectIPVirusTotal queries VirusTotal for an IP address's reputation. Reuses
// the same key as the domain collector (OSINT_VIRUSTOTAL_API_KEY, falling back
// to SUBFINDER_VIRUSTOTAL).
func collectIPVirusTotal(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	if env.keys.VirusTotal == "" {
		return nil, errNoAPIKey
	}
	u := "https://www.virustotal.com/api/v3/ip_addresses/" + url.PathEscape(env.target)
	var r vtDomainResponse // same {attributes:{last_analysis_stats,reputation}} shape
	status, err := httpGetJSON(ctx, rlVT, u, map[string]string{"x-apikey": env.keys.VirusTotal}, &r)
	if err != nil {
		return nil, err
	}
	if status == 401 {
		return nil, fmt.Errorf("VirusTotal rejected the API key (HTTP 401)")
	}
	if status == 404 {
		env.emit("[*] virustotal: IP not present in VT dataset")
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("VirusTotal returned HTTP %d", status)
	}

	st := r.Data.Attributes.LastAnalysisStats
	f := newFinding("virustotal", "reputation", "VirusTotal verdict",
		fmt.Sprintf("malicious %d - suspicious %d - harmless %d - reputation %d",
			st.Malicious, st.Suspicious, st.Harmless, r.Data.Attributes.Reputation))
	switch {
	case st.Malicious > 0:
		f.Severity = "high"
	case st.Suspicious > 0:
		f.Severity = "medium"
	}
	return []models.OsintFinding{f}, nil
}

// -- AbuseIPDB (optional key) --------------------------------------------------

type abuseIPDBResponse struct {
	Data struct {
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		TotalReports         int    `json:"totalReports"`
		CountryCode          string `json:"countryCode"`
		UsageType            string `json:"usageType"`
		ISP                  string `json:"isp"`
		Domain               string `json:"domain"`
		LastReportedAt       string `json:"lastReportedAt"`
	} `json:"data"`
}

// collectAbuseIPDB checks an IP's abuse reputation. Needs OSINT_ABUSEIPDB_API_KEY.
func collectAbuseIPDB(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	if env.keys.AbuseIPDB == "" {
		return nil, errNoAPIKey
	}
	u := "https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress=" +
		url.QueryEscape(env.target)
	var r abuseIPDBResponse
	status, err := httpGetJSON(ctx, nil, u, map[string]string{
		"Key":    env.keys.AbuseIPDB,
		"Accept": "application/json",
	}, &r)
	if err != nil {
		return nil, err
	}
	if status == 401 {
		return nil, fmt.Errorf("AbuseIPDB rejected the API key (HTTP 401)")
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("AbuseIPDB returned HTTP %d", status)
	}

	d := r.Data
	f := newFinding("abuseipdb", "reputation", "Abuse confidence score",
		fmt.Sprintf("%d%% - %d report(s) in the last 90 days", d.AbuseConfidenceScore, d.TotalReports))
	switch {
	case d.AbuseConfidenceScore >= 75:
		f.Severity = "high"
	case d.AbuseConfidenceScore >= 25:
		f.Severity = "medium"
	case d.AbuseConfidenceScore > 0:
		f.Severity = "low"
	}
	out := []models.OsintFinding{f}
	if d.UsageType != "" {
		out = append(out, newFinding("abuseipdb", "network", "Usage type", d.UsageType))
	}
	if d.Domain != "" {
		df := newFinding("abuseipdb", "network", "Associated domain", d.Domain)
		out = append(out, withRelated(df, RelatedEntity{Type: TargetDomain, Value: d.Domain}))
	}
	return out, nil
}

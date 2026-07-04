package egress

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Identity is the public "face" an outbound connection presents to the world when
// routed through a given proxy: the exit IP, its geo/ASN, and whether it is a Tor
// exit. The Proxy Manager surfaces this so the operator knows what identity their
// OSINT/recon traffic actually exposes.
type Identity struct {
	IP        string    `json:"ip"`
	Country   string    `json:"country"`
	Org       string    `json:"org"`
	IsTor     bool      `json:"is_tor"`
	CheckedAt time.Time `json:"checked_at"`
	Err       string    `json:"error,omitempty"`
}

// ProbeIdentity discovers the exit identity by making lookups THROUGH the given
// proxy (never the live egress client, so it works before switching). It queries
// an IP/geo echo service and the Tor Project's check endpoint.
func ProbeIdentity(proxyURL string) Identity {
	out := Identity{CheckedAt: time.Now()}
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL == "" {
		out.Err = "empty proxy URL"
		return out
	}
	pu, err := url.Parse(proxyURL)
	if err != nil {
		out.Err = "invalid proxy URL"
		return out
	}
	client := &http.Client{
		Timeout:   12 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(pu)},
	}

	// Exit IP + geo/ASN.
	var geo struct {
		Status  string `json:"status"`
		Query   string `json:"query"`
		Country string `json:"country"`
		As      string `json:"as"`
		Org     string `json:"org"`
	}
	if e := getJSONThrough(client, "http://ip-api.com/json/?fields=status,query,country,as,org", &geo); e != nil {
		out.Err = e.Error()
	} else if geo.Status == "success" {
		out.IP = geo.Query
		out.Country = geo.Country
		out.Org = firstNonEmpty(geo.As, geo.Org)
	}

	// Tor exit detection (best-effort; never overrides a geo error).
	var tor struct {
		IsTor bool   `json:"IsTor"`
		IP    string `json:"IP"`
	}
	if e := getJSONThrough(client, "https://check.torproject.org/api/ip", &tor); e == nil {
		out.IsTor = tor.IsTor
		if out.IP == "" {
			out.IP = tor.IP
		}
	}
	return out
}

// LeakTestResult is the outcome of an exit-consistency self-test: the exit IP
// each independent echo service reports through the proxy. When they all agree,
// the proxy presents one stable identity; a disagreement (or a failure to reach
// some services) can indicate split routing or a partially-applied proxy.
type LeakTestResult struct {
	ExitIPs    map[string]string `json:"exit_ips"`
	ExitIP     string            `json:"exit_ip"`
	Consistent bool              `json:"consistent"`
	CheckedAt  time.Time         `json:"checked_at"`
	Err        string            `json:"error,omitempty"`
}

// LeakTest asks several independent echo services, THROUGH the proxy, what exit
// IP they see. Agreement across services is evidence the proxy is applied
// consistently to egress; disagreement is a red flag worth investigating.
func LeakTest(proxyURL string) LeakTestResult {
	out := LeakTestResult{ExitIPs: map[string]string{}, CheckedAt: time.Now()}
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL == "" {
		out.Err = "empty proxy URL"
		return out
	}
	pu, err := url.Parse(proxyURL)
	if err != nil {
		out.Err = "invalid proxy URL"
		return out
	}
	client := &http.Client{
		Timeout:   12 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(pu)},
	}

	// api.ipify.org (JSON).
	var ipify struct {
		IP string `json:"ip"`
	}
	if e := getJSONThrough(client, "https://api.ipify.org/?format=json", &ipify); e == nil && ipify.IP != "" {
		out.ExitIPs["ipify"] = ipify.IP
	}
	// ip-api.com (JSON).
	var ipapi struct {
		Query string `json:"query"`
	}
	if e := getJSONThrough(client, "http://ip-api.com/json/?fields=query", &ipapi); e == nil && ipapi.Query != "" {
		out.ExitIPs["ip-api"] = ipapi.Query
	}
	// icanhazip.com (plain text).
	if ip := getTextThrough(client, "https://icanhazip.com/"); ip != "" {
		out.ExitIPs["icanhazip"] = ip
	}

	if len(out.ExitIPs) == 0 {
		out.Err = "no echo service reachable through the proxy"
		return out
	}
	first := ""
	out.Consistent = true
	for _, ip := range out.ExitIPs {
		if first == "" {
			first = ip
			out.ExitIP = ip
		} else if ip != first {
			out.Consistent = false
		}
	}
	return out
}

func getTextThrough(client *http.Client, u string) string {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "AnalysisHub-ProxyLeakTest/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
	return strings.TrimSpace(string(b))
}

func getJSONThrough(client *http.Client, u string, dst interface{}) error {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "AnalysisHub-ProxyIdentity/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(dst)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

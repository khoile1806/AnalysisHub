package osint

// keyGatedCollector reports, for a collector that skips entirely without an API
// key, whether that key is currently configured. Collectors not listed here run
// unauthenticated (or need no key) and are always available.
func (k Keys) keyGatedCollector(name string) (gated, available bool) {
	switch name {
	case "virustotal":
		return true, k.VirusTotal != ""
	case "shodan":
		return true, k.Shodan != ""
	case "abuseipdb":
		return true, k.AbuseIPDB != ""
	case "hibp":
		return true, k.HIBP != ""
	case "numverify":
		return true, k.NumVerify != ""
	case "pulsedive":
		return true, k.Pulsedive != ""
	case "opencorporates":
		return true, k.OpenCorp != ""
	}
	return false, true
}

// UnavailableCollectors returns the subset of names that will be skipped because
// the optional API key they require is not configured. The UI uses it to grey
// out key-gated collectors before a scan is launched.
func (e *Engine) UnavailableCollectors(names []string) []string {
	out := make([]string, 0)
	for _, n := range names {
		if gated, available := e.keys.keyGatedCollector(n); gated && !available {
			out = append(out, n)
		}
	}
	return out
}

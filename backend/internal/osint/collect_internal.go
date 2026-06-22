package osint

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/forensichub/backend/internal/models"
)

// localIOCTypes maps an OSINT target type to the matching IOC-store Type values
// (the STIX-ish type names ForensicHub's OpenCTI sync and manual-IOC entry use).
func localIOCTypes(ttype string) []string {
	switch ttype {
	case TargetIP:
		return []string{"IPv4-Addr", "IPv6-Addr"}
	case TargetDomain:
		return []string{"Domain-Name", "Hostname"}
	case TargetEmail:
		return []string{"Email-Addr"}
	case TargetHash:
		return []string{"File-Hash", "StixFile", "File"}
	case TargetWallet:
		return []string{"Cryptocurrency-Wallet", "BTC-Addr", "ETH-Addr", "WalletAddress"}
	}
	return nil
}

// collectLocalThreatIntel cross-checks the target against ForensicHub's own IOC
// store (OpenCTI sync + manually added IOCs). This is the defensive value-add the
// offensive OSINT lacked: "do we already know this indicator?". A match is a
// strong signal during incident response - the indicator is already on a
// watchlist or was seen in prior intel.
func collectLocalThreatIntel(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	if env.db == nil {
		return nil, nil
	}
	types := localIOCTypes(env.ttype)
	if len(types) == 0 {
		return nil, nil
	}

	q := env.db.WithContext(ctx).Where("type IN ?", types)
	if env.ttype == TargetHash {
		q = q.Where("LOWER(value) = ?", strings.ToLower(env.target))
	} else {
		q = q.Where("value = ?", env.target)
	}
	var iocs []models.IOC
	if err := q.Find(&iocs).Error; err != nil {
		return nil, err
	}

	if len(iocs) == 0 {
		f := newFinding("local_intel", "reputation",
			"Not in local threat-intel store",
			"No matching IOC in ForensicHub's OpenCTI / IOC store")
		f.Severity = "info"
		return []models.OsintFinding{f}, nil
	}

	out := make([]models.OsintFinding, 0, len(iocs))
	for _, ioc := range iocs {
		src := ioc.Source
		if src == "" {
			src = "local"
		}
		detail := ioc.Description
		if detail == "" {
			detail = fmt.Sprintf("Type %s - added %s", ioc.Type, ioc.CreatedAt.Format("2006-01-02"))
		}
		f := newFinding("local_intel", "reputation",
			fmt.Sprintf("[!] KNOWN IOC - present in local threat-intel store (%s)", src),
			detail)
		f.Severity = "high"
		out = append(out, f)
	}
	return out, nil
}

// collectHashVirusTotal looks up a file hash's reputation on VirusTotal. Reuses
// the VirusTotal key already configured for threat-intel enrichment.
func collectHashVirusTotal(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	if env.keys.VirusTotal == "" {
		return nil, errNoAPIKey
	}
	u := "https://www.virustotal.com/api/v3/files/" + url.PathEscape(env.target)
	var r vtDomainResponse // same {attributes:{last_analysis_stats,reputation}} shape
	status, err := httpGetJSON(ctx, rlVT, u, map[string]string{"x-apikey": env.keys.VirusTotal}, &r)
	if err != nil {
		return nil, err
	}
	if status == 401 {
		return nil, fmt.Errorf("VirusTotal rejected the API key (HTTP 401)")
	}
	if status == 404 {
		env.emit("[*] virustotal: hash not present in VT dataset")
		f := newFinding("virustotal", "reputation", "VirusTotal: unknown file",
			"Hash not found in VirusTotal - no analysis data")
		f.Severity = "info"
		return []models.OsintFinding{f}, nil
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
		f.Severity = "critical"
	case st.Suspicious > 0:
		f.Severity = "medium"
	}
	return []models.OsintFinding{f}, nil
}

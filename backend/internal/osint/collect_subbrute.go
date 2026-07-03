package osint

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/analysishub/backend/internal/models"
)

// subBruteCap limits how many live brute-forced subdomains are recorded.
const subBruteCap = 150

// subdomainWordlist is a curated list of the most common subdomain labels. It
// deliberately favours high-hit-rate names (infrastructure, dev/stage, mail,
// admin panels, common services) over an exhaustive list, so the active probe
// stays fast while still finding hosts that never appeared in a TLS certificate.
var subdomainWordlist = []string{
	"www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "ns3", "ns4",
	"smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal", "ns",
	"ww1", "host", "support", "dev", "web", "bbs", "mx", "mx1", "mx2", "email",
	"cloud", "1", "mail1", "2", "forum", "owa", "www2", "gw", "admin", "store",
	"mobile", "mx3", "mssql", "dns", "dns1", "dns2", "exchange", "old", "lists",
	"app", "en", "img", "news", "api", "media", "images", "www1", "intranet",
	"docs", "git", "gitlab", "jenkins", "jira", "confluence", "staging", "stage",
	"beta", "demo", "sandbox", "uat", "qa", "prod", "production", "internal",
	"corp", "vpn2", "ssh", "rdp", "ts", "citrix", "autodiscover", "lync", "sip",
	"voip", "static", "assets", "cdn", "files", "file", "upload", "uploads",
	"download", "downloads", "video", "videos", "photo", "photos", "pics",
	"wiki", "help", "status", "dashboard", "panel", "cpanel", "whm", "plesk",
	"login", "sso", "auth", "oauth", "idp", "adfs", "ldap", "ad", "db", "sql",
	"mysql", "redis", "mongo", "postgres", "elastic", "kibana", "grafana",
	"prometheus", "nagios", "zabbix", "monitor", "monitoring", "metrics",
	"proxy", "gateway", "fw", "firewall", "router", "switch", "backup", "bak",
	"new", "v1", "v2", "api2", "apiv1", "apiv2", "rest", "graphql", "ws", "chat",
	"crm", "erp", "hr", "finance", "billing", "pay", "payment", "payments",
	"checkout", "cart", "my", "account", "accounts", "user", "users", "member",
	"members", "client", "clients", "partner", "partners", "vendor", "careers",
	"jobs", "community", "events", "training", "learn", "edu", "research",
	"labs", "lab", "ci", "cd", "registry", "docker", "k8s", "kube", "kubernetes",
	"vault", "consul", "nomad", "rancher", "argocd", "harbor", "nexus", "artifactory",
	"sentry", "splunk", "elk", "logstash", "syslog", "smtp2", "relay", "edge",
	"origin", "lb", "ssl", "ns5", "vps", "node", "node1", "node2", "host1", "host2",
	"web3", "app1", "app2", "service", "services", "micro", "gw1", "gw2",
	"office", "share", "sharepoint", "teams", "meet", "zoom", "calendar",
	"mailgw", "spam", "antispam", "mta", "imap", "pop", "pop3", "ns0",
}

// collectSubBrute actively brute-forces common subdomain labels against the
// target via DNS. It complements passive Certificate-Transparency enumeration:
// CT only shows hosts that ever had a TLS certificate, while this finds live
// hosts (internal tools, dev/stage, mail infrastructure) that never did. Only
// names that actually resolve to a public IP are reported; each becomes a
// subdomain + IP pivot.
func collectSubBrute(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	target := strings.ToLower(strings.TrimSpace(env.target))
	if target == "" {
		return nil, nil
	}

	candidates := make([]string, 0, len(subdomainWordlist))
	for _, label := range subdomainWordlist {
		candidates = append(candidates, label+"."+target)
	}

	live := resolveHosts(ctx, candidates)
	if len(live) == 0 {
		env.emit("[*] subbrute: no additional subdomains resolved from the wordlist")
		return nil, nil
	}

	hosts := make([]string, 0, len(live))
	for h := range live {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	if len(hosts) > subBruteCap {
		hosts = hosts[:subBruteCap]
	}

	out := make([]models.OsintFinding, 0, len(hosts)+1)
	out = append(out, newFinding("subbrute", "certificate", "Brute-forced live subdomains",
		fmt.Sprintf("%d common subdomain(s) resolve live (not necessarily in CT logs)", len(live))))
	for _, h := range hosts {
		ips := live[h]
		rels := []RelatedEntity{{Type: TargetDomain, Value: h}}
		for _, ip := range ips {
			rels = append(rels, RelatedEntity{Type: TargetIP, Value: ip})
		}
		f := newFinding("subbrute", "certificate", "Subdomain (brute-forced)",
			h+" -> "+strings.Join(ips, ", "))
		out = append(out, withRelated(f, rels...))
	}
	env.emit(fmt.Sprintf("[+] subbrute: %d live subdomain(s) found via wordlist", len(live)))
	return out, nil
}

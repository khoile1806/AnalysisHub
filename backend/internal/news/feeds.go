// Package news holds the source-of-truth list of RSS/Atom feeds the news
// aggregator polls, plus category metadata used by the frontend tab UI.
//
// The lists are intentionally hardcoded: changes are reviewed in PRs alongside
// the rest of the codebase, and there is no need for runtime configuration.
package news

// Category groups feeds into the user-facing tab buckets shown in the
// CVE Collection page (one tab per category).
//
// Icon is a lucide-react icon name the frontend can resolve dynamically.
type Category struct {
	Slug  string `json:"slug"`
	Label string `json:"label"`
	Icon  string `json:"icon"`
}

// Feed is one RSS/Atom endpoint.
//
// Language is optional and only used by categories that show a language
// filter (currently only "world-news"). Values: "vi", "en". Empty means
// language is not tracked for this feed's category.
type Feed struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Category string `json:"category"` // must match a Category.Slug
	Language string `json:"language,omitempty"`
}

// Categories is the ordered list of news tabs.
var Categories = []Category{
	{Slug: "general", Label: "General Cybersecurity News", Icon: "Newspaper"},
	{Slug: "threat-intel", Label: "Threat Intelligence & Research", Icon: "Shield"},
	{Slug: "gov-alerts", Label: "Government / Official Alerts", Icon: "Building"},
	{Slug: "darkweb", Label: "Dark Web / Deep Web News", Icon: "Eye"},
	{Slug: "high-quality", Label: "Additional High-Quality Feeds", Icon: "Star"},
	{Slug: "world-news", Label: "World News", Icon: "Globe"},
}

// Feeds is the flat list of every feed polled by the worker.
var Feeds = []Feed{
	// ───────── 1. General Cybersecurity News ─────────
	{Name: "The Hacker News", URL: "https://feeds.feedburner.com/TheHackersNews", Category: "general"},
	{Name: "Dark Reading", URL: "https://www.darkreading.com/rss.xml", Category: "general"},
	{Name: "Krebs on Security", URL: "https://krebsonsecurity.com/feed/", Category: "general"},
	{Name: "BleepingComputer", URL: "https://www.bleepingcomputer.com/feed/", Category: "general"},
	{Name: "Sophos News", URL: "https://news.sophos.com/en-us/feed/", Category: "general"},
	{Name: "Threatpost", URL: "https://threatpost.com/feed/", Category: "general"},
	{Name: "Help Net Security", URL: "https://www.helpnetsecurity.com/feed/", Category: "general"},
	{Name: "SecurityWeek", URL: "https://www.securityweek.com/feed/", Category: "general"},
	{Name: "CyberWire", URL: "https://thecyberwire.com/feeds/rss.xml", Category: "general"},
	{Name: "WeLiveSecurity (ESET)", URL: "https://www.welivesecurity.com/feed/", Category: "general"},
	{Name: "Graham Cluley", URL: "https://grahamcluley.com/feed/", Category: "general"},
	{Name: "HackRead", URL: "https://hackread.com/feed/", Category: "general"},
	{Name: "Cyber Defense Magazine", URL: "https://www.cyberdefensemagazine.com/feed/", Category: "general"},
	{Name: "SC Media", URL: "https://www.scworld.com/rss", Category: "general"},
	{Name: "CyberSecurity News", URL: "https://cybersecuritynews.com/feed/", Category: "general"},
	{Name: "Have I Been Pwned", URL: "https://feeds.feedburner.com/HaveIBeenPwnedLatestBreaches", Category: "general"},

	// ───────── 2. Threat Intelligence & Research ─────────
	{Name: "Check Point Research", URL: "https://research.checkpoint.com/feed", Category: "threat-intel"},
	{Name: "Cisco Talos", URL: "https://feeds.feedburner.com/feedburner/Talos", Category: "threat-intel"},
	{Name: "Securelist (Kaspersky)", URL: "https://securelist.com/feed/", Category: "threat-intel"},
	{Name: "nao_sec", URL: "https://nao-sec.org/feed", Category: "threat-intel"},
	{Name: "McAfee ATR", URL: "https://www.mcafee.com/blogs/tag/advanced-threat-research/feed", Category: "threat-intel"},
	{Name: "SANS Internet Storm Center", URL: "https://isc.sans.edu/rssfeed_full.xml", Category: "threat-intel"},
	{Name: "Malware Traffic Analysis", URL: "http://www.malware-traffic-analysis.net/blog-entries.rss", Category: "threat-intel"},
	{Name: "Troy Hunt", URL: "https://www.troyhunt.com/rss/", Category: "threat-intel"},
	{Name: "Schneier on Security", URL: "https://www.schneier.com/feed/atom/", Category: "threat-intel"},
	{Name: "Darknet UK", URL: "http://www.darknet.org.uk/feed/", Category: "threat-intel"},
	{Name: "The DFIR Report", URL: "https://thedfirreport.com/feed/", Category: "threat-intel"},
	{Name: "Unit 42 (Palo Alto)", URL: "https://unit42.paloaltonetworks.com/feed/", Category: "threat-intel"},
	{Name: "Microsoft Security", URL: "https://www.microsoft.com/en-us/security/blog/feed/", Category: "threat-intel"},
	{Name: "Intel 471", URL: "https://intel471.com/blog/feed/", Category: "threat-intel"},
	{Name: "SOCRadar", URL: "https://socradar.io/feed/", Category: "threat-intel"},
	{Name: "Cyble Blog", URL: "https://cyble.com/blog/feed/", Category: "threat-intel"},
	{Name: "DarkOwl", URL: "https://www.darkowl.com/feed/", Category: "threat-intel"},
	{Name: "Recorded Future", URL: "https://www.recordedfuture.com/feed", Category: "threat-intel"},
	{Name: "BushidoToken", URL: "https://blog.bushidotoken.net/feeds/posts/default", Category: "threat-intel"},
	{Name: "The Record (Recorded Future News)", URL: "https://therecord.media/feed/", Category: "threat-intel"},
	{Name: "Security Affairs (Ransomware)", URL: "https://securityaffairs.com/tag/ransomware/feed/", Category: "threat-intel"},

	// ───────── 3. Government / Official Alerts ─────────
	{Name: "CISA Advisories (All)", URL: "https://www.cisa.gov/cybersecurity-advisories/all.xml", Category: "gov-alerts"},
	{Name: "CISA Alerts", URL: "https://us-cert.cisa.gov/ncas/alerts.xml", Category: "gov-alerts"},
	{Name: "CISA Current Activity", URL: "https://us-cert.cisa.gov/ncas/current-activity.xml", Category: "gov-alerts"},
	{Name: "CISA ICS Advisories", URL: "https://us-cert.cisa.gov/ics/advisories/advisories.xml", Category: "gov-alerts"},
	{Name: "CISA Blog", URL: "https://www.cisa.gov/cisa/blog.xml", Category: "gov-alerts"},
	{Name: "CISA News", URL: "https://www.cisa.gov/news.xml", Category: "gov-alerts"},
	{Name: "Center for Internet Security (CIS)", URL: "https://www.cisecurity.org/feed/advisories", Category: "gov-alerts"},
	{Name: "BSI Germany", URL: "https://www.bsi.bund.de/SiteGlobals/Functions/RSSFeed/RSSNewsfeed/RSSNewsfeed.xml", Category: "gov-alerts"},
	{Name: "NCSC UK", URL: "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml", Category: "gov-alerts"},
	{Name: "Europol", URL: "https://www.europol.europa.eu/cms/api/rss/news", Category: "gov-alerts"},
	{Name: "FBI IC3 PSA", URL: "https://www.ic3.gov/PSA/RSS", Category: "gov-alerts"},

	// ───────── 4. Dark Web / Deep Web News & Monitoring ─────────
	{Name: "TechCrunch Dark Web", URL: "https://techcrunch.com/tag/dark-web/feed/", Category: "darkweb"},
	{Name: "MakeUseOf Dark Web", URL: "https://www.makeuseof.com/feed/tag/dark-web/", Category: "darkweb"},
	{Name: "Dark Web Informer", URL: "https://darkwebinformer.com/news-feed/", Category: "darkweb"},
	{Name: "The Dark Web Links", URL: "https://thedarkweblinks.net/feed", Category: "darkweb"},
	{Name: "DeepWebsitesLinks Blog", URL: "https://www.deepwebsiteslinks.com/feed/", Category: "darkweb"},
	{Name: "Vice Dark Web", URL: "https://www.vice.com/en/rss/search?q=Dark%20Web", Category: "darkweb"},
	{Name: "CyberTalk Dark Web", URL: "https://www.cybertalk.org/tag/dark-web/feed/", Category: "darkweb"},
	{Name: "PYMNTS Dark Web", URL: "https://www.pymnts.com/tag/dark-web/feed/", Category: "darkweb"},
	{Name: "The Conversation Dark Web", URL: "https://theconversation.com/topics/dark-web-8437/articles.atom", Category: "darkweb"},
	{Name: "Darknet Diaries (Podcast)", URL: "https://podcast.darknetdiaries.com/", Category: "darkweb"},
	{Name: "Lapsus.by", URL: "https://lapsus.by/", Category: "darkweb"},
	// HIGH-RISK: raw extortion aggregator. Reading should be done from a
	// separate OPSEC environment — tab UI forces a Tor Browser prompt.
	{Name: "Ransomware.live", URL: "https://www.ransomware.live/rss.xml", Category: "darkweb"},
	{Name: "DataBreaches.net", URL: "https://www.databreaches.net/feed/", Category: "darkweb"},
	{Name: "Security Affairs (Dark Web)", URL: "https://securityaffairs.com/tag/dark-web/feed/", Category: "darkweb"},

	// ───────── 5. Additional High-Quality Feeds ─────────
	{Name: "AlienVault / Anomali", URL: "https://www.anomali.com/site/blog-rss", Category: "high-quality"},
	{Name: "AWS Security Blog", URL: "https://aws.amazon.com/blogs/security/feed/", Category: "high-quality"},
	{Name: "Avast Threat Labs", URL: "https://decoded.avast.io/feed/", Category: "high-quality"},
	{Name: "BankInfoSecurity", URL: "https://www.bankinfosecurity.com/rss-feeds", Category: "high-quality"},
	{Name: "Cloud Security Alliance", URL: "https://cloudsecurityalliance.org/blog/feed/", Category: "high-quality"},
	{Name: "Imperva Blog", URL: "https://www.imperva.com/blog/feed/", Category: "high-quality"},
	{Name: "Praetorian Blog", URL: "https://www.praetorian.com/blog/feed/", Category: "high-quality"},
	{Name: "ZeroFox", URL: "https://www.zerofox.com/blog/feed", Category: "high-quality"},
	{Name: "MIT Cybersecurity", URL: "https://news.mit.edu/topic/mitcyber-security-rss.xml", Category: "high-quality"},
	{Name: "NY Times Cybersecurity", URL: "https://www.nytimes.com/svc/collections/v1/publish/https://www.nytimes.com/spotlight/cybersecurity/rss.xml", Category: "high-quality"},

	// ───────── 6. World News ─────────
	// Vietnamese sources
	{Name: "VNExpress Latest", URL: "https://vnexpress.net/rss/tin-moi-nhat.rss", Category: "world-news", Language: "vi"},
	{Name: "VNExpress World", URL: "https://vnexpress.net/rss/the-gioi.rss", Category: "world-news", Language: "vi"},
	{Name: "VNExpress Kinh Doanh", URL: "https://vnexpress.net/rss/kinh-doanh.rss", Category: "world-news", Language: "vi"},
	{Name: "VNExpress Current Affairs", URL: "https://vnexpress.net/rss/thoi-su.rss", Category: "world-news", Language: "vi"},
	{Name: "Tuoi Tre World", URL: "https://tuoitre.vn/rss/the-gioi.rss", Category: "world-news", Language: "vi"},
	{Name: "Tuoi Tre Business", URL: "https://tuoitre.vn/rss/kinh-doanh.rss", Category: "world-news", Language: "vi"},
	{Name: "Tuoi Tre Politics & Society", URL: "https://tuoitre.vn/rss/chinh-tri-xa-hoi.rss", Category: "world-news", Language: "vi"},
	{Name: "Thanh Nien World", URL: "https://thanhnien.vn/rss/the-gioi.rss", Category: "world-news", Language: "vi"},
	{Name: "Thanh Nien Current Affairs", URL: "https://thanhnien.vn/rss/thoi-su.rss", Category: "world-news", Language: "vi"},
	{Name: "VietnamNet Current Affairs", URL: "https://vietnamnet.vn/rss/thoi-su.rss", Category: "world-news", Language: "vi"},
	{Name: "VietnamNet World", URL: "https://vietnamnet.vn/rss/the-gioi.rss", Category: "world-news", Language: "vi"},
	{Name: "VietnamNet Kinh Doanh", URL: "https://vietnamnet.vn/rss/kinh-doanh.rss", Category: "world-news", Language: "vi"},
	{Name: "Nguoi Lao Dong Current Affairs", URL: "https://nld.com.vn/rss/thoi-su.rss", Category: "world-news", Language: "vi"},
	{Name: "BBC Vietnamese", URL: "https://feeds.bbci.co.uk/vietnamese/rss.xml", Category: "world-news", Language: "vi"},
	{Name: "Bao Tin Tuc (TTXVN)", URL: "https://baotintuc.vn/tin-moi-nhat.rss", Category: "world-news", Language: "vi"},

	// English sources
	{Name: "BBC News World", URL: "https://feeds.bbci.co.uk/news/world/rss.xml", Category: "world-news", Language: "en"},
	{Name: "BBC News Business", URL: "https://feeds.bbci.co.uk/news/business/rss.xml", Category: "world-news", Language: "en"},
	{Name: "Al Jazeera", URL: "https://www.aljazeera.com/xml/rss/all.xml", Category: "world-news", Language: "en"},
	{Name: "France 24", URL: "https://www.france24.com/en/rss", Category: "world-news", Language: "en"},
	{Name: "NPR World", URL: "https://feeds.npr.org/1004/rss.xml", Category: "world-news", Language: "en"},
	{Name: "NPR Politics", URL: "https://feeds.npr.org/1014/rss.xml", Category: "world-news", Language: "en"},
	{Name: "Axios", URL: "https://api.axios.com/feed/", Category: "world-news", Language: "en"},
	{Name: "War on the Rocks", URL: "https://warontherocks.com/feed/", Category: "world-news", Language: "en"},
	{Name: "Long War Journal", URL: "https://www.longwarjournal.org/feed", Category: "world-news", Language: "en"},
	{Name: "Defense News", URL: "https://www.defensenews.com/arc/outboundfeeds/rss/?outputType=xml", Category: "world-news", Language: "en"},
}

// FeedsByCategory returns all feeds whose Category matches slug.
func FeedsByCategory(slug string) []Feed {
	out := make([]Feed, 0)
	for _, f := range Feeds {
		if f.Category == slug {
			out = append(out, f)
		}
	}
	return out
}

// IsValidCategory reports whether slug matches any registered category.
func IsValidCategory(slug string) bool {
	for _, c := range Categories {
		if c.Slug == slug {
			return true
		}
	}
	return false
}

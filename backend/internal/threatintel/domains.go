package threatintel

import "strings"

// domains.go — whether a regex match can actually be a hostname.
//
// Moved here from the malware package so there is one answer instead of two.
// The extractor in this package had its own, narrower TLD list which happened to
// omit exactly the TLDs that matter — .app, .dev, .zip, .click, .icu — so an
// indicator on abuse-heavy infrastructure was dropped by the very filter meant
// to keep the noise out, while the malware package kept it.

// NotATLD are final labels that look like a TLD to a regex but never are: file
// extensions, code suffixes and build artifacts.
//
// This is the dominant source of fake indicators, and it affects EVERY PE the
// platform analyses, not any one sample. A regex over the import table of an
// ordinary signed binary yields "kernel32.dll", "api-ms-win-core-heap-l1-1-0.dll",
// "curl.pdb", "disallowedcert.stl", "url.fragment" — across three clean Windows
// binaries, 140 "domains" were extracted of which three were real. Each one became
// an IOC, an export row, and a generated Suricata rule telling a sensor to alert
// on DNS lookups for "kernel32.dll".
//
// A denylist rather than a TLD allowlist on purpose: it only ever removes things
// that are definitely not hostnames, so an obscure but real malware TLD (.top,
// .xyz, .cf, .win, .pw) is never lost. Recall matters more than tidiness here.
var NotATLD = map[string]bool{
	// Executables and libraries
	"dll": true, "exe": true, "sys": true, "so": true, "dylib": true, "ocx": true,
	"node": true, "pyd": true, "jar": true, "class": true, "lib": true, "obj": true,
	"a": true, "o": true, "ko": true, "drv": true, "cpl": true, "scr": true, "efi": true,
	// Build and debug artifacts
	"pdb": true, "map": true, "sym": true, "res": true, "rc": true, "def": true,
	"manifest": true, "cpp": true, "hpp": true, "cs": true, "vb": true, "asm": true,
	// Archives and compression
	"gz": true, "xz": true, "bz2": true, "zst": true, "lzma": true, "lzo": true,
	"tar": true, "zip": true, "rar": true, "cab": true, "msi": true, "iso": true,
	// Documents, data and config
	"txt": true, "log": true, "json": true, "xml": true, "yml": true, "yaml": true,
	"ini": true, "cfg": true, "conf": true, "toml": true, "csv": true, "tsv": true,
	"dat": true, "bin": true, "db": true, "sqlite": true, "ldb": true, "tmp": true,
	"bak": true, "old": true, "lock": true, "pid": true, "netrc": true,
	"html": true, "htm": true, "css": true, "md": true, "rst": true, "pdf": true,
	"doc": true, "docx": true, "xls": true, "xlsx": true, "ppt": true, "pptx": true, "rtf": true,
	// Media and fonts
	"png": true, "jpg": true, "jpeg": true, "gif": true, "bmp": true, "ico": true,
	"svg": true, "webp": true, "mp3": true, "mp4": true, "wav": true, "avi": true,
	"ttf": true, "otf": true, "woff": true, "woff2": true, "eot": true,
	// Certificates and crypto material
	"crl": true, "cer": true, "crt": true, "pem": true, "der": true, "pfx": true,
	"p12": true, "p7b": true, "stl": true, "cat": true, "sst": true,
	// Scripts (a .js/.ps1 in a string table is a file name, not a host)
	"js": true, "mjs": true, "cjs": true, "ts": true, "py": true, "rb": true,
	"php": true, "pl": true, "sh": true, "bat": true, "cmd": true, "ps1": true,
	"psm1": true, "vbs": true, "wsf": true, "lua": true, "sql": true,
}

// KnownGTLD is the generic top-level domains a hostname may end in. Two-letter
// TLDs are accepted separately as country codes, which covers the rest.
//
// A positive check is what generalises. The denylist above removes file
// extensions, but the residue is code identifiers — "url.fragment",
// "dpapi.cryptprotectmemory", "microsoft.windows.security.certificates" — and
// there is no end to those; adding each one as it appears is chasing the last
// sample rather than fixing the rule. Requiring a real TLD settles the whole
// class at once.
//
// Deliberately inclusive of the cheap and abuse-heavy TLDs (.top, .xyz, .win,
// .tk, .cf, .gq, .click, .zip): those are where C2 actually lives, and a filter
// that trimmed noise by narrowing to respectable TLDs would drop the indicators
// the report exists to produce.
var KnownGTLD = map[string]bool{
	// Legacy and infrastructure
	"com": true, "net": true, "org": true, "edu": true, "gov": true, "mil": true,
	"int": true, "arpa": true, "biz": true, "info": true, "name": true, "pro": true,
	"mobi": true, "asia": true, "tel": true, "travel": true, "jobs": true, "coop": true,
	"aero": true, "museum": true, "cat": true, "post": true,
	// Common new gTLDs
	"online": true, "site": true, "website": true, "space": true, "store": true,
	"shop": true, "app": true, "dev": true, "cloud": true, "tech": true, "digital": true,
	"agency": true, "solutions": true, "services": true, "systems": true, "network": true,
	"email": true, "host": true, "hosting": true, "domains": true, "zone": true,
	"link": true, "click": true, "live": true, "life": true, "world": true, "today": true,
	"news": true, "media": true, "blog": true, "wiki": true, "page": true, "one": true,
	"team": true, "group": true, "company": true, "center": true, "support": true,
	"tools": true, "software": true, "codes": true, "computer": true, "download": true,
	"cloudns": true, "ltd": true, "inc": true, "llc": true, "global": true, "vip": true,
	"club": true, "fun": true, "art": true, "design": true, "studio": true,
	"cash": true, "money": true, "finance": true, "bank": true, "trade": true, "market": true,
	"security": true, "protection": true, "expert": true, "guru": true, "ninja": true,
	"pics": true, "photo": true, "video": true, "games": true, "chat": true, "social": true,
	"party": true, "review": true, "science": true, "date": true, "faith": true, "cricket": true,
	"accountant": true, "racing": true, "stream": true, "loan": true, "men": true,
	"win": true, "bid": true, "webcam": true, "top": true, "xyz": true,
	"icu": true, "cyou": true, "sbs": true, "rest": true, "bar": true, "buzz": true,
	"monster": true, "quest": true, "beauty": true, "hair": true, "skin": true, "makeup": true,
	"zip": true, "mov": true, "foo": true, "boo": true, "rsvp": true, "day": true,
	"cfd": true, "lol": true, "autos": true, "motorcycles": true, "boats": true, "homes": true,
	"onion": true, "local": true, "localhost": true, "test": true, "example": true, "invalid": true,
}

// PlausibleTLD reports whether a final label can be a real top-level domain.
// Any two-letter alphabetic label is treated as a country code — that is what the
// ccTLD space is, and enumerating 250 of them adds nothing.
func PlausibleTLD(tld string) bool {
	if tld == "" {
		return false
	}
	if KnownGTLD[tld] {
		return true
	}
	if len(tld) == 2 {
		for _, r := range tld {
			if r < 'a' || r > 'z' {
				return false
			}
		}
		return true
	}
	// Internationalised TLDs are punycode; they are real and rare.
	return strings.HasPrefix(tld, "xn--")
}

// ShortRealDomains are the genuinely-short hostnames worth keeping. They are
// listed explicitly because the length rule below would otherwise discard them,
// and several are real malware infrastructure (t.me for Telegram C2, the URL
// shorteners used for staging).
var ShortRealDomains = map[string]bool{
	"t.me": true, "t.co": true, "x.com": true, "vk.com": true, "qq.com": true,
	"ok.ru": true, "is.gd": true, "j.mp": true, "db.tt": true, "fb.me": true,
	"wa.me": true, "ip.sb": true, "ix.io": true, "0x0.st": true,
}

// PlausibleDomains drops the accidental matches that a domain regex produces when
// it is run over a binary's string table.
//
// The extractor is shared with OSINT and network analysis, where its input is
// prose and its output is trustworthy. Here the input is a string table — and an
// obfuscated sample's is full of short random tokens, so fragments like "0.cf",
// "5.io" and "vl.ru" match the pattern perfectly. They then travel all the way
// into the C2 inventory, where a responder is asked to block them. Reporting six
// invented domains alongside a real one is worse than reporting none, because it
// costs the reader their trust in the list.
func PlausibleDomains(in []string) []string {
	out := make([]string, 0, len(in))
	for _, d := range in {
		low := strings.ToLower(strings.TrimSpace(d))
		if low == "" || ShortRealDomains[low] {
			out = append(out, d)
			continue
		}
		labels := strings.Split(low, ".")
		// A file name is not a host. Checked first because it removes the great
		// majority of the noise regardless of how many labels the name has —
		// "kernel32.dll" and "api-ms-win-core-heap-l1-1-0.dll" both die here.
		tld := labels[len(labels)-1]
		if NotATLD[tld] {
			continue
		}
		// And the final label has to be a TLD that exists. This is what closes the
		// residue the extension denylist cannot reach — code identifiers such as
		// "url.fragment" and "dpapi.cryptprotectmemory".
		if !PlausibleTLD(tld) {
			continue
		}
		// Only two-label names are judged on length. A multi-label name
		// ("cdn.example.co.uk") carries enough structure to be a real host, and
		// applying the rule to it would discard the "co" in every ccTLD domain.
		if len(labels) != 2 {
			out = append(out, d)
			continue
		}
		sld := labels[0]
		// A one- or two-character second-level label that is not a known short
		// domain is a token boundary, not a host.
		if len(sld) < 3 {
			continue
		}
		// An all-digit label is a version number or an array index that happened to
		// sit next to something TLD-shaped.
		if strings.IndexFunc(sld, func(r rune) bool { return r < '0' || r > '9' }) < 0 {
			continue
		}
		out = append(out, d)
	}
	return out
}

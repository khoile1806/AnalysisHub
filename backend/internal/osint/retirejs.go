package osint

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"strings"
	"sync"
)

// retirejs.json is the official RetireJS vulnerability database (script-src URI /
// filename regexes + per-version-range vulnerabilities). Embedding it gives broad,
// curated JavaScript-library detection + accurate known-vuln mapping without any
// runtime download.
//
//go:embed data/retirejs.json
var retireJSRaw []byte

// retireVersionToken is what RetireJS's "§§version§§" placeholder expands to — a
// dotted version capture used inside the extractor regexes.
const retireVersionToken = `([0-9][0-9.a-z_\-]+)`

type retireRawEntry struct {
	Extractors struct {
		URI      []string `json:"uri"`
		Filename []string `json:"filename"`
	} `json:"extractors"`
	Vulnerabilities []struct {
		AtOrAbove   string `json:"atOrAbove"`
		Above       string `json:"above"`
		Below       string `json:"below"`
		AtOrBelow   string `json:"atOrBelow"`
		Severity    string `json:"severity"`
		Identifiers struct {
			CVE     []string `json:"CVE"`
			Summary string   `json:"summary"`
		} `json:"identifiers"`
		Info []string `json:"info"`
	} `json:"vulnerabilities"`
}

type retireLib struct {
	name     string
	patterns []*regexp.Regexp
	vulns    []retireVuln
}

type retireVuln struct {
	atOrAbove, above, below, atOrBelow string
	severity                           string
	cves                               []string
	summary, info                      string
}

var (
	retireOnce sync.Once
	retireMu   sync.RWMutex
	retireLibs []retireLib
)

// ensureRetire lazily loads the embedded DB on first use.
func ensureRetire() {
	retireOnce.Do(func() { _, _ = reloadRetireBytes(retireJSRaw) })
}

// parseRetire compiles a retire.js JSON blob into the in-memory library set. Each
// library's extractor regexes are compiled (RE2-incompatible JS patterns silently
// skipped) and its vuln ranges captured.
func parseRetire(data []byte) ([]retireLib, error) {
	var raw map[string]retireRawEntry
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	var libs []retireLib
	for name, e := range raw {
		lib := retireLib{name: name}
		compileInto := func(pats []string) {
			for _, p := range pats {
				p = strings.ReplaceAll(p, "§§version§§", retireVersionToken)
				re, err := regexp.Compile("(?i)" + p)
				if err != nil {
					continue
				}
				lib.patterns = append(lib.patterns, re)
			}
		}
		compileInto(e.Extractors.URI)
		compileInto(e.Extractors.Filename)
		for _, v := range e.Vulnerabilities {
			rv := retireVuln{
				atOrAbove: v.AtOrAbove, above: v.Above, below: v.Below, atOrBelow: v.AtOrBelow,
				severity: strings.ToLower(v.Severity), cves: v.Identifiers.CVE, summary: v.Identifiers.Summary,
			}
			if len(v.Info) > 0 {
				rv.info = v.Info[0]
			}
			lib.vulns = append(lib.vulns, rv)
		}
		if len(lib.patterns) > 0 {
			libs = append(libs, lib)
		}
	}
	return libs, nil
}

// reloadRetireBytes swaps the active library set for one parsed from data (used by
// the periodic updater to hot-reload a freshly downloaded DB). Returns lib count.
func reloadRetireBytes(data []byte) (int, error) {
	libs, err := parseRetire(data)
	if err != nil {
		return 0, err
	}
	retireMu.Lock()
	retireLibs = libs
	retireMu.Unlock()
	return len(libs), nil
}

// ReloadRetireFromBytes hot-reloads the retire.js DB from a JSON blob. Exported for
// the updater.
func ReloadRetireFromBytes(data []byte) (int, error) { return reloadRetireBytes(data) }

// RetireLibCount returns how many libraries are currently loaded.
func RetireLibCount() int {
	ensureRetire()
	retireMu.RLock()
	defer retireMu.RUnlock()
	return len(retireLibs)
}

// detectRetireJS scans the page's <script src> URLs against the retire.js database,
// returning one Technology per matched library with its version and the exact
// known vulnerabilities affecting that version.
func detectRetireJS(srcs []string) []Technology {
	ensureRetire()
	retireMu.RLock()
	defer retireMu.RUnlock()
	if len(retireLibs) == 0 {
		return nil
	}
	found := map[string]Technology{}
	for _, src := range srcs {
		for i := range retireLibs {
			lib := &retireLibs[i]
			key := strings.ToLower(lib.name)
			if _, dup := found[key]; dup {
				continue
			}
			for _, re := range lib.patterns {
				m := re.FindStringSubmatch(src)
				if m == nil {
					continue
				}
				ver := pickRetireVersion(m)
				if ver == "" {
					continue
				}
				t := Technology{
					Name:       retireDisplayName(lib.name),
					Version:    ver,
					Categories: []string{"JavaScript library"},
					Source:     "retirejs",
					CPE:        jsLibCPE[key],
					KnownVulns: matchRetireVulns(lib, ver),
				}
				found[key] = t
				break
			}
		}
	}
	out := make([]Technology, 0, len(found))
	for _, t := range found {
		out = append(out, t)
	}
	return out
}

// retireNumVer trims a captured token to its leading numeric dotted version, so
// the greedy §§version§§ class (which also allows letters) doesn't leak a ".min"
// / ".slim" suffix into the version (e.g. "3.3.7.min" → "3.3.7").
var retireNumVer = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){1,3}`)

// pickRetireVersion returns the first submatch that looks like a dotted version,
// cleaned to its numeric prefix.
func pickRetireVersion(m []string) string {
	for _, g := range m[1:] {
		g = strings.TrimSpace(g)
		if len(g) >= 3 && g[0] >= '0' && g[0] <= '9' && strings.Contains(g, ".") {
			if v := retireNumVer.FindString(g); v != "" {
				return v
			}
		}
	}
	return ""
}

// matchRetireVulns returns the retire.js vulnerabilities whose version range covers
// version, flattened to one LibVuln per CVE (CVE-less advisories keep an empty CVE).
func matchRetireVulns(lib *retireLib, version string) []LibVuln {
	var out []LibVuln
	seen := map[string]bool{}
	for _, v := range lib.vulns {
		if !retireInRange(version, v) {
			continue
		}
		sev := v.severity
		if sev == "" {
			sev = "medium"
		}
		if len(v.cves) == 0 {
			out = append(out, LibVuln{Severity: sev, Summary: v.summary, Info: v.info})
			continue
		}
		for _, cve := range v.cves {
			if cve == "" || seen[cve] {
				continue
			}
			seen[cve] = true
			out = append(out, LibVuln{CVE: cve, Severity: sev, Summary: v.summary, Info: v.info})
		}
	}
	return out
}

// retireInRange reports whether version falls in a vuln's [above/atOrAbove,
// below/atOrBelow) window. Empty bounds are open.
func retireInRange(version string, v retireVuln) bool {
	if v.atOrAbove != "" && verLess(version, v.atOrAbove) {
		return false
	}
	if v.above != "" && !verLess(v.above, version) { // version must be strictly > above
		return false
	}
	if v.below != "" && !verLess(version, v.below) { // version must be strictly < below
		return false
	}
	if v.atOrBelow != "" && verLess(v.atOrBelow, version) { // version must be <= atOrBelow
		return false
	}
	return true
}

// jsLibCPE maps a retire.js library key to an NVD CPE vendor:product, so the
// handler can still add EPSS/KEV and (where useful) NVD context.
var jsLibCPE = map[string]string{
	"jquery":     "cpe:2.3:a:jquery:jquery",
	"jquery-ui":  "cpe:2.3:a:jquery:jquery_ui",
	"bootstrap":  "cpe:2.3:a:getbootstrap:bootstrap",
	"angularjs":  "cpe:2.3:a:angularjs:angular.js",
	"vue":        "cpe:2.3:a:vuejs:vue",
	"react":      "cpe:2.3:a:facebook:react",
	"lodash":     "cpe:2.3:a:lodash:lodash",
	"moment.js":  "cpe:2.3:a:momentjs:moment",
	"dojo":       "cpe:2.3:a:dojotoolkit:dojo",
	"handlebars": "cpe:2.3:a:handlebarsjs:handlebars",
	"axios":      "cpe:2.3:a:axios:axios",
	"tinymce":    "cpe:2.3:a:tiny:tinymce",
	"ckeditor":   "cpe:2.3:a:ckeditor:ckeditor",
}

// retireDisplayName prettifies a lowercase retire.js key for display.
var retireNamePretty = map[string]string{
	"jquery": "jQuery", "jquery-ui": "jQuery UI", "jquery.mobile": "jQuery Mobile",
	"angularjs": "AngularJS", "vue": "Vue.js", "moment.js": "Moment.js",
	"dompurify": "DOMPurify", "ckeditor": "CKEditor", "tinymce": "TinyMCE",
}

func retireDisplayName(key string) string {
	if p, ok := retireNamePretty[key]; ok {
		return p
	}
	// Title-case the first rune for a reasonable default (e.g. "bootstrap" → "Bootstrap").
	if key == "" {
		return key
	}
	return strings.ToUpper(key[:1]) + key[1:]
}

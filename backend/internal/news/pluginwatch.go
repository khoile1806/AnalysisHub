// Ingest for the plugin-release-watch tool (tools/plugin-release-watch).
//
// That tool polls the wordpress.org plugin API, remembers the version it saw
// last time, and writes a report describing what changed. This file is the
// consumer side: it reads that report and hands the news worker something it
// can turn into articles.
//
// It is deliberately a file hand-off rather than an HTTP call. The tool runs on
// a schedule (Task Scheduler, cron, a CI job) and may not be running at all;
// reading a file means the worker degrades to "no new plugin articles" instead
// of blocking on a service that does not exist.
//
// The JSON shape is the tool's documented contract - see
// tools/plugin-release-watch/watcher/models.py. Renaming a field there is a
// breaking change here.
package news

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PluginWatchSignal mirrors watcher.models.Signal.
type PluginWatchSignal string

const (
	SignalSecurityFix PluginWatchSignal = "security_fix"
	SignalNewPlugin   PluginWatchSignal = "new_plugin"
	SignalRelease     PluginWatchSignal = "release"
)

// PluginWatchCategory is the news category these articles land in. It has no
// Feed entry because nothing here is fetched over RSS.
const PluginWatchCategory = "wp-plugin-watch"

// PluginWatchMatch is one security-flavoured changelog line, kept with its
// context so a reader can judge the release without opening the plugin.
type PluginWatchMatch struct {
	Keyword string `json:"keyword"`
	Line    string `json:"line"`
}

// PluginWatchEvent is one thing that changed since the tool's previous run.
type PluginWatchEvent struct {
	Slug            string             `json:"slug"`
	Name            string             `json:"name"`
	Signal          PluginWatchSignal  `json:"signal"`
	PreviousVersion *string            `json:"previous_version"`
	CurrentVersion  string             `json:"current_version"`
	// ActiveInstalls is wp.org's PUBLISHED figure, rounded DOWN to a bucket:
	// 20000 means "20,000+", not "exactly 20,000". Downloaded is the exact
	// cumulative count. Keeping both means the UI can state which is measured
	// and which is a floor, instead of implying a precision wp.org never gives.
	ActiveInstalls  int                `json:"active_installs"`
	Downloaded      int                `json:"downloaded"`
	LastUpdated     string             `json:"last_updated"`
	ChangelogHead   string             `json:"changelog_head"`
	Matches         []PluginWatchMatch `json:"matches"`
}

// PluginWatchReport is one run of the tool.
type PluginWatchReport struct {
	GeneratedAt time.Time          `json:"generated_at"`
	Watched     int                `json:"watched"`
	Unreachable []string           `json:"unreachable"`
	Events      []PluginWatchEvent `json:"events"`
}

// PluginWatchReportPath resolves where the report is expected.
//
// Env var first so a deployment can point at a shared volume without a rebuild;
// the default sits beside the other worker state under data/.
func PluginWatchReportPath() string {
	if p := strings.TrimSpace(os.Getenv("PLUGIN_WATCH_REPORT")); p != "" {
		return p
	}
	return filepath.Join("data", "plugin-watch", "report.json")
}

// LoadPluginWatchReport reads the report if it exists.
//
// A missing file is not an error: it just means the tool has never run, which
// is the normal state on an install that does not use it.
func LoadPluginWatchReport(path string) (*PluginWatchReport, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("doc report plugin-watch: %w", err)
	}

	var report PluginWatchReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("report plugin-watch khong hop le: %w", err)
	}
	return &report, nil
}

// Title is the headline shown in the news list.
//
// The install count is in the title on purpose: when scanning a list, "how many
// sites does this affect" is the first thing that decides whether to read on.
func (e PluginWatchEvent) Title() string {
	name := e.Name
	if name == "" {
		name = e.Slug
	}
	// Every headline carries name, version and reach, whatever the signal: those
	// three are what decides whether a release is worth opening, and a reader
	// scanning a list should not have to click to learn any of them.
	reach := humanInstalls(e.ActiveInstalls)
	switch e.Signal {
	case SignalSecurityFix:
		return fmt.Sprintf("[Security] %s %s - ban va bao mat (%s cai dat)",
			name, e.CurrentVersion, reach)
	case SignalNewPlugin:
		if e.ActiveInstalls <= 0 {
			return fmt.Sprintf("[Plugin moi] %s %s", name, e.CurrentVersion)
		}
		return fmt.Sprintf("[Plugin moi] %s %s (%s cai dat)", name, e.CurrentVersion, reach)
	default:
		prev := ""
		if e.PreviousVersion != nil {
			prev = *e.PreviousVersion + " -> "
		}
		return fmt.Sprintf("%s %s%s (%s cai dat)", name, prev, e.CurrentVersion, reach)
	}
}

// Description explains why the item is in the list and what to do next.
func (e PluginWatchEvent) Description() string {
	var b strings.Builder

	if len(e.Matches) > 0 {
		b.WriteString("Dong changelog dang chu y: ")
		lines := make([]string, 0, len(e.Matches))
		for _, m := range e.Matches {
			lines = append(lines, m.Line)
		}
		b.WriteString(strings.Join(lines, " | "))
	} else if head := firstLines(e.ChangelogHead, 3); head != "" {
		b.WriteString(head)
	}

	if e.Signal == SignalSecurityFix && e.PreviousVersion != nil {
		b.WriteString(fmt.Sprintf(
			" -- Buoc tiep theo: diff %s va %s de xem vendor them kiem soat nao, roi soi cac ham anh em.",
			*e.PreviousVersion, e.CurrentVersion))
	}
	return strings.TrimSpace(b.String())
}

// Tags let the frontend filter without re-deriving anything.
func (e PluginWatchEvent) Tags() []string {
	tags := []string{"wordpress", "plugin", string(e.Signal)}
	if e.Signal == SignalSecurityFix {
		tags = append(tags, "security-fix", "incomplete-fix-candidate")
	}
	if e.ActiveInstalls >= 100000 {
		tags = append(tags, "high-install")
	}
	return tags
}

// Link points at the plugin's changelog on wp.org, which is the page a reader
// wants next.
func (e PluginWatchEvent) Link() string {
	return "https://wordpress.org/plugins/" + e.Slug + "/#developers"
}

// ArticleID must be stable across runs, or every worker cycle re-adds the same
// item. Slug plus version is exactly the identity of "this release".
func (e PluginWatchEvent) ArticleID() string {
	return "wp-plugin:" + e.Slug + "@" + e.CurrentVersion
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.TrimSpace(strings.Join(lines, " "))
}

// humanInstalls renders wp.org's install bucket. The trailing "+" is not
// decoration: the API rounds DOWN, so 20000 is the floor of a range and printing
// a bare "20k" would claim a precision the source does not have.
func humanInstalls(n int) string {
	switch {
	case n <= 0:
		// wp.org's buckets start at 10, so an unlisted count means fewer than
		// that — which for a plugin published hours ago is the expected answer,
		// not missing data.
		return "<10"
	case n >= 1_000_000:
		return fmt.Sprintf("%dtr+", n/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%dk+", n/1_000)
	default:
		return fmt.Sprintf("%d+", n)
	}
}

// DisplayName is the plugin's published name, falling back to the slug. wp.org
// occasionally returns an empty name for a freshly-submitted plugin, and a blank
// cell in the list is worse than showing the slug the reader can search on.
func (e PluginWatchEvent) DisplayName() string {
	if n := strings.TrimSpace(e.Name); n != "" {
		return n
	}
	return e.Slug
}

// InstallsLabel is the reach figure rendered for display, carrying the "+" that
// marks it as a floor rather than a count.
func (e PluginWatchEvent) InstallsLabel() string { return humanInstalls(e.ActiveInstalls) }

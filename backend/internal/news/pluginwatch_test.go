package news

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleReport = `{
  "generated_at": "2026-08-15T09:00:00Z",
  "watched": 3,
  "unreachable": [],
  "events": [
    {
      "slug": "dsgvo-all-in-one-for-wp",
      "name": "DSGVO All in one for WP",
      "signal": "security_fix",
      "previous_version": "4.9",
      "current_version": "5.0",
      "active_installs": 20000,
      "last_updated": "2026-04-11 8:25am GMT",
      "changelog_head": "5.0\nSecurity: Fixed missing capability check",
      "matches": [{"keyword": "Security", "line": "Security: Fixed missing capability check"}]
    },
    {
      "slug": "brand-new-thing",
      "name": "Brand New Thing",
      "signal": "new_plugin",
      "previous_version": null,
      "current_version": "1.0.0",
      "active_installs": 0,
      "last_updated": "",
      "changelog_head": "Mot plugin vua xuat hien",
      "matches": []
    }
  ]
}`

func writeReport(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("khong ghi duoc report: %v", err)
	}
	return path
}

func TestLoadReportParsesEvents(t *testing.T) {
	report, err := LoadPluginWatchReport(writeReport(t, sampleReport))
	if err != nil {
		t.Fatalf("loi doc report: %v", err)
	}
	if report == nil {
		t.Fatal("report nil")
	}
	if got := len(report.Events); got != 2 {
		t.Fatalf("mong doi 2 su kien, nhan %d", got)
	}
	if report.Events[0].Signal != SignalSecurityFix {
		t.Errorf("signal sai: %q", report.Events[0].Signal)
	}
	if report.Events[1].PreviousVersion != nil {
		t.Error("plugin moi khong duoc co previous_version")
	}
}

// A missing file is the normal state on an install that never runs the tool,
// so it must not surface as an error the worker logs every cycle.
func TestMissingReportIsNotAnError(t *testing.T) {
	report, err := LoadPluginWatchReport(filepath.Join(t.TempDir(), "khong-ton-tai.json"))
	if err != nil {
		t.Fatalf("file thieu khong duoc bao loi: %v", err)
	}
	if report != nil {
		t.Error("mong doi nil khi khong co file")
	}
}

func TestCorruptReportIsAnError(t *testing.T) {
	if _, err := LoadPluginWatchReport(writeReport(t, "{khong phai json")); err == nil {
		t.Error("report hong phai bao loi")
	}
}

// ArticleID is what stops the worker re-adding the same release every cycle.
func TestArticleIDIsStablePerRelease(t *testing.T) {
	report, _ := LoadPluginWatchReport(writeReport(t, sampleReport))
	ev := report.Events[0]

	if got, want := ev.ArticleID(), "wp-plugin:dsgvo-all-in-one-for-wp@5.0"; got != want {
		t.Errorf("ArticleID = %q, mong doi %q", got, want)
	}
	if ev.ArticleID() != report.Events[0].ArticleID() {
		t.Error("ArticleID phai on dinh giua cac lan goi")
	}
}

func TestSecurityTitleCarriesInstallCount(t *testing.T) {
	report, _ := LoadPluginWatchReport(writeReport(t, sampleReport))
	title := report.Events[0].Title()

	if !strings.Contains(title, "[Security]") {
		t.Errorf("thieu nhan Security: %q", title)
	}
	if !strings.Contains(title, "20k") {
		t.Errorf("thieu so cai dat: %q", title)
	}
}

// The whole point of a security release alert is the diff that follows it.
func TestSecurityDescriptionPointsAtTheDiff(t *testing.T) {
	report, _ := LoadPluginWatchReport(writeReport(t, sampleReport))
	desc := report.Events[0].Description()

	if !strings.Contains(desc, "missing capability check") {
		t.Errorf("thieu dong changelog: %q", desc)
	}
	if !strings.Contains(desc, "4.9") || !strings.Contains(desc, "5.0") {
		t.Errorf("thieu goi y diff hai phien ban: %q", desc)
	}
}

func TestSecurityEventIsTaggedForFollowUp(t *testing.T) {
	report, _ := LoadPluginWatchReport(writeReport(t, sampleReport))
	tags := strings.Join(report.Events[0].Tags(), ",")

	for _, want := range []string{"wordpress", "security-fix", "incomplete-fix-candidate"} {
		if !strings.Contains(tags, want) {
			t.Errorf("thieu tag %q trong %q", want, tags)
		}
	}
}

func TestReportPathHonoursEnvOverride(t *testing.T) {
	t.Setenv("PLUGIN_WATCH_REPORT", "/tmp/custom/report.json")
	if got := PluginWatchReportPath(); got != "/tmp/custom/report.json" {
		t.Errorf("khong ton trong bien moi truong: %q", got)
	}
}

func TestReportPathDefaultsUnderData(t *testing.T) {
	t.Setenv("PLUGIN_WATCH_REPORT", "")
	if got := PluginWatchReportPath(); !strings.Contains(got, "plugin-watch") {
		t.Errorf("duong dan mac dinh bat thuong: %q", got)
	}
}

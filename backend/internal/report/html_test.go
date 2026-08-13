package report

import (
	"strings"
	"testing"
)

// The renderer decides which language edition a bilingual document opens on.
// English is the default deliverable language; an explicit request wins.
func TestRenderReportHTMLDefaultsToEnglish(t *testing.T) {
	editions := []Edition{
		{Lang: "vi", Markdown: "# VI\n\n## Một\n\ntext\n"},
		{Lang: "en", Markdown: "# EN\n\n## One\n\ntext\n"},
	}
	// No preference expressed → English, even when it is not the first edition.
	if got := defaultLang(editions, ""); got != "en" {
		t.Errorf("defaultLang = %q, want en", got)
	}
	if got := defaultLang(editions, "vi"); got != "vi" {
		t.Errorf("an explicit request for vi was ignored: %q", got)
	}
	// A single-edition document shows without any switch.
	solo := RenderMulti(editions[:1], DocMeta{Title: "t", Generated: "now"})
	if strings.Contains(solo, `<div class="langbar">`) || strings.Contains(solo, `type="radio"`) {
		t.Error("a one-language report should not render a language switch")
	}
	if !strings.Contains(solo, "doc only") {
		t.Error("a one-language report must be visible without a radio selection")
	}
}


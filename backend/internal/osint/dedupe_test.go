package osint

import (
	"testing"

	"github.com/forensichub/backend/internal/models"
)

// TestNormValue checks the dedupe value canonicalisation: lower-cased, trimmed,
// and trailing dots stripped so a hostname surfaced with and without the FQDN
// trailing dot collapses to one key.
func TestNormValue(t *testing.T) {
	cases := map[string]string{
		"Example.COM.":   "example.com",
		"  host.tld  ":   "host.tld",
		"a.b.c...":       "a.b.c",
		"NoChange":       "nochange",
	}
	for in, want := range cases {
		if got := normValue(in); got != want {
			t.Errorf("normValue(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDedupeKeyCollapsesTrailingDot confirms the trailing-dot normalisation makes
// the same hostname from the same source dedupe to one key.
func TestDedupeKeyCollapsesTrailingDot(t *testing.T) {
	a := models.OsintFinding{Source: "crtsh", Category: "certificate", Title: "Subdomain", Value: "api.example.com"}
	b := models.OsintFinding{Source: "crtsh", Category: "certificate", Title: "Subdomain", Value: "api.example.com."}
	if dedupeKey(&a) != dedupeKey(&b) {
		t.Error("expected trailing-dot and bare hostname to share a dedupe key")
	}
	c := models.OsintFinding{Source: "crtsh", Category: "certificate", Title: "Subdomain", Value: "other.example.com"}
	if dedupeKey(&a) == dedupeKey(&c) {
		t.Error("distinct hostnames must not share a dedupe key")
	}
}

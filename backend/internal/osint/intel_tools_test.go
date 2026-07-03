package osint

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"

	"github.com/analysishub/backend/internal/models"
)

func TestGenerateEmailCandidates(t *testing.T) {
	cands := GenerateEmailCandidates("John Doe", "acme.com")
	if len(cands) == 0 {
		t.Fatal("expected candidates")
	}
	got := map[string]bool{}
	for _, c := range cands {
		got[c.Email] = true
		if !strings.HasSuffix(c.Email, "@acme.com") {
			t.Errorf("candidate not at domain: %s", c.Email)
		}
	}
	for _, want := range []string{"john.doe@acme.com", "johndoe@acme.com", "jdoe@acme.com", "john@acme.com"} {
		if !got[want] {
			t.Errorf("missing expected pattern %q", want)
		}
	}
}

func TestGenerateEmailCandidates_Diacritics(t *testing.T) {
	// Vietnamese name should fold to ASCII locals.
	cands := GenerateEmailCandidates("Nguyễn Văn Á", "corp.vn")
	for _, c := range cands {
		local := strings.TrimSuffix(c.Email, "@corp.vn")
		for _, r := range local {
			if r > 127 {
				t.Errorf("local part has non-ASCII rune: %q", c.Email)
			}
		}
	}
}

func TestGenerateHandleVariants(t *testing.T) {
	v := GenerateHandleVariants("john.doe")
	set := map[string]bool{}
	for _, x := range v {
		set[x] = true
		if x == "john.doe" {
			t.Error("variants must exclude the input itself")
		}
	}
	for _, want := range []string{"johndoe", "jdoe", "john_doe"} {
		if !set[want] {
			t.Errorf("missing expected variant %q (got %v)", want, v)
		}
	}
	if len(v) > 8 {
		t.Errorf("variant list should be bounded, got %d", len(v))
	}
}

// buildDOCX synthesises a minimal Office package with author metadata.
func buildDOCX(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	write := func(name, content string) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	write("word/document.xml", `<?xml version="1.0"?><document/>`)
	write("docProps/core.xml", `<?xml version="1.0"?>
<cp:coreProperties xmlns:cp="x" xmlns:dc="x">
<dc:creator>Jane Author</dc:creator>
<cp:lastModifiedBy>Bob Editor</cp:lastModifiedBy>
<dc:title>Secret Plan</dc:title>
</cp:coreProperties>`)
	write("docProps/app.xml", `<?xml version="1.0"?>
<Properties><Application>Microsoft Word</Application><Company>Acme Corp</Company></Properties>`)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestParseDocumentMetadata_DOCX(t *testing.T) {
	m := ParseDocumentMetadata(buildDOCX(t))
	if m.Format != "docx" {
		t.Errorf("format = %q want docx", m.Format)
	}
	if m.Creator != "Jane Author" || m.LastModBy != "Bob Editor" {
		t.Errorf("authors not parsed: %+v", m)
	}
	if m.Company != "Acme Corp" || m.Application != "Microsoft Word" {
		t.Errorf("app/company not parsed: %+v", m)
	}
	if !m.Found {
		t.Error("Found should be true")
	}
}

func TestParseDocumentMetadata_PDF(t *testing.T) {
	pdf := []byte("%PDF-1.7\n... /Author (Alice Smith) /Creator (LibreOffice) /Title (Report) ...")
	m := ParseDocumentMetadata(pdf)
	if m.Format != "pdf" {
		t.Errorf("format = %q want pdf", m.Format)
	}
	if m.Creator != "Alice Smith" || m.Application != "LibreOffice" {
		t.Errorf("pdf metadata not parsed: %+v", m)
	}
}

func TestParseDocumentMetadata_Unknown(t *testing.T) {
	if m := ParseDocumentMetadata([]byte("just text")); m.Found {
		t.Error("plain text must not yield metadata")
	}
}

func TestReverseImageLinks(t *testing.T) {
	links := ReverseImageLinks("https://example.com/a.jpg")
	if len(links) < 3 {
		t.Fatalf("expected several engines, got %d", len(links))
	}
	for _, l := range links {
		if !strings.Contains(l.URL, "example.com") {
			t.Errorf("engine %q did not embed the image URL: %s", l.Name, l.URL)
		}
	}
	if ReverseImageLinks("") != nil {
		t.Error("empty URL should yield no links")
	}
}

func TestComputeIdentityConfidence_TimezoneCorroboration(t *testing.T) {
	// Same timezone from two independent sources → a corroboration signal.
	findings := []models.OsintFinding{
		{Source: "geoip", Title: "Timezone", Value: "America/New_York"},
		{Source: "phone_meta", Title: "Timezone(s)", Value: "America/New_York, America/Detroit"},
	}
	ic := ComputeIdentityConfidence(findings)
	found := false
	for _, s := range ic.Signals {
		if s.Key == "timezone_consistent" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected timezone_consistent signal, got %+v", ic.Signals)
	}

	// A single source must NOT raise the signal.
	single := ComputeIdentityConfidence([]models.OsintFinding{
		{Source: "geoip", Title: "Timezone", Value: "America/New_York"},
	})
	for _, s := range single.Signals {
		if s.Key == "timezone_consistent" {
			t.Error("single-source timezone must not corroborate")
		}
	}
}

func TestComputeIdentityConfidence_AccountAge(t *testing.T) {
	// ≥2 "Account created" findings → the account_age timeline signal fires.
	findings := []models.OsintFinding{
		accountCreatedFinding("social_profile", "2019-03-01T00:00:00Z", "https://reddit.com/u/x"),
		accountCreatedFinding("github_intel", "2019-04-01T00:00:00Z", "https://github.com/x"),
	}
	ic := ComputeIdentityConfidence(findings)
	found := false
	for _, s := range ic.Signals {
		if s.Key == "account_age" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected account_age signal from 2 creation dates, got %+v", ic.Signals)
	}
}

func TestComputeIdentityConfidence(t *testing.T) {
	// No signals → minimal.
	if ic := ComputeIdentityConfidence(nil); ic.Grade != "minimal" || ic.Score != 0 {
		t.Errorf("empty graph should be minimal/0, got %+v", ic)
	}

	findings := []models.OsintFinding{
		{Source: "keybase", Title: "Proven twitter account - jdoe"},
		{Source: "keybase", Title: "Proven github account - jdoe"},
		{Source: "github_intel", Title: "GitHub login behind this e-mail - jdoe", Value: "jdoe"},
		{Source: "email_validate", Confidence: "verified", Title: "SMTP mailbox verification"},
		{Source: "x", Value: "avatar_phash:abc123", Title: "Avatar fingerprint"},
		// Duplicate keybase findings must NOT inflate the score beyond the single signal.
		{Source: "keybase", Title: "Proven reddit account - jdoe"},
	}
	ic := ComputeIdentityConfidence(findings)
	if ic.Score < 40 {
		t.Errorf("multiple strong independent signals should score moderate+, got %d", ic.Score)
	}
	if len(ic.Signals) == 0 {
		t.Error("expected signal breakdown")
	}
	// Independence: the keybase_proven signal appears once despite 3 findings.
	count := 0
	for _, s := range ic.Signals {
		if s.Key == "keybase_proven" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("keybase_proven should be a single independent signal, got %d", count)
	}
}

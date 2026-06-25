package handlers

import (
	"archive/zip"
	"bytes"
	"image"
	_ "image/png"
	"io"
	"strings"
	"testing"
)

// buildMinimalDocx returns a tiny but structurally-valid .docx (a Zip with the
// parts weaponizeDocx cares about). withRels toggles whether a
// word/_rels/document.xml.rels part is present.
func buildMinimalDocx(t *testing.T, withRels bool) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	zw := zip.NewWriter(buf)
	write := func(name, body string) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	write("[Content_Types].xml", `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>`)
	write("word/document.xml", `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Quarterly report</w:t></w:r></w:p></w:body></w:document>`)
	if withRels {
		write("word/_rels/document.xml.rels", `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>`)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// readZipEntry returns the bytes of a named entry inside a zip, or fails.
func readZipEntry(t *testing.T, data []byte, name string) (string, bool) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("output is not a valid zip: %v", err)
	}
	for _, f := range zr.File {
		if f.Name == name {
			rc, _ := f.Open()
			b, _ := io.ReadAll(rc)
			rc.Close()
			return string(b), true
		}
	}
	return "", false
}

func TestWeaponizeDocx_WithRels(t *testing.T) {
	const beacon = "https://promo-event.io/c/abc123XYZ0"
	out, err := weaponizeDocx(buildMinimalDocx(t, true), beacon)
	if err != nil {
		t.Fatalf("weaponizeDocx error: %v", err)
	}

	// Output must still be a valid zip preserving the original parts.
	if _, ok := readZipEntry(t, out, "[Content_Types].xml"); !ok {
		t.Error("original [Content_Types].xml was dropped")
	}

	doc, ok := readZipEntry(t, out, "word/document.xml")
	if !ok {
		t.Fatal("word/document.xml missing from output")
	}
	if !strings.Contains(doc, "Quarterly report") {
		t.Error("original document text was lost (file would read wrong)")
	}
	if !strings.Contains(doc, `r:link="`+canaryRelID+`"`) {
		t.Error("beacon drawing was not injected into document.xml")
	}
	if !strings.Contains(doc, "<w:body>") {
		t.Error("body element was corrupted")
	}

	rels, ok := readZipEntry(t, out, "word/_rels/document.xml.rels")
	if !ok {
		t.Fatal("relationships part missing from output")
	}
	if !strings.Contains(rels, canaryRelID) || !strings.Contains(rels, `TargetMode="External"`) {
		t.Error("external beacon relationship was not added")
	}
	if !strings.Contains(rels, "promo-event.io/c/abc123XYZ0") {
		t.Error("beacon URL missing from relationship target")
	}
}

func TestWeaponizeDocx_WithoutRels(t *testing.T) {
	const beacon = "https://x.test/c/slug0"
	out, err := weaponizeDocx(buildMinimalDocx(t, false), beacon)
	if err != nil {
		t.Fatalf("weaponizeDocx error: %v", err)
	}
	rels, ok := readZipEntry(t, out, "word/_rels/document.xml.rels")
	if !ok {
		t.Fatal("relationships part was not created for a doc that lacked one")
	}
	if !strings.Contains(rels, canaryRelID) {
		t.Error("beacon relationship missing from newly-created rels part")
	}
}

func TestWeaponizeDocx_RejectsNonDocx(t *testing.T) {
	if _, err := weaponizeDocx([]byte("not a zip at all"), "https://x/c/y"); err == nil {
		t.Error("expected error for non-zip input")
	}
	// A valid zip that isn't a Word doc must also be rejected.
	buf := &bytes.Buffer{}
	zw := zip.NewWriter(buf)
	w, _ := zw.Create("hello.txt")
	_, _ = w.Write([]byte("hi"))
	zw.Close()
	if _, err := weaponizeDocx(buf.Bytes(), "https://x/c/y"); err == nil {
		t.Error("expected error for a zip without word/document.xml")
	}
}

func TestPixelPNGIsValid1x1(t *testing.T) {
	cfg, format, err := image.DecodeConfig(bytes.NewReader(pixelPNG))
	if err != nil {
		t.Fatalf("pixelPNG is not a decodable image: %v", err)
	}
	if format != "png" {
		t.Errorf("pixel format = %q, want png", format)
	}
	if cfg.Width != 1 || cfg.Height != 1 {
		t.Errorf("pixel size = %dx%d, want 1x1", cfg.Width, cfg.Height)
	}
}

func TestCountryMatches(t *testing.T) {
	cases := []struct {
		code, name string
		want       bool
	}{
		{"VN", "Vietnam", true},
		{"US", "United States", true},
		{"US", "Russia", false},
		{"ZZ", "Nowhere", true}, // unknown code → no mismatch flag
		{"GB", "United Kingdom", true},
	}
	for _, c := range cases {
		if got := countryMatches(c.code, c.name); got != c.want {
			t.Errorf("countryMatches(%q,%q) = %v, want %v", c.code, c.name, got, c.want)
		}
	}
}

func TestCanaryKind(t *testing.T) {
	cases := map[string]string{
		"": "link", "link": "link", "image": "image", "IMAGE": "image",
		"document": "document", "docx": "document", "doc": "document", "weird": "link",
	}
	for in, want := range cases {
		if got := canaryKind(in); got != want {
			t.Errorf("canaryKind(%q) = %q, want %q", in, got, want)
		}
	}
}

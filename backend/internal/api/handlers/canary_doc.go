package handlers

import (
	"archive/zip"
	"bytes"
	"errors"
	"html"
	"io"
	"strings"
)

// canaryRelID is the relationship id used for the injected beacon image. It is
// deliberately high/namespaced so it cannot collide with ids a real authoring
// tool produced (those are sequential "rId1", "rId2", …).
const canaryRelID = "rId900900"

// docxContentType is the OOXML WordprocessingML document media type.
const docxContentType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

// errNotDocx is returned when the uploaded bytes are not a usable .docx (a Zip
// with a word/document.xml part).
var errNotDocx = errors.New("not a valid .docx document (expected an Office Open XML Word file)")

// weaponizeDocx returns a copy of a .docx with a 1×1 remote ("external") image
// embedded in the body, pointing at beaconURL. When the document is opened in
// Word the image is fetched from beaconURL, which the canary endpoint serves as
// a transparent pixel — recording the open without altering how the document
// reads. Every original part is preserved byte-for-byte except word/document.xml
// (gains the drawing) and word/_rels/document.xml.rels (gains the external
// relationship), so the file opens without a repair prompt.
//
// It only ever ADDS an inline drawing + an external relationship; it never
// touches [Content_Types].xml (external image links need no media part or
// content-type override), which keeps the package valid across Word versions.
func weaponizeDocx(orig []byte, beaconURL string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(orig), int64(len(orig)))
	if err != nil {
		return nil, errNotDocx
	}

	// Verify it really is a Word doc and locate the parts we rewrite.
	var hasDoc bool
	for _, f := range zr.File {
		if f.Name == "word/document.xml" {
			hasDoc = true
			break
		}
	}
	if !hasDoc {
		return nil, errNotDocx
	}

	out := &bytes.Buffer{}
	zw := zip.NewWriter(out)
	relsWritten := false

	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, err
		}

		switch f.Name {
		case "word/document.xml":
			data = injectDocumentDrawing(data)
		case "word/_rels/document.xml.rels":
			data = injectExternalRel(data, beaconURL)
			relsWritten = true
		}

		// Preserve the original compression method / metadata where practical.
		hdr := f.FileHeader
		w, err := zw.CreateHeader(&hdr)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(data); err != nil {
			return nil, err
		}
	}

	// A document with no relationships part has none on disk yet — create one so
	// the external image link resolves.
	if !relsWritten {
		w, err := zw.Create("word/_rels/document.xml.rels")
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(newRelsPart(beaconURL))); err != nil {
			return nil, err
		}
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// canaryDrawingXML is the inline picture run referencing the external beacon via
// r:link (external), not r:embed (a packaged media part). All non-`w` namespaces
// are declared inline on wp:inline so the snippet is valid regardless of which
// namespaces the host document declared on its root element.
const canaryDrawingXML = `<w:p><w:r><w:drawing>` +
	`<wp:inline xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" ` +
	`xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" ` +
	`xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture" ` +
	`xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" ` +
	`distT="0" distB="0" distL="0" distR="0">` +
	`<wp:extent cx="9525" cy="9525"/>` +
	`<wp:effectExtent l="0" t="0" r="0" b="0"/>` +
	`<wp:docPr id="900900" name="img900900"/>` +
	`<wp:cNvGraphicFramePr/>` +
	`<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">` +
	`<pic:pic><pic:nvPicPr><pic:cNvPr id="900900" name="img900900"/><pic:cNvPicPr/></pic:nvPicPr>` +
	`<pic:blipFill><a:blip r:link="` + canaryRelID + `"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>` +
	`<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="9525" cy="9525"/></a:xfrm>` +
	`<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>` +
	`</pic:pic></a:graphicData></a:graphic></wp:inline>` +
	`</w:drawing></w:r></w:p>`

// injectDocumentDrawing inserts the beacon drawing as the first block in the
// body. If <w:body> can't be located the document is returned unchanged (the
// caller still produces a valid, if non-beaconing, file rather than corrupting it).
func injectDocumentDrawing(doc []byte) []byte {
	s := string(doc)
	idx := strings.Index(s, "<w:body>")
	if idx < 0 {
		// Some writers emit attributes on the body element; match the open tag.
		if i := strings.Index(s, "<w:body"); i >= 0 {
			if j := strings.IndexByte(s[i:], '>'); j >= 0 {
				pos := i + j + 1
				return []byte(s[:pos] + canaryDrawingXML + s[pos:])
			}
		}
		return doc
	}
	pos := idx + len("<w:body>")
	return []byte(s[:pos] + canaryDrawingXML + s[pos:])
}

// injectExternalRel adds the external image relationship before </Relationships>.
func injectExternalRel(rels []byte, beaconURL string) []byte {
	s := string(rels)
	rel := `<Relationship Id="` + canaryRelID +
		`" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="` +
		html.EscapeString(beaconURL) + `" TargetMode="External"/>`
	if i := strings.LastIndex(s, "</Relationships>"); i >= 0 {
		return []byte(s[:i] + rel + s[i:])
	}
	// Malformed/empty rels — rebuild a minimal valid part.
	return []byte(newRelsPart(beaconURL))
}

// newRelsPart builds a complete document.xml.rels containing only the beacon
// relationship, used when the document had no relationships part at all.
func newRelsPart(beaconURL string) string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="` + canaryRelID +
		`" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="` +
		html.EscapeString(beaconURL) + `" TargetMode="External"/>` +
		`</Relationships>`
}

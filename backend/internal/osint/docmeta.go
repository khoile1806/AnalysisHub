package osint

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"regexp"
	"strings"
)

// docmeta.go — documents leak their author the way photos leak GPS. Office files
// (DOCX/XLSX/PPTX) embed the creator, last-editor, the authoring application and
// the company in docProps; PDFs carry Author/Creator/Producer in their Info
// dictionary. Extracting this from an evidence document often de-anonymises who
// really wrote it. Pure standard-library parsing, no external tools.

// DocMetadata is the author/tool metadata recovered from a document.
type DocMetadata struct {
	Format      string `json:"format"`            // docx | xlsx | pptx | pdf | unknown
	Creator     string `json:"creator,omitempty"` // original author
	LastModBy   string `json:"last_modified_by,omitempty"`
	Company     string `json:"company,omitempty"`
	Application string `json:"application,omitempty"` // authoring software
	Title       string `json:"title,omitempty"`
	Created     string `json:"created,omitempty"`
	Modified    string `json:"modified,omitempty"`
	Found       bool   `json:"found"`
}

// ParseDocumentMetadata dispatches on the file's magic bytes.
func ParseDocumentMetadata(data []byte) DocMetadata {
	switch {
	case len(data) >= 4 && data[0] == 'P' && data[1] == 'K' && (data[2] == 3 || data[2] == 5 || data[2] == 7):
		return parseOOXML(data)
	case len(data) >= 5 && string(data[:5]) == "%PDF-":
		return parsePDFMeta(data)
	}
	return DocMetadata{Format: "unknown"}
}

// parseOOXML reads docProps/core.xml + docProps/app.xml from an Office package.
func parseOOXML(data []byte) DocMetadata {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return DocMetadata{Format: "unknown"}
	}
	m := DocMetadata{Format: ooxmlFormat(zr)}

	if b := readZipEntry(zr, "docProps/core.xml"); b != nil {
		var core struct {
			Creator   string `xml:"creator"`
			LastModBy string `xml:"lastModifiedBy"`
			Title     string `xml:"title"`
			Created   string `xml:"created"`
			Modified  string `xml:"modified"`
		}
		if xml.Unmarshal(b, &core) == nil {
			m.Creator = strings.TrimSpace(core.Creator)
			m.LastModBy = strings.TrimSpace(core.LastModBy)
			m.Title = strings.TrimSpace(core.Title)
			m.Created = strings.TrimSpace(core.Created)
			m.Modified = strings.TrimSpace(core.Modified)
		}
	}
	if b := readZipEntry(zr, "docProps/app.xml"); b != nil {
		var app struct {
			Application string `xml:"Application"`
			Company     string `xml:"Company"`
		}
		if xml.Unmarshal(b, &app) == nil {
			m.Application = strings.TrimSpace(app.Application)
			m.Company = strings.TrimSpace(app.Company)
		}
	}
	m.Found = m.Creator != "" || m.LastModBy != "" || m.Company != "" || m.Application != ""
	return m
}

func ooxmlFormat(zr *zip.Reader) string {
	for _, f := range zr.File {
		switch {
		case strings.HasPrefix(f.Name, "word/"):
			return "docx"
		case strings.HasPrefix(f.Name, "xl/"):
			return "xlsx"
		case strings.HasPrefix(f.Name, "ppt/"):
			return "pptx"
		}
	}
	return "ooxml"
}

func readZipEntry(zr *zip.Reader, name string) []byte {
	for _, f := range zr.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				return nil
			}
			defer rc.Close()
			buf := new(bytes.Buffer)
			if _, err := buf.ReadFrom(io.LimitReader(rc, 1<<20)); err != nil {
				return nil
			}
			return buf.Bytes()
		}
	}
	return nil
}

// pdfMetaRe extracts simple /Key (value) pairs from a PDF Info dictionary.
var (
	pdfAuthor   = regexp.MustCompile(`/Author\s*\((.*?)\)`)
	pdfCreator  = regexp.MustCompile(`/Creator\s*\((.*?)\)`)
	pdfProducer = regexp.MustCompile(`/Producer\s*\((.*?)\)`)
	pdfTitle    = regexp.MustCompile(`/Title\s*\((.*?)\)`)
	pdfCreated  = regexp.MustCompile(`/CreationDate\s*\(D:(\d{8,14})`)
	pdfModified = regexp.MustCompile(`/ModDate\s*\(D:(\d{8,14})`)
)

// parsePDFMeta best-effort-extracts the Info dictionary fields from a PDF. It
// scans the raw bytes (PDF Info is plain text unless the file is encrypted),
// which covers the common case without a full PDF parser.
func parsePDFMeta(data []byte) DocMetadata {
	s := string(data)
	m := DocMetadata{Format: "pdf"}
	first := func(re *regexp.Regexp) string {
		if g := re.FindStringSubmatch(s); g != nil {
			return strings.TrimSpace(pdfUnescape(g[1]))
		}
		return ""
	}
	m.Creator = first(pdfAuthor)
	m.Application = firstNonEmptyStr(first(pdfCreator), first(pdfProducer))
	m.Title = first(pdfTitle)
	m.Created = first(pdfCreated)
	m.Modified = first(pdfModified)
	m.Found = m.Creator != "" || m.Application != "" || m.Title != ""
	return m
}

func pdfUnescape(s string) string {
	s = strings.ReplaceAll(s, `\(`, "(")
	s = strings.ReplaceAll(s, `\)`, ")")
	s = strings.ReplaceAll(s, `\\`, `\`)
	return s
}

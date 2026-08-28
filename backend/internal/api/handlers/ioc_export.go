package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/analysishub/backend/internal/models"
)

// ioc_export.go — getting indicators back out in the formats other tools read.
//
// The malware feature could already emit STIX, MISP, OpenIOC and Suricata for a
// single sample, but the IOC store — the place indicators accumulate from every
// source — could only be read through the UI. So the platform could share what
// it learned about one file and not what it knew overall, which is backwards:
// the store is the thing worth pushing to a SIEM or a partner.

const iocExportMax = 50000

// ExportIOCStore renders the store in a machine-readable format.
//
// GET /api/v1/iocs/export?format=stix|misp|csv|suricata&type=&source=&active=1
func ExportIOCStore(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}

	q := db.Model(&models.IOC{})
	// Default to active only: exporting retired indicators would push a partner's
	// sensor to alert on infrastructure this platform has already decided is
	// stale.
	if c.DefaultQuery("active", "1") != "0" {
		q = ActiveIOCs(q)
	}
	if t := strings.TrimSpace(c.Query("type")); t != "" {
		q = q.Where("type = ?", t)
	}
	if s := strings.TrimSpace(c.Query("source")); s != "" {
		q = q.Where("source = ?", s)
	}

	var rows []models.IOC
	if err := q.Order("id").Limit(iocExportMax).Find(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "database error"})
		return
	}

	stamp := time.Now().UTC().Format("20060102-150405")
	switch strings.ToLower(c.DefaultQuery("format", "csv")) {
	case "stix":
		send(c, "application/json", "iocs-"+stamp+".json", iocsToSTIX(rows))
	case "misp":
		send(c, "application/json", "iocs-"+stamp+"-misp.json", iocsToMISP(rows))
	case "suricata":
		send(c, "text/plain", "iocs-"+stamp+".rules", iocsToSuricata(rows))
	default:
		send(c, "text/csv", "iocs-"+stamp+".csv", iocsToCSV(rows))
	}
}

func send(c *gin.Context, mime, filename string, body []byte) {
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Data(http.StatusOK, mime, body)
}

// csvCell neutralises spreadsheet formula injection.
//
// The values in this store are attacker-controlled — a domain, a file name, a
// description copied out of a sample — and a cell beginning = + - or @ is
// executed by Excel when the export is opened. The analyst reading the report
// about the malware is exactly who gets hit.
func csvCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

func iocsToCSV(rows []models.IOC) []byte {
	var b strings.Builder
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"value", "type", "source", "confidence", "tlp", "campaign",
		"attck", "first_seen", "last_seen", "expires_at", "hit_count", "enabled", "description"})
	for _, r := range rows {
		expires := ""
		if r.ExpiresAt != nil {
			expires = r.ExpiresAt.UTC().Format(time.RFC3339)
		}
		_ = w.Write([]string{
			csvCell(r.Value), csvCell(r.Type), csvCell(r.Source),
			fmt.Sprint(r.Confidence), csvCell(r.TLP), csvCell(r.Campaign), csvCell(r.ATTCK),
			r.FirstSeen.UTC().Format(time.RFC3339), r.LastSeen.UTC().Format(time.RFC3339),
			expires, fmt.Sprint(r.HitCount), fmt.Sprint(r.Enabled), csvCell(r.Description),
		})
	}
	w.Flush()
	return []byte(b.String())
}

// stixPattern maps a store type to a STIX 2.1 pattern.
func stixPattern(t, v string) string {
	esc := strings.ReplaceAll(v, "'", "\\'")
	switch t {
	case "IPv4-Addr":
		return fmt.Sprintf("[ipv4-addr:value = '%s']", esc)
	case "IPv6-Addr":
		return fmt.Sprintf("[ipv6-addr:value = '%s']", esc)
	case "Domain-Name":
		return fmt.Sprintf("[domain-name:value = '%s']", esc)
	case "URL":
		return fmt.Sprintf("[url:value = '%s']", esc)
	case "Email-Address":
		return fmt.Sprintf("[email-addr:value = '%s']", esc)
	case "Mac-Addr":
		return fmt.Sprintf("[mac-addr:value = '%s']", esc)
	case "File-Hash":
		// The algorithm is implied by length, which is how every consumer reads it.
		switch len(v) {
		case 32:
			return fmt.Sprintf("[file:hashes.'MD5' = '%s']", esc)
		case 40:
			return fmt.Sprintf("[file:hashes.'SHA-1' = '%s']", esc)
		case 64:
			return fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", esc)
		}
		return fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", esc)
	}
	return ""
}

func iocsToSTIX(rows []models.IOC) []byte {
	objects := make([]map[string]interface{}, 0, len(rows)+1)
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	identity := "identity--" + uuid.NewSHA1(uuid.NameSpaceOID, []byte("analysishub")).String()
	objects = append(objects, map[string]interface{}{
		"type": "identity", "spec_version": "2.1", "id": identity,
		"created": now, "modified": now,
		"name": "AnalysisHub", "identity_class": "system",
	})

	for _, r := range rows {
		pattern := stixPattern(r.Type, r.Value)
		if pattern == "" {
			continue // a type with no STIX equivalent is omitted, not guessed at
		}
		obj := map[string]interface{}{
			"type": "indicator", "spec_version": "2.1",
			"id":                  "indicator--" + uuid.NewSHA1(uuid.NameSpaceOID, []byte(r.Type+"|"+r.Value)).String(),
			"created_by_ref":      identity,
			"created":             r.FirstSeen.UTC().Format("2006-01-02T15:04:05.000Z"),
			"modified":            r.LastSeen.UTC().Format("2006-01-02T15:04:05.000Z"),
			"name":                r.Value,
			"pattern":             pattern,
			"pattern_type":        "stix",
			"valid_from":          r.FirstSeen.UTC().Format("2006-01-02T15:04:05.000Z"),
			"confidence":          r.Confidence,
			"indicator_types":     []string{"malicious-activity"},
			"object_marking_refs": []string{tlpMarking(r.TLP)},
		}
		if r.ExpiresAt != nil {
			obj["valid_until"] = r.ExpiresAt.UTC().Format("2006-01-02T15:04:05.000Z")
		}
		if r.Description != "" {
			obj["description"] = r.Description
		}
		if r.ATTCK != "" {
			refs := make([]map[string]string, 0)
			for _, t := range strings.Split(r.ATTCK, ",") {
				if t = strings.TrimSpace(t); t != "" {
					refs = append(refs, map[string]string{
						"source_name": "mitre-attack", "external_id": t,
					})
				}
			}
			if len(refs) > 0 {
				obj["external_references"] = refs
			}
		}
		objects = append(objects, obj)
	}

	bundle := map[string]interface{}{
		"type": "bundle", "id": "bundle--" + uuid.NewString(), "objects": objects,
	}
	out, _ := json.MarshalIndent(bundle, "", "  ")
	return out
}

// tlpMarking returns the STIX 2.1 marking-definition id for a TLP label. The ids
// are fixed by the specification, not generated.
func tlpMarking(tlp string) string {
	switch strings.ToLower(strings.TrimSpace(tlp)) {
	case "white", "clear":
		return "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
	case "green":
		return "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
	case "red":
		return "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
	default: // amber
		return "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
	}
}

// mispType maps a store type to a MISP attribute type.
func mispType(t, v string) string {
	switch t {
	case "IPv4-Addr", "IPv6-Addr":
		return "ip-dst"
	case "Domain-Name":
		return "domain"
	case "URL":
		return "url"
	case "Email-Address":
		return "email-src"
	case "Mac-Addr":
		return "mac-address"
	case "File-Hash":
		switch len(v) {
		case 32:
			return "md5"
		case 40:
			return "sha1"
		default:
			return "sha256"
		}
	}
	return ""
}

func iocsToMISP(rows []models.IOC) []byte {
	attrs := make([]map[string]interface{}, 0, len(rows))
	for _, r := range rows {
		mt := mispType(r.Type, r.Value)
		if mt == "" {
			continue
		}
		a := map[string]interface{}{
			"type": mt, "value": r.Value, "category": "Network activity",
			"to_ids":    r.Confidence >= 70, // only confident indicators drive detection
			"comment":   strings.TrimSpace(r.Description + " (source: " + r.Source + ")"),
			"timestamp": fmt.Sprint(r.LastSeen.UTC().Unix()),
		}
		if mt == "md5" || mt == "sha1" || mt == "sha256" {
			a["category"] = "Payload delivery"
		}
		attrs = append(attrs, a)
	}
	event := map[string]interface{}{
		"Event": map[string]interface{}{
			"info":            "AnalysisHub IOC store export",
			"date":            time.Now().UTC().Format("2006-01-02"),
			"published":       false,
			"threat_level_id": "2",
			"analysis":        "2",
			"Attribute":       attrs,
		},
	}
	out, _ := json.MarshalIndent(event, "", "  ")
	return out
}

func iocsToSuricata(rows []models.IOC) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Suricata rules from the AnalysisHub IOC store — %s\n",
		time.Now().UTC().Format(time.RFC3339))
	b.WriteString("# SIDs start at 9200000 (local range) and are stable per indicator.\n\n")
	sid := 9200000
	// Strip the characters that would terminate a rule option early.
	esc := func(s string) string {
		return strings.NewReplacer(`"`, "", ";", "", "\\", "").Replace(s)
	}
	for _, r := range rows {
		msg := esc(fmt.Sprintf("AnalysisHub IOC %s (%s)", r.Value, r.Source))
		switch r.Type {
		case "IPv4-Addr", "IPv6-Addr":
			fmt.Fprintf(&b, `alert ip any any -> %s any (msg:"%s"; sid:%d; rev:1;)`+"\n",
				esc(r.Value), msg, sid)
		case "Domain-Name":
			fmt.Fprintf(&b, `alert dns any any -> any any (msg:"%s"; dns.query; content:"%s"; nocase; sid:%d; rev:1;)`+"\n",
				msg, esc(r.Value), sid)
		case "URL":
			path := esc(r.Value)
			if i := strings.Index(path, "://"); i >= 0 {
				path = path[i+3:]
			}
			fmt.Fprintf(&b, `alert http any any -> any any (msg:"%s"; http.uri; content:"%s"; nocase; sid:%d; rev:1;)`+"\n",
				msg, path, sid)
		default:
			continue
		}
		sid++
	}
	return []byte(b.String())
}

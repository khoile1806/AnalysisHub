// Package logsearch parses collected log files (evtx, web access, firewall,
// syslog, json, csv) into ECS-shaped documents and bulk-indexes them into the
// built-in Elasticsearch so they are searchable from the SIEM Threat Hunting
// page. It is the ingestion half that complements the existing ELK hunt client.
package logsearch

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Doc is one parsed log record. Field names follow ECS so the same query
// (e.g. source.ip:1.2.3.4) matches across every log type.
type Doc = map[string]interface{}

// EmitFunc receives each parsed document; returning an error stops parsing.
type EmitFunc func(Doc) error

// Known log types. "auto" asks DetectLogType to classify by content.
const (
	TypeAuto      = "auto"
	TypeEvtx      = "evtx"
	TypeAccess    = "access"
	TypeIIS       = "iis"
	TypeFortigate = "fortigate"
	TypeIptables  = "iptables"
	TypeCEF       = "cef"
	TypeSyslog    = "syslog"
	TypeJSON      = "json"
	TypeCSV       = "csv"
	TypePlaintext = "plaintext"
)

// LogTypes is the ordered list surfaced to the UI.
var LogTypes = []string{
	TypeAuto, TypeEvtx, TypeAccess, TypeIIS, TypeFortigate,
	TypeIptables, TypeCEF, TypeSyslog, TypeJSON, TypeCSV, TypePlaintext,
}

// LogTypeCategory maps a log type to its platform category, used for index
// naming (hunt-<category>-<case>-<type>) and grouping in the hunt UI.
var LogTypeCategory = map[string]string{
	TypeEvtx:      "windows",
	TypeSyslog:    "linux",
	TypeFortigate: "firewall",
	TypeIptables:  "firewall",
	TypeCEF:       "firewall",
	TypeAccess:    "web",
	TypeIIS:       "web",
	TypeJSON:      "app",
	TypeCSV:       "other",
	TypePlaintext: "other",
}

var evtxMagic = []byte("ElfFile\x00")

// openText opens a log file as a line reader, transparently gunzipping.
func openText(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	head := make([]byte, 2)
	n, _ := f.Read(head)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	if n == 2 && head[0] == 0x1f && head[1] == 0x8b {
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &gzReadCloser{gz: gz, f: f}, nil
	}
	return f, nil
}

type gzReadCloser struct {
	gz *gzip.Reader
	f  *os.File
}

func (g *gzReadCloser) Read(p []byte) (int, error) { return g.gz.Read(p) }
func (g *gzReadCloser) Close() error               { g.gz.Close(); return g.f.Close() }

// scanner returns a bufio.Scanner with a large line buffer (log lines can be
// long, e.g. FortiGate/Sysmon).
func scanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	return sc
}

// timeLayouts tried by toISO, most specific first.
var timeLayouts = []string{
	time.RFC3339Nano, time.RFC3339,
	"2006-01-02T15:04:05.999999999Z07:00",
	"2006-01-02 15:04:05.999999999Z07:00",
	"2006-01-02 15:04:05-07:00",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05",
	"02/Jan/2006:15:04:05 -0700",
	"2006/01/02 15:04:05",
	"01/02/2006 15:04:05",
	"Mon Jan 2 15:04:05 2006",
	"2006-01-02",
}

// toISO best-effort parses a timestamp string into RFC3339. Empty return means
// it could not be parsed.
func toISO(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.Format(time.RFC3339Nano)
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

// DetectLogType classifies a file by magic bytes then content sampling.
func DetectLogType(path, filename string) string {
	if f, err := os.Open(path); err == nil {
		head := make([]byte, 8)
		n, _ := f.Read(head)
		f.Close()
		if n == 8 && string(head) == string(evtxMagic) {
			return TypeEvtx
		}
	}

	sample := readSampleLines(path, 20)
	name := strings.ToLower(filename)

	if isJSONL(sample) {
		return TypeJSON
	}
	if anyMatch(sample, isIISHeader) {
		return TypeIIS
	}
	if anyMatch(sample, isCEFLine) {
		return TypeCEF
	}
	if countMatch(sample, isAccessLine) >= max(1, len(sample)/2) {
		return TypeAccess
	}
	if anyMatch(sample, isFortigateLine) {
		return TypeFortigate
	}
	if anyMatch(sample, isIptablesLine) {
		return TypeIptables
	}
	if countMatch(sample, isSyslogLine) >= max(1, len(sample)/2) {
		return TypeSyslog
	}
	if strings.HasSuffix(name, ".csv") || strings.HasSuffix(name, ".csv.gz") {
		return TypeCSV
	}
	return TypePlaintext
}

func readSampleLines(path string, maxLines int) []string {
	r, err := openText(path)
	if err != nil {
		return nil
	}
	defer r.Close()
	sc := scanner(r)
	var out []string
	for sc.Scan() && len(out) < maxLines {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func countMatch(lines []string, pred func(string) bool) int {
	n := 0
	for _, l := range lines {
		if pred(l) {
			n++
		}
	}
	return n
}

func anyMatch(lines []string, pred func(string) bool) bool {
	for _, l := range lines {
		if pred(l) {
			return true
		}
	}
	return false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Parse dispatches to the parser for the given (already-detected) log type,
// streaming documents to emit.
func Parse(path, logType string, emit EmitFunc) error {
	switch logType {
	case TypeEvtx:
		return parseEvtx(path, emit)
	case TypeAccess:
		return parseAccess(path, emit)
	case TypeIIS:
		return parseIIS(path, emit)
	case TypeCEF:
		return parseCEF(path, emit)
	case TypeFortigate:
		return parseFortigate(path, emit)
	case TypeIptables:
		return parseIptables(path, emit)
	case TypeSyslog:
		return parseSyslog(path, emit)
	case TypeJSON:
		return parseJSONL(path, emit)
	case TypeCSV:
		return parseCSV(path, emit)
	default:
		return parsePlaintext(path, emit)
	}
}

// ---------------------------------------------------------------------------
// Web access log (Apache/Nginx common & combined)
// ---------------------------------------------------------------------------

var accessRe = regexp.MustCompile(
	`^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+)(?: ([^"]*))?" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?`)

func isAccessLine(line string) bool { return accessRe.MatchString(line) }

func parseAccess(path string, emit EmitFunc) error {
	r, err := openText(path)
	if err != nil {
		return err
	}
	defer r.Close()
	sc := scanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		m := accessRe.FindStringSubmatch(line)
		if m == nil {
			if err := emit(Doc{"message": line, "event": Doc{"kind": "event", "outcome": "unparsed"}}); err != nil {
				return err
			}
			continue
		}
		resp := Doc{"status_code": atoiOr(m[7], 0)}
		if b, err := strconv.Atoi(m[8]); err == nil {
			resp["body"] = Doc{"bytes": b}
		}
		httpObj := Doc{
			"request":  Doc{"method": m[4]},
			"response": resp,
		}
		if v := strings.TrimPrefix(m[6], "HTTP/"); v != "" {
			httpObj["version"] = v
		}
		doc := Doc{
			"@timestamp": toISO(m[3]),
			"source":     Doc{"ip": m[1]},
			"http":       httpObj,
			"url":        Doc{"original": m[5]},
			"message":    line,
		}
		if m[2] != "" && m[2] != "-" {
			doc["user"] = Doc{"name": m[2]}
		}
		if m[9] != "" && m[9] != "-" {
			httpObj["request"].(Doc)["referrer"] = m[9]
		}
		if m[10] != "" && m[10] != "-" {
			doc["user_agent"] = Doc{"original": m[10]}
		}
		if err := emit(doc); err != nil {
			return err
		}
	}
	return sc.Err()
}

// ---------------------------------------------------------------------------
// FortiGate key=value
// ---------------------------------------------------------------------------

var kvRe = regexp.MustCompile(`(\w+)=("[^"]*"|\S+)`)

func kvParse(line string) map[string]string {
	out := map[string]string{}
	for _, m := range kvRe.FindAllStringSubmatch(line, -1) {
		out[m[1]] = strings.Trim(m[2], `"`)
	}
	return out
}

func isFortigateLine(line string) bool {
	kvs := kvParse(line)
	_, hasSrc := kvs["srcip"]
	_, hasDst := kvs["dstip"]
	_, hasDev := kvs["devname"]
	return hasSrc && (hasDst || hasDev)
}

var fortiFieldMap = map[string][2]string{
	"srcip":   {"source", "ip"},
	"srcport": {"source", "port"},
	"dstip":   {"destination", "ip"},
	"dstport": {"destination", "port"},
	"action":  {"event", "action"},
	"devname": {"observer", "name"},
	"srcintf": {"observer", "ingress_interface"},
	"dstintf": {"observer", "egress_interface"},
}

func parseFortigate(path string, emit EmitFunc) error {
	r, err := openText(path)
	if err != nil {
		return err
	}
	defer r.Close()
	sc := scanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		kvs := kvParse(line)
		if len(kvs) == 0 {
			if err := emit(Doc{"message": line, "event": Doc{"kind": "event", "outcome": "unparsed"}}); err != nil {
				return err
			}
			continue
		}
		var ts string
		if d, okd := kvs["date"]; okd {
			if t, okt := kvs["time"]; okt {
				ts = toISO(d + " " + t)
			}
		}
		if ts == "" {
			if et, ok := kvs["eventtime"]; ok {
				if ns, err := strconv.ParseInt(et, 10, 64); err == nil {
					if ns > 1e12 {
						ts = time.Unix(0, ns).UTC().Format(time.RFC3339Nano)
					} else {
						ts = time.Unix(ns, 0).UTC().Format(time.RFC3339Nano)
					}
				}
			}
		}
		forti := Doc{}
		doc := Doc{"@timestamp": ts, "message": line, "fortigate": forti}
		for k, v := range kvs {
			if mapped, ok := fortiFieldMap[k]; ok {
				top, sub := mapped[0], mapped[1]
				obj, _ := doc[top].(Doc)
				if obj == nil {
					obj = Doc{}
					doc[top] = obj
				}
				if sub == "port" {
					if p, err := strconv.Atoi(v); err == nil {
						obj[sub] = p
						continue
					}
				}
				obj[sub] = v
			} else {
				forti[k] = v
			}
		}
		if err := emit(doc); err != nil {
			return err
		}
	}
	return sc.Err()
}

// ---------------------------------------------------------------------------
// iptables / netfilter (over syslog)
// ---------------------------------------------------------------------------

var iptSrcRe = regexp.MustCompile(`\bSRC=(\S+) DST=(\S+)`)
var iptKvRe = regexp.MustCompile(`\b([A-Z]{2,10})=(\S*)`)

func isIptablesLine(line string) bool { return iptSrcRe.MatchString(line) }

func parseIptables(path string, emit EmitFunc) error {
	return parseSyslogInner(path, func(doc Doc) error {
		msg, _ := doc["message"].(string)
		kvs := map[string]string{}
		for _, m := range iptKvRe.FindAllStringSubmatch(msg, -1) {
			kvs[m[1]] = m[2]
		}
		if src, ok := kvs["SRC"]; ok {
			doc["source"] = Doc{"ip": src}
			doc["destination"] = Doc{"ip": kvs["DST"]}
			if p, err := strconv.Atoi(kvs["SPT"]); err == nil {
				doc["source"].(Doc)["port"] = p
			}
			if p, err := strconv.Atoi(kvs["DPT"]); err == nil {
				doc["destination"].(Doc)["port"] = p
			}
			if proto := kvs["PROTO"]; proto != "" {
				doc["network"] = Doc{"transport": strings.ToLower(proto)}
			}
			ipt := Doc{}
			for k, v := range kvs {
				if v != "" {
					ipt[strings.ToLower(k)] = v
				}
			}
			doc["iptables"] = ipt
		}
		return emit(doc)
	})
}

// ---------------------------------------------------------------------------
// Syslog (RFC3164) + SSH/sudo enrichment
// ---------------------------------------------------------------------------

var syslogRe = regexp.MustCompile(
	`^(?:<\d+>)?([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}:\d{2}:\d{2}) (\S+) ([^:\[\s]+)(?:\[(\d+)\])?:?\s?(.*)$`)

var months = map[string]time.Month{
	"Jan": time.January, "Feb": time.February, "Mar": time.March, "Apr": time.April,
	"May": time.May, "Jun": time.June, "Jul": time.July, "Aug": time.August,
	"Sep": time.September, "Oct": time.October, "Nov": time.November, "Dec": time.December,
}

func isSyslogLine(line string) bool { return syslogRe.MatchString(line) }

func parseSyslog(path string, emit EmitFunc) error {
	return parseSyslogInner(path, emit)
}

func parseSyslogInner(path string, emit EmitFunc) error {
	r, err := openText(path)
	if err != nil {
		return err
	}
	defer r.Close()
	now := time.Now().UTC()
	sc := scanner(r)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\n")
		if strings.TrimSpace(line) == "" {
			continue
		}
		m := syslogRe.FindStringSubmatch(line)
		if m == nil {
			if err := emit(Doc{"message": line, "event": Doc{"kind": "event", "outcome": "unparsed"}}); err != nil {
				return err
			}
			continue
		}
		var ts string
		if mon, ok := months[m[1]]; ok {
			day := atoiOr(m[2], 1)
			hms := strings.Split(m[3], ":")
			if len(hms) == 3 {
				dt := time.Date(now.Year(), mon, day, atoiOr(hms[0], 0), atoiOr(hms[1], 0), atoiOr(hms[2], 0), 0, time.UTC)
				if dt.After(now) {
					dt = dt.AddDate(-1, 0, 0)
				}
				ts = dt.Format(time.RFC3339Nano)
			}
		}
		tag := m[5]
		msg := m[7]
		if msg == "" {
			msg = line
		}
		doc := Doc{
			"@timestamp": ts,
			"host":       Doc{"name": m[4]},
			"process":    Doc{"name": tag},
			"message":    msg,
		}
		if m[6] != "" {
			doc["process"].(Doc)["pid"] = atoiOr(m[6], 0)
		}
		enrichAuth(doc, tag, msg)
		if err := emit(doc); err != nil {
			return err
		}
	}
	return sc.Err()
}

var (
	sshFailRe    = regexp.MustCompile(`Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)`)
	sshOKRe      = regexp.MustCompile(`Accepted (?:password|publickey|keyboard-interactive\S*) for (\S+) from (\S+) port (\d+)`)
	sshInvalidRe = regexp.MustCompile(`Invalid user (\S+) from (\S+)`)
	sudoRe       = regexp.MustCompile(`USER=(\S+)\s*;\s*COMMAND=(.+)$`)
)

func enrichAuth(doc Doc, tag, msg string) {
	if m := sshFailRe.FindStringSubmatch(msg); m != nil {
		doc["user"] = Doc{"name": m[1]}
		doc["source"] = Doc{"ip": m[2], "port": atoiOr(m[3], 0)}
		doc["event"] = Doc{"category": "authentication", "action": "ssh_login", "outcome": "failure", "kind": "event"}
		return
	}
	if m := sshOKRe.FindStringSubmatch(msg); m != nil {
		doc["user"] = Doc{"name": m[1]}
		doc["source"] = Doc{"ip": m[2], "port": atoiOr(m[3], 0)}
		doc["event"] = Doc{"category": "authentication", "action": "ssh_login", "outcome": "success", "kind": "event"}
		return
	}
	if m := sshInvalidRe.FindStringSubmatch(msg); m != nil {
		doc["user"] = Doc{"name": m[1]}
		doc["source"] = Doc{"ip": m[2]}
		doc["event"] = Doc{"category": "authentication", "action": "ssh_invalid_user", "outcome": "failure", "kind": "event"}
		return
	}
	if tag == "sudo" {
		if m := sudoRe.FindStringSubmatch(msg); m != nil {
			doc["event"] = Doc{"category": "process", "action": "sudo", "kind": "event"}
			proc, _ := doc["process"].(Doc)
			if proc == nil {
				proc = Doc{}
				doc["process"] = proc
			}
			proc["command_line"] = strings.TrimSpace(m[2])
			doc["user"] = Doc{"name": m[1]}
		}
	}
}

// ---------------------------------------------------------------------------
// JSON (NDJSON or a single JSON array of objects) + CSV
// ---------------------------------------------------------------------------

var timestampKeys = []string{
	"@timestamp", "timestamp", "Timestamp", "TimeCreated", "time", "Time",
	"datetime", "date", "eventTime", "event_time", "ts", "_time", "UtcTime",
}

func extractTimestamp(rec Doc) string {
	for _, k := range timestampKeys {
		v, ok := rec[k]
		if !ok || v == nil || v == "" {
			continue
		}
		switch t := v.(type) {
		case float64:
			secs := t
			if secs > 1e11 {
				secs = secs / 1000
			}
			return time.Unix(int64(secs), 0).UTC().Format(time.RFC3339Nano)
		case string:
			if iso := toISO(t); iso != "" {
				return iso
			}
		}
	}
	return ""
}

func isJSONL(sample []string) bool {
	if len(sample) == 0 {
		return false
	}
	first := strings.TrimSpace(sample[0])
	if strings.HasPrefix(first, "{") {
		var obj map[string]interface{}
		return json.Unmarshal([]byte(sample[0]), &obj) == nil
	}
	if strings.HasPrefix(first, "[") {
		for _, l := range sample[1:] {
			s := strings.TrimSpace(l)
			if strings.HasPrefix(s, "{") || strings.HasPrefix(s, `"`) || strings.HasPrefix(s, "]") {
				return true
			}
		}
	}
	return false
}

func parseJSONL(path string, emit EmitFunc) error {
	r, err := openText(path)
	if err != nil {
		return err
	}
	defer r.Close()
	buf, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	trimmed := strings.TrimSpace(string(buf))
	var records []Doc
	if strings.HasPrefix(trimmed, "[") {
		var arr []Doc
		if json.Unmarshal(buf, &arr) == nil {
			records = arr
		}
	}
	if records == nil {
		for _, line := range strings.Split(string(buf), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var obj Doc
			if json.Unmarshal([]byte(line), &obj) == nil {
				records = append(records, obj)
			}
		}
	}
	for _, rec := range records {
		if ts := extractTimestamp(rec); ts != "" {
			rec["@timestamp"] = ts
		}
		if err := emit(rec); err != nil {
			return err
		}
	}
	return nil
}

func parseCSV(path string, emit EmitFunc) error {
	r, err := openText(path)
	if err != nil {
		return err
	}
	defer r.Close()
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	header, err := cr.Read()
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}
	for {
		row, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		rec := Doc{}
		for i, col := range header {
			if i < len(row) && col != "" && row[i] != "" {
				rec[col] = row[i]
			}
		}
		if ts := extractTimestamp(rec); ts != "" {
			rec["@timestamp"] = ts
		}
		if err := emit(rec); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Plaintext fallback
// ---------------------------------------------------------------------------

var leadingTSRe = regexp.MustCompile(
	`^[\[\(]?(\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)`)

func parsePlaintext(path string, emit EmitFunc) error {
	r, err := openText(path)
	if err != nil {
		return err
	}
	defer r.Close()
	sc := scanner(r)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\n")
		if strings.TrimSpace(line) == "" {
			continue
		}
		doc := Doc{"message": line}
		if m := leadingTSRe.FindStringSubmatch(line); m != nil {
			if iso := toISO(strings.ReplaceAll(m[1], ",", ".")); iso != "" {
				doc["@timestamp"] = iso
			}
		}
		if err := emit(doc); err != nil {
			return err
		}
	}
	return sc.Err()
}

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

// Sanitize turns an arbitrary case/type string into an index-name-safe segment.
func Sanitize(part string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(part) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
		} else if !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "default"
	}
	return out
}

// baseName is used by the EVTX parser for process.name from an executable path.
func baseName(p string) string {
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, "\\", "/")
	return filepath.Base(p)
}

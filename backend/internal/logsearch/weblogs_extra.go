package logsearch

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// cefKeyRe matches a CEF extension key ("word=") optionally preceded by space.
var cefKeyRe = regexp.MustCompile(`(?:^|\s)[A-Za-z][A-Za-z0-9_]*=`)

func epochMillisToISO(ms int64) string {
	return time.Unix(0, ms*int64(time.Millisecond)).UTC().Format(time.RFC3339Nano)
}

// ---------------------------------------------------------------------------
// IIS / W3C Extended Log Format
//
//   #Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port
//            cs-username c-ip cs(User-Agent) sc-status ...
// Data lines are space-separated values in that column order. Common IIS fields
// are lifted to ECS; everything is kept under iis.*.
// ---------------------------------------------------------------------------

func isIISHeader(line string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "#fields:")
}

var iisFieldMap = map[string]string{
	"c-ip":           "source.ip",
	"s-ip":           "destination.ip",
	"cs-method":      "http.request.method",
	"sc-status":      "http.response.status_code",
	"cs-username":    "user.name",
	"cs(user-agent)": "user_agent.original",
	"cs(referer)":    "http.request.referrer",
	"cs-host":        "url.domain",
}

func parseIIS(path string, emit EmitFunc) error {
	r, err := openText(path)
	if err != nil {
		return err
	}
	defer r.Close()
	sc := scanner(r)
	var fields []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if isIISHeader(line) {
				fields = strings.Fields(strings.TrimSpace(line[len("#Fields:"):]))
			}
			continue
		}
		if len(fields) == 0 {
			continue
		}
		vals := strings.Fields(line)
		iis := Doc{}
		doc := Doc{"message": line, "iis": iis, "event": Doc{"kind": "event"}}
		var date, timeStr, uriStem, uriQuery string
		for i, f := range fields {
			if i >= len(vals) {
				break
			}
			v := vals[i]
			if v == "-" || v == "" {
				continue
			}
			key := strings.ToLower(f)
			switch key {
			case "date":
				date = v
			case "time":
				timeStr = v
			case "cs-uri-stem":
				uriStem = v
			case "cs-uri-query":
				uriQuery = v
			}
			if ecs, ok := iisFieldMap[key]; ok {
				if strings.HasSuffix(ecs, "status_code") {
					assignNested(doc, strings.Split(ecs, "."), atoiOr(v, 0))
				} else {
					assignNested(doc, strings.Split(ecs, "."), v)
				}
			}
			iis[f] = v
		}
		if date != "" && timeStr != "" {
			doc["@timestamp"] = toISO(date + "T" + timeStr + "Z")
		}
		if uriStem != "" {
			url := uriStem
			if uriQuery != "" && uriQuery != "-" {
				url += "?" + uriQuery
			}
			assignNested(doc, []string{"url", "original"}, url)
		}
		if err := emit(doc); err != nil {
			return err
		}
	}
	return sc.Err()
}

// ---------------------------------------------------------------------------
// CEF (Common Event Format) — appliances/IDS/firewalls
//
//   CEF:Version|Vendor|Product|PVersion|SignatureID|Name|Severity|k=v k=v …
// An optional syslog header may precede "CEF:". The extension key=values are
// mapped to ECS where known; the rest is kept under cef.*.
// ---------------------------------------------------------------------------

func isCEFLine(line string) bool {
	return strings.Contains(line, "CEF:")
}

var cefFieldMap = map[string]string{
	"src":   "source.ip",
	"spt":   "source.port",
	"dst":   "destination.ip",
	"dpt":   "destination.port",
	"suser": "source.user.name",
	"duser": "user.name",
	"act":   "event.action",
	"proto": "network.transport",
	"dhost": "destination.domain",
}

func parseCEF(path string, emit EmitFunc) error {
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
		idx := strings.Index(line, "CEF:")
		if idx < 0 {
			if err := emit(Doc{"message": line, "event": Doc{"kind": "event", "outcome": "unparsed"}}); err != nil {
				return err
			}
			continue
		}
		// split header into 8 parts: CEF:Ver|Vendor|Product|PVer|SigID|Name|Sev|Extension
		parts := strings.SplitN(line[idx:], "|", 8)
		cef := Doc{}
		doc := Doc{"message": line, "cef": cef, "event": Doc{"kind": "event"}}
		if len(parts) >= 7 {
			cef["vendor"] = parts[1]
			cef["product"] = parts[2]
			cef["signature_id"] = parts[4]
			cef["name"] = parts[5]
			assignNested(doc, []string{"observer", "vendor"}, parts[1])
			assignNested(doc, []string{"observer", "product"}, parts[2])
			assignNested(doc, []string{"event", "severity"}, parts[6])
		}
		if len(parts) == 8 {
			for k, v := range cefExtension(parts[7]) {
				if ecs, ok := cefFieldMap[k]; ok {
					if strings.HasSuffix(ecs, "port") {
						if p, e := strconv.Atoi(v); e == nil {
							assignNested(doc, strings.Split(ecs, "."), p)
							continue
						}
					}
					assignNested(doc, strings.Split(ecs, "."), v)
				} else if k == "rt" {
					// receipt time, epoch millis
					if ms, e := strconv.ParseInt(v, 10, 64); e == nil {
						doc["@timestamp"] = epochMillisToISO(ms)
					}
				} else if k == "msg" {
					doc["message"] = v
				} else {
					cef[k] = v
				}
			}
		}
		if err := emit(doc); err != nil {
			return err
		}
	}
	return sc.Err()
}

// cefExtension parses "k=v k=v" honouring backslash-escaped '=' and '\' and
// spaces inside values (CEF escapes them as \= \\ and keeps spaces in values).
func cefExtension(s string) map[string]string {
	out := map[string]string{}
	// Find keys as tokens matching `\bword=`; split on the position before each key.
	tokens := cefKeyRe.FindAllStringIndex(s, -1)
	for i, t := range tokens {
		keyStart := t[0]
		eq := t[1] - 1 // position of '='
		key := strings.TrimSpace(s[keyStart:eq])
		valStart := t[1]
		valEnd := len(s)
		if i+1 < len(tokens) {
			valEnd = tokens[i+1][0]
		}
		val := strings.TrimSpace(s[valStart:valEnd])
		val = strings.NewReplacer(`\=`, "=", `\\`, `\`, `\n`, "\n").Replace(val)
		if key != "" {
			out[key] = val
		}
	}
	return out
}

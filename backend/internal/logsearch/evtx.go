package logsearch

import (
	"fmt"
	"strings"
	"time"

	"github.com/0xrawsec/golang-evtx/evtx"
)

// parseEvtx streams Windows Event Log records as ECS documents. It lifts the
// most useful Security/Sysmon EventData fields to ECS top-level so IOC pivots
// (source.ip, user.name, process.*) work across every source, while keeping the
// original values under winlog.event_data.*.
func parseEvtx(path string, emit EmitFunc) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("evtx parse panic: %v", r)
		}
	}()

	ef, err := evtx.OpenDirty(path)
	if err != nil {
		return fmt.Errorf("open evtx: %w", err)
	}

	for e := range ef.FastEvents() {
		if e == nil {
			continue
		}
		raw := map[string]interface{}(*e)
		event, _ := asMap(raw["Event"])
		if event == nil {
			continue
		}
		system, _ := asMap(event["System"])
		if system == nil {
			continue
		}

		computer := scalarStr(system["Computer"])
		providerName := ""
		if prov, ok := asMap(system["Provider"]); ok {
			providerName = scalarStr(prov["Name"])
		}

		winlog := Doc{
			"channel":       scalarStr(system["Channel"]),
			"computer_name": computer,
			"provider_name": providerName,
			"record_id":     scalarStr(system["EventRecordID"]),
			"task":          scalarStr(system["Task"]),
			"opcode":        scalarStr(system["Opcode"]),
			"level":         scalarStr(system["Level"]),
		}
		pruneEmpty(winlog)

		eventObj := Doc{"kind": "event"}
		if code := scalarStr(system["EventID"]); code != "" {
			eventObj["code"] = code
		}
		if providerName != "" {
			eventObj["provider"] = providerName
		}

		doc := Doc{
			"@timestamp": evtxTimestamp(system),
			"event":      eventObj,
			"winlog":     winlog,
		}
		if computer != "" {
			doc["host"] = Doc{"name": computer}
		}

		ed := flattenEventData(event["EventData"])
		if len(ed) > 0 {
			winlog["event_data"] = ed
			applyECS(doc, ed)
		}

		if err := emit(doc); err != nil {
			return err
		}
	}
	return nil
}

func evtxTimestamp(system map[string]interface{}) string {
	tc, ok := asMap(system["TimeCreated"])
	if !ok {
		return ""
	}
	st := tc["SystemTime"]
	if ut, ok := st.(evtx.UTCTime); ok {
		return time.Time(ut).UTC().Format(time.RFC3339Nano)
	}
	return toISO(scalarStr(st))
}

// flattenEventData renders <Data Name="X">Y</Data> (however the library shapes
// it) into a flat map[string]string.
func flattenEventData(v interface{}) map[string]string {
	out := map[string]string{}
	m, ok := asMap(v)
	if !ok {
		if v != nil {
			if s := scalarStr(v); s != "" {
				out["Data"] = s
			}
		}
		return out
	}
	for k, val := range m {
		if strings.HasPrefix(k, "#") {
			continue
		}
		if s := scalarStr(val); s != "" {
			out[k] = s
		}
	}
	return out
}

// ECS lift map: EventData keys (checked case-insensitively) → ECS setter.
func applyECS(doc Doc, ed map[string]string) {
	ci := map[string]string{}
	for k, v := range ed {
		ci[strings.ToLower(k)] = v
	}
	first := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := ci[strings.ToLower(k)]; ok && v != "" && v != "-" {
				return v
			}
		}
		return ""
	}

	setPath(doc, "user.name", first("TargetUserName", "SubjectUserName", "User", "AccountName", "SamAccountName"))
	setPath(doc, "user.domain", first("TargetDomainName", "SubjectDomainName"))
	setPath(doc, "source.user.name", first("SubjectUserName"))
	setPath(doc, "source.ip", first("IpAddress", "SourceIp", "ClientAddress", "SourceNetworkAddress"))
	setPathInt(doc, "source.port", first("IpPort", "SourcePort"))
	setPath(doc, "destination.ip", first("DestinationIp", "DestAddress"))
	setPathInt(doc, "destination.port", first("DestinationPort", "DestPort"))
	setPath(doc, "network.transport", first("Protocol"))

	image := first("NewProcessName", "Image", "ProcessName", "Application")
	setPath(doc, "process.executable", image)
	setPath(doc, "process.name", baseName(image))
	setPath(doc, "process.command_line", first("CommandLine", "ProcessCommandLine"))
	parent := first("ParentImage", "ParentProcessName", "CreatorProcessName")
	setPath(doc, "process.parent.executable", parent)
	setPath(doc, "process.parent.name", baseName(parent))

	setPath(doc, "file.path", first("TargetFilename", "Filename"))
	setPath(doc, "registry.path", first("TargetObject"))
}

// ---- small helpers ----

// asMap normalises the several map shapes the evtx library emits — plain
// map[string]interface{} and its named type evtx.GoEvtxMap — into a plain map.
func asMap(v interface{}) (map[string]interface{}, bool) {
	switch m := v.(type) {
	case map[string]interface{}:
		return m, true
	case evtx.GoEvtxMap:
		return map[string]interface{}(m), true
	}
	return nil, false
}

// scalarStr coerces an event value to a display string. EventData/System values
// may be scalars or wrapper maps like {"Value": ...}.
func scalarStr(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return fmt.Sprintf("%t", t)
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	case int, int64, uint, uint64:
		return fmt.Sprintf("%d", t)
	default:
		if m, ok := asMap(v); ok {
			if val, ok := m["Value"]; ok {
				return scalarStr(val)
			}
			if val, ok := m["#text"]; ok {
				return scalarStr(val)
			}
			return ""
		}
		return fmt.Sprintf("%v", t)
	}
}

var emptyECS = map[string]bool{"": true, "-": true, "::": true, "0.0.0.0": true, "::1": true}

func setPath(doc Doc, path, value string) {
	value = strings.TrimSpace(value)
	if emptyECS[value] {
		return
	}
	assignNested(doc, strings.Split(path, "."), value)
}

func setPathInt(doc Doc, path, value string) {
	value = strings.TrimSpace(value)
	if emptyECS[value] {
		return
	}
	if n := atoiOr(value, -1); n >= 0 {
		assignNested(doc, strings.Split(path, "."), n)
	}
}

func assignNested(doc Doc, parts []string, value interface{}) {
	cur := doc
	for _, p := range parts[:len(parts)-1] {
		next, ok := cur[p].(Doc)
		if !ok {
			next = Doc{}
			cur[p] = next
		}
		cur = next
	}
	cur[parts[len(parts)-1]] = value
}

func pruneEmpty(m Doc) {
	for k, v := range m {
		if s, ok := v.(string); ok && s == "" {
			delete(m, k)
		}
	}
}

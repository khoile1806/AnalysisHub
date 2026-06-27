package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/forensichub/backend/internal/models"
)

// superMaxPerSource caps how many events one artifact source may contribute, so
// a 100k-entry MFT dump cannot flood the timeline.
const superMaxPerSource = 2000

// superEvent is a normalized, time-anchored event extracted from a raw
// EdgeForensics artifact, ready to become a models.TimelineEvent.
type superEvent struct {
	EventTime time.Time
	Title     string
	Detail    string
	Severity  string
	Value     string // IOC candidate (hash / path)
	IOCType   string
}

// artifactSource is one EdgeForensics result block in a build request.
type artifactSource struct {
	Type string          `json:"type"` // mft | prefetch | shimcache | processes | evtx
	Data json.RawMessage `json:"data"` // raw JSON returned by the agent
}

// BuildSuperTimeline explodes one or more raw EdgeForensics artifact result
// sets into normalized, chronologically-anchored timeline events on a case —
// turning scattered live-response output (MFT, Prefetch, Shimcache, processes,
// EVTX) into one unified attack timeline in a single call.
//
// POST /api/v1/cases/:id/timeline/build-super
//
//	{
//	  "host": "WS-01",
//	  "only_suspicious": true,
//	  "sources": [ { "type": "mft", "data": <raw> }, { "type": "prefetch", "data": <raw> } ]
//	}
func (h *TimelineHandler) BuildSuperTimeline(c *gin.Context) {
	caseID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case id"})
		return
	}
	var caseObj models.Case
	if err := h.DB.First(&caseObj, "id = ?", caseID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "case not found"})
		return
	}

	var body struct {
		Host           string           `json:"host"`
		OnlySuspicious bool             `json:"only_suspicious"`
		Sources        []artifactSource `json:"sources"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	if len(body.Sources) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "no sources supplied"})
		return
	}

	var userUUID uuid.UUID
	if v, ok := c.Get("userID"); ok {
		if uid, perr := uuid.Parse(v.(string)); perr == nil {
			userUUID = uid
		}
	}
	host := strings.TrimSpace(body.Host)

	perSource := map[string]int{}
	created := 0
	skipped := 0
	for _, src := range body.Sources {
		typ := strings.ToLower(strings.TrimSpace(src.Type))
		events := normalizeArtifact(typ, src.Data, body.OnlySuspicious)
		for _, ev := range events {
			tev := models.TimelineEvent{
				CaseID:    caseID,
				EventTime: ev.EventTime,
				Source:    "edge:" + typ,
				Host:      host,
				Severity:  ev.Severity,
				Title:     ev.Title,
				Detail:    ev.Detail,
				CreatedBy: userUUID,
			}
			if !insertAutoTimelineEvent(h.DB, &tev) {
				skipped++ // duplicate (idempotent re-run) or insert error
				continue
			}
			created++
			perSource[typ]++
		}
	}

	writeAudit(c, h.DB, &userUUID, nil, "timeline.build_super", caseID.String(),
		fmt.Sprintf("host=%s created=%d", host, created))

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"events_created": created,
		"skipped":        skipped,
		"per_source":     perSource,
	}})
}

// SuperTimeline returns a case's full merged timeline (all sources, sorted) plus
// aggregates that drive the unified timeline view: counts by source and
// severity, the host list, and the overall time span.
//
// GET /api/v1/cases/:id/timeline/super
func (h *TimelineHandler) SuperTimeline(c *gin.Context) {
	caseID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case id"})
		return
	}

	var events []models.TimelineEvent
	h.DB.Where("case_id = ?", caseID).Order("event_time asc").Find(&events)

	bySource := map[string]int{}
	bySeverity := map[string]int{}
	hostSet := map[string]struct{}{}
	var first, last time.Time
	for _, e := range events {
		bySource[e.Source]++
		bySeverity[e.Severity]++
		if h := strings.TrimSpace(e.Host); h != "" {
			hostSet[h] = struct{}{}
		}
		if first.IsZero() || e.EventTime.Before(first) {
			first = e.EventTime
		}
		if last.IsZero() || e.EventTime.After(last) {
			last = e.EventTime
		}
	}
	hosts := make([]string, 0, len(hostSet))
	for h := range hostSet {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"events": events,
		"summary": gin.H{
			"total":       len(events),
			"by_source":   bySource,
			"by_severity": bySeverity,
			"hosts":       hosts,
			"first_event": timeOrNil(first),
			"last_event":  timeOrNil(last),
		},
	}})
}

func timeOrNil(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t
}

// normalizeArtifact converts a raw EdgeForensics artifact payload into
// time-anchored events. Entries without a usable timestamp are dropped (they
// belong on the artifact view, not the timeline). When onlySuspicious is true,
// only flagged entries are emitted.
func normalizeArtifact(typ string, raw json.RawMessage, onlySuspicious bool) []superEvent {
	rows := decodeArtifactRows(raw)
	if len(rows) == 0 {
		return nil
	}

	var out []superEvent
	for _, row := range rows {
		if len(out) >= superMaxPerSource {
			break
		}
		susp := suspiciousMarkers(row)
		isSusp := len(susp) > 0
		if onlySuspicious && !isSusp {
			continue
		}
		sev := "info"
		if isSusp {
			sev = "high"
		}

		switch typ {
		case "mft":
			t := parseArtifactTime(row["created"])
			if t.IsZero() {
				t = parseArtifactTime(row["mod_time"])
			}
			if t.IsZero() {
				continue
			}
			name := str(row["name"])
			path := str(row["file_path"])
			out = append(out, superEvent{
				EventTime: t,
				Severity:  sev,
				Title:     "File created: " + firstNonBlank(name, path),
				Detail:    joinDetail("path="+path, "sha256="+str(row["sha256"]), suspDetail(susp)),
				Value:     str(row["sha256"]),
				IOCType:   "File-Hash",
			})

		case "prefetch":
			exe := firstNonBlank(str(row["executable"]), str(row["exe_path"]))
			// Expand each recorded run into its own event.
			runs := timeList(row["last_run_times"])
			if len(runs) == 0 {
				if t := parseArtifactTime(row["last_run_time"]); !t.IsZero() {
					runs = []time.Time{t}
				}
			}
			for _, t := range runs {
				if len(out) >= superMaxPerSource {
					break
				}
				out = append(out, superEvent{
					EventTime: t,
					Severity:  sev,
					Title:     "Program executed: " + exe,
					Detail:    joinDetail("run_count="+str(row["run_count"]), "sha256="+str(row["sha256"]), suspDetail(susp)),
					Value:     str(row["sha256"]),
					IOCType:   "File-Hash",
				})
			}

		case "shimcache":
			t := parseArtifactTime(row["last_modified"])
			if t.IsZero() {
				continue
			}
			path := str(row["path"])
			out = append(out, superEvent{
				EventTime: t,
				Severity:  sev,
				Title:     "Execution evidence (Shimcache): " + firstNonBlank(str(row["name"]), path),
				Detail:    joinDetail("path="+path, suspDetail(susp)),
				Value:     path,
				IOCType:   "File-Path",
			})

		case "processes", "process":
			t := parseArtifactTime(row["created"])
			if t.IsZero() {
				continue
			}
			name := str(row["name"])
			out = append(out, superEvent{
				EventTime: t,
				Severity:  sev,
				Title:     fmt.Sprintf("Process started: %s (pid %s)", name, str(row["pid"])),
				Detail:    joinDetail("cmdline="+str(row["cmdline"]), "user="+str(row["user"]), "parent="+str(row["parent_name"]), suspDetail(susp)),
				Value:     str(row["sha256"]),
				IOCType:   "File-Hash",
			})

		case "evtx":
			t := parseArtifactTime(firstPresent(row, "time_created", "timestamp", "time", "@timestamp"))
			if t.IsZero() {
				continue
			}
			title := firstNonBlank(str(row["message"]), str(row["event_id"]), "Windows event")
			if len(title) > 160 {
				title = title[:160] + "…"
			}
			out = append(out, superEvent{
				EventTime: t,
				Severity:  sev,
				Title:     "Log: " + title,
				Detail:    joinDetail("event_id="+str(row["event_id"]), "channel="+str(row["channel"]), "provider="+str(row["provider"])),
			})
		}
	}
	return out
}

// decodeArtifactRows tolerantly turns a raw payload into a list of row maps,
// accepting a top-level array, a single object, or an object wrapping the rows
// under a common key (entries/results/items/data/events).
func decodeArtifactRows(raw json.RawMessage) []map[string]interface{} {
	raw = json.RawMessage(strings.TrimSpace(string(raw)))
	if len(raw) == 0 {
		return nil
	}
	var arr []map[string]interface{}
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil
	}
	for _, key := range []string{"entries", "results", "items", "data", "events", "records"} {
		if v, ok := obj[key].([]interface{}); ok {
			return toRowMaps(v)
		}
	}
	// A single object is one row.
	return []map[string]interface{}{obj}
}

func toRowMaps(v []interface{}) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(v))
	for _, item := range v {
		if m, ok := item.(map[string]interface{}); ok {
			out = append(out, m)
		}
	}
	return out
}

// suspiciousMarkers returns the suspicious reasons on a row, handling both the
// []string form (mft/shimcache/process) and the bool form (prefetch).
func suspiciousMarkers(row map[string]interface{}) []string {
	switch v := row["suspicious"].(type) {
	case []interface{}:
		var s []string
		for _, x := range v {
			s = append(s, str(x))
		}
		return s
	case bool:
		if v {
			return []string{"flagged"}
		}
	case string:
		if v != "" {
			return []string{v}
		}
	}
	return nil
}

// parseArtifactTime parses a timestamp from a string (multiple layouts) or a
// numeric epoch. A zero/empty value yields the zero time.
func parseArtifactTime(v interface{}) time.Time {
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(t)
		if s == "" || strings.HasPrefix(s, "0001-01-01") {
			return time.Time{}
		}
		for _, layout := range []string{
			time.RFC3339Nano, time.RFC3339,
			"2006-01-02T15:04:05.000Z", "2006-01-02 15:04:05",
			"2006-01-02 15:04:05.000", "01/02/2006 15:04:05",
		} {
			if parsed, err := time.Parse(layout, s); err == nil {
				return parsed
			}
		}
	case float64:
		if t <= 0 {
			return time.Time{}
		}
		if t > 1e12 {
			return time.UnixMilli(int64(t))
		}
		return time.Unix(int64(t), 0)
	}
	return time.Time{}
}

func timeList(v interface{}) []time.Time {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	var out []time.Time
	for _, item := range arr {
		if t := parseArtifactTime(item); !t.IsZero() {
			out = append(out, t)
		}
	}
	return out
}

func firstPresent(row map[string]interface{}, keys ...string) interface{} {
	for _, k := range keys {
		if v, ok := row[k]; ok {
			return v
		}
	}
	return nil
}

func str(v interface{}) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case float64:
		// Render integers without a trailing ".000000".
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%v", x)
	default:
		return fmt.Sprintf("%v", x)
	}
}

func firstNonBlank(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// joinDetail joins non-empty "key=value" fragments, dropping ones whose value
// is blank (i.e. "key=").
func joinDetail(parts ...string) string {
	var kept []string
	for _, p := range parts {
		if p == "" || strings.HasSuffix(p, "=") {
			continue
		}
		kept = append(kept, p)
	}
	return strings.Join(kept, "  ")
}

func suspDetail(susp []string) string {
	if len(susp) == 0 {
		return ""
	}
	return "suspicious=" + strings.Join(susp, ",")
}

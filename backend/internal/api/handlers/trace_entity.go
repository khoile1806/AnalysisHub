package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// trace_entity.go — "trace the origin of this thing". Given a process / file /
// app the analyst spotted in EdgeForensics or EVTX, reconstruct its story:
// the parent-process chain that launched it (who → who → it), the user and start
// time, plus every related trace across the collected artifacts (prefetch runs,
// MFT file timestamps, shimcache execution, EVTX log lines), merged into one
// focused chronological timeline. Pure correlation over already-collected
// artifacts — no new agent calls in this handler.

// traceSource is one raw artifact block fed to the tracer.
type traceSource struct {
	Type string          `json:"type"` // processes | prefetch | mft | shimcache | evtx
	Data json.RawMessage `json:"data"`
}

// traceProc is one node in the process-ancestry chain.
type traceProc struct {
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid"`
	Name       string `json:"name"`
	ParentName string `json:"parent_name,omitempty"`
	User       string `json:"user,omitempty"`
	Created    string `json:"created,omitempty"`
	Cmdline    string `json:"cmdline,omitempty"`
	Path       string `json:"path,omitempty"`
}

// traceEvent is one entry on the focused origin timeline.
type traceEvent struct {
	Time   string `json:"time"`
	Kind   string `json:"kind"` // process | prefetch | file | shimcache | log
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	Source string `json:"source"`

	ts time.Time // internal sort key
}

// traceResult is the reconstructed origin of an entity.
type traceResult struct {
	Target   string       `json:"target"`
	Found    bool         `json:"found"`
	Ancestry []traceProc  `json:"ancestry"` // root → … → target
	Timeline []traceEvent `json:"timeline"`
	Summary  gin.H        `json:"summary"`
}

// TraceEntity reconstructs the origin/lineage of a selected entity.
//
// POST /api/v1/trace/entity
//
//	{ "target": "powershell.exe", "pid": 4242,
//	  "sources": [ {"type":"processes","data":<raw>}, {"type":"prefetch","data":<raw>}, … ] }
func TraceEntity(c *gin.Context) {
	var body struct {
		Target  string        `json:"target" binding:"required"`
		PID     int           `json:"pid"`
		Sources []traceSource `json:"sources"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	res := buildEntityTrace(strings.TrimSpace(body.Target), body.PID, body.Sources)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": res})
}

// buildEntityTrace is the pure correlation core (testable without HTTP/DB).
func buildEntityTrace(target string, pid int, sources []traceSource) traceResult {
	res := traceResult{Target: target}
	bySrc := map[string][]map[string]interface{}{}
	for _, s := range sources {
		bySrc[strings.ToLower(strings.TrimSpace(s.Type))] = decodeArtifactRows(s.Data)
	}

	procRows := bySrc["processes"]
	if len(procRows) == 0 {
		procRows = bySrc["process"]
	}

	// Index processes by PID for ancestry walking.
	byPID := map[int]map[string]interface{}{}
	for _, r := range procRows {
		byPID[toInt(r["pid"])] = r
	}

	tl := strings.ToLower(target)
	base := strings.ToLower(path.Base(target))

	// matchProc decides whether a process row is "the target".
	matchProc := func(r map[string]interface{}) bool {
		if pid > 0 {
			return toInt(r["pid"]) == pid
		}
		name := strings.ToLower(str(r["name"]))
		p := strings.ToLower(str(r["path"]))
		return name == tl || name == base ||
			strings.Contains(name, tl) ||
			(p != "" && (strings.Contains(p, tl) || path.Base(p) == base))
	}

	var events []traceEvent
	addEvent := func(tsRaw interface{}, kind, title, detail, source string) {
		ts := parseArtifactTime(tsRaw)
		events = append(events, traceEvent{
			Time: formatTraceTime(ts),
			Kind: kind, Title: title, Detail: detail, Source: source, ts: ts,
		})
	}

	// 1) Process ancestry: find target process(es), walk up the PPID chain.
	seenChain := map[int]bool{}
	var targetUser, targetParent, targetCreated string
	for _, r := range procRows {
		if !matchProc(r) {
			continue
		}
		res.Found = true
		// Walk root → target by collecting the chain then reversing.
		var chainUp []map[string]interface{}
		cur := r
		for depth := 0; depth < 32; depth++ {
			cpid := toInt(cur["pid"])
			if seenChain[cpid] {
				break
			}
			seenChain[cpid] = true
			chainUp = append(chainUp, cur)
			parent, ok := byPID[toInt(cur["ppid"])]
			if !ok || toInt(cur["ppid"]) == cpid {
				break
			}
			cur = parent
		}
		// chainUp is target → … → root; reverse into ancestry root → target.
		for i := len(chainUp) - 1; i >= 0; i-- {
			p := chainUp[i]
			tp := traceProc{
				PID: toInt(p["pid"]), PPID: toInt(p["ppid"]),
				Name: str(p["name"]), ParentName: str(p["parent_name"]),
				User: str(p["user"]), Created: str(p["created"]),
				Cmdline: str(p["cmdline"]), Path: str(p["path"]),
			}
			res.Ancestry = append(res.Ancestry, tp)
			addEvent(p["created"], "process",
				fmt.Sprintf("Process started: %s (pid %d)", tp.Name, tp.PID),
				joinDetail("user="+tp.User, "parent="+tp.ParentName, "cmdline="+tp.Cmdline), "processes")
		}
		// Remember the target's own facts for the summary.
		targetUser = str(r["user"])
		targetParent = str(r["parent_name"])
		targetCreated = str(r["created"])
	}

	// 2) Related traces across the other artifacts (matched by name/path).
	nameMatch := func(s string) bool {
		s = strings.ToLower(s)
		return s != "" && (s == tl || s == base || strings.Contains(s, base) || strings.Contains(s, tl))
	}

	for _, r := range bySrc["prefetch"] {
		exe := firstNonBlank(str(r["executable"]), path.Base(str(r["exe_path"])))
		if !nameMatch(exe) {
			continue
		}
		runs := r["last_run_times"]
		if arr, ok := runs.([]interface{}); ok && len(arr) > 0 {
			for _, t := range arr {
				addEvent(t, "prefetch", "Executed (Prefetch): "+exe,
					joinDetail("run_count="+str(r["run_count"])), "prefetch")
			}
		} else {
			addEvent(r["last_run_time"], "prefetch", "Executed (Prefetch): "+exe, "", "prefetch")
		}
	}

	for _, r := range bySrc["mft"] {
		p := str(r["file_path"])
		if !nameMatch(str(r["name"])) && !nameMatch(p) {
			continue
		}
		addEvent(firstPresent(r, "created", "mod_time"), "file",
			"File timestamp (MFT): "+firstNonBlank(str(r["name"]), p),
			joinDetail("path="+p, "sha256="+str(r["sha256"])), "mft")
	}

	for _, r := range bySrc["shimcache"] {
		p := str(r["path"])
		if !nameMatch(p) && !nameMatch(str(r["name"])) {
			continue
		}
		addEvent(r["last_modified"], "shimcache", "Execution evidence (Shimcache): "+firstNonBlank(str(r["name"]), p),
			joinDetail("path="+p), "shimcache")
	}

	for _, r := range bySrc["evtx"] {
		hay := strings.ToLower(str(r["message"]) + " " + str(r["command"]) + " " + str(r["image"]) + " " + str(r["process"]))
		if !strings.Contains(hay, base) && !strings.Contains(hay, tl) {
			continue
		}
		title := firstNonBlank(str(r["event_id"]), "Windows event")
		addEvent(firstPresent(r, "time_created", "timestamp", "time", "@timestamp"), "log",
			"Log: "+title, truncate(str(r["message"]), 200), "evtx")
	}

	// 6) Browser history: the URL a binary was downloaded from (or a page
	// navigated to) is frequently the TRUE origin of a dropped file. Match on
	// the URL's basename (e.g. an .exe download) or a substring of the target.
	for _, r := range bySrc["browser"] {
		u := str(r["url"])
		if u == "" {
			continue
		}
		if !nameMatch(path.Base(u)) && !strings.Contains(strings.ToLower(u), tl) {
			continue
		}
		flags := ""
		if arr, ok := r["suspicious"].([]interface{}); ok && len(arr) > 0 {
			var s []string
			for _, f := range arr {
				s = append(s, str(f))
			}
			flags = "flags=" + strings.Join(s, ",")
		}
		addEvent(firstPresent(r, "last_visit"), "download", "Browser: "+truncate(u, 120),
			joinDetail("browser="+str(r["browser"]), "profile="+str(r["profile"]), flags), "browser")
	}

	// 7) Autoruns / persistence: if the target binary is also registered as an
	// autostart entry, surface HOW it persists. These records carry no reliable
	// timestamp, so they sort to the end of the timeline as undated context.
	for _, r := range bySrc["autoruns"] {
		if !nameMatch(str(r["image_path"])) && !nameMatch(str(r["name"])) && !nameMatch(str(r["command"])) {
			continue
		}
		addEvent(nil, "persistence",
			"Persistence: "+firstNonBlank(str(r["category"]), "autostart")+" — "+str(r["name"]),
			joinDetail("location="+str(r["location"]), "command="+str(r["command"]), "signature="+str(r["signature"])), "autoruns")
	}

	// Sort the focused timeline oldest-first; the first entry is the origin.
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].ts.IsZero() != events[j].ts.IsZero() {
			return !events[i].ts.IsZero() // dated events before undated
		}
		return events[i].ts.Before(events[j].ts)
	})
	res.Timeline = events

	origin := ""
	for _, e := range events {
		if e.ts.IsZero() {
			continue
		}
		origin = e.Time
		break
	}
	res.Summary = gin.H{
		"user":        targetUser,
		"parent":      targetParent,
		"created":     targetCreated,
		"origin":      origin,
		"event_count": len(events),
		"chain_depth": len(res.Ancestry),
	}
	// Never return nil slices: Go marshals a nil slice as JSON `null`, which the
	// frontend would dereference (.length / .map) and crash on. This happens
	// whenever no live process matches (tracing a file, or an exited process).
	if res.Ancestry == nil {
		res.Ancestry = []traceProc{}
	}
	if res.Timeline == nil {
		res.Timeline = []traceEvent{}
	}
	return res
}

// toInt coerces a JSON number/string field to an int.
func toInt(v interface{}) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(x))
		return n
	}
	return 0
}

func formatTraceTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04:05")
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

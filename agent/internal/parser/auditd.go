package parser

import (
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// This file holds the PURE parsing core of the Linux event feed (auditd record
// format, journald JSON, auth.log lines). It carries no build tag so the record
// parser is unit-testable on any dev host; only the collection side — reading
// /var/log/audit, running journalctl, resolving /proc — is Linux-tagged.

// ── contract ─────────────────────────────────────────────────────────────────

// LinuxEvent is one normalized process / security event from a Linux host. It is
// the Linux counterpart of the Windows EVTX stream: a flat, rule-friendly shape
// the Sigma engine can evaluate directly.
type LinuxEvent struct {
	Time        string `json:"time"`         // RFC3339
	Source      string `json:"source"`       // auditd | journald | authlog
	RecordType  string `json:"record_type"`  // SYSCALL | EXECVE | USER_CMD | USER_AUTH | ...
	EventID     string `json:"event_id"`     // synthetic category, see auEventCategory
	Executable  string `json:"executable"`   // full path (auditd `exe`)
	CommandLine string `json:"command_line"` // joined EXECVE argv
	ParentExe   string `json:"parent_exe"`   // when resolvable
	Comm        string `json:"comm"`
	PID         int    `json:"pid"`
	PPID        int    `json:"ppid"`
	User        string `json:"user"` // resolved from uid when possible
	UID         string `json:"uid"`
	AUID        string `json:"auid"` // the login uid — who really did it
	TTY         string `json:"tty"`
	CWD         string `json:"cwd"`
	Path        string `json:"path"` // PATH record name
	Key         string `json:"key"`  // auditd rule key
	Success     string `json:"success"`
	Host        string `json:"host"`
	Raw         string `json:"raw"` // trimmed original, for the analyst
}

// LinuxEventOptions bounds one scan. Hours 0 means "no time filter".
type LinuxEventOptions struct {
	Hours   int    `json:"hours"`
	Max     int    `json:"max"`
	Keyword string `json:"keyword"`
}

const (
	defaultLinuxEventMax = 2000
	maxLinuxEventMax     = 20000
	maxLinuxEventRaw     = 2000 // per-event Raw budget
)

// Synthetic event categories. A detection rule gates on these instead of on the
// raw record type, which differs between auditd / journald / auth.log.
const (
	evProcessCreation = "process_creation"
	evUserCmd         = "user_cmd"
	evUserAuth        = "user_auth"
	evFileAccess      = "file_access"
	evNetwork         = "network"
	evOther           = "other"
)

// normalize clamps the caller-supplied bounds.
func (o LinuxEventOptions) normalize() LinuxEventOptions {
	if o.Max <= 0 {
		o.Max = defaultLinuxEventMax
	}
	if o.Max > maxLinuxEventMax {
		o.Max = maxLinuxEventMax
	}
	if o.Hours < 0 {
		o.Hours = 0
	}
	o.Keyword = strings.TrimSpace(o.Keyword)
	return o
}

// ── auditd record parsing ────────────────────────────────────────────────────

// auRecord is one `type=… msg=audit(<epoch>.<ms>:<serial>): …` line. Several
// records sharing the same ID describe ONE kernel event and are merged later.
type auRecord struct {
	Type   string
	ID     string // "<epoch>.<ms>:<serial>" — the group key
	Time   time.Time
	Node   string
	Fields map[string]string
	Args   []string // EXECVE argv, in a0…aN order
	Raw    string
}

// auKV is one key=value token of an auditd field list.
type auKV struct {
	Key    string
	Val    string
	Quoted bool
}

// auParseKV splits an auditd field list into ordered key/value tokens, honouring
// single- and double-quoted values. Bare values are returned verbatim; whether
// they are hex-encoded is decided per field by auDecodeValue.
func auParseKV(s string) []auKV {
	var out []auKV
	for i := 0; i < len(s); {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		start := i
		for i < len(s) && s[i] != '=' && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		if i >= len(s) || s[i] != '=' {
			continue // bare word (e.g. a node prefix without '=') — ignore
		}
		key := s[start:i]
		i++
		var kv auKV
		kv.Key = key
		if i < len(s) && (s[i] == '"' || s[i] == '\'') {
			q := s[i]
			i++
			vs := i
			for i < len(s) && s[i] != q {
				i++
			}
			kv.Val, kv.Quoted = s[vs:i], true
			if i < len(s) {
				i++ // closing quote
			}
		} else {
			vs := i
			for i < len(s) && s[i] != ' ' && s[i] != '\t' {
				i++
			}
			kv.Val = s[vs:i]
		}
		out = append(out, kv)
	}
	return out
}

// auHexFields are the auditd fields that are normally quoted. auditd drops the
// quotes and hex-encodes the value whenever it contains a space, a quote or a
// control character, so an UNQUOTED value on one of these fields is hex.
var auHexFields = map[string]bool{
	"exe": true, "comm": true, "cwd": true, "name": true, "key": true,
	"proctitle": true, "cmd": true, "acct": true, "data": true, "obj": true,
	"path": true, "old": true, "new": true, "cmdline": true,
}

// auHexDecode decodes a bare hex value, refusing anything that does not come out
// as sane text — `arch=c000003e` and friends must never be "decoded".
func auHexDecode(s string) (string, bool) {
	if len(s) < 2 || len(s)%2 != 0 {
		return "", false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", false
	}
	if !utf8.Valid(b) {
		return "", false
	}
	for _, c := range b {
		if c == 0 || c == '\t' || c == '\n' {
			continue // proctitle separates argv with NUL
		}
		if c < 0x20 || c == 0x7f {
			return "", false
		}
	}
	// Only the NUL terminator is dropped — a genuine trailing space matters when
	// a long argument arrives split across aN[0], aN[1]… fragments.
	return strings.ReplaceAll(strings.TrimRight(string(b), "\x00"), "\x00", " "), true
}

// auDecodeValue normalizes one field value: quoted values are taken as-is,
// auditd's placeholders collapse to empty, and bare string fields are
// hex-decoded. recType is needed because a0…a3 mean argv on EXECVE but raw
// syscall registers on SYSCALL.
func auDecodeValue(recType, key, val string, quoted bool) string {
	if quoted {
		return val
	}
	switch val {
	case "", "(null)", "?", "(none)":
		return ""
	}
	if auHexFields[key] || (recType == "EXECVE" && auIsExecveArg(key)) {
		if d, ok := auHexDecode(val); ok {
			return d
		}
	}
	return val
}

// auIsExecveArg reports whether key is an EXECVE argv slot (a0, a12, a3[0]).
func auIsExecveArg(key string) bool {
	_, _, ok := auExecveArgIndex(key)
	return ok
}

// auExecveArgIndex parses an EXECVE argv key. Long arguments are split by auditd
// into aN[0], aN[1]… fragments that must be concatenated in order.
func auExecveArgIndex(key string) (idx, frag int, ok bool) {
	if len(key) < 2 || key[0] != 'a' {
		return 0, 0, false
	}
	body := key[1:]
	frag = -1
	if b := strings.IndexByte(body, '['); b >= 0 {
		if !strings.HasSuffix(body, "]") {
			return 0, 0, false
		}
		f, err := strconv.Atoi(body[b+1 : len(body)-1])
		if err != nil {
			return 0, 0, false
		}
		frag, body = f, body[:b]
	}
	i, err := strconv.Atoi(body)
	if err != nil || i < 0 {
		return 0, 0, false
	}
	return i, frag, true
}

// auParseEventID extracts the group key and timestamp from `audit(<epoch>.<ms>:<serial>):`.
func auParseEventID(v string) (string, time.Time, bool) {
	if !strings.HasPrefix(v, "audit(") {
		return "", time.Time{}, false
	}
	body := v[len("audit("):]
	if e := strings.IndexByte(body, ')'); e >= 0 {
		body = body[:e]
	}
	stamp, _, ok := strings.Cut(body, ":")
	if !ok {
		return "", time.Time{}, false
	}
	secStr, msStr, _ := strings.Cut(stamp, ".")
	sec, err := strconv.ParseInt(secStr, 10, 64)
	if err != nil || sec <= 0 {
		return "", time.Time{}, false
	}
	ms, _ := strconv.Atoi(msStr)
	return body, time.Unix(sec, int64(ms)*int64(time.Millisecond)).UTC(), true
}

// auParseRecord parses one audit.log line. ok=false for blank / non-audit lines.
func auParseRecord(line string) (auRecord, bool) {
	line = strings.TrimSpace(line)
	if line == "" || !strings.Contains(line, "msg=audit(") {
		return auRecord{}, false
	}
	rec := auRecord{Fields: map[string]string{}, Raw: line}
	// Record type must be known before the values are decoded (a0 handling).
	for _, kv := range auParseKV(line) {
		if kv.Key == "type" {
			rec.Type = kv.Val
			break
		}
	}

	argFrags := map[int]map[int]string{}
	// apply recurses into the nested field list USER_* records carry in msg='…'.
	var apply func([]auKV)
	apply = func(kvs []auKV) {
		for _, kv := range kvs {
			switch kv.Key {
			case "type":
				continue
			case "node":
				rec.Node = kv.Val
				continue
			case "msg":
				if id, ts, ok := auParseEventID(kv.Val); ok {
					rec.ID, rec.Time = id, ts
					continue
				}
				// USER_* records nest a second field list inside msg='…'.
				apply(auParseKV(kv.Val))
				continue
			}
			val := auDecodeValue(rec.Type, kv.Key, kv.Val, kv.Quoted)
			if rec.Type == "EXECVE" {
				if idx, frag, ok := auExecveArgIndex(kv.Key); ok {
					if argFrags[idx] == nil {
						argFrags[idx] = map[int]string{}
					}
					if frag < 0 {
						frag = 0
					}
					argFrags[idx][frag] = val
					continue
				}
			}
			rec.Fields[kv.Key] = val
		}
	}
	apply(auParseKV(line))

	if rec.Type == "" || rec.ID == "" {
		return auRecord{}, false
	}
	if len(argFrags) > 0 {
		idxs := make([]int, 0, len(argFrags))
		for i := range argFrags {
			idxs = append(idxs, i)
		}
		sort.Ints(idxs)
		for _, i := range idxs {
			fr := argFrags[i]
			fidxs := make([]int, 0, len(fr))
			for f := range fr {
				fidxs = append(fidxs, f)
			}
			sort.Ints(fidxs)
			var sb strings.Builder
			for _, f := range fidxs {
				sb.WriteString(fr[f])
			}
			rec.Args = append(rec.Args, sb.String())
		}
	}
	return rec, true
}

// auParseRecords parses a chunk of audit.log into records, skipping junk lines.
func auParseRecords(chunk string) []auRecord {
	var out []auRecord
	for _, line := range strings.Split(chunk, "\n") {
		if rec, ok := auParseRecord(line); ok {
			out = append(out, rec)
		}
	}
	return out
}

// ── syscall names ────────────────────────────────────────────────────────────

// auSyscallTables maps the auditd `arch` value to the syscall numbers we care
// about. Only the handful used for categorisation is listed — a full table would
// be thousands of entries for no detection benefit.
var auSyscallTables = map[string]map[string]string{
	"c000003e": { // x86_64
		"2": "open", "42": "connect", "43": "accept", "44": "sendto", "49": "bind",
		"59": "execve", "82": "rename", "87": "unlink", "85": "creat", "90": "chmod",
		"257": "openat", "263": "unlinkat", "264": "renameat", "268": "fchmodat",
		"288": "accept4", "316": "renameat2", "322": "execveat", "437": "openat2",
	},
	"40000003": { // i386
		"5": "open", "8": "creat", "10": "unlink", "11": "execve", "15": "chmod",
		"38": "rename", "295": "openat", "301": "unlinkat", "302": "renameat",
		"358": "execveat", "437": "openat2",
	},
	"c00000b7": { // aarch64
		"35": "unlinkat", "38": "renameat", "53": "fchmodat", "56": "openat",
		"200": "bind", "202": "accept", "203": "connect", "206": "sendto",
		"221": "execve", "242": "accept4", "276": "renameat2", "281": "execveat",
		"437": "openat2",
	},
}

// auSyscallName resolves a numeric syscall for a known arch. auditd installations
// running with `auditd -i` already write names, which pass straight through.
func auSyscallName(arch, syscall string) string {
	if syscall == "" {
		return ""
	}
	if _, err := strconv.Atoi(syscall); err != nil {
		return syscall // already interpreted
	}
	if t := auSyscallTables[strings.ToLower(arch)]; t != nil {
		return t[syscall]
	}
	return ""
}

var (
	auExecSyscalls = map[string]bool{"execve": true, "execveat": true}
	auNetSyscalls  = map[string]bool{"connect": true, "bind": true, "accept": true, "accept4": true, "sendto": true}
	auFileSyscalls = map[string]bool{
		"open": true, "openat": true, "openat2": true, "creat": true, "truncate": true,
		"unlink": true, "unlinkat": true, "rename": true, "renameat": true, "renameat2": true,
		"chmod": true, "fchmodat": true, "chown": true, "fchownat": true,
	}
)

// ── merging ──────────────────────────────────────────────────────────────────

// auRecordTypeRank picks the record type that best names a merged group.
func auRecordTypeRank(t string) int {
	switch t {
	case "SYSCALL":
		return 0
	case "USER_CMD":
		return 1
	case "USER_AUTH", "USER_LOGIN", "USER_ACCT", "CRED_ACQ":
		return 2
	case "EXECVE":
		return 3
	case "PATH":
		return 5
	case "CWD", "PROCTITLE":
		return 6
	}
	return 4
}

// auEventCategory derives the synthetic EventID a detection rule gates on.
func auEventCategory(types map[string]bool, syscall string, hasPath bool) string {
	switch {
	case types["USER_CMD"]:
		return evUserCmd
	case types["USER_AUTH"], types["USER_LOGIN"], types["USER_ACCT"], types["CRED_ACQ"]:
		return evUserAuth
	case types["EXECVE"], auExecSyscalls[syscall]:
		return evProcessCreation
	case auNetSyscalls[syscall], types["SOCKADDR"]:
		return evNetwork
	case hasPath && auFileSyscalls[syscall]:
		return evFileAccess
	case hasPath && syscall == "":
		// Unknown arch/syscall but a PATH record is present — a file touch is the
		// only honest reading.
		return evFileAccess
	}
	return evOther
}

// auMergeRecords folds records sharing an audit event ID into one LinuxEvent:
// SYSCALL carries the process identity, EXECVE the real argv, CWD/PATH the file
// context. Group order follows first appearance in the log.
func auMergeRecords(recs []auRecord, host string) []LinuxEvent {
	type group struct {
		recs []auRecord
	}
	order := make([]string, 0, len(recs))
	groups := map[string]*group{}
	for _, r := range recs {
		g := groups[r.ID]
		if g == nil {
			g = &group{}
			groups[r.ID] = g
			order = append(order, r.ID)
		}
		g.recs = append(g.recs, r)
	}

	out := make([]LinuxEvent, 0, len(order))
	for _, id := range order {
		if ev, ok := auMergeGroup(groups[id].recs, host); ok {
			out = append(out, ev)
		}
	}
	return out
}

// auMergeGroup builds one event from the records of a single audit event ID.
func auMergeGroup(recs []auRecord, host string) (LinuxEvent, bool) {
	if len(recs) == 0 {
		return LinuxEvent{}, false
	}
	ev := LinuxEvent{Source: "auditd", Host: host}
	types := map[string]bool{}
	var (
		arch, syscall, proctitle string
		argv                     []string
		raws                     []string
		bestRank                 = 99
	)

	for _, r := range recs {
		types[r.Type] = true
		if rank := auRecordTypeRank(r.Type); rank < bestRank {
			bestRank, ev.RecordType = rank, r.Type
		}
		if ev.Time == "" && !r.Time.IsZero() {
			ev.Time = r.Time.Format(time.RFC3339)
		}
		if r.Node != "" {
			ev.Host = r.Node
		}
		if len(r.Args) > 0 {
			argv = r.Args
		}
		raws = append(raws, r.Raw)

		f := r.Fields
		auSetIfEmpty(&ev.Executable, f["exe"])
		auSetIfEmpty(&ev.Comm, f["comm"])
		auSetIfEmpty(&ev.CWD, f["cwd"])
		auSetIfEmpty(&ev.Key, f["key"])
		auSetIfEmpty(&ev.UID, f["uid"])
		auSetIfEmpty(&ev.AUID, f["auid"])
		auSetIfEmpty(&ev.User, f["acct"])
		auSetIfEmpty(&ev.TTY, f["tty"])
		auSetIfEmpty(&ev.TTY, f["terminal"])
		auSetIfEmpty(&ev.Success, f["success"])
		auSetIfEmpty(&ev.Success, f["res"])
		auSetIfEmpty(&arch, f["arch"])
		auSetIfEmpty(&syscall, f["syscall"])
		auSetIfEmpty(&proctitle, f["proctitle"])
		if r.Type == "PATH" {
			auSetIfEmpty(&ev.Path, f["name"])
		}
		if ev.PID == 0 {
			ev.PID = auAtoi(f["pid"])
		}
		if ev.PPID == 0 {
			ev.PPID = auAtoi(f["ppid"])
		}
		// USER_CMD carries the sudo command line in its nested msg.
		auSetIfEmpty(&ev.CommandLine, f["cmd"])
	}

	if len(argv) > 0 {
		ev.CommandLine = strings.Join(argv, " ")
	} else if ev.CommandLine == "" {
		auSetIfEmpty(&ev.CommandLine, proctitle)
	}
	if ev.Time == "" {
		return LinuxEvent{}, false
	}
	ev.EventID = auEventCategory(types, auSyscallName(arch, syscall), ev.Path != "")
	ev.Raw = auTrunc(strings.Join(raws, "\n"), maxLinuxEventRaw)
	return ev, true
}

func auSetIfEmpty(dst *string, v string) {
	if *dst == "" && v != "" {
		*dst = v
	}
}

func auAtoi(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

func auTrunc(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// auParseAuditChunk is the whole auditd pipeline for one log window.
func auParseAuditChunk(chunk, host string) []LinuxEvent {
	return auMergeRecords(auParseRecords(chunk), host)
}

// ── journald ─────────────────────────────────────────────────────────────────

// auJournalString reads one journald JSON field. journalctl emits plain strings,
// arrays when a field repeats, and byte arrays for non-UTF8 values.
func auJournalString(e map[string]json.RawMessage, key string) string {
	raw, ok := e[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) != nil || len(arr) == 0 {
		return ""
	}
	var first string
	if json.Unmarshal(arr[0], &first) == nil {
		return first
	}
	b := make([]byte, 0, len(arr))
	for _, it := range arr {
		var n int
		if json.Unmarshal(it, &n) != nil || n < 0 || n > 255 {
			return ""
		}
		b = append(b, byte(n))
	}
	return string(b)
}

var auAuthMarkers = []string{
	"authentication failure", "session opened", "session closed", "accepted ",
	"failed password", "failed publickey", "invalid user", "authentication error",
	"pam_unix(", "login failure", "auth could not", "maximum authentication",
}

// auLooksLikeAuth reports whether a syslog/journal message describes an
// authentication outcome rather than ordinary daemon chatter.
func auLooksLikeAuth(msg string) bool {
	l := strings.ToLower(msg)
	for _, m := range auAuthMarkers {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

// auClassifyUnit maps a syslog identifier / comm plus the message to a record
// type and synthetic category. journald has no syscall data, so the process
// identity is all we have to go on.
func auClassifyUnit(ident, comm, msg string) (string, string) {
	name := strings.ToLower(ident)
	if name == "" {
		name = strings.ToLower(comm)
	}
	name = strings.TrimSuffix(name, "-session")
	switch name {
	case "sudo":
		if strings.Contains(msg, "COMMAND=") {
			return "USER_CMD", evUserCmd
		}
		return "USER_AUTH", evUserAuth
	case "su", "login", "sshd", "systemd-logind", "polkitd", "gdm-password":
		if auLooksLikeAuth(msg) {
			return "USER_AUTH", evUserAuth
		}
	}
	if auLooksLikeAuth(msg) {
		return "USER_AUTH", evUserAuth
	}
	return "JOURNAL", evOther
}

// auJournalToEvent normalizes one `journalctl -o json` entry.
func auJournalToEvent(e map[string]json.RawMessage, host string) (LinuxEvent, bool) {
	ts := auJournalString(e, "__REALTIME_TIMESTAMP")
	usec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || usec <= 0 {
		return LinuxEvent{}, false
	}
	msg := auJournalString(e, "MESSAGE")
	ident := auJournalString(e, "SYSLOG_IDENTIFIER")
	comm := auJournalString(e, "_COMM")
	recType, category := auClassifyUnit(ident, comm, msg)

	h := auJournalString(e, "_HOSTNAME")
	if h == "" {
		h = host
	}
	ev := LinuxEvent{
		Time:        time.Unix(usec/1e6, (usec%1e6)*1000).UTC().Format(time.RFC3339),
		Source:      "journald",
		RecordType:  recType,
		EventID:     category,
		Executable:  auJournalString(e, "_EXE"),
		CommandLine: strings.TrimSpace(strings.ReplaceAll(auJournalString(e, "_CMDLINE"), "\x00", " ")),
		Comm:        comm,
		PID:         auAtoi(auJournalString(e, "_PID")),
		UID:         auJournalString(e, "_UID"),
		AUID:        auJournalString(e, "_AUDIT_LOGINUID"),
		Host:        h,
		Raw:         auTrunc(strings.TrimSpace(msg), maxLinuxEventRaw),
	}
	if u := auMessageUser(msg); u != "" {
		ev.User = u
	}
	if category == evUserAuth || category == evUserCmd {
		ev.Success = auAuthOutcome(msg)
	}
	return ev, true
}

// ── auth.log / secure ────────────────────────────────────────────────────────

var auAuthLogTags = map[string]bool{"sudo": true, "su": true, "sshd": true}

// auParseAuthLogLine parses one syslog line from auth.log / secure, keeping only
// the sudo / su / sshd events. now supplies the year, which syslog omits.
func auParseAuthLogLine(line string, now time.Time, host string) (LinuxEvent, bool) {
	line = strings.TrimSpace(line)
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return LinuxEvent{}, false
	}
	var (
		ts  time.Time
		idx int
	)
	if t, err := time.Parse(time.RFC3339, fields[0]); err == nil {
		ts, idx = t.UTC(), 1
	} else {
		t, err := time.Parse("Jan 2 15:04:05 2006", strings.Join(fields[:3], " ")+" "+strconv.Itoa(now.Year()))
		if err != nil {
			return LinuxEvent{}, false
		}
		// A stamp in the future means the line belongs to the previous year.
		if t.After(now.Add(24 * time.Hour)) {
			t = t.AddDate(-1, 0, 0)
		}
		ts, idx = t.UTC(), 3
	}
	if len(fields) < idx+2 {
		return LinuxEvent{}, false
	}
	hostname := fields[idx]
	tag := strings.TrimSuffix(fields[idx+1], ":")
	pid := 0
	if b := strings.IndexByte(tag, '['); b >= 0 && strings.HasSuffix(tag, "]") {
		pid = auAtoi(tag[b+1 : len(tag)-1])
		tag = tag[:b]
	}
	base := strings.TrimSuffix(tag, "-session")
	if !auAuthLogTags[base] {
		return LinuxEvent{}, false
	}
	rest := strings.TrimSpace(strings.Join(fields[idx+2:], " "))
	if rest == "" {
		return LinuxEvent{}, false
	}

	ev := LinuxEvent{
		Time:    ts.Format(time.RFC3339),
		Source:  "authlog",
		PID:     pid,
		Host:    hostname,
		Success: auAuthOutcome(rest),
		Raw:     auTrunc(line, maxLinuxEventRaw),
	}
	if ev.Host == "" {
		ev.Host = host
	}

	if base == "sudo" && strings.Contains(rest, "COMMAND=") {
		ev.RecordType, ev.EventID = "USER_CMD", evUserCmd
		if u, _, ok := strings.Cut(rest, " : "); ok {
			ev.User = strings.TrimSpace(u)
		}
		ev.TTY = auSudoField(rest, "TTY=")
		ev.CWD = auSudoField(rest, "PWD=")
		if c := strings.Index(rest, "COMMAND="); c >= 0 {
			ev.CommandLine = strings.TrimSpace(rest[c+len("COMMAND="):])
			if f := strings.Fields(ev.CommandLine); len(f) > 0 {
				ev.Executable = f[0]
			}
		}
		if ev.Success == "" {
			ev.Success = "yes"
		}
		return ev, true
	}
	if !auLooksLikeAuth(rest) {
		return LinuxEvent{}, false
	}
	ev.RecordType, ev.EventID = "USER_AUTH", evUserAuth
	ev.Comm = base
	ev.User = auMessageUser(rest)
	return ev, true
}

// auSudoField pulls one `KEY=value` out of a sudo log line (fields are separated
// by " ; ").
func auSudoField(rest, key string) string {
	i := strings.Index(rest, key)
	if i < 0 {
		return ""
	}
	v := rest[i+len(key):]
	if s := strings.Index(v, " ;"); s >= 0 {
		v = v[:s]
	}
	return strings.TrimSpace(v)
}

// auMessageUser extracts the account an auth message refers to.
func auMessageUser(msg string) string {
	for _, marker := range []string{"for invalid user ", "invalid user ", "for user ", "for ", "user="} {
		i := strings.Index(msg, marker)
		if i < 0 {
			continue
		}
		f := strings.Fields(msg[i+len(marker):])
		if len(f) == 0 {
			continue
		}
		u := strings.Trim(f[0], "\"',;:")
		if u != "" && u != "from" {
			return u
		}
	}
	return ""
}

// auAuthOutcome maps an auth message to the Success column.
func auAuthOutcome(msg string) string {
	l := strings.ToLower(msg)
	switch {
	case strings.Contains(l, "res=success"), strings.Contains(l, "accepted "),
		strings.Contains(l, "session opened"), strings.Contains(l, "session closed"):
		return "yes"
	case strings.Contains(l, "res=failed"), strings.Contains(l, "failure"),
		strings.Contains(l, "failed "), strings.Contains(l, "invalid user"):
		return "no"
	}
	return ""
}

// ── filtering ────────────────────────────────────────────────────────────────

// auEventMatchesKeyword does a case-insensitive substring match over the fields
// an analyst would search on.
func auEventMatchesKeyword(ev LinuxEvent, keyword string) bool {
	if keyword == "" {
		return true
	}
	k := strings.ToLower(keyword)
	for _, f := range []string{ev.Executable, ev.CommandLine, ev.Comm, ev.User, ev.Path, ev.Key, ev.ParentExe, ev.Raw} {
		if f != "" && strings.Contains(strings.ToLower(f), k) {
			return true
		}
	}
	return false
}

// auFilterEvents drops events older than since (zero = keep all) and those that
// do not match keyword.
func auFilterEvents(evts []LinuxEvent, since time.Time, keyword string) []LinuxEvent {
	out := evts[:0:0]
	for _, ev := range evts {
		if !since.IsZero() {
			t, err := time.Parse(time.RFC3339, ev.Time)
			if err != nil || t.Before(since) {
				continue
			}
		}
		if !auEventMatchesKeyword(ev, keyword) {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// auCapNewest keeps the newest max events, assuming chronological input.
func auCapNewest(evts []LinuxEvent, max int) []LinuxEvent {
	sort.SliceStable(evts, func(i, j int) bool { return evts[i].Time < evts[j].Time })
	if max > 0 && len(evts) > max {
		evts = evts[len(evts)-max:]
	}
	return evts
}

// auParsePasswd builds a uid → username map from /etc/passwd content. Parsing the
// file directly avoids cgo-dependent lookups in statically linked agents.
func auParsePasswd(content string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 3 || f[0] == "" {
			continue
		}
		if _, ok := out[f[2]]; !ok {
			out[f[2]] = f[0]
		}
	}
	return out
}

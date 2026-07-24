//go:build linux

package parser

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Linux event feed — the collection half. The record parsing itself lives in the
// untagged auditd.go so it can be unit-tested on any host.

const (
	auditLogPath    = "/var/log/audit/audit.log"
	auditLogRotated = "/var/log/audit/audit.log.1"

	// Bounds on the tail window read from a log file. audit.log is routinely
	// hundreds of MB, so it is NEVER slurped whole: we read backwards from the
	// end and keep the newest slice that can plausibly hold Max events.
	auTailMinBytes = 4 << 20
	auTailMaxBytes = 32 << 20
	auTailPerEvent = 2048

	auJournalTimeout = 90 * time.Second
	auJournalMaxRows = 200000 // decoder guard, independent of -n
	auProcAgeLimit   = 5 * time.Minute
)

var auAuthLogPaths = []string{"/var/log/auth.log", "/var/log/secure"}

// ScanLinuxEvents produces a normalized process / security event stream for the
// Sigma engine. Sources are tried in descending fidelity — auditd, then
// journald, then the auth log — and the winning source is reported per event in
// LinuxEvent.Source. A host where every source is missing or unreadable yields
// an error rather than an empty slice, so a permission problem is never read as
// "nothing happened".
func ScanLinuxEvents(opts LinuxEventOptions) ([]LinuxEvent, error) {
	opts = opts.normalize()
	host, _ := os.Hostname()

	var since time.Time
	if opts.Hours > 0 {
		since = time.Now().Add(-time.Duration(opts.Hours) * time.Hour).UTC()
	}

	sources := []struct {
		name    string
		collect func(LinuxEventOptions, time.Time, string) ([]LinuxEvent, error)
	}{
		{"auditd", auCollectAuditd},
		{"journald", auCollectJournald},
		{"authlog", auCollectAuthLog},
	}

	var (
		reasons  []string
		readable bool
	)
	for _, src := range sources {
		evts, err := src.collect(opts, since, host)
		if err != nil {
			reasons = append(reasons, err.Error())
			continue
		}
		readable = true
		if len(evts) == 0 {
			reasons = append(reasons, src.name+" readable but had no matching records")
			continue
		}
		evts = auCapNewest(evts, opts.Max)
		auEnrichEvents(evts)
		log.Printf("[linux_events] source=%s events=%d hours=%d max=%d", src.name, len(evts), opts.Hours, opts.Max)
		return evts, nil
	}

	if readable {
		// At least one source was genuinely readable — an empty result is the
		// honest answer, not a failure.
		log.Printf("[linux_events] no matching events (%s)", strings.Join(reasons, ", "))
		return []LinuxEvent{}, nil
	}
	return nil, fmt.Errorf("no Linux event source available (%s) - the agent likely needs root", strings.Join(reasons, ", "))
}

// ── auditd ───────────────────────────────────────────────────────────────────

// auCollectAuditd parses the tail of audit.log (+ the rotated one, oldest first
// so the merged stream stays chronological).
func auCollectAuditd(opts LinuxEventOptions, since time.Time, host string) ([]LinuxEvent, error) {
	window := auTailWindow(opts.Max)
	var (
		recs    []auRecord
		denied  []string
		present bool
	)
	for _, p := range []string{auditLogRotated, auditLogPath} {
		if _, err := os.Stat(p); err != nil {
			if !os.IsNotExist(err) {
				present = true
				denied = append(denied, p+": "+auErrText(err))
			}
			continue
		}
		present = true
		chunk, err := auReadTail(p, window)
		if err != nil {
			denied = append(denied, p+": "+auErrText(err))
			continue
		}
		recs = append(recs, auParseRecords(string(chunk))...)
	}

	if len(recs) == 0 {
		if len(denied) > 0 {
			return nil, fmt.Errorf("auditd log unreadable (%s)", strings.Join(denied, "; "))
		}
		if !present {
			return nil, fmt.Errorf("auditd log not present (%s)", auditLogPath)
		}
	}
	return auFilterEvents(auMergeRecords(recs, host), since, opts.Keyword), nil
}

// auTailWindow sizes the tail read from the requested event count. A merged
// auditd event costs roughly 1 KB across its records; 2 KB per event leaves
// headroom without ever reading an unbounded amount.
func auTailWindow(max int) int64 {
	n := int64(max) * auTailPerEvent
	if n < auTailMinBytes {
		n = auTailMinBytes
	}
	if n > auTailMaxBytes {
		n = auTailMaxBytes
	}
	return n
}

// auReadTail reads at most n bytes from the END of a file. When the read did not
// start at offset 0 the leading partial line is dropped.
func auReadTail(path string, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	off := int64(0)
	if fi.Size() > n {
		off = fi.Size() - n
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, err
	}
	// +1 MB slack in case the file grew between Stat and Read; still bounded.
	buf, err := io.ReadAll(io.LimitReader(f, n+(1<<20)))
	if err != nil {
		return nil, err
	}
	if off > 0 {
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:]
		}
	}
	return buf, nil
}

// ── journald ─────────────────────────────────────────────────────────────────

// auCollectJournald shells out to journalctl and normalizes its JSON stream. It
// is the fallback when auditd is not installed; a non-root agent still gets its
// own journal, which is honest (readable) rather than an error.
func auCollectJournald(opts LinuxEventOptions, since time.Time, host string) ([]LinuxEvent, error) {
	bin, err := exec.LookPath("journalctl")
	if err != nil {
		return nil, fmt.Errorf("journalctl not found")
	}

	rows := opts.Max * 4
	if rows > auJournalMaxRows {
		rows = auJournalMaxRows
	}
	args := []string{"-o", "json", "--no-pager", "-n", strconv.Itoa(rows)}
	if !since.IsZero() {
		args = append(args, "--since", since.Local().Format("2006-01-02 15:04:05"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), auJournalTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("journalctl unusable: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("journalctl failed to start: %v", err)
	}

	var evts []LinuxEvent
	dec := json.NewDecoder(bufio.NewReaderSize(stdout, 256<<10))
	for seen := 0; seen < auJournalMaxRows; seen++ {
		var entry map[string]json.RawMessage
		if err := dec.Decode(&entry); err != nil {
			break
		}
		if ev, ok := auJournalToEvent(entry, host); ok {
			evts = append(evts, ev)
		}
	}
	_, _ = io.Copy(io.Discard, stdout)
	if err := cmd.Wait(); err != nil && len(evts) == 0 {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("journalctl failed (%s)", auTrunc(msg, 200))
	}
	return auFilterEvents(evts, since, opts.Keyword), nil
}

// ── auth.log / secure ────────────────────────────────────────────────────────

// auCollectAuthLog is the last resort: sudo / su / sshd lines only, which is all
// a plain syslog auth file reliably carries.
func auCollectAuthLog(opts LinuxEventOptions, since time.Time, host string) ([]LinuxEvent, error) {
	window := auTailWindow(opts.Max)
	now := time.Now()
	var (
		evts    []LinuxEvent
		denied  []string
		present bool
	)
	for _, p := range auAuthLogPaths {
		if _, err := os.Stat(p); err != nil {
			if !os.IsNotExist(err) {
				present = true
				denied = append(denied, p+": "+auErrText(err))
			}
			continue
		}
		present = true
		chunk, err := auReadTail(p, window)
		if err != nil {
			denied = append(denied, p+": "+auErrText(err))
			continue
		}
		for _, line := range strings.Split(string(chunk), "\n") {
			if ev, ok := auParseAuthLogLine(line, now, host); ok {
				evts = append(evts, ev)
			}
		}
	}

	if len(evts) == 0 {
		if len(denied) > 0 {
			return nil, fmt.Errorf("auth log unreadable (%s)", strings.Join(denied, "; "))
		}
		if !present {
			return nil, fmt.Errorf("auth log not present (%s)", strings.Join(auAuthLogPaths, ", "))
		}
	}
	return auFilterEvents(evts, since, opts.Keyword), nil
}

// ── enrichment ───────────────────────────────────────────────────────────────

// auEnrichEvents fills User from /etc/passwd and ParentExe from /proc. Parent
// resolution is limited to very recent events: PIDs are recycled, so naming the
// parent of an hour-old record would be a guess dressed up as evidence.
func auEnrichEvents(evts []LinuxEvent) {
	users := auPasswdMap()
	parents := map[int]string{}
	cutoff := time.Now().Add(-auProcAgeLimit)

	for i := range evts {
		if evts[i].User == "" && evts[i].UID != "" {
			evts[i].User = users[evts[i].UID]
		}
		if evts[i].ParentExe != "" || evts[i].PPID <= 0 {
			continue
		}
		t, err := time.Parse(time.RFC3339, evts[i].Time)
		if err != nil || t.Before(cutoff) {
			continue
		}
		exe, cached := parents[evts[i].PPID]
		if !cached {
			exe, _ = os.Readlink(fmt.Sprintf("/proc/%d/exe", evts[i].PPID))
			parents[evts[i].PPID] = exe
		}
		evts[i].ParentExe = exe
	}
}

func auPasswdMap() map[string]string {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return map[string]string{}
	}
	return auParsePasswd(string(data))
}

// auErrText strips the repeated "open <path>:" prefix so joined reasons stay
// readable.
func auErrText(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i >= 0 {
		return msg[i+2:]
	}
	return msg
}

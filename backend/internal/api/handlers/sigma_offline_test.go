package handlers

import (
	"reflect"
	"strings"
	"testing"
)

func TestSanitizeIndexTarget(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    []string
		wantErr bool
	}{
		{name: "concrete index", in: "hunt-windows-case1-host1-evtx", want: []string{"hunt-windows-case1-host1-evtx"}},
		{name: "trims and lowercases", in: "  HUNT-Windows-Case1-Host1-EVTX ", want: []string{"hunt-windows-case1-host1-evtx"}},
		{name: "wildcard inside the namespace", in: "hunt-windows-*", want: []string{"hunt-windows-*"}},
		{name: "whole namespace", in: "hunt-*", want: []string{"hunt-*"}},
		{name: "comma list of hunt indices", in: "hunt-windows-a-evtx,hunt-linux-a-syslog",
			want: []string{"hunt-windows-a-evtx", "hunt-linux-a-syslog"}},
		{name: "dedupes and drops blanks", in: "hunt-a-evtx, ,hunt-a-evtx", want: []string{"hunt-a-evtx"}},

		{name: "empty", in: "   ", wantErr: true},
		{name: "outside the hunt namespace", in: "logstash-2024.01.01", wantErr: true},
		{name: "bare wildcard", in: "*", wantErr: true},
		{name: "_all", in: "_all", wantErr: true},
		{name: "wildcard before the prefix", in: "*hunt-windows-evtx", wantErr: true},
		{name: "one bad element poisons the list", in: "hunt-windows-evtx,logstash-*", wantErr: true},
		{name: "exclusion syntax", in: "hunt-*,-hunt-windows-*", wantErr: true},
		{name: "path escape", in: "hunt-a/../../_cluster/health", wantErr: true},
		{name: "path separator", in: "hunt-a/_search", wantErr: true},
		{name: "query string injection", in: "hunt-a?pretty", wantErr: true},
		{name: "dot dot", in: "hunt-..-a", wantErr: true},
		{name: "whitespace inside", in: "hunt-a b", wantErr: true},
		{name: "newline injection", in: "hunt-a\nGET /_all", wantErr: true},
		{name: "url encoded traversal", in: "hunt-a%2f_cluster", wantErr: true},
		{name: "too many elements", in: strings.TrimSuffix(strings.Repeat("hunt-a-evtx,", maxIndexTargets+1), ","), wantErr: true},
		{name: "over long element", in: "hunt-" + strings.Repeat("a", 300), wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sanitizeIndexTarget(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q, got %v", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.in, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMatchIndexPattern(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"hunt-windows-a-evtx", "hunt-windows-a-evtx", true},
		{"hunt-windows-a-evtx", "hunt-windows-a-syslog", false},
		{"hunt-*", "hunt-windows-a-evtx", true},
		{"hunt-windows-*", "hunt-linux-a-syslog", false},
		{"hunt-*-host1-*", "hunt-windows-case1-host1-evtx", true},
		{"hunt-*-host1-*", "hunt-windows-case1-host2-evtx", false},
		{"hunt-*-evtx", "hunt-windows-case1-host1-evtx", true},
		{"hunt-*-evtx", "hunt-windows-case1-host1-evtx-old", false},
	}
	for _, tc := range cases {
		if got := matchIndexPattern(tc.pattern, tc.name); got != tc.want {
			t.Errorf("matchIndexPattern(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.want)
		}
	}
}

func TestFlattenESEvent(t *testing.T) {
	cases := []struct {
		name string
		src  map[string]interface{}
		want map[string]interface{}
	}{
		{
			name: "sysmon process creation",
			src: map[string]interface{}{
				"@timestamp": "2026-07-01T10:00:00Z",
				"message":    "Process Create",
				"event":      map[string]interface{}{"code": "1", "provider": "Microsoft-Windows-Sysmon", "kind": "event"},
				"winlog": map[string]interface{}{
					"channel":       "Microsoft-Windows-Sysmon/Operational",
					"computer_name": "WS01",
					"provider_name": "Microsoft-Windows-Sysmon",
					"record_id":     "4711",
					"level":         "4",
					"event_data": map[string]interface{}{
						"Image":       `C:\Windows\System32\cmd.exe`,
						"CommandLine": `cmd.exe /c whoami`,
						"ParentImage": `C:\Windows\explorer.exe`,
					},
				},
				"host":    map[string]interface{}{"name": "WS01"},
				"process": map[string]interface{}{"command_line": "cmd.exe /c whoami"},
			},
			want: map[string]interface{}{
				"Image":       `C:\Windows\System32\cmd.exe`,
				"CommandLine": `cmd.exe /c whoami`,
				"ParentImage": `C:\Windows\explorer.exe`,
				"EventID":     1,
				"Provider":    "Microsoft-Windows-Sysmon",
				"Channel":     "Microsoft-Windows-Sysmon/Operational",
				"Computer":    "WS01",
				"Level":       "4",
				"RecordID":    "4711",
				"Message":     "Process Create",
				"TimeCreated": "2026-07-01T10:00:00Z",
			},
		},
		{
			// The whole point of the overlay order: an EventData element named
			// EventID/Provider must not shadow the identity fields the logsource
			// gating reads, or every rule on the channel silently misses.
			name: "identity fields win over same-named event_data",
			src: map[string]interface{}{
				"@timestamp": "2026-07-01T11:00:00Z",
				"event":      map[string]interface{}{"code": "4688", "provider": "Microsoft-Windows-Security-Auditing"},
				"winlog": map[string]interface{}{
					"channel":       "Security",
					"computer_name": "DC01",
					"event_data": map[string]interface{}{
						"EventID":        "9999",
						"Provider":       "Bogus",
						"Computer":       "SPOOFED",
						"Channel":        "Bogus",
						"Message":        "spoofed",
						"NewProcessName": `C:\Windows\System32\net.exe`,
					},
				},
				"message": "A new process has been created.",
			},
			want: map[string]interface{}{
				"NewProcessName": `C:\Windows\System32\net.exe`,
				"EventID":        4688,
				"Provider":       "Microsoft-Windows-Security-Auditing",
				"Channel":        "Security",
				"Computer":       "DC01",
				"Message":        "A new process has been created.",
				"TimeCreated":    "2026-07-01T11:00:00Z",
			},
		},
		{
			name: "numeric event code and json numbers",
			src: map[string]interface{}{
				"@timestamp": "2026-07-01T12:00:00Z",
				"event":      map[string]interface{}{"code": float64(4104)},
				"winlog": map[string]interface{}{
					"channel":    "Microsoft-Windows-PowerShell/Operational",
					"record_id":  float64(88),
					"event_data": map[string]interface{}{"ScriptBlockText": "Invoke-Mimikatz"},
				},
			},
			want: map[string]interface{}{
				"ScriptBlockText": "Invoke-Mimikatz",
				"EventID":         4104,
				"Channel":         "Microsoft-Windows-PowerShell/Operational",
				"RecordID":        "88",
				"TimeCreated":     "2026-07-01T12:00:00Z",
			},
		},
		{
			name: "provider falls back to winlog, computer to host.name",
			src: map[string]interface{}{
				"event":  map[string]interface{}{"code": "7045"},
				"winlog": map[string]interface{}{"channel": "System", "provider_name": "Service Control Manager"},
				"host":   map[string]interface{}{"name": "SRV02"},
			},
			want: map[string]interface{}{
				"EventID":  7045,
				"Provider": "Service Control Manager",
				"Channel":  "System",
				"Computer": "SRV02",
			},
		},
		{
			name: "non-evtx document keeps its top-level scalars",
			src: map[string]interface{}{
				"@timestamp": "2026-07-01T13:00:00Z",
				"message":    "sshd: Failed password for root",
				"host":       map[string]interface{}{"name": "linux01"},
				"tags":       []interface{}{"syslog"},
			},
			want: map[string]interface{}{
				"@timestamp":  "2026-07-01T13:00:00Z",
				"message":     "sshd: Failed password for root",
				"Computer":    "linux01",
				"Message":     "sshd: Failed password for root",
				"TimeCreated": "2026-07-01T13:00:00Z",
			},
		},
		{name: "empty document", src: map[string]interface{}{}, want: nil},
		{name: "nil document", src: nil, want: nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := flattenESEvent(tc.src)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("flattenESEvent mismatch\n got: %#v\nwant: %#v", got, tc.want)
			}
		})
	}
}

func TestSigmaChannelSelectorShape(t *testing.T) {
	selector, channels := sigmaChannelSelector(nil)
	if selector != nil || channels != nil {
		t.Fatalf("empty ruleset must not produce a filter, got %v / %v", selector, channels)
	}
}

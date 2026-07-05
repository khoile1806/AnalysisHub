package logsearch

import (
	"os"
	"path/filepath"
	"testing"
)

// smokeDir points at a directory of sample logs used to validate the parser
// port. Set LOGSEARCH_SAMPLE_DIR to run it; the test skips when unset/absent so
// it never fails on CI or other machines.
var smokeDir = os.Getenv("LOGSEARCH_SAMPLE_DIR")

func TestDetectAndParseSamples(t *testing.T) {
	if smokeDir == "" {
		t.Skip("LOGSEARCH_SAMPLE_DIR not set")
	}
	cases := []struct {
		rel        string
		wantType   string
		wantMinDoc int
	}{
		{`web-logs\nginx-access.log`, TypeAccess, 15},
		{`firewall-logs\fortigate-traffic.log`, TypeFortigate, 8},
		{`firewall-logs\iptables-kernel.log`, TypeIptables, 5},
		{`linux-logs\auth.log`, TypeSyslog, 10},
		{`json-logs\sysmon.ndjson`, TypeJSON, 5},
		{`json-logs\cloudtrail.json`, TypeJSON, 5},
		{`csv-logs\dns-queries.csv`, TypeCSV, 8},
		{`evtx-logs\Security.evtx`, TypeEvtx, 10},
	}
	for _, tc := range cases {
		path := filepath.Join(smokeDir, tc.rel)
		if _, err := os.Stat(path); err != nil {
			t.Skipf("sample %s not present, skipping", tc.rel)
			continue
		}
		got := DetectLogType(path, filepath.Base(path))
		if got != tc.wantType {
			t.Errorf("%s: detected %q, want %q", tc.rel, got, tc.wantType)
		}
		n := 0
		var withTS, withSrcIP int
		err := Parse(path, got, func(d Doc) error {
			n++
			if d["@timestamp"] != nil && d["@timestamp"] != "" {
				withTS++
			}
			if src, ok := d["source"].(Doc); ok {
				if src["ip"] != nil {
					withSrcIP++
				}
			}
			return nil
		})
		if err != nil {
			t.Errorf("%s: parse error: %v", tc.rel, err)
		}
		if n < tc.wantMinDoc {
			t.Errorf("%s: got %d docs, want >= %d", tc.rel, n, tc.wantMinDoc)
		}
		t.Logf("%-32s type=%-10s docs=%-6d withTS=%-6d withSrcIP=%d", tc.rel, got, n, withTS, withSrcIP)
	}
}

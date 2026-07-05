package logsearch

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func collect(t *testing.T, rel, logType string) []Doc {
	t.Helper()
	var docs []Doc
	err := Parse(filepath.Join("testdata", rel), logType, func(d Doc) error {
		docs = append(docs, d)
		return nil
	})
	if err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	return docs
}

// nested reads doc["a"]["b"]... returning the leaf or nil.
func nested(d Doc, path ...string) interface{} {
	cur := interface{}(d)
	for _, p := range path {
		m, ok := cur.(Doc)
		if !ok {
			return nil
		}
		cur = m[p]
	}
	return cur
}

func TestDetectAndParse(t *testing.T) {
	cases := []struct {
		file     string
		wantType string
		minDocs  int
	}{
		{"access.log", TypeAccess, 3},
		{"fortigate.log", TypeFortigate, 2},
		{"auth.log", TypeSyslog, 3},
		{"iptables.log", TypeIptables, 2},
		{"sysmon.ndjson", TypeJSON, 2},
		{"cloudtrail.json", TypeJSON, 2},
		{"dns.csv", TypeCSV, 2},
		{"iis.log", TypeIIS, 2},
		{"cef.log", TypeCEF, 2},
	}
	for _, tc := range cases {
		got := DetectLogType(filepath.Join("testdata", tc.file), tc.file)
		if got != tc.wantType {
			t.Errorf("%s: detected %q, want %q", tc.file, got, tc.wantType)
		}
		docs := collect(t, tc.file, got)
		if len(docs) < tc.minDocs {
			t.Errorf("%s: got %d docs, want >= %d", tc.file, len(docs), tc.minDocs)
		}
	}
}

func TestAccessFields(t *testing.T) {
	docs := collect(t, "access.log", TypeAccess)
	if ip := nested(docs[0], "source", "ip"); ip != "203.0.113.42" {
		t.Errorf("source.ip = %v, want 203.0.113.42", ip)
	}
	if sc := nested(docs[0], "http", "response", "status_code"); sc != 200 {
		t.Errorf("status_code = %v, want 200", sc)
	}
}

func TestSyslogSSHEnrichment(t *testing.T) {
	docs := collect(t, "auth.log", TypeSyslog)
	var failFound bool
	for _, d := range docs {
		if nested(d, "event", "action") == "ssh_login" && nested(d, "event", "outcome") == "failure" {
			if nested(d, "source", "ip") == "198.51.100.7" {
				failFound = true
			}
		}
	}
	if !failFound {
		t.Error("expected an enriched SSH failed-login with source.ip 198.51.100.7")
	}
}

func TestFortigateAndCEFDeny(t *testing.T) {
	for _, tc := range []struct{ file, typ string }{{"fortigate.log", TypeFortigate}, {"cef.log", TypeCEF}} {
		docs := collect(t, tc.file, tc.typ)
		var denyC2 bool
		for _, d := range docs {
			if nested(d, "event", "action") == "deny" && nested(d, "destination", "port") == 4444 {
				denyC2 = true
			}
		}
		if !denyC2 {
			t.Errorf("%s: expected a deny to destination.port 4444", tc.file)
		}
	}
}

func TestIISFields(t *testing.T) {
	docs := collect(t, "iis.log", TypeIIS)
	if ip := nested(docs[0], "source", "ip"); ip != "203.0.113.42" {
		t.Errorf("iis source.ip = %v, want 203.0.113.42", ip)
	}
	if sc := nested(docs[0], "http", "response", "status_code"); sc != 200 {
		t.Errorf("iis status_code = %v, want 200", sc)
	}
}

func TestSysmonProcessParent(t *testing.T) {
	docs := collect(t, "sysmon.ndjson", TypeJSON)
	if pn := nested(docs[0], "process", "parent", "name"); pn != "winword.exe" {
		t.Errorf("process.parent.name = %v, want winword.exe", pn)
	}
}

func TestCEFExtension(t *testing.T) {
	kv := cefExtension(`src=1.2.3.4 dpt=443 msg=hello world act=deny`)
	if kv["src"] != "1.2.3.4" || kv["dpt"] != "443" || kv["act"] != "deny" {
		t.Errorf("cefExtension parsed wrong: %+v", kv)
	}
	if kv["msg"] != "hello world" {
		t.Errorf("cefExtension should keep spaces in value: msg=%q", kv["msg"])
	}
}

func TestExtractZip(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "bundle.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, name := range []string{"a/access.log", "b/auth.log"} {
		w, _ := zw.Create(name)
		w.Write([]byte("line1\nline2\n"))
	}
	zw.Close()
	f.Close()

	out, err := extractArchive(zipPath, t.TempDir())
	if err != nil {
		t.Fatalf("extractArchive: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("extracted %d files, want 2", len(out))
	}
}

func TestSanitize(t *testing.T) {
	if got := Sanitize("Incident 2026/07!!"); got != "incident-2026-07" {
		t.Errorf("Sanitize = %q, want incident-2026-07", got)
	}
}

func TestIndexNaming(t *testing.T) {
	if got := IndexName("Incident 2026-07", "evtx"); got != "hunt-windows-incident-2026-07-evtx" {
		t.Errorf("IndexName = %q", got)
	}
}

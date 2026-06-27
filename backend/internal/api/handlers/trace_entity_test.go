package handlers

import (
	"encoding/json"
	"testing"
)

func TestBuildEntityTrace_ProcessAncestry(t *testing.T) {
	// explorer(100) → cmd(200) → powershell(300, target)
	procs := `[
		{"pid":100,"ppid":4,"name":"explorer.exe","user":"CORP\\alice","created":"2026-06-01T09:00:00Z","cmdline":"explorer.exe"},
		{"pid":200,"ppid":100,"name":"cmd.exe","parent_name":"explorer.exe","user":"CORP\\alice","created":"2026-06-01T09:05:00Z","cmdline":"cmd /c x"},
		{"pid":300,"ppid":200,"name":"powershell.exe","parent_name":"cmd.exe","user":"CORP\\alice","created":"2026-06-01T09:06:00Z","cmdline":"powershell -enc ..."}
	]`
	prefetch := `[{"executable":"POWERSHELL.EXE","run_count":3,"last_run_times":["2026-06-01T09:06:00Z","2026-05-30T08:00:00Z"]}]`

	res := buildEntityTrace("powershell.exe", 0, []traceSource{
		{Type: "processes", Data: json.RawMessage(procs)},
		{Type: "prefetch", Data: json.RawMessage(prefetch)},
	})

	if !res.Found {
		t.Fatal("expected target to be found")
	}
	// Ancestry must be root → target: explorer, cmd, powershell.
	if len(res.Ancestry) != 3 ||
		res.Ancestry[0].Name != "explorer.exe" ||
		res.Ancestry[2].Name != "powershell.exe" {
		t.Fatalf("unexpected ancestry: %+v", res.Ancestry)
	}
	if res.Summary["user"] != "CORP\\alice" || res.Summary["parent"] != "cmd.exe" {
		t.Errorf("summary user/parent wrong: %+v", res.Summary)
	}
	// Timeline should include the 3 process-start events + 2 prefetch runs = 5.
	if len(res.Timeline) != 5 {
		t.Errorf("expected 5 timeline events, got %d", len(res.Timeline))
	}
	// Oldest first: the earliest dated event is the 2026-05-30 prefetch run.
	if res.Timeline[0].ts.IsZero() || res.Timeline[0].Time != "2026-05-30 08:00:00" {
		t.Errorf("timeline not sorted oldest-first: first=%+v", res.Timeline[0])
	}
}

func TestBuildEntityTrace_ByPID(t *testing.T) {
	procs := `[
		{"pid":10,"ppid":0,"name":"a.exe"},
		{"pid":11,"ppid":10,"name":"b.exe"}
	]`
	res := buildEntityTrace("ignored-name", 11, []traceSource{{Type: "processes", Data: json.RawMessage(procs)}})
	if !res.Found || len(res.Ancestry) != 2 || res.Ancestry[1].PID != 11 {
		t.Fatalf("PID match/ancestry failed: %+v", res.Ancestry)
	}
}

func TestBuildEntityTrace_NoProcessStillTracesArtifacts(t *testing.T) {
	// No process snapshot, but MFT + shimcache mention the file.
	mft := `[{"name":"evil.exe","file_path":"C:\\Temp\\evil.exe","created":"2026-06-01T10:00:00Z","sha256":"abc"}]`
	shim := `[{"path":"C:\\Temp\\evil.exe","last_modified":"2026-05-31T10:00:00Z"}]`
	res := buildEntityTrace("evil.exe", 0, []traceSource{
		{Type: "mft", Data: json.RawMessage(mft)},
		{Type: "shimcache", Data: json.RawMessage(shim)},
	})
	if len(res.Timeline) != 2 {
		t.Fatalf("expected 2 artifact events, got %d", len(res.Timeline))
	}
	// Found is false (no process) but artifacts still traced.
	if res.Found {
		t.Error("Found should be false without a matching process")
	}
}

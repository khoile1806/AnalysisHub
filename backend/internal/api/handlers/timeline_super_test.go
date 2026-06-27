package handlers

import (
	"encoding/json"
	"testing"
)

func TestNormalizeArtifact_MFT_Array(t *testing.T) {
	raw := json.RawMessage(`[
		{"name":"evil.exe","file_path":"C:\\Temp\\evil.exe","created":"2026-06-01T10:00:00Z","sha256":"abc","suspicious":["temp-dir exe"]},
		{"name":"clean.txt","file_path":"C:\\Users\\a.txt","created":"2026-06-01T09:00:00Z"}
	]`)

	all := normalizeArtifact("mft", raw, false)
	if len(all) != 2 {
		t.Fatalf("expected 2 events, got %d", len(all))
	}

	onlySusp := normalizeArtifact("mft", raw, true)
	if len(onlySusp) != 1 {
		t.Fatalf("only_suspicious should yield 1 event, got %d", len(onlySusp))
	}
	if onlySusp[0].Severity != "high" {
		t.Errorf("suspicious entry should be high severity, got %s", onlySusp[0].Severity)
	}
	if onlySusp[0].Value != "abc" {
		t.Errorf("expected sha256 IOC value, got %q", onlySusp[0].Value)
	}
}

func TestNormalizeArtifact_Prefetch_ExpandsRuns(t *testing.T) {
	// Wrapped under "entries" and with multiple run times → one event per run.
	raw := json.RawMessage(`{"entries":[
		{"executable":"POWERSHELL.EXE","run_count":3,"last_run_times":["2026-06-01T10:00:00Z","2026-06-01T11:00:00Z"],"suspicious":true}
	]}`)
	got := normalizeArtifact("prefetch", raw, false)
	if len(got) != 2 {
		t.Fatalf("expected 2 run events, got %d", len(got))
	}
	for _, e := range got {
		if e.Severity != "high" {
			t.Errorf("prefetch suspicious=true should be high, got %s", e.Severity)
		}
	}
}

func TestNormalizeArtifact_DropsUntimedEntries(t *testing.T) {
	// Shimcache rows without last_modified must be dropped (no timeline anchor).
	raw := json.RawMessage(`[{"path":"C:\\x.exe","name":"x.exe"}]`)
	if got := normalizeArtifact("shimcache", raw, false); len(got) != 0 {
		t.Fatalf("untimed shimcache entry should be dropped, got %d", len(got))
	}
}

func TestDecodeArtifactRows_SingleObject(t *testing.T) {
	rows := decodeArtifactRows(json.RawMessage(`{"name":"a","created":"2026-01-01T00:00:00Z"}`))
	if len(rows) != 1 {
		t.Fatalf("single object should decode to 1 row, got %d", len(rows))
	}
}

func TestParseArtifactTime(t *testing.T) {
	if parseArtifactTime("0001-01-01T00:00:00Z").IsZero() != true {
		t.Error("Go zero time string should parse as zero")
	}
	if parseArtifactTime("2026-06-01T10:00:00Z").IsZero() {
		t.Error("RFC3339 should parse")
	}
	if parseArtifactTime(float64(1_700_000_000)).IsZero() {
		t.Error("epoch seconds should parse")
	}
}

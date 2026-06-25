package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestStorage roots a LocalStorage at a throwaway temp dir.
func newTestStorage(t *testing.T) *LocalStorage {
	t.Helper()
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// assertWithin fails if abs escapes the storage BasePath. This is the core
// security guarantee: no stored file may land outside BasePath, regardless of
// what filename the (untrusted) uploader supplies.
func assertWithin(t *testing.T, base, abs string) {
	t.Helper()
	baseAbs, _ := filepath.Abs(base)
	gotAbs, _ := filepath.Abs(abs)
	rel, err := filepath.Rel(baseAbs, gotAbs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		t.Errorf("path escapes BasePath: base=%q path=%q (rel=%q)", baseAbs, gotAbs, rel)
	}
}

// traversalNames are filenames an attacker might supply to break out of the
// storage root. On Windows both "/" and "\" are path separators, so both
// forms are exercised; absolute and drive-qualified paths are included too.
var traversalNames = []string{
	"../../../etc/passwd",
	"..\\..\\..\\Windows\\System32\\evil.dll",
	"/etc/shadow",
	"C:\\Windows\\system32\\drivers\\etc\\hosts",
	"....//....//secret",
	"normal.txt",
}

func TestSaveTool_StaysWithinRoot(t *testing.T) {
	s := newTestStorage(t)
	for _, name := range traversalNames {
		stored, err := s.SaveTool(name, strings.NewReader("payload"))
		if err != nil {
			t.Fatalf("SaveTool(%q): %v", name, err)
		}
		// Returned name must be a bare basename (no separators).
		if strings.ContainsAny(stored, `/\`) {
			t.Errorf("SaveTool(%q) returned non-basename %q", name, stored)
		}
		assertWithin(t, s.BasePath, s.GetToolPath(stored))
	}
}

func TestSaveArtifact_StaysWithinRoot(t *testing.T) {
	s := newTestStorage(t)
	for _, name := range traversalNames {
		rel, err := s.SaveArtifact("job-123", name, strings.NewReader("x"))
		if err != nil {
			t.Fatalf("SaveArtifact(%q): %v", name, err)
		}
		assertWithin(t, s.BasePath, s.GetArtifactByRelPath(rel))
		// The relative path must remain anchored under artifacts/<jobID>/.
		if !strings.HasPrefix(filepath.ToSlash(rel), "artifacts/job-123/") {
			t.Errorf("SaveArtifact(%q) rel=%q not anchored under artifacts/job-123/", name, rel)
		}
	}
}

func TestSaveCaseEvidence_StaysWithinRoot(t *testing.T) {
	s := newTestStorage(t)
	for _, name := range traversalNames {
		rel, err := s.SaveCaseEvidence("case-abc", "uniq", name, strings.NewReader("x"))
		if err != nil {
			t.Fatalf("SaveCaseEvidence(%q): %v", name, err)
		}
		assertWithin(t, s.BasePath, s.GetEvidencePath(rel))
		if !strings.HasPrefix(filepath.ToSlash(rel), "case-evidence/case-abc/") {
			t.Errorf("SaveCaseEvidence(%q) rel=%q not anchored under case-evidence/case-abc/", name, rel)
		}
	}
}

func TestSaveAnalysisUpload_StaysWithinRoot(t *testing.T) {
	s := newTestStorage(t)
	for _, name := range traversalNames {
		rel, err := s.SaveAnalysisUpload("sess-1", name, strings.NewReader("x"))
		if err != nil {
			t.Fatalf("SaveAnalysisUpload(%q): %v", name, err)
		}
		assertWithin(t, s.BasePath, s.GetAnalysisUploadPath(rel))
	}
}

func TestRoundTrip_ToolContents(t *testing.T) {
	s := newTestStorage(t)
	want := "binary-content-\x00\x01\x02"
	stored, err := s.SaveTool("agent.exe", strings.NewReader(want))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s.GetToolPath(stored))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(raw) != want {
		t.Errorf("tool round-trip mismatch: got %q want %q", string(raw), want)
	}
}

func TestRemoveByRelPath_EmptyIsNoOp(t *testing.T) {
	s := newTestStorage(t)
	if err := s.RemoveByRelPath(""); err != nil {
		t.Errorf("RemoveByRelPath(\"\") should be a no-op, got %v", err)
	}
}

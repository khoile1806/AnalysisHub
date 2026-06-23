package offline

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestSelfExtractRoundTrip proves the core single-exe mechanism: a ZIP appended
// to arbitrary leading bytes (the agent executable) is read back correctly and
// the payload extracts, including a nested tools/ file.
func TestSelfExtractRoundTrip(t *testing.T) {
	// 1. Build a fake "exe": leading junk bytes that are NOT a zip.
	var buf bytes.Buffer
	buf.Write(bytes.Repeat([]byte("MZ\x90\x00FAKE-PE-STUB-BYTES"), 500))

	// 2. Append a real ZIP carrying bundle.json + a tool file.
	zw := zip.NewWriter(&buf)
	bj, _ := zw.Create("bundle.json")
	bj.Write([]byte(`{"name":"Test","platform":"windows","tools":[{"id":"t1","name":"X","file_name":"x.exe"}]}`))
	tf, _ := zw.Create("tools/t1/x.exe")
	tf.Write([]byte("BINARYCONTENT"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	// 3. Write it to a temp file and extract via the production code path.
	exe := filepath.Join(t.TempDir(), "agent-offline.exe")
	if err := os.WriteFile(exe, buf.Bytes(), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "out")

	dir, ok, err := extractEmbeddedFrom(exe, target)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !ok {
		t.Fatal("expected embedded bundle to be detected")
	}

	// 4. Verify bundle.json + the nested tool extracted intact.
	if _, err := os.Stat(filepath.Join(dir, "bundle.json")); err != nil {
		t.Errorf("bundle.json missing: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "tools", "t1", "x.exe"))
	if err != nil || string(got) != "BINARYCONTENT" {
		t.Errorf("tool file not extracted correctly: %q err=%v", got, err)
	}

	// 5. Manifest loads from the extracted dir.
	SetBundleDir(dir)
	defer SetBundleDir("")
	m, err := LoadManifest()
	if err != nil {
		t.Fatalf("LoadManifest from extracted dir: %v", err)
	}
	if m.Name != "Test" || len(m.Tools) != 1 {
		t.Errorf("unexpected manifest: %+v", m)
	}
}

// TestNoEmbeddedPayload confirms a plain binary (no appended zip) is treated as
// legacy mode, not an error.
func TestNoEmbeddedPayload(t *testing.T) {
	plain := filepath.Join(t.TempDir(), "plain.exe")
	os.WriteFile(plain, []byte("just an executable, no zip"), 0o755)
	_, ok, err := extractEmbeddedFrom(plain, t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("plain binary should not be detected as self-contained")
	}
}

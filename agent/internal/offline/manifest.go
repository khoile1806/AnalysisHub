package offline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// BundleManifest is the parsed content of bundle.json sitting next to the
// offline agent binary. It describes every tool that was pre-packaged into
// this bundle at generation time.
type BundleManifest struct {
	Name      string       `json:"name"`
	CreatedAt time.Time    `json:"created_at"`
	Platform  string       `json:"platform"` // "windows", "linux", "both"
	CaseID    string       `json:"case_id,omitempty"`
	CaseName  string       `json:"case_name,omitempty"`
	Operator  string       `json:"operator,omitempty"` // who generated the bundle (chain-of-custody)
	Tools     []BundleTool `json:"tools"`
	// Playbooks are named, ordered collections the responder can run with one
	// click. Empty = the agent synthesises a default "Collect Everything".
	Playbooks []Playbook `json:"playbooks,omitempty"`
	// Reference holds operator-selected checklists + reference playbooks (raw
	// pass-through JSON) shown in the agent's "Guide" tab during hunting.
	Reference json.RawMessage `json:"reference,omitempty"`
}

// Playbook is a named, ordered set of tool steps for one-click hunting.
type Playbook struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Steps       []PlaybookStep `json:"steps"`
}

// PlaybookStep is one tool invocation inside a playbook.
type PlaybookStep struct {
	ToolID string `json:"tool_id"`
	Args   string `json:"args,omitempty"` // overrides the tool's default args when set
}

// BundleTool describes one tool entry inside the bundle.
type BundleTool struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	FileName       string `json:"file_name"`       // e.g. "yara-scanner.zip"
	ExecutablePath string `json:"executable_path"` // e.g. "linux/yara-scanner" or "{{OS}}/tool{{EXT}}"
	DefaultArgs    string `json:"default_args"`
	Category       string `json:"category"`
	// RequiresAdmin marks tools that need elevation; the agent offers a single
	// "Restart as Administrator" when any selected tool needs it.
	RequiresAdmin bool `json:"requires_admin,omitempty"`
	// Presets are one-click argument presets (label → args) surfaced in the UI,
	// replacing the old hard-coded webshell C:\/IIS/Users buttons.
	Presets []Preset `json:"presets,omitempty"`
	// ReportPath, when set, is a path (relative to the tool dir) to an HTML report
	// the tool produces, so the UI can offer a "View Report" link for ANY tool.
	ReportPath string `json:"report_path,omitempty"`
}

// Preset is a labelled argument shortcut for a tool.
type Preset struct {
	Label string `json:"label"`
	Args  string `json:"args"`
}

// LoadManifest reads bundle.json from the same directory as the running binary.
// Falls back to the current working directory when the binary path is unavailable.
func LoadManifest() (*BundleManifest, error) {
	dir, err := bundleDir()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(filepath.Join(dir, "bundle.json"))
	if err != nil {
		return nil, fmt.Errorf("bundle.json not found in %s: %w", dir, err)
	}

	var m BundleManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("bundle.json parse error: %w", err)
	}
	if len(m.Tools) == 0 {
		return nil, fmt.Errorf("bundle.json contains no tools")
	}
	return &m, nil
}

// EffectivePlaybooks returns the manifest playbooks, or a synthesised
// "Collect Everything" playbook (every tool with its default args) when none
// were baked in — so the responder always has a one-click option.
func (m *BundleManifest) EffectivePlaybooks() []Playbook {
	if len(m.Playbooks) > 0 {
		return m.Playbooks
	}
	steps := make([]PlaybookStep, 0, len(m.Tools))
	for _, t := range m.Tools {
		steps = append(steps, PlaybookStep{ToolID: t.ID})
	}
	return []Playbook{{
		ID:          "collect-everything",
		Name:        "Collect Everything",
		Description: "Run every bundled tool in sequence.",
		Steps:       steps,
	}}
}

// RequiresAdmin reports whether any bundled tool needs elevation.
func (m *BundleManifest) RequiresAdmin() bool {
	for _, t := range m.Tools {
		if t.RequiresAdmin {
			return true
		}
	}
	return false
}

// ToolDir returns the absolute path to the pre-extracted directory for a tool.
// Layout: <bundle_dir>/tools/<toolID>/
func ToolDir(toolID string) (string, error) {
	dir, err := bundleDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tools", toolID), nil
}

// bundleDir returns the directory that holds bundle.json and tools/. For a
// single self-contained .exe this is the temp folder the embedded payload was
// extracted into (set via SetBundleDir); otherwise it is the directory of the
// running binary (legacy loose-files layout).
func bundleDir() (string, error) {
	if extractedDir != "" {
		return extractedDir, nil
	}
	exe, err := os.Executable()
	if err != nil {
		// Fallback: use working directory.
		return os.Getwd()
	}
	return filepath.Dir(exe), nil
}

// outputDir returns the directory where user-facing artefacts (reports) are
// saved. It is always the real location of the .exe the user launched (NOT the
// temp extraction dir), so a single self-contained .exe still drops its reports
// right next to where the operator put it. Falls back to the working directory.
func outputDir() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

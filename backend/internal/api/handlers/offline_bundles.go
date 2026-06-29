package handlers

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/models"
	"github.com/forensichub/backend/internal/storage"
)

// offlineBundleTool mirrors the JSON shape written to bundle.json inside
// the generated ZIP. Kept local to this handler — no shared model needed.
type offlineBundleTool struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	FileName       string `json:"file_name"`
	ExecutablePath string `json:"executable_path"`
	DefaultArgs    string `json:"default_args"`
	Category       string `json:"category"`
}

type offlineBundleManifest struct {
	Name      string              `json:"name"`
	CreatedAt time.Time           `json:"created_at"`
	Platform  string              `json:"platform"`
	CaseID    string              `json:"case_id,omitempty"`
	CaseName  string              `json:"case_name,omitempty"`
	Tools     []offlineBundleTool `json:"tools"`
}

// GenerateOfflineBundle builds a self-contained ZIP bundle for offline hunting.
//
// POST /api/v1/offline-bundles/generate
//
//	{
//	  "name":     "WebServer Hunting",
//	  "tool_ids": ["uuid1", "uuid2"],
//	  "platform": "windows"   // "windows" | "linux" | "both"
//	}
//
// The response is a streaming ZIP download. The ZIP contains:
//   - agent-offline.exe / agent-offline-linux  (pre-built binaries from /app/defaults/)
//   - bundle.json                              (tool manifest)
//   - tools/<toolID>/<original-filename>       (tool archives copied from storage)
//   - run.bat / run.sh                         (convenience launchers)
func GenerateOfflineBundle(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	store, ok := mustGetStorage(c)
	if !ok {
		return
	}
	_ = store

	var req struct {
		Name           string   `json:"name"     binding:"required"`
		ToolIDs        []string `json:"tool_ids" binding:"required,min=1"`
		Platform       string   `json:"platform"`
		CaseID         string   `json:"case_id"`          // optional: link bundle to a case
		CaseName       string   `json:"case_name"`        // optional: display name of the case
		CustomYaraRule string   `json:"custom_yara_rule"` // optional: custom YARA rule content
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	if req.Platform == "" {
		req.Platform = "both"
	}
	if req.Platform != "windows" && req.Platform != "linux" && req.Platform != "both" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "platform must be windows, linux, or both"})
		return
	}

	// Load tool records from DB.
	var tools []models.Tool
	if err := db.Where("id IN ?", req.ToolIDs).Find(&tools).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to load tools"})
		return
	}
	if len(tools) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "no valid tools found"})
		return
	}

	// Build manifest.
	manifest := offlineBundleManifest{
		Name:      req.Name,
		CreatedAt: time.Now().UTC(),
		Platform:  req.Platform,
		CaseID:    req.CaseID,
		CaseName:  req.CaseName,
	}
	for _, t := range tools {
		args := t.Args
		// If custom yara rule is provided, append the args for yara-scanner
		if req.CustomYaraRule != "" && strings.Contains(strings.ToLower(t.Name), "webshell scanner") {
			args += " --all-files --yara-rules custom_rules"
		}

		manifest.Tools = append(manifest.Tools, offlineBundleTool{
			ID:             t.ID.String(),
			Name:           t.Name,
			Description:    t.Description,
			FileName:       t.FileName,
			ExecutablePath: t.ExecutablePath,
			DefaultArgs:    args,
			Category:       t.Category,
		})
	}

	// Resolve where the pre-built offline-agent stubs live.
	defaultsDir := os.Getenv("DEFAULTS_PATH")
	if defaultsDir == "" {
		defaultsDir = "/app/defaults"
	}

	// Derive a safe filename base.
	safeBundle := safeZipName(req.Name)
	ts := time.Now().Format("20060102")

	zipName := fmt.Sprintf("offline-bundle-%s-%s.zip", safeBundle, ts)

	c.Header("Content-Type", "application/zip")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, zipName))
	c.Status(http.StatusOK)

	zw := zip.NewWriter(c.Writer)
	defer zw.Close()

	// 1. bundle.json
	if err := writeJSONEntry(zw, "bundle.json", manifest); err != nil {
		log.Printf("[offline-bundle] write manifest: %v", err)
		return
	}

	// 1.5 Custom YARA Rule if any
	if req.CustomYaraRule != "" {
		writeLauncher(zw, "custom_rules/custom.yar", req.CustomYaraRule)
	}

	// 2. Tool files — one subdirectory per tool.
	// ZIP-based tools are extracted inline so the bundle ships ready-to-run
	// files (the offline agent has no DownloadJob phase to extract archives).
	for _, t := range tools {
		toolPath := store.GetToolPath(t.ID.String() + filepath.Ext(t.FileName))
		if err := addToolToZip(zw, toolPath, t.ID.String(), t.FileName); err != nil {
			log.Printf("[offline-bundle] add tool %s: %v", t.Name, err)
		}
	}

	// 3. Pre-built offline agent binaries from /app/defaults/ (if available).
	addOfflineAgentBinaries(zw, defaultsDir, req.Platform)

	// 4. Convenience launchers.
	if req.Platform == "windows" || req.Platform == "both" {
		bat := "@echo off\r\n" +
			":: Request Administrator Privileges (Required for most forensics tools)\r\n" +
			"net session >nul 2>&1\r\n" +
			"if %errorLevel% neq 0 (\r\n" +
			"    echo Requesting Administrative Privileges...\r\n" +
			"    powershell -Command \"Start-Process -FilePath '%~f0' -Verb RunAs\"\r\n" +
			"    exit /b\r\n" +
			")\r\n" +
			"cd /d \"%~dp0\"\r\n" +
			"echo ForensicHub Offline Agent\r\n" +
			"echo Bundle : " + req.Name + "\r\n"
		if req.CaseName != "" {
			bat += "echo Case   : " + req.CaseName + "\r\n"
		}
		bat += "echo.\r\n" +
			"if not exist \"%~dp0agent-offline.exe\" (\r\n" +
			"    echo [ERROR] agent-offline.exe not found in this directory.\r\n" +
			"    echo         The bundle may be incomplete. Contact your administrator.\r\n" +
			"    pause\r\n" +
			"    exit /b 1\r\n" +
			")\r\n" +
			"start \"\" \"%~dp0agent-offline.exe\"\r\n"
		writeLauncher(zw, "run.bat", bat)
	}
	if req.Platform == "linux" || req.Platform == "both" {
		sh := "#!/bin/sh\n" +
			"echo 'ForensicHub Offline Agent'\n" +
			"echo 'Bundle : " + req.Name + "'\n"
		if req.CaseName != "" {
			sh += "echo 'Case   : " + req.CaseName + "'\n"
		}
		sh += "SCRIPT_DIR=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\n" +
			"BIN=\"$SCRIPT_DIR/agent-offline-linux\"\n" +
			"if [ ! -f \"$BIN\" ]; then\n" +
			"    echo '[ERROR] agent-offline-linux not found in this directory.'\n" +
			"    exit 1\n" +
			"fi\n" +
			"chmod +x \"$BIN\"\n" +
			"\"$BIN\" \"$@\"\n"
		writeLauncher(zw, "run.sh", sh)
	}

	// 5. README
	writeLauncher(zw, "README.txt", buildReadme(req.Name, req.Platform, req.CaseName, tools))

	log.Printf("[offline-bundle] generated %q (%d tools, platform=%s)", req.Name, len(tools), req.Platform)
}

// generateSelfExtractingExe streams a single self-contained Windows executable:
// the pre-built offline-agent stub with a ZIP payload (bundle.json + tools/)
// appended to it. The agent opens its own file as a ZIP at startup, unpacks the
// payload to a temp dir, and runs - so the operator just double-clicks ONE .exe,
// no installer and no loose files. Go's archive/zip locates the appended ZIP's
// end-of-central-directory from the end of the file, so the leading exe bytes are
// transparently ignored on read.
func generateSelfExtractingExe(c *gin.Context, db *gorm.DB, store *storage.LocalStorage,
	defaultsDir string, manifest offlineBundleManifest, tools []models.Tool, exeName string) {
	_ = db

	stubPath := filepath.Join(defaultsDir, "agent-offline.exe")
	stub, err := os.Open(stubPath)
	if err != nil {
		log.Printf("[offline-bundle] stub agent-offline.exe not found at %s: %v", stubPath, err)
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false,
			"error": "windows offline-agent binary not available on the server (build it with `make build-offline-all` in agent/)"})
		return
	}
	defer stub.Close()

	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, exeName))
	c.Status(http.StatusOK)

	// 1. Write the agent stub executable.
	if _, err := io.Copy(c.Writer, stub); err != nil {
		log.Printf("[offline-bundle] write stub: %v", err)
		return
	}

	// 2. Append the bundle payload as a ZIP (continues in the same stream).
	zw := zip.NewWriter(c.Writer)
	defer zw.Close()
	if err := writeJSONEntry(zw, "bundle.json", manifest); err != nil {
		log.Printf("[offline-bundle] write manifest: %v", err)
		return
	}
	for _, t := range tools {
		toolPath := store.GetToolPath(t.ID.String() + filepath.Ext(t.FileName))
		if err := addToolToZip(zw, toolPath, t.ID.String(), t.FileName); err != nil {
			log.Printf("[offline-bundle] add tool %s: %v", t.Name, err)
		}
	}
	log.Printf("[offline-bundle] generated single-exe %q (%d tools)", exeName, len(tools))
}

// ── helpers ──────────────────────────────────────────────────────────────────

// addOfflineAgentBinaries copies pre-built offline agent binaries into the ZIP.
// Missing binaries are skipped with a warning — the operator can build them
// from the agent/ directory using `make build-offline-all`.
func addOfflineAgentBinaries(zw *zip.Writer, defaultsDir, platform string) {
	type entry struct {
		src  string
		dest string
	}
	candidates := []entry{
		{"agent-offline.exe", "agent-offline.exe"},
		{"agent-offline-linux", "agent-offline-linux"},
	}
	if platform == "windows" {
		candidates = candidates[:1]
	} else if platform == "linux" {
		candidates = candidates[1:]
	}

	for _, e := range candidates {
		src := filepath.Join(defaultsDir, e.src)
		if err := addFileToZip(zw, src, e.dest); err != nil {
			log.Printf("[offline-bundle] binary %s not found at %s — skipping (run `make build-offline-all` in agent/)", e.src, src)
		}
	}
}

func writeJSONEntry(zw *zip.Writer, name string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// addToolToZip adds a single tool into the bundle under tools/<toolID>/.
// ZIP archives are extracted inline (tools/<toolID>/<entry>...) so the bundle
// is ready-to-run; non-ZIP tools are copied as a single file.
func addToolToZip(zw *zip.Writer, srcPath, toolID, fileName string) error {
	dest := "tools/" + toolID + "/"
	if strings.EqualFold(filepath.Ext(fileName), ".zip") {
		return extractZipIntoBundle(zw, srcPath, dest)
	}
	return addFileToZip(zw, srcPath, dest+fileName)
}

// extractZipIntoBundle reads a stored tool ZIP and re-adds every file entry to
// the bundle ZIP under destPrefix, preventing path traversal.
func extractZipIntoBundle(zw *zip.Writer, zipPath, destPrefix string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		// ZIP entries use forward slashes; reject traversal attempts.
		name := strings.TrimPrefix(f.Name, "/")
		if strings.Contains(name, "..") {
			continue
		}
		rc, openErr := f.Open()
		if openErr != nil {
			return openErr
		}
		w, createErr := zw.Create(destPrefix + name)
		if createErr != nil {
			rc.Close()
			return createErr
		}
		_, copyErr := io.Copy(w, rc)
		rc.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	return nil
}

func addFileToZip(zw *zip.Writer, src, dest string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = dest
	header.Method = zip.Deflate

	w, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, f)
	return err
}

func writeLauncher(zw *zip.Writer, name, content string) {
	w, err := zw.Create(name)
	if err != nil {
		log.Printf("[offline-bundle] create %s: %v", name, err)
		return
	}
	w.Write([]byte(content))
}

func buildReadme(bundleName, platform, caseName string, tools []models.Tool) string {
	var sb strings.Builder
	sb.WriteString("ForensicHub Offline Agent Bundle\n")
	sb.WriteString("Bundle: " + bundleName + "\n")
	if caseName != "" {
		sb.WriteString("Case:   " + caseName + "\n")
	}
	sb.WriteString("\n")

	sb.WriteString("USAGE\n-----\n")
	if platform == "windows" || platform == "both" {
		sb.WriteString("Windows: double-click run.bat  OR  run agent-offline.exe\n")
	}
	if platform == "linux" || platform == "both" {
		sb.WriteString("Linux:   chmod +x run.sh && ./run.sh\n")
		sb.WriteString("         For SSH sessions without a browser, use: ./agent-offline-linux --cli\n")
		sb.WriteString("         For SSH tunnel: ssh -L 7474:localhost:7474 user@victim\n")
	}

	sb.WriteString("\nBUNDLED TOOLS\n-------------\n")
	for i, t := range tools {
		sb.WriteString(fmt.Sprintf("  %d. %s (%s)\n", i+1, t.Name, t.Category))
		if t.Description != "" {
			sb.WriteString("     " + t.Description + "\n")
		}
	}

	sb.WriteString("\nNOTE: This bundle is completely offline. No internet connection is required.\n")
	sb.WriteString("      All output is saved to report-<hostname>-<timestamp>.html/.json\n")
	return sb.String()
}

func safeZipName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	result := b.String()
	// Collapse consecutive dashes.
	for strings.Contains(result, "--") {
		result = strings.ReplaceAll(result, "--", "-")
	}
	return strings.Trim(result, "-")
}

// ListOfflineBundles is a placeholder — bundles are generated on-demand and
// streamed directly without being stored in the database.
func ListOfflineBundles(c *gin.Context) {
	_ = c.MustGet("db").(*gorm.DB)
	c.JSON(http.StatusOK, gin.H{"bundles": []interface{}{}})
}

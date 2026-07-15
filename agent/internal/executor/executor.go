package executor

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// JobRequest describes a forensics job to be executed on this agent.
type JobRequest struct {
	// JobID is the unique identifier for this job.
	JobID string

	// ToolID is the tool UUID — used as the shared directory name so the
	// same tool is downloaded only once and reused across jobs.
	ToolID string

	// ToolName is the display name of the tool (used as the local filename base).
	ToolName string

	// FileName is the original stored filename on the server (e.g. "abc123.zip").
	// Its extension is used to detect ZIP bundles vs plain binaries.
	FileName string

	// DownloadURL is the full URL from which the tool binary will be fetched.
	DownloadURL string

	// Args contains additional CLI arguments passed to the tool.
	// They are split using shellSplit before being forwarded to exec.Command.
	Args string

	// ExecutablePath is the relative path to the executable within the tool
	// directory. For ZIP tools this points to the specific binary inside the
	// extracted archive (e.g. "bin/DumpIt.exe"). For single-file tools this
	// can be left empty — the downloaded binary is executed directly.
	ExecutablePath string

	// AgentToken is sent as X-Agent-Token header when downloading the tool.
	AgentToken string

	// ServerURL is the base URL of the AnalysisHub server.
	ServerURL string

	// Resource limits for Throttling on Production.
	CPULimit int
	RAMLimit int
	Priority string // "normal" or "idle"
}

// DownloadJob downloads the tool (if not already cached) into a shared tools
// directory and extracts ZIP bundles when applicable. It does NOT execute the
// tool — execution is deferred to ExecuteJob, triggered by a "job_run" command
// from the server.
//
// Tools are stored in workDir/tools/<tool_id>/ and reused across jobs.
// outputCh is closed when download + extract finishes (or fails).
func DownloadJob(ctx context.Context, req JobRequest, workDir string, outputCh chan<- string) error {
	defer close(outputCh)

	toolDir, err := prepareToolDir(workDir, req)
	if err != nil {
		return err
	}

	downloadedPath, err := ensureTool(ctx, req, toolDir, outputCh)
	if err != nil {
		return err
	}

	if strings.EqualFold(filepath.Ext(downloadedPath), ".zip") {
		if err := ensureExtracted(ctx, downloadedPath, toolDir, outputCh); err != nil {
			return err
		}
	}

	send(ctx, outputCh, "[+] Tool ready — waiting for operator to trigger run")
	return nil
}

// ExecuteJob runs a tool that has already been downloaded by DownloadJob.
// It resolves the executable path, streams stdout/stderr to outputCh, and
// closes outputCh when the process exits (or is cancelled via ctx).
//
// Cancelling ctx kills the running process — used by the "job_stop" command.
func ExecuteJob(ctx context.Context, req JobRequest, workDir string, outputCh chan<- string) error {
	defer close(outputCh)

	toolDir, err := prepareToolDir(workDir, req)
	if err != nil {
		return err
	}
	send(ctx, outputCh, fmt.Sprintf("[+] Tool dir: %s", toolDir))

	downloadedPath := filepath.Join(toolDir, SanitizeFilename(firstNonEmpty(req.FileName, req.ToolName)))
	isZip := strings.EqualFold(filepath.Ext(downloadedPath), ".zip")

	var execPath string
	if req.ExecutablePath != "" {
		// Support {{OS}} and {{EXT}} placeholders for cross-platform tools
		ext := ""
		if runtime.GOOS == "windows" {
			ext = ".exe"
		}
		relPath := strings.ReplaceAll(req.ExecutablePath, "{{OS}}", runtime.GOOS)
		relPath = strings.ReplaceAll(relPath, "{{EXT}}", ext)
		execPath = filepath.Join(toolDir, filepath.Clean(relPath))
		if !strings.HasPrefix(filepath.Clean(execPath), filepath.Clean(toolDir)+string(os.PathSeparator)) {
			return fmt.Errorf("executor: executable_path %q escapes tool directory", req.ExecutablePath)
		}
	} else if !isZip {
		execPath = downloadedPath
	} else {
		send(ctx, outputCh, "[!] No executable_path specified for a ZIP tool — nothing to run")
		return fmt.Errorf("executor: executable_path required for ZIP tool")
	}

	send(ctx, outputCh, fmt.Sprintf("[+] Resolved executable: %s", execPath))

	// If not found at given path, search for the basename recursively.
	if _, err := os.Stat(execPath); err != nil {
		send(ctx, outputCh, fmt.Sprintf("[!] stat failed (%v) — searching by basename", err))
		targetName := filepath.Base(execPath)
		var found []string
		filepath.Walk(toolDir, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil || info.IsDir() {
				return nil
			}
			if strings.EqualFold(filepath.Base(path), targetName) {
				rel, _ := filepath.Rel(toolDir, path)
				found = append(found, rel)
			}
			return nil
		})
		if len(found) > 0 {
			sort.Slice(found, func(i, j int) bool {
				return len(found[i]) < len(found[j])
			})
			if len(found) > 1 {
				send(ctx, outputCh, fmt.Sprintf("[!] Found %d matches, using the shortest path: %s", len(found), found[0]))
			} else {
				send(ctx, outputCh, fmt.Sprintf("[!] executable_path %q not found, auto-using: %s", req.ExecutablePath, found[0]))
			}
			execPath = filepath.Join(toolDir, found[0])
		} else {
			return fmt.Errorf("executor: executable not found: %s", execPath)
		}
	}

	send(ctx, outputCh, fmt.Sprintf("[+] Running: %s %s", filepath.Base(execPath), req.Args))

	return runToolProcess(ctx, execPath, shellSplit(req.Args), req, toolDir, outputCh)
}

// prepareToolDir resolves and ensures the shared tool directory exists.
func prepareToolDir(workDir string, req JobRequest) (string, error) {
	toolID := req.ToolID
	if toolID == "" {
		toolID = SanitizeFilename(req.ToolName)
	}
	toolDir := filepath.Join(workDir, "tools", toolID)
	if err := os.MkdirAll(toolDir, 0o755); err != nil {
		return "", fmt.Errorf("executor: create tool dir %s: %w", toolDir, err)
	}
	return toolDir, nil
}

// firstNonEmpty returns the first non-empty string from the arguments.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// rebaseDownloadURL rewrites the scheme+host of a server-provided download URL
// to the agent's own ServerURL (the host it connected through), keeping the
// path and query. This makes tool downloads robust to the backend advertising a
// PUBLIC_URL/domain the agent cannot reach. Returns the original URL if
// serverURL is empty or either URL fails to parse.
func rebaseDownloadURL(rawURL, serverURL string) string {
	if strings.TrimSpace(serverURL) == "" {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	base, err := url.Parse(serverURL)
	if err != nil || base.Host == "" {
		return rawURL
	}
	u.Scheme = base.Scheme
	u.Host = base.Host
	return u.String()
}

// ensureTool downloads the tool to toolDir if not already present.
// Returns the path to the downloaded file.
func ensureTool(ctx context.Context, req JobRequest, toolDir string, outputCh chan<- string) (string, error) {
	// Use the original uploaded filename so the file keeps its real name.
	// Fall back to tool display name if FileName is missing.
	toolName := SanitizeFilename(req.FileName)
	if toolName == "" || toolName == "tool" {
		toolName = SanitizeFilename(req.ToolName)
	}
	toolPath := filepath.Join(toolDir, toolName)

	// If the file already exists, skip download (tool is cached).
	if info, err := os.Stat(toolPath); err == nil && info.Size() > 0 {
		send(ctx, outputCh, fmt.Sprintf("[+] Tool cached: %s", toolPath))
		return toolPath, nil
	}

	send(ctx, outputCh, fmt.Sprintf("[+] Downloading tool: %s", req.ToolName))

	// Always download from the server this agent is actually connected to, not
	// whatever host the backend baked into the URL (its PUBLIC_URL/domain may be
	// unreachable from the agent, e.g. a LAN agent vs a public domain). We keep
	// only the path/query and re-base the scheme+host onto our own ServerURL.
	dlURL := rebaseDownloadURL(req.DownloadURL, req.ServerURL)
	if dlURL != req.DownloadURL {
		send(ctx, outputCh, fmt.Sprintf("[i] Re-based download URL to agent server: %s", dlURL))
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, dlURL, nil)
	if err != nil {
		return "", fmt.Errorf("executor: build download request: %w", err)
	}
	httpReq.Header.Set("X-Agent-Token", req.AgentToken)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("executor: download %s: %w", dlURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("executor: download %s: server returned %s", dlURL, resp.Status)
	}

	f, err := os.OpenFile(toolPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", fmt.Errorf("executor: create tool file %s: %w", toolPath, err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return "", fmt.Errorf("executor: write tool binary: %w", err)
	}

	send(ctx, outputCh, fmt.Sprintf("[+] Downloaded to: %s", toolPath))
	return toolPath, nil
}

// ensureExtracted extracts the ZIP if it hasn't been extracted yet.
// Detection: if the toolDir contains files/dirs besides the zip itself,
// extraction is skipped. Always reports the full recursive tree so the
// user can see exact paths for executable_path.
func ensureExtracted(ctx context.Context, zipPath, toolDir string, outputCh chan<- string) error {
	zipBase := filepath.Base(zipPath)

	// Check if already extracted.
	alreadyExtracted := false
	entries, _ := os.ReadDir(toolDir)
	for _, e := range entries {
		if e.Name() != zipBase {
			alreadyExtracted = true
			break
		}
	}

	if alreadyExtracted {
		send(ctx, outputCh, "[+] Tool already extracted, skipping")
	} else {
		send(ctx, outputCh, fmt.Sprintf("[+] Extracting to: %s", toolDir))
		if err := extractZip(zipPath, toolDir); err != nil {
			return fmt.Errorf("executor: extract zip: %w", err)
		}
	}

	// Limit output to prevent flooding the WebSocket and UI.
	send(ctx, outputCh, "[+] Tool contents:")
	count := 0
	listTree(ctx, toolDir, toolDir, zipBase, outputCh, &count)
	if count > 50 {
		send(ctx, outputCh, fmt.Sprintf("    ... and %d more files/directories hidden to save space.", count-50))
	}

	return nil
}

// listTree recursively lists all files/dirs under root, streaming each entry
// to outputCh with indented relative paths. Skips the zip file itself.
func listTree(ctx context.Context, root, dir, skipName string, outputCh chan<- string, count *int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if dir == root && e.Name() == skipName {
			continue
		}
		*count++
		rel, _ := filepath.Rel(root, filepath.Join(dir, e.Name()))

		if *count <= 50 {
			if e.IsDir() {
				send(ctx, outputCh, fmt.Sprintf("    %s/", rel))
			} else {
				info, _ := e.Info()
				if info != nil {
					send(ctx, outputCh, fmt.Sprintf("    %s (%s)", rel, humanSize(info.Size())))
				} else {
					send(ctx, outputCh, fmt.Sprintf("    %s", rel))
				}
			}
		}

		if e.IsDir() {
			listTree(ctx, root, filepath.Join(dir, e.Name()), skipName, outputCh, count)
		}
	}
}

// send is a helper to write a line to outputCh without blocking on context cancel.
func send(ctx context.Context, ch chan<- string, line string) bool {
	select {
	case ch <- line:
		return true
	case <-ctx.Done():
		return false
	}
}

// humanSize returns a human-readable representation of a byte count.
func humanSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// extractZip extracts all files from zipPath into destDir, preventing path
// traversal by rejecting entries whose cleaned path escapes destDir.
func extractZip(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		// ZIP spec uses POSIX (forward-slash) paths — use path.Clean (not filepath.Clean)
		// to normalize without converting separators prematurely.
		// filepath.Clean("/"+f.Name) produces an absolute path on both Windows and Linux,
		// causing filepath.Join to discard destDir entirely (path traversal + silent failure).
		cleanName := path.Clean(f.Name)

		// Reject absolute POSIX paths and directory-traversal sequences.
		if path.IsAbs(cleanName) || strings.HasPrefix(cleanName, "..") {
			return fmt.Errorf("zip entry %q escapes destination", f.Name)
		}

		// Convert POSIX separators to OS separators and join with destDir.
		entryPath := filepath.Join(destDir, filepath.FromSlash(cleanName))

		// Defence-in-depth: verify the resolved path stays inside destDir.
		if !strings.HasPrefix(entryPath, filepath.Clean(destDir)+string(os.PathSeparator)) &&
			entryPath != filepath.Clean(destDir) {
			return fmt.Errorf("zip entry %q escapes destination", f.Name)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(entryPath, 0o755); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(entryPath), 0o755); err != nil {
			return err
		}

		out, err := os.OpenFile(entryPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			out.Close()
			return err
		}

		_, copyErr := io.Copy(out, rc)
		rc.Close()
		out.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	return nil
}

// shellSplit splits a string into tokens, honouring single- and double-quoted
// substrings so that arguments containing spaces can be passed correctly.
// For an empty or whitespace-only string it returns nil.
//
// Examples:
//
//	`-o output.txt --verbose`        → ["-o", "output.txt", "--verbose"]
//	`-c "get-processes --all"`       → ["-c", "get-processes --all"]
//	`--path '/tmp/my dir/file.txt'`  → ["--path", "/tmp/my dir/file.txt"]
func shellSplit(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	var tokens []string
	var buf strings.Builder
	var inQuote rune

	for _, ch := range s {
		switch {
		case inQuote != 0:
			if ch == inQuote {
				inQuote = 0
			} else {
				buf.WriteRune(ch)
			}
		case ch == '\'' || ch == '"':
			inQuote = ch
		case ch == ' ' || ch == '\t':
			if buf.Len() > 0 {
				tokens = append(tokens, buf.String())
				buf.Reset()
			}
		default:
			buf.WriteRune(ch)
		}
	}
	if buf.Len() > 0 {
		tokens = append(tokens, buf.String())
	}

	return tokens
}

// SanitizeFilename strips directory components and characters that are unsafe
// in filenames on both Windows and Linux.
func SanitizeFilename(name string) string {
	// Keep only the base name to prevent path traversal.
	name = filepath.Base(name)

	// Replace characters that are illegal in Windows filenames.
	illegal := `<>:"/\|?*`
	for _, c := range illegal {
		name = strings.ReplaceAll(name, string(c), "_")
	}

	if name == "" || name == "." {
		name = "tool"
	}
	return name
}

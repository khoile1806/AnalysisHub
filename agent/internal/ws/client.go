package ws

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/rand"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"encoding/base64"

	"github.com/analysishub/agent/internal/config"
	"github.com/analysishub/agent/internal/executor"
	"github.com/analysishub/agent/internal/fs"
	"github.com/analysishub/agent/internal/monitor"
	"github.com/analysishub/agent/internal/parser"
	"github.com/analysishub/agent/internal/terminal"
	"github.com/gorilla/websocket"

	osExec "os/exec"
)

// ----------------------------------------------------------------------------
// Wire-protocol message types
// ----------------------------------------------------------------------------

// inboundMsg represents any message received from the AnalysisHub server.
type inboundMsg struct {
	Type           string `json:"type"`
	JobID          string `json:"job_id,omitempty"`
	ToolID         string `json:"tool_id,omitempty"`
	ToolName       string `json:"tool_name,omitempty"`
	FileName       string `json:"file_name,omitempty"`
	DownloadURL    string `json:"download_url,omitempty"`
	Args           string `json:"args,omitempty"`
	ExecutablePath string `json:"executable_path,omitempty"`
	CPULimit       int    `json:"cpu_limit,omitempty"`
	RAMLimit       int    `json:"ram_limit,omitempty"`
	Priority       string `json:"priority,omitempty"`

	// Result-collection spec (auto-pull tool output files back to the server).
	CollectResult   bool   `json:"collect_result,omitempty"`
	OutputGlobs     string `json:"output_globs,omitempty"`
	OutputScope     string `json:"output_scope,omitempty"`
	ResultProcessor string `json:"result_processor,omitempty"`
	MaxResultMB     int    `json:"max_result_mb,omitempty"`

	// Terminal (interactive PTY) fields.
	SessionID string `json:"session_id,omitempty"`
	Shell     string `json:"shell,omitempty"`
	Cols      int    `json:"cols,omitempty"`
	Rows      int    `json:"rows,omitempty"`
	Data      string `json:"data,omitempty"` // base64 stdin for shell_input

	// Filesystem browser fields.
	FsOp    string   `json:"fs_op,omitempty"`    // "list" | "read_file" | "read_folder" | "read_bundle"
	FsPath  string   `json:"fs_path,omitempty"`  // for list / read_file / read_folder
	FsPaths []string `json:"fs_paths,omitempty"` // for read_bundle (multi-select)

	// Containment fields.
	Pid int `json:"pid,omitempty"` // for kill_process
}

// outboundMsg represents any message sent to the AnalysisHub server.
type outboundMsg struct {
	Type     string `json:"type"`
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
	IP       string `json:"ip,omitempty"`
	JobID    string `json:"job_id,omitempty"`
	Data     string `json:"data,omitempty"`
	Done     bool   `json:"done,omitempty"`
	DataType string `json:"data_type,omitempty"`
	Payload  string `json:"payload,omitempty"`
	Status   string `json:"status,omitempty"` // for type=="job_status": "ready" | "stopped"

	// Terminal (interactive PTY) fields.
	SessionID string `json:"session_id,omitempty"`
	ExitCode  int    `json:"exit_code,omitempty"`

	// Resource telemetry (type=="resource_report").
	CPUPercent  float64 `json:"cpu_percent,omitempty"`
	MemUsedMB   int64   `json:"mem_used_mb,omitempty"`
	MemTotalMB  int64   `json:"mem_total_mb,omitempty"`
	DiskUsedGB  float64 `json:"disk_used_gb,omitempty"`
	DiskTotalGB float64 `json:"disk_total_gb,omitempty"`

	// Filesystem browser response fields (type=="fs_response").
	FsOp        string     `json:"fs_op,omitempty"`
	FsEntries   []fs.Entry `json:"fs_entries,omitempty"`   // for op=list
	FsTruncated bool       `json:"fs_truncated,omitempty"` // true when list was capped at maxListEntries
	FsData      string     `json:"fs_data,omitempty"`      // base64 chunk for read_file/read_folder/read_bundle
	FsSize      int64      `json:"fs_size,omitempty"`      // total size in first read_file frame
	FsDone      bool       `json:"fs_done,omitempty"`
	FsError     string     `json:"fs_error,omitempty"`
}

const (
	// writeWait is the maximum time allowed for a single write to complete.
	// Set to 30 s to accommodate bursts of PTY shell output that hold the
	// write mutex for an extended period; a 10 s deadline caused spurious
	// disconnects when the terminal was active.
	writeWait = 30 * time.Second
	// pongWait is the maximum time to wait for any inbound traffic (message or
	// WebSocket pong) before declaring the connection dead.
	pongWait = 60 * time.Second
	// pingInterval is how often the agent sends a WebSocket-level ping frame to
	// keep the connection alive through NAT / proxies and detect dead peers.
	pingInterval = 30 * time.Second
	// realtimeWriteWait is the deadline for realtime telemetry frames only.
	// These are low-priority: if the connection is congested (e.g. heavy shell
	// output) we drop the frame rather than block or close the connection.
	realtimeWriteWait = 5 * time.Second
)

// ----------------------------------------------------------------------------
// Client
// ----------------------------------------------------------------------------

// Client manages a persistent WebSocket connection to the AnalysisHub server.
// It reconnects automatically with exponential back-off on any disconnect.
type Client struct {
	cfg *config.Config

	// conn is the live WebSocket connection. Protected by writeMu for writes;
	// only the reader goroutine and reconnect logic touch it otherwise.
	conn    *websocket.Conn
	writeMu sync.Mutex

	// runningJobs tracks currently-executing jobs so they can be cancelled by
	// a "job_stop" command. Each entry maps jobID → cancel function.
	runningJobs   map[string]context.CancelFunc
	runningJobsMu sync.Mutex

	// terminalSessions tracks live PTY sessions keyed by sessionID.
	terminalSessions   map[string]*terminal.Session
	terminalSessionsMu sync.Mutex

	spooler *Spooler
}

// NewClient creates a Client for the supplied configuration. Call Run() to
// start the connection loop.
func NewClient(cfg *config.Config) *Client {
	sp, err := NewSpooler(cfg.WorkDir)
	if err != nil {
		log.Printf("[ws] warning: could not initialize spooler: %v", err)
	}

	return &Client{
		cfg:              cfg,
		runningJobs:      make(map[string]context.CancelFunc),
		terminalSessions: make(map[string]*terminal.Session),
		spooler:          sp,
	}
}

// Run starts the connect-reconnect loop. It blocks until ctx is cancelled.
func (c *Client) Run(ctx context.Context) {
	backoff := time.Second
	const maxBackoff = 60 * time.Second

	for {
		log.Printf("[ws] connecting to %s …", c.serverWSURL())
		start := time.Now()
		err := c.connect(ctx)
		if err != nil {
			log.Printf("[ws] session ended: %v", err)
		}

		// Reset back-off if the connection was healthy for a meaningful duration.
		// This avoids a long wait after a brief transient drop of a stable session.
		if time.Since(start) > 30*time.Second {
			backoff = time.Second
		}

		select {
		case <-ctx.Done():
			log.Println("[ws] context cancelled — shutting down")
			return
		default:
		}

		// Equal jitter: wait between backoff/2 and backoff. Spreading the wait
		// stops a whole fleet that dropped together (server restart, network
		// blip) from reconnecting in lockstep and hammering the server.
		wait := backoff/2 + time.Duration(rand.Int63n(int64(backoff/2)+1))
		log.Printf("[ws] reconnecting in %s …", wait)
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return
		}

		// Exponential back-off with ceiling.
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// connect establishes one WebSocket session and drives it until it ends.
// A successful session resets the back-off on the next iteration (handled by
// the caller — connect returns nil only on clean shutdown).
func (c *Client) connect(ctx context.Context) error {
	wsURL := c.serverWSURL()

	dialer := websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
	}

	conn, resp, err := dialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("dial %s: HTTP %d: %w", wsURL, resp.StatusCode, err)
		}
		return fmt.Errorf("dial %s: %w", wsURL, err)
	}
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}

	c.writeMu.Lock()
	c.conn = conn
	c.writeMu.Unlock()

	log.Printf("[ws] connected to %s", wsURL)

	// Send the initial register message.
	if err := c.sendRegister(); err != nil {
		conn.Close()
		return fmt.Errorf("register: %w", err)
	}

	// Flush any spooled messages from when we were offline.
	if c.spooler != nil {
		go c.spooler.DequeueAll(func(msg outboundMsg) error {
			// Write directly using the unspooled message, bypassing the spooling logic
			return c.writeJSONDirect(msg)
		})
	}

	// Start periodic realtime data streaming.
	// Pass conn so goroutines can close it on write error to force a reconnect.
	streamCtx, cancelStream := context.WithCancel(ctx)
	go c.streamRealtime(streamCtx, conn, "processes", 1*time.Second)
	go c.streamRealtime(streamCtx, conn, "netstat", 1*time.Second)
	go c.streamRealtime(streamCtx, conn, "netconn", 2*time.Second)
	go c.streamRealtime(streamCtx, conn, "sysinfo", 30*time.Second)
	go c.reportResources(streamCtx, 30*time.Second)
	go c.drainResultSpool(streamCtx) // re-ship any results spooled while offline
	defer cancelStream()

	// Start a ping goroutine that sends WebSocket-level control pings every
	// pingInterval. This keeps NAT/proxy sessions alive and detects dead
	// connections faster than waiting for the 60s read deadline to fire.
	go c.pingLoop(streamCtx, conn)

	// Drive the read loop until the connection drops or ctx is done.
	err = c.readLoop(ctx, conn)

	conn.Close()
	c.writeMu.Lock()
	c.conn = nil
	c.writeMu.Unlock()

	log.Printf("[ws] disconnected from %s: %v", wsURL, err)
	return err
}

// pingLoop sends a WebSocket-level control ping frame every pingInterval.
// It relies on conn being closed (by readLoop or streamRealtime) to exit.
func (c *Client) pingLoop(ctx context.Context, conn *websocket.Conn) {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.writeMu.Lock()
			if c.conn != conn {
				// Connection has been replaced; this loop is stale.
				c.writeMu.Unlock()
				return
			}
			conn.SetWriteDeadline(time.Now().Add(writeWait))
			err := conn.WriteMessage(websocket.PingMessage, nil)
			c.writeMu.Unlock()
			if err != nil {
				log.Printf("[ws] ping error: %v — closing connection", err)
				conn.Close()
				return
			}
		}
	}
}

// readLoop processes incoming messages from conn until it is closed or ctx is
// cancelled. It returns nil only when the context is done.
func (c *Client) readLoop(ctx context.Context, conn *websocket.Conn) error {
	// Close the connection when the context is cancelled so the blocking Read
	// call returns.
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	// Refresh the read deadline whenever a WebSocket-level pong is received
	// (response to the control pings sent by pingLoop).
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	// Set an initial read deadline. It is refreshed after every received message
	// and on pong receipt, so the connection is only dropped when truly dead.
	conn.SetReadDeadline(time.Now().Add(pongWait))

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			if ctx.Err() != nil {
				// Context cancellation triggered the close — not an error.
				return nil
			}
			return fmt.Errorf("read: %w", err)
		}
		// Any received message (realtime ACK, ping, job_start…) proves the
		// connection is alive — push the deadline forward.
		conn.SetReadDeadline(time.Now().Add(pongWait))

		var msg inboundMsg
		if err := json.Unmarshal(raw, &msg); err != nil {
			slog.Warn("unparseable message", "error", err, "raw", string(raw))
			continue
		}

		slog.Debug("received message", "type", msg.Type, "job_id", msg.JobID, "tool_id", msg.ToolID)

		switch msg.Type {
		case "job_start":
			c.handleJobStart(ctx, msg)
		case "job_run":
			c.handleJobRun(ctx, msg)
		case "job_stop":
			c.handleJobStop(msg)
		case "cmd_exec":
			c.handleCmdExec(ctx, msg)
		case "shell_open":
			c.handleShellOpen(ctx, msg)
		case "shell_input":
			c.handleShellInput(msg)
		case "shell_resize":
			c.handleShellResize(msg)
		case "shell_close":
			c.handleShellClose(msg)
		case "fs_request":
			go c.handleFsRequest(msg)
		case "edge_parse_registry":
			go c.handleEdgeParseRegistry(msg)
		case "edge_parse_evtx":
			go c.handleEdgeParseEvtx(msg)
		case "edge_parse_mft":
			go c.handleEdgeParseMFT(msg)
		case "edge_parse_prefetch":
			go c.handleEdgeParsePrefetch(msg)
		case "edge_parse_processes":
			go c.handleEdgeParseProcesses(msg)
		case "edge_parse_autoruns":
			go c.handleEdgeParseAutoruns(msg)
		case "edge_parse_netconn":
			go c.handleEdgeParseNetwork(msg)
		case "edge_parse_dlls":
			go c.handleEdgeParseDlls(msg)
		case "edge_parse_shimcache":
			go c.handleEdgeParseShimcache(msg)
		case "edge_parse_browser":
			go c.handleEdgeParseBrowser(msg)
		case "edge_parse_triage":
			go c.handleEdgeParseTriage(msg)
		case "edge_parse_containers":
			go c.handleEdgeParseContainers(msg)
		case "edge_parse_linux_triage":
			go c.handleEdgeParseLinuxTriage(msg)
		case "edge_parse_linux_events":
			go c.handleEdgeParseLinuxEvents(msg)
		case "collect_os_logs":
			go c.handleCollectOSLogs(msg)
		case "kill_process":
			go c.handleKillProcess(msg)
		case "ping":
			c.handlePing()
		case "cleanup":
			c.handleCleanup()
		default:
			log.Printf("[ws] unknown message type: %q", msg.Type)
		}
	}
}

// handleJobStart downloads + extracts the tool (no execution). When finished
// it sends a "job_status: ready" message so the operator can trigger a run.
func (c *Client) handleJobStart(ctx context.Context, msg inboundMsg) {
	req := executor.JobRequest{
		JobID:          msg.JobID,
		ToolID:         msg.ToolID,
		ToolName:       msg.ToolName,
		FileName:       msg.FileName,
		DownloadURL:    msg.DownloadURL,
		Args:           msg.Args,
		ExecutablePath: msg.ExecutablePath,
		CPULimit:       msg.CPULimit,
		RAMLimit:       msg.RAMLimit,
		Priority:       msg.Priority,
		AgentToken:     c.cfg.AgentToken,
		ServerURL:      c.cfg.ServerURL,
	}

	log.Printf("[job:%s] downloading tool=%s", msg.JobID, msg.ToolName)

	go func() {
		outputCh := make(chan string, 256)
		errCh := make(chan error, 1)
		go func() {
			errCh <- executor.DownloadJob(ctx, req, c.cfg.WorkDir, outputCh)
		}()

		for line := range outputCh {
			if err := c.sendOutput(msg.JobID, line, false); err != nil {
				log.Printf("[job:%s] send output error: %v", msg.JobID, err)
			}
		}

		if err := <-errCh; err != nil {
			log.Printf("[job:%s] download error: %v", msg.JobID, err)
			_ = c.sendOutput(msg.JobID, fmt.Sprintf("[agent error] %v", err), false)
			_ = c.sendOutput(msg.JobID, "", true) // mark failed
			return
		}

		// Signal ready — server will transition pending → ready.
		if err := c.writeJSON(outboundMsg{Type: "job_status", JobID: msg.JobID, Status: "ready"}); err != nil {
			log.Printf("[job:%s] send ready error: %v", msg.JobID, err)
		}
		log.Printf("[job:%s] ready", msg.JobID)
	}()
}

// handleJobRun executes a previously-downloaded tool. A per-job cancellable
// context is registered in runningJobs so handleJobStop can kill the process.
func (c *Client) handleJobRun(parentCtx context.Context, msg inboundMsg) {
	// Result collection: create a per-job output dir inside the tool dir so a tool
	// can be told to write to {{OUTDIR}}, and so post-run collection has a root.
	runToolID := msg.ToolID
	if runToolID == "" {
		runToolID = executor.SanitizeFilename(msg.ToolName)
	}
	runToolDir := filepath.Join(c.cfg.WorkDir, "tools", runToolID)
	runOutDir := filepath.Join(runToolDir, "_results", msg.JobID)
	_ = os.MkdirAll(runOutDir, 0o755)
	resolvedArgs := strings.ReplaceAll(msg.Args, "{{OUTDIR}}", runOutDir)
	runStart := time.Now()

	req := executor.JobRequest{
		JobID:          msg.JobID,
		ToolID:         msg.ToolID,
		ToolName:       msg.ToolName,
		FileName:       msg.FileName,
		Args:           resolvedArgs,
		ExecutablePath: msg.ExecutablePath,
		CPULimit:       msg.CPULimit,
		RAMLimit:       msg.RAMLimit,
		Priority:       msg.Priority,
	}

	log.Printf("[job:%s] received job_run tool=%s tool_id=%s file=%s exec_path=%q args=%q",
		msg.JobID, msg.ToolName, msg.ToolID, msg.FileName, msg.ExecutablePath, msg.Args)

	runCtx, cancel := context.WithCancel(parentCtx)
	c.runningJobsMu.Lock()
	c.runningJobs[msg.JobID] = cancel
	c.runningJobsMu.Unlock()

	go func() {
		defer func() {
			// A panic anywhere in job execution/collection must not crash the agent
			// (which would drop the WS connection and stall future job dispatch).
			if r := recover(); r != nil {
				log.Printf("[job:%s] recovered panic: %v", msg.JobID, r)
			}
			c.runningJobsMu.Lock()
			delete(c.runningJobs, msg.JobID)
			c.runningJobsMu.Unlock()
			cancel()
		}()

		outputCh := make(chan string, 256)
		errCh := make(chan error, 1)
		go func() {
			errCh <- executor.ExecuteJob(runCtx, req, c.cfg.WorkDir, outputCh)
		}()

		for line := range outputCh {
			batch := []string{line}
			done := false
			for len(batch) < 50 && !done {
				select {
				case l, ok := <-outputCh:
					if !ok {
						done = true
					} else {
						batch = append(batch, l)
					}
				default:
					done = true
				}
			}

			combined := strings.Join(batch, "\n")
			if err := c.sendOutput(msg.JobID, combined, false); err != nil {
				log.Printf("[job:%s] send output error: %v", msg.JobID, err)
			}
		}

		err := <-errCh
		if runCtx.Err() != nil {
			// Cancelled by job_stop — report stopped, don't mark as done/failed.
			if err := c.writeJSON(outboundMsg{Type: "job_status", JobID: msg.JobID, Status: "stopped"}); err != nil {
				log.Printf("[job:%s] send stopped error: %v", msg.JobID, err)
			}
			log.Printf("[job:%s] stopped", msg.JobID)
			return
		}

		if err != nil {
			log.Printf("[job:%s] executor error: %v", msg.JobID, err)
			_ = c.sendOutput(msg.JobID, fmt.Sprintf("[agent error] %v", err), false)
		}

		// --- NEW: Automatic Artifact Upload for YARA Scanner ---
		// Look for "report/report.html" and upload it before marking the job as
		// done. Match on either ToolName (normalized — strips spaces/dashes so
		// "YARA Scanner", "yara-scanner", "yara_scanner" all hit) or
		// FileName as a fallback.
		toolNameNorm := strings.ToLower(msg.ToolName)
		toolNameNorm = strings.ReplaceAll(toolNameNorm, " ", "")
		toolNameNorm = strings.ReplaceAll(toolNameNorm, "-", "")
		toolNameNorm = strings.ReplaceAll(toolNameNorm, "_", "")
		isYaraScanner := strings.Contains(toolNameNorm, "webshellscanner") ||
			strings.Contains(strings.ToLower(msg.FileName), "yara-scanner")
		if isYaraScanner {
			workDir := c.cfg.WorkDir
			toolID := msg.ToolID
			if toolID == "" {
				toolID = executor.SanitizeFilename(msg.ToolName)
			}
			// The report is written to a "report/" dir relative to the scanner's own
			// folder, which differs per platform (report/, linux/report/,
			// windows/report/, …). Search the whole tool dir for the freshest
			// report.html rather than assuming one fixed path.
			toolDir := filepath.Join(workDir, "tools", toolID)
			reportPath := findNewestReportHTML(toolDir)

			if reportPath != "" {
				log.Printf("[job:%s] uploading yara-scanner report: %s", msg.JobID, reportPath)
				if upErr := c.uploadArtifact(runCtx, msg.JobID, reportPath); upErr != nil {
					log.Printf("[job:%s] artifact upload failed: %v", msg.JobID, upErr)
					_ = c.sendOutput(msg.JobID, fmt.Sprintf("[agent error] report upload failed: %v", upErr), false)
				} else {
					log.Printf("[job:%s] report uploaded successfully", msg.JobID)
					_ = c.sendOutput(msg.JobID, "[+] Report uploaded successfully", false)
				}
			} else {
				log.Printf("[job:%s] report.html not found under %s", msg.JobID, toolDir)
			}
		}

		isMemDump := strings.Contains(toolNameNorm, "winpmem") || strings.Contains(toolNameNorm, "memdump")
		if isMemDump {
			workDir := c.cfg.WorkDir
			toolID := msg.ToolID
			if toolID == "" {
				toolID = executor.SanitizeFilename(msg.ToolName)
			}
			toolDir := filepath.Join(workDir, "tools", toolID)

			var dumpFile string
			var maxSize int64
			filepath.Walk(toolDir, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}
				ext := strings.ToLower(filepath.Ext(path))
				if ext == ".raw" || ext == ".mem" || ext == ".zip" {
					if info.Size() > maxSize {
						maxSize = info.Size()
						dumpFile = path
					}
				}
				return nil
			})

			if dumpFile != "" {
				log.Printf("[job:%s] uploading memory dump: %s", msg.JobID, dumpFile)
				_ = c.sendOutput(msg.JobID, fmt.Sprintf("[+] Uploading memory dump (%.2f MB)...", float64(maxSize)/(1024*1024)), false)
				if upErr := c.uploadArtifact(runCtx, msg.JobID, dumpFile); upErr != nil {
					log.Printf("[job:%s] artifact upload failed: %v", msg.JobID, upErr)
					_ = c.sendOutput(msg.JobID, fmt.Sprintf("[agent error] memory dump upload failed: %v", upErr), false)
				} else {
					log.Printf("[job:%s] memory dump uploaded successfully", msg.JobID)
					_ = c.sendOutput(msg.JobID, "[+] Memory dump uploaded successfully", false)
				}
			} else {
				log.Printf("[job:%s] memory dump file not found in %s", msg.JobID, toolDir)
			}
		}

		// Generic result collection per the tool's declared output spec.
		if msg.CollectResult {
			exitCode := 0 // coarse: 0 = executor completed, 1 = executor error
			if err != nil {
				exitCode = 1
			}
			c.collectResults(runCtx, msg, runToolDir, runOutDir, runStart, resolvedArgs, exitCode)
		}

		if err := c.sendOutput(msg.JobID, "", true); err != nil {
			log.Printf("[job:%s] send done error: %v", msg.JobID, err)
		}
		log.Printf("[job:%s] finished", msg.JobID)
	}()
}

// collectResults gathers the tool's output files after a run and uploads each as
// a ToolResult. Sources: everything under the per-job {{OUTDIR}}, plus any file
// in the tool dir that matches OutputGlobs and was modified during this run
// (so pre-bundled tool files are not mistaken for results).
func (c *Client) collectResults(ctx context.Context, msg inboundMsg, toolDir, outDir string, since time.Time, cmdline string, exitCode int) {
	maxBytes := int64(msg.MaxResultMB) * 1024 * 1024
	if maxBytes <= 0 {
		maxBytes = 200 * 1024 * 1024 // default 200 MB/file
	}
	globs := splitGlobs(msg.OutputGlobs)
	scope := msg.OutputScope
	if scope == "" {
		scope = "both"
	}

	seen := map[string]bool{}
	var files []string
	add := func(p string, size int64) {
		if size > maxBytes {
			_ = c.sendOutput(msg.JobID, fmt.Sprintf("[!] result %s skipped (%.1f MB exceeds %d MB cap)",
				filepath.Base(p), float64(size)/(1024*1024), maxBytes/(1024*1024)), false)
			return
		}
		ap, _ := filepath.Abs(p)
		if seen[ap] {
			return
		}
		seen[ap] = true
		files = append(files, p)
	}

	if scope == "both" || scope == "outdir" {
		_ = filepath.Walk(outDir, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				add(p, info.Size())
			}
			return nil
		})
	}
	if (scope == "both" || scope == "tooldir") && len(globs) > 0 {
		resultsRoot := filepath.Join(toolDir, "_results")
		_ = filepath.Walk(toolDir, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				if strings.HasPrefix(p, resultsRoot) {
					return filepath.SkipDir // already covered by outDir scan
				}
				return nil
			}
			if !info.ModTime().After(since.Add(-2 * time.Second)) {
				return nil // pre-existing bundled file, not a fresh result
			}
			if matchGlobs(filepath.Base(p), globs) {
				add(p, info.Size())
			}
			return nil
		})
	}

	const maxFiles = 50
	if len(files) > maxFiles {
		_ = c.sendOutput(msg.JobID, fmt.Sprintf("[!] %d result files found; uploading first %d", len(files), maxFiles), false)
		files = files[:maxFiles]
	}
	if len(files) == 0 {
		_ = c.sendOutput(msg.JobID, "[i] no result files matched the tool output spec", false)
		return
	}

	prov := resultProvenance{processor: msg.ResultProcessor, cmdline: cmdline, exitCode: exitCode}

	// Upload with bounded concurrency so many small results ship quickly without
	// flooding a slow uplink. Each file settles (waitStable) inside its worker so
	// settling also runs in parallel.
	const uploadConcurrency = 3
	sem := make(chan struct{}, uploadConcurrency)
	var wg sync.WaitGroup
	for _, p := range files {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[result-upload] recovered for %s: %v", filepath.Base(path), r)
				}
			}()
			sem <- struct{}{}
			defer func() { <-sem }()
			waitStable(path)
			_ = c.sendOutput(msg.JobID, fmt.Sprintf("[+] Uploading result: %s", filepath.Base(path)), false)
			c.shipResult(ctx, msg.JobID, path, prov)
		}(p)
	}
	wg.Wait()
}

// resultProvenance carries the per-job context attached to every collected file
// (chain-of-custody): the resolved command line, coarse exit code and requested
// processor.
type resultProvenance struct {
	processor string
	cmdline   string
	exitCode  int
}

// shipResult delivers one result file to the server. It first tries a content
// LINK (skip the transfer when the server already holds this exact sha256), then
// falls back to a compressed upload, and finally SPOOLS the file to disk for
// later retry if the server is unreachable — so a result is never silently lost.
func (c *Client) shipResult(ctx context.Context, jobID, filePath string, prov resultProvenance) {
	sum := fileSHA256(filePath)
	if sum != "" && c.tryLinkResult(ctx, jobID, filePath, sum, prov) {
		_ = c.sendOutput(jobID, fmt.Sprintf("[+] Result linked (dedup): %s", filepath.Base(filePath)), false)
		return
	}
	if err := c.uploadResult(ctx, jobID, filePath, sum, prov); err != nil {
		_ = c.sendOutput(jobID, fmt.Sprintf("[agent error] result upload failed (%s): %v — spooled for retry", filepath.Base(filePath), err), false)
		c.spoolResult(jobID, filePath, sum, prov)
	}
}

// waitStable blocks until a file's size and mtime stop changing across two
// consecutive samples (so a tool still flushing/writing isn't shipped partial),
// or a hard timeout elapses.
func waitStable(path string) {
	const interval = 1500 * time.Millisecond
	const maxWait = 30 * time.Second
	deadline := time.Now().Add(maxWait)
	var lastSize int64 = -1
	var lastMod time.Time
	for time.Now().Before(deadline) {
		info, err := os.Stat(path)
		if err != nil {
			return
		}
		if info.Size() == lastSize && info.ModTime().Equal(lastMod) {
			return // two identical samples ⇒ stable
		}
		lastSize = info.Size()
		lastMod = info.ModTime()
		time.Sleep(interval)
	}
}

// fileSHA256 returns the lowercase hex SHA-256 of a file, or "" on error.
func fileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func splitGlobs(s string) []string {
	var out []string
	for _, g := range strings.Split(s, ",") {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}

// matchGlobs matches a base filename against a set of glob patterns. Patterns
// may include a directory prefix (e.g. "report/*.html"); only the trailing
// filename pattern is applied to the base name.
func matchGlobs(name string, globs []string) bool {
	for _, g := range globs {
		pat := g
		if i := strings.LastIndexAny(g, `/\`); i >= 0 {
			pat = g[i+1:]
		}
		if ok, _ := filepath.Match(pat, name); ok {
			return true
		}
	}
	return false
}

// uploadResult uploads a single collected result file to the server's
// per-job result endpoint, tagging it with the processor hint.
// uploadResult ships one collected result file to the server. The transfer is
// gzip-compressed (result files are mostly text — logs/CSV/JSON — and compress
// heavily) and retried with backoff so a transient network drop doesn't lose the
// evidence. The raw-file SHA-256 is sent so the server can verify integrity after
// decompression.
func (c *Client) uploadResult(ctx context.Context, jobID, filePath, sum string, prov resultProvenance) error {
	if sum == "" {
		sum = fileSHA256(filePath)
	}
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if err := c.uploadResultOnce(ctx, jobID, filePath, sum, prov); err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return err
			}
			if attempt < 3 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(time.Duration(attempt) * 2 * time.Second):
				}
			}
			continue
		}
		return nil
	}
	return lastErr
}

func (c *Client) uploadResultOnce(ctx context.Context, jobID, filePath, sum string, prov resultProvenance) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open result %s: %w", filePath, err)
	}
	defer f.Close()

	pr, pw := io.Pipe()
	w := multipart.NewWriter(pw)
	go func() {
		if prov.processor != "" {
			_ = w.WriteField("processor", prov.processor)
		}
		if sum != "" {
			_ = w.WriteField("sha256", sum)
		}
		_ = w.WriteField("filename", filepath.Base(filePath))
		_ = w.WriteField("content_encoding", "gzip")
		if prov.cmdline != "" {
			_ = w.WriteField("cmdline", prov.cmdline)
		}
		_ = w.WriteField("exit_code", fmt.Sprintf("%d", prov.exitCode))
		part, err := w.CreateFormFile("file", filepath.Base(filePath))
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		gz := gzip.NewWriter(part)
		if _, err := io.Copy(gz, f); err != nil {
			pw.CloseWithError(err)
			return
		}
		if err := gz.Close(); err != nil {
			pw.CloseWithError(err)
			return
		}
		pw.CloseWithError(w.Close())
	}()

	uploadURL := fmt.Sprintf("%s/api/v1/jobs/%s/result", c.cfg.ServerURL, jobID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, pr)
	if err != nil {
		return fmt.Errorf("build result upload: %w", err)
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("X-Agent-Token", c.cfg.AgentToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("dispatch result upload: %w", err)
	}
	defer resp.Body.Close()
	// The server queues the result and returns 202 Accepted (async processing);
	// 200 is also fine. Anything outside 2xx is a real failure.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("result upload failed: %s: %s", resp.Status, string(body))
	}
	return nil
}

// tryLinkResult asks the server to LINK this result by content hash instead of
// transferring it: if the server already stores an identical file it clones the
// stored copy + parsed output for this job and returns linked=true, so a large
// identical file (e.g. a re-collected bundle) is never re-uploaded. Any error or
// a miss returns false and the caller uploads normally.
func (c *Client) tryLinkResult(ctx context.Context, jobID, filePath, sum string, prov resultProvenance) bool {
	payload, _ := json.Marshal(map[string]interface{}{
		"sha256":    sum,
		"filename":  filepath.Base(filePath),
		"processor": prov.processor,
		"cmdline":   prov.cmdline,
		"exit_code": prov.exitCode,
	})
	url := fmt.Sprintf("%s/api/v1/jobs/%s/result/link", c.cfg.ServerURL, jobID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Token", c.cfg.AgentToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}
	var out struct {
		Data struct {
			Linked bool `json:"linked"`
		} `json:"data"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return false
	}
	return out.Data.Linked
}

// ── Durable result spool ─────────────────────────────────────────────────────
// When a result upload fails outright (server unreachable after retries), the
// file is copied into a local spool directory with its metadata so it survives an
// agent restart. A background drainer re-ships spooled results whenever the agent
// is connected, so a collected result is never silently lost.

type spoolMeta struct {
	JobID     string `json:"job_id"`
	FileName  string `json:"file_name"`
	Sha256    string `json:"sha256"`
	Processor string `json:"processor"`
	Cmdline   string `json:"cmdline"`
	ExitCode  int    `json:"exit_code"`
}

func (c *Client) resultSpoolDir() string {
	return filepath.Join(c.cfg.WorkDir, "_result_spool")
}

func (c *Client) spoolResult(jobID, filePath, sum string, prov resultProvenance) {
	base := filepath.Join(c.resultSpoolDir(), fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Intn(1_000_000)))
	if err := os.MkdirAll(base, 0o755); err != nil {
		return
	}
	// Copy the file so it outlives cleanup of the tool's output directory.
	if err := spoolCopyFile(filePath, filepath.Join(base, filepath.Base(filePath))); err != nil {
		_ = os.RemoveAll(base)
		return
	}
	mb, _ := json.Marshal(spoolMeta{
		JobID: jobID, FileName: filepath.Base(filePath), Sha256: sum,
		Processor: prov.processor, Cmdline: prov.cmdline, ExitCode: prov.exitCode,
	})
	_ = os.WriteFile(filepath.Join(base, "meta.json"), mb, 0o644)
}

// drainResultSpool periodically re-ships spooled results while connected.
func (c *Client) drainResultSpool(ctx context.Context) {
	drain := func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[result-spool] drain recovered: %v", r)
			}
		}()
		entries, err := os.ReadDir(c.resultSpoolDir())
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			base := filepath.Join(c.resultSpoolDir(), e.Name())
			mb, rerr := os.ReadFile(filepath.Join(base, "meta.json"))
			if rerr != nil {
				continue
			}
			var m spoolMeta
			if json.Unmarshal(mb, &m) != nil {
				continue
			}
			filePath := filepath.Join(base, m.FileName)
			if _, serr := os.Stat(filePath); serr != nil {
				_ = os.RemoveAll(base) // file gone — nothing to ship
				continue
			}
			prov := resultProvenance{processor: m.Processor, cmdline: m.Cmdline, exitCode: m.ExitCode}
			if m.Sha256 != "" && c.tryLinkResult(ctx, m.JobID, filePath, m.Sha256, prov) {
				_ = os.RemoveAll(base)
				continue
			}
			if uerr := c.uploadResult(ctx, m.JobID, filePath, m.Sha256, prov); uerr == nil {
				_ = os.RemoveAll(base)
			}
		}
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(10 * time.Second):
		drain()
	}
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			drain()
		}
	}
}

func spoolCopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

// handleJobStop cancels the running job's context, which kills the child
// process (exec.CommandContext uses ctx to signal termination).
func (c *Client) handleJobStop(msg inboundMsg) {
	c.runningJobsMu.Lock()
	cancel, ok := c.runningJobs[msg.JobID]
	c.runningJobsMu.Unlock()

	if !ok {
		log.Printf("[job:%s] stop received but job is not running", msg.JobID)
		return
	}

	log.Printf("[job:%s] stop requested — cancelling context", msg.JobID)
	cancel()
}

// handleCmdExec runs a raw shell command and streams its output back as "output"
// messages, reusing the same job-output pipeline as handleJobRun. The command
// is passed in msg.Args; msg.JobID is used as the correlation key. Cancellation
// via "job_stop" works because the cancel func is registered in runningJobs.
func (c *Client) handleCmdExec(parentCtx context.Context, msg inboundMsg) {
	if msg.JobID == "" || msg.Args == "" {
		log.Printf("[cmd_exec] missing job_id or args — ignoring")
		return
	}

	runCtx, cancel := context.WithCancel(parentCtx)
	c.runningJobsMu.Lock()
	c.runningJobs[msg.JobID] = cancel
	c.runningJobsMu.Unlock()

	go func() {
		defer func() {
			// A panic anywhere in job execution/collection must not crash the agent
			// (which would drop the WS connection and stall future job dispatch).
			if r := recover(); r != nil {
				log.Printf("[job:%s] recovered panic: %v", msg.JobID, r)
			}
			c.runningJobsMu.Lock()
			delete(c.runningJobs, msg.JobID)
			c.runningJobsMu.Unlock()
			cancel()
		}()

		var cmd *osExec.Cmd
		if runtime.GOOS == "windows" {
			cmd = osExec.CommandContext(runCtx, "cmd.exe", "/c", msg.Args)
		} else {
			cmd = osExec.CommandContext(runCtx, "/bin/bash", "-c", msg.Args)
		}

		pr, pw := io.Pipe()
		cmd.Stdout = pw
		cmd.Stderr = pw

		if err := cmd.Start(); err != nil {
			pw.Close()
			pr.Close()
			_ = c.sendOutput(msg.JobID, fmt.Sprintf("[cmd_exec error] %v", err), false)
			_ = c.sendOutput(msg.JobID, "", true)
			return
		}

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer pr.Close()
			scanner := bufio.NewScanner(pr)
			buf := make([]byte, 64*1024)
			scanner.Buffer(buf, 1024*1024)
			for scanner.Scan() {
				if err := c.sendOutput(msg.JobID, scanner.Text(), false); err != nil {
					log.Printf("[cmd_exec:%s] send output error: %v", msg.JobID, err)
				}
			}
		}()

		cmdErr := cmd.Wait()
		pw.Close()
		wg.Wait()

		if runCtx.Err() != nil {
			_ = c.writeJSON(outboundMsg{Type: "job_status", JobID: msg.JobID, Status: "stopped"})
			log.Printf("[cmd_exec:%s] stopped", msg.JobID)
			return
		}
		if cmdErr != nil {
			// Non-zero exit codes from forensic commands are expected (e.g. inactive
			// services, missing features). The actual error text is already in the
			// output via stderr; appending a duplicate [cmd_exec error] line adds noise.
			log.Printf("[cmd_exec:%s] exited: %v", msg.JobID, cmdErr)
		}
		_ = c.sendOutput(msg.JobID, "", true)
		log.Printf("[cmd_exec:%s] finished", msg.JobID)
	}()
}

// handleShellOpen spawns a new PTY session running the requested shell and
// pipes its output back to the server as "shell_output" messages.
func (c *Client) handleShellOpen(parentCtx context.Context, msg inboundMsg) {
	if msg.SessionID == "" {
		log.Printf("[shell] shell_open without session_id — ignoring")
		return
	}

	c.terminalSessionsMu.Lock()
	if _, exists := c.terminalSessions[msg.SessionID]; exists {
		c.terminalSessionsMu.Unlock()
		log.Printf("[shell:%s] already open — ignoring duplicate shell_open", msg.SessionID)
		return
	}
	c.terminalSessionsMu.Unlock()

	sess, err := terminal.New(msg.SessionID, msg.Shell, msg.Cols, msg.Rows)
	if err != nil {
		log.Printf("[shell:%s] open error: %v", msg.SessionID, err)
		_ = c.writeJSON(outboundMsg{
			Type:      "shell_closed",
			SessionID: msg.SessionID,
			ExitCode:  -1,
			Data:      base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("failed to open shell: %v\r\n", err))),
		})
		return
	}

	c.terminalSessionsMu.Lock()
	c.terminalSessions[msg.SessionID] = sess
	c.terminalSessionsMu.Unlock()
	log.Printf("[shell:%s] opened shell=%s", msg.SessionID, msg.Shell)

	sess.Stream(parentCtx,
		func(data []byte) {
			_ = c.writeJSON(outboundMsg{
				Type:      "shell_output",
				SessionID: msg.SessionID,
				Data:      base64.StdEncoding.EncodeToString(data),
			})
		},
		func(exitCode int) {
			c.terminalSessionsMu.Lock()
			delete(c.terminalSessions, msg.SessionID)
			c.terminalSessionsMu.Unlock()
			_ = c.writeJSON(outboundMsg{
				Type:      "shell_closed",
				SessionID: msg.SessionID,
				ExitCode:  exitCode,
			})
			log.Printf("[shell:%s] closed (exit=%d)", msg.SessionID, exitCode)
		},
	)
}

// handleShellInput forwards stdin bytes from the server to the PTY.
func (c *Client) handleShellInput(msg inboundMsg) {
	c.terminalSessionsMu.Lock()
	sess, ok := c.terminalSessions[msg.SessionID]
	c.terminalSessionsMu.Unlock()
	if !ok {
		return
	}
	data, err := base64.StdEncoding.DecodeString(msg.Data)
	if err != nil {
		log.Printf("[shell:%s] decode input error: %v", msg.SessionID, err)
		return
	}
	if _, err := sess.Write(data); err != nil {
		log.Printf("[shell:%s] write error: %v", msg.SessionID, err)
	}
}

// handleShellResize updates the PTY window dimensions.
func (c *Client) handleShellResize(msg inboundMsg) {
	c.terminalSessionsMu.Lock()
	sess, ok := c.terminalSessions[msg.SessionID]
	c.terminalSessionsMu.Unlock()
	if !ok {
		return
	}
	if msg.Cols <= 0 || msg.Rows <= 0 {
		return
	}
	_ = sess.Resize(msg.Cols, msg.Rows)
}

// handleShellClose terminates the PTY session. The stream callback will still
// fire to emit the final "shell_closed" message.
func (c *Client) handleShellClose(msg inboundMsg) {
	c.terminalSessionsMu.Lock()
	sess, ok := c.terminalSessions[msg.SessionID]
	c.terminalSessionsMu.Unlock()
	if !ok {
		return
	}
	_ = sess.Close()
}

// handleFsRequest dispatches a filesystem operation to the fs package and
// streams each fs.Response back as an "fs_response" WebSocket message.
// The sessionID from the request is echoed on every frame so the backend's
// FsSession correlation can route the chunks to the right HTTP handler.
func (c *Client) handleFsRequest(msg inboundMsg) {
	if msg.SessionID == "" {
		log.Printf("[fs] fs_request without session_id — ignoring")
		return
	}
	req := fs.Request{
		Op:    msg.FsOp,
		Path:  msg.FsPath,
		Paths: msg.FsPaths,
	}
	send := func(r fs.Response) error {
		return c.writeJSON(outboundMsg{
			Type:        "fs_response",
			SessionID:   msg.SessionID,
			FsOp:        r.Op,
			FsEntries:   r.Entries,
			FsTruncated: r.Truncated,
			FsData:      r.Data,
			FsSize:      r.Size,
			FsDone:      r.Done,
			FsError:     r.Error,
		})
	}
	if err := fs.Handle(req, send); err != nil {
		log.Printf("[fs:%s] send error: %v", msg.SessionID, err)
	}
}

// runEdgeScan executes an edge-forensics collector and ships its JSON back to
// the dashboard. When the agent already runs elevated it calls inProc directly —
// no ShellExecuteEx "runas", so NO UAC prompt and no child process. Otherwise it
// falls back to a UAC-elevated child running `<subcmd> "<tmpfile>" ["<extraArg>"]`
// that writes the same JSON to tmpfile (the original behaviour).
func (c *Client) runEdgeScan(jobID, name, tmpPrefix, subcmd, extraArg string, inProc func() (any, error)) {
	if jobID == "" {
		return
	}
	finish := func(b []byte) {
		_ = c.writeJSON(outboundMsg{Type: "artifact_data", JobID: jobID, Data: string(b)})
		_ = c.sendOutput(jobID, "[+] "+name+" complete.", false)
		_ = c.sendOutput(jobID, "", true)
	}
	fail := func(format string, args ...any) {
		_ = c.sendOutput(jobID, fmt.Sprintf(format, args...), false)
		_ = c.sendOutput(jobID, "", true)
	}

	// Fast path: agent is already elevated → run in-process, zero UAC.
	if executor.IsElevated() {
		_ = c.sendOutput(jobID, "[*] Agent already elevated — running "+name+" in-process (no UAC).", false)
		res, err := inProc()
		if err != nil {
			fail("[agent error] %s failed: %v", name, err)
			return
		}
		b, err := json.Marshal(res)
		if err != nil {
			fail("[agent error] marshal failed: %v", err)
			return
		}
		finish(b)
		return
	}

	// Non-Windows (Linux/macOS): there is no UAC. Privilege comes from running the
	// agent as root (systemd service / sudo). Instead of failing, collect
	// best-effort in-process — many artifacts are readable without root, and each
	// collector skips the paths it cannot read — while telling the operator that
	// root is needed for full coverage.
	if runtime.GOOS != "windows" {
		_ = c.sendOutput(jobID, "[!] Agent is not running as root — collecting "+name+" with limited privileges. Run the agent as root (or sudo) for full coverage.", false)
		res, err := inProc()
		if err != nil {
			fail("[agent error] %s failed: %v", name, err)
			return
		}
		b, err := json.Marshal(res)
		if err != nil {
			fail("[agent error] marshal failed: %v", err)
			return
		}
		finish(b)
		return
	}

	// Windows medium-integrity: elevate a child via UAC, read its JSON output.
	_ = c.sendOutput(jobID, "[*] Requesting Administrator privileges (UAC) for "+name+"...", false)
	exe, _ := os.Executable()
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("%s_%s.json", tmpPrefix, jobID))
	scanArgs := subcmd + " \"" + tmpFile + "\""
	if extraArg != "" {
		scanArgs += " \"" + extraArg + "\""
	}
	if err := executor.RunElevatedAndWait(exe, scanArgs); err != nil {
		fail("[agent error] UAC failed or denied: %v", err)
		return
	}
	b, err := os.ReadFile(tmpFile)
	if err != nil {
		fail("[agent error] Failed to read %s results: %v", name, err)
		return
	}
	os.Remove(tmpFile)
	finish(b)
}

// handleEdgeParseMFT parses the MFT (elevated; in-process when already admin).
func (c *Client) handleEdgeParseMFT(msg inboundMsg) {
	log.Printf("[edge_mft:%s] MFT scan", msg.JobID)
	c.runEdgeScan(msg.JobID, "MFT Edge Forensic Scan", "mft", "scan-mft", strings.TrimSpace(msg.FsPath),
		func() (any, error) { return parser.ParseMFT(strings.TrimSpace(msg.FsPath)) })
}

// handleEdgeParsePrefetch parses the Prefetch (elevated; in-process when admin).
func (c *Client) handleEdgeParsePrefetch(msg inboundMsg) {
	log.Printf("[edge_prefetch:%s] Prefetch scan", msg.JobID)
	c.runEdgeScan(msg.JobID, "Prefetch Edge Forensic Scan", "pf", "scan-prefetch", "",
		func() (any, error) { return parser.ParsePrefetch() })
}

// handleEdgeParseProcesses collects a detailed running-process snapshot
// (lineage + owner + command line + exe hashes; in-process when already admin).
func (c *Client) handleEdgeParseProcesses(msg inboundMsg) {
	log.Printf("[edge_proc:%s] process snapshot", msg.JobID)
	c.runEdgeScan(msg.JobID, "Process snapshot", "proc", "scan-processes", "",
		func() (any, error) { return parser.ScanProcesses() })
}

// handleEdgeParseAutoruns enumerates autostart / persistence locations (Run
// keys, services, tasks, startup, Winlogon, IFEO …); in-process when already admin.
func (c *Client) handleEdgeParseAutoruns(msg inboundMsg) {
	log.Printf("[edge_autoruns:%s] autoruns scan", msg.JobID)
	c.runEdgeScan(msg.JobID, "Autoruns scan", "autoruns", "scan-autoruns", "",
		func() (any, error) { return parser.ScanAutoruns() })
}

// handleEdgeParseContainers enumerates containers + their misconfiguration
// (privileged, docker-socket mount, host namespaces, dangerous caps). Linux-only.
func (c *Client) handleEdgeParseContainers(msg inboundMsg) {
	log.Printf("[edge_containers:%s] container forensics", msg.JobID)
	c.runEdgeScan(msg.JobID, "Container forensics", "containers", "scan-containers", "",
		func() (any, error) { return parser.ScanContainers() })
}

// handleEdgeParseLinuxTriage gathers Linux persistence / execution-history /
// privesc artifacts (shell history, cron, ssh keys, ld.so.preload, SUID, kernel
// modules). Linux-only.
func (c *Client) handleEdgeParseLinuxTriage(msg inboundMsg) {
	log.Printf("[edge_linux_triage:%s] linux triage", msg.JobID)
	c.runEdgeScan(msg.JobID, "Linux triage", "linuxtriage", "scan-linux-triage", "",
		func() (any, error) { return parser.ScanLinuxTriage() })
}

// handleEdgeParseLinuxEvents builds a normalized process / security event stream
// (auditd → journald → auth.log) so the Sigma engine has something to evaluate
// on Linux hosts. Args carry {"hours":24,"max":2000,"keyword":""}. Linux-only.
func (c *Client) handleEdgeParseLinuxEvents(msg inboundMsg) {
	log.Printf("[edge_linux_events:%s] linux event stream (args=%q)", msg.JobID, msg.Args)
	var opts parser.LinuxEventOptions
	if args := strings.TrimSpace(msg.Args); args != "" {
		if err := json.Unmarshal([]byte(args), &opts); err != nil {
			log.Printf("[edge_linux_events:%s] invalid args %q: %v — using defaults", msg.JobID, args, err)
		}
	}
	c.runEdgeScan(msg.JobID, "Linux event stream", "linuxevents", "scan-linux-events", msg.Args,
		func() (any, error) { return parser.ScanLinuxEvents(opts) })
}

// handleEdgeParseDlls enumerates loaded modules across processes (ListDLLs-style)
// with hashes + Authenticode + hijack flags; in-process when already admin.
func (c *Client) handleEdgeParseDlls(msg inboundMsg) {
	log.Printf("[edge_dlls:%s] loaded-DLL scan", msg.JobID)
	c.runEdgeScan(msg.JobID, "Loaded DLLs scan", "dlls", "scan-dlls", "",
		func() (any, error) { return parser.ScanLoadedDLLs() })
}

// handleEdgeParseShimcache parses the AppCompatCache (Shimcache) execution
// evidence; in-process when already admin, else via a UAC-elevated child.
func (c *Client) handleEdgeParseShimcache(msg inboundMsg) {
	log.Printf("[edge_shimcache:%s] shimcache scan", msg.JobID)
	c.runEdgeScan(msg.JobID, "Shimcache scan", "shimcache", "scan-shimcache", "",
		func() (any, error) { return parser.ScanShimcache() })
}

// handleEdgeParseBrowser recovers browser history (Chrome/Edge/Brave/Firefox)
// across all local user profiles; elevated so other users' profiles are readable.
func (c *Client) handleEdgeParseBrowser(msg inboundMsg) {
	log.Printf("[edge_browser:%s] browser history scan", msg.JobID)
	c.runEdgeScan(msg.JobID, "Browser history scan", "browser", "scan-browser", "",
		func() (any, error) { return parser.ScanBrowserHistory() })
}

// handleEdgeParseTriage runs a 1-click triage collection (KAPE-style) — a curated
// set of collectors gathered in ONE elevated pass so the operator sees at most a
// single UAC prompt. The requested artifact types arrive as a CSV in msg.Args.
func (c *Client) handleEdgeParseTriage(msg inboundMsg) {
	log.Printf("[edge_triage:%s] triage collection (types=%q)", msg.JobID, msg.Args)
	types := splitCSV(msg.Args)
	c.runEdgeScan(msg.JobID, "Triage collection", "triage", "scan-triage", msg.Args,
		func() (any, error) { return parser.CollectTriage(types), nil })
}

// splitCSV parses a comma-separated list, trimming blanks.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// handleKillProcess terminates a process (containment). Runs in-process when the
// agent is already elevated, else via a UAC-elevated `kill <pid>` child so it can
// terminate other users' / elevated processes.
func (c *Client) handleKillProcess(msg inboundMsg) {
	if msg.JobID == "" {
		return
	}
	log.Printf("[kill:%s] terminating pid %d", msg.JobID, msg.Pid)
	var err error
	if executor.IsElevated() || runtime.GOOS != "windows" {
		// Root/admin (or any Unix agent): kill in-process. A non-root Unix agent
		// simply gets a permission error, which is the honest result — there is no
		// per-action elevation on Unix.
		err = executor.KillProcess(msg.Pid)
	} else {
		// Windows medium-integrity: elevate a UAC child to reach other users' /
		// elevated processes.
		exe, _ := os.Executable()
		err = executor.RunElevatedAndWait(exe, fmt.Sprintf("kill %d", msg.Pid))
	}
	if err != nil {
		_ = c.sendOutput(msg.JobID, fmt.Sprintf("[agent error] kill failed: %v", err), false)
	} else {
		_ = c.sendOutput(msg.JobID, fmt.Sprintf("[+] Process %d terminated", msg.Pid), false)
	}
	_ = c.sendOutput(msg.JobID, "", true)
}

// handleEdgeParseNetwork enumerates live TCP/UDP connections (with owning
// process + image path + reverse DNS) and the DNS resolver cache, native via
// the Windows IP Helper API. No UAC needed — the local socket tables are
// readable in the agent's normal user context, which is also what lets the
// Network tab stream live.
func (c *Client) handleEdgeParseNetwork(msg inboundMsg) {
	if msg.JobID == "" {
		return
	}
	log.Printf("[edge_netconn:%s] enumerating network connections", msg.JobID)
	_ = c.sendOutput(msg.JobID, "[*] Enumerating TCP/UDP connections + DNS cache...", false)

	res, err := parser.ScanNetwork()
	if err != nil {
		_ = c.sendOutput(msg.JobID, fmt.Sprintf("[agent error] %v", err), false)
		_ = c.sendOutput(msg.JobID, "", true)
		return
	}
	b, err := json.Marshal(res)
	if err != nil {
		_ = c.sendOutput(msg.JobID, fmt.Sprintf("[agent error] marshal failed: %v", err), false)
		_ = c.sendOutput(msg.JobID, "", true)
		return
	}

	_ = c.writeJSON(outboundMsg{
		Type:  "artifact_data",
		JobID: msg.JobID,
		Data:  string(b),
	})

	_ = c.sendOutput(msg.JobID, fmt.Sprintf("[+] Network scan complete — %d connections, %d DNS records.", len(res.Connections), len(res.DNS)), false)
	_ = c.sendOutput(msg.JobID, "", true)
}

// handleEdgeParseRegistry parses a Windows registry key and sends back the artifact.
// The path should be in FsPath, e.g. "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
func (c *Client) handleEdgeParseRegistry(msg inboundMsg) {
	if msg.JobID == "" || msg.FsPath == "" {
		log.Printf("[edge_registry] missing job_id or fs_path")
		return
	}

	parts := strings.SplitN(msg.FsPath, "\\", 2)
	if len(parts) != 2 {
		_ = c.sendOutput(msg.JobID, "[agent error] invalid registry path format. Expected ROOT\\Path", false)
		_ = c.sendOutput(msg.JobID, "", true)
		return
	}

	root := parts[0]
	path := parts[1]

	log.Printf("[edge_registry:%s] parsing %s\\%s", msg.JobID, root, path)
	jsonData, err := parser.ParseRegistry(root, path)

	if err != nil {
		_ = c.sendOutput(msg.JobID, fmt.Sprintf("[agent error] %v", err), false)
		_ = c.sendOutput(msg.JobID, "", true)
		return
	}

	// Send the JSON result as artifact_data
	err = c.writeJSON(outboundMsg{
		Type:  "artifact_data",
		JobID: msg.JobID,
		Data:  jsonData,
	})
	if err != nil {
		log.Printf("[edge_registry:%s] send error: %v", msg.JobID, err)
	}

	// Mark the job as done
	_ = c.sendOutput(msg.JobID, "[+] Registry parsing complete.", false)
	_ = c.sendOutput(msg.JobID, "", true)
}

// handleEdgeParseEvtx runs a PowerShell script to query Windows Event Logs by ID and returns JSON.
func (c *Client) handleEdgeParseEvtx(msg inboundMsg) {
	if msg.JobID == "" || msg.Args == "" {
		log.Printf("[edge_evtx] missing job_id or args")
		return
	}

	// Args is a JSON query: {"log":"Security","ids":[4624,4625],"hours":24,"max":500,"keyword":""}
	// A legacy "LogName|EventID" string is still accepted for backward compatibility.
	var q struct {
		Log     string `json:"log"`
		IDs     []int  `json:"ids"`
		Hours   int    `json:"hours"`
		Max     int    `json:"max"`
		Keyword string `json:"keyword"`
	}
	if strings.HasPrefix(strings.TrimSpace(msg.Args), "{") {
		_ = json.Unmarshal([]byte(msg.Args), &q)
	} else if parts := strings.SplitN(msg.Args, "|", 2); len(parts) == 2 {
		q.Log = parts[0]
		for _, p := range strings.Split(parts[1], ",") {
			if n := strings.TrimSpace(p); n != "" {
				var id int
				if _, err := fmt.Sscanf(n, "%d", &id); err == nil {
					q.IDs = append(q.IDs, id)
				}
			}
		}
	}
	if strings.TrimSpace(q.Log) == "" {
		_ = c.sendOutput(msg.JobID, "[agent error] missing log name", false)
		_ = c.sendOutput(msg.JobID, "", true)
		return
	}
	maxEvents := q.Max
	if maxEvents <= 0 || maxEvents > 5000 {
		maxEvents = 500
	}

	// Build the FilterHashtable clauses.
	logEsc := strings.ReplaceAll(q.Log, "'", "''")
	idClause := ""
	if len(q.IDs) > 0 {
		var ids []string
		for _, id := range q.IDs {
			ids = append(ids, fmt.Sprintf("%d", id))
		}
		idClause = "; $f.Id = @(" + strings.Join(ids, ",") + ")"
	}
	startClause := ""
	if q.Hours > 0 {
		startClause = fmt.Sprintf("; $f.StartTime = (Get-Date).AddHours(-%d)", q.Hours)
	}
	kwClause := ""
	if kw := strings.TrimSpace(q.Keyword); kw != "" {
		kwClause = fmt.Sprintf("; $evts = $evts | Where-Object { $_.Message -like '*%s*' }", strings.ReplaceAll(kw, "'", "''"))
	}

	log.Printf("[edge_evtx:%s] querying %s ids=%v hours=%d max=%d", msg.JobID, q.Log, q.IDs, q.Hours, maxEvents)

	// Pull events, then expand each event's XML EventData into a key/value map so
	// the UI can show structured fields (User, Process, Parent, CommandLine, IP,
	// Hashes …) rather than only the rendered Message blob.
	psCmd := fmt.Sprintf(`$ErrorActionPreference='Stop'; try {
$f = @{ LogName='%s' }%s%s;
$evts = Get-WinEvent -FilterHashtable $f -MaxEvents %d%s;
$out = foreach ($e in $evts) {
  $data = [ordered]@{};
  try { $x=[xml]$e.ToXml(); $di=0; foreach ($d in $x.Event.EventData.Data) { if ($d.Name) { $data[[string]$d.Name] = [string]$d.'#text' } else { $data["Data$di"] = [string]$d.'#text'; $di++ } } } catch {}
  [pscustomobject]@{ time=$e.TimeCreated.ToString('o'); id=$e.Id; level=$e.LevelDisplayName; provider=$e.ProviderName; computer=$e.MachineName; record_id=$e.RecordId; message=$e.Message; data=$data }
};
if ($out) { $out | ConvertTo-Json -Compress -Depth 5 } else { '[]' }
} catch { '[]' }`, logEsc, idClause, startClause, maxEvents, kwClause)

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", psCmd)
	out, err := cmd.CombinedOutput()

	jsonData := strings.TrimSpace(string(out))
	if err != nil && jsonData == "" {
		_ = c.sendOutput(msg.JobID, fmt.Sprintf("[agent error] %v", err), false)
		_ = c.sendOutput(msg.JobID, "", true)
		return
	}

	if jsonData == "" {
		jsonData = "[]" // Empty array if no events found
	}

	// Send the JSON result as artifact_data
	err = c.writeJSON(outboundMsg{
		Type:  "artifact_data",
		JobID: msg.JobID,
		Data:  jsonData,
	})
	if err != nil {
		log.Printf("[edge_evtx:%s] send error: %v", msg.JobID, err)
	}

	// Mark the job as done
	_ = c.sendOutput(msg.JobID, "[+] EVTX parsing complete.", false)
	_ = c.sendOutput(msg.JobID, "", true)
}

// handlePing responds to a server ping with a pong.
func (c *Client) handlePing() {
	if err := c.writeJSON(outboundMsg{Type: "pong"}); err != nil {
		log.Printf("[ws] pong error: %v", err)
	}
}

// handleCleanup removes all agent-created files (tools, workdir, config) and
// then deletes the agent binary itself — restoring the machine to its pre-agent
// state. On Windows the binary self-delete is done via a background cmd.exe
// process that waits for the agent to exit before removing it.
// stopAllWork cancels every running job and closes every live PTY session so
// their child processes are terminated cleanly rather than orphaned when the
// agent exits. Used by handleCleanup before the binary self-deletes.
func (c *Client) stopAllWork() {
	c.runningJobsMu.Lock()
	cancels := make([]context.CancelFunc, 0, len(c.runningJobs))
	for id, cancel := range c.runningJobs {
		cancels = append(cancels, cancel)
		delete(c.runningJobs, id)
	}
	c.runningJobsMu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}

	c.terminalSessionsMu.Lock()
	sessions := make([]*terminal.Session, 0, len(c.terminalSessions))
	for id, sess := range c.terminalSessions {
		sessions = append(sessions, sess)
		delete(c.terminalSessions, id)
	}
	c.terminalSessionsMu.Unlock()
	for _, sess := range sessions {
		_ = sess.Close()
	}

	if len(cancels) > 0 || len(sessions) > 0 {
		log.Printf("[cleanup] stopped %d job(s) and %d terminal session(s)", len(cancels), len(sessions))
	}
}

func (c *Client) handleCleanup() {
	log.Println("[cleanup] received cleanup command — removing agent")

	// Terminate our own children first so no tool/PTY process is orphaned when
	// the binary self-deletes. This also releases file handles those children
	// may hold under WorkDir, making the subsequent removal more reliable.
	c.stopAllWork()

	workDir := c.cfg.WorkDir
	exePath, _ := os.Executable()

	// 1. Remove config file (next to binary). Small file, not held open by us,
	//    safe to remove immediately on every OS.
	if exePath != "" {
		confFile := filepath.Join(filepath.Dir(exePath), "analysishub-agent.conf")
		log.Printf("[cleanup] removing config: %s", confFile)
		os.Remove(confFile)
	}

	// 2. Schedule full removal of workdir + install dir.
	//    On Windows the agent holds open handles — agent.log under WorkDir
	//    (default ~/Desktop/AnalysisHub_Tools) and the binary itself under
	//    installDir — so deletion MUST happen from a detached process that
	//    waits for this agent to exit and Windows to release the locks.
	//    Linux can unlink open files directly, so we do it in-process there.
	if runtime.GOOS == "windows" {
		installDir := ""
		if exePath != "" {
			installDir = filepath.Dir(exePath)
		}

		// PS1 cleanup script — pure ASCII content, paths injected via env vars so
		// Unicode usernames/paths (e.g. Vietnamese) are handled correctly.
		// Using a PS1 file avoids the ANSI-vs-UTF-8 encoding issue that causes
		// cmd.exe batch scripts to garble non-ASCII paths and silently fail.
		const ps1Body = `
$workDir    = $env:FH_WORK_DIR
$installDir = $env:FH_INSTALL_DIR
$agentPid   = $env:FH_AGENT_PID
# Wait for the agent process itself to exit so Windows releases its binary/log
# handles, instead of guessing with a fixed sleep. This is both faster (no wait
# when the agent exits immediately) and more reliable (no race if exit is slow).
if ($agentPid) {
    try { Wait-Process -Id ([int]$agentPid) -Timeout 30 -ErrorAction Stop } catch { Start-Sleep -Seconds 3 }
} else {
    Start-Sleep -Seconds 5
}
# Kill AnalysisHub tool windows before deletion so their files are not locked.
Get-Process | Where-Object { $_.MainWindowTitle -like 'AnalysisHub - *' } |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
# Retry removal up to 5 times; AV or Explorer may briefly hold transient locks.
1..5 | ForEach-Object {
    if ($workDir    -and (Test-Path $workDir))    { Remove-Item -Recurse -Force -Path $workDir    -ErrorAction SilentlyContinue }
    if ($installDir -and (Test-Path $installDir)) { Remove-Item -Recurse -Force -Path $installDir -ErrorAction SilentlyContinue }
    $anyLeft = ($workDir -and (Test-Path $workDir)) -or ($installDir -and (Test-Path $installDir))
    if (-not $anyLeft) { break }
    Start-Sleep -Seconds 2
}
Remove-Item -Force -Path $MyInvocation.MyCommand.Path -ErrorAction SilentlyContinue
`
		// Write UTF-8 BOM so PowerShell 5.1 reads the file correctly.
		bom := []byte{0xEF, 0xBB, 0xBF}
		ps1Content := append(bom, []byte(ps1Body)...)
		// Randomize the script name so a low-privilege user cannot pre-plant or
		// symlink a predictable path in %TEMP% that we would then execute.
		ps1Name := fmt.Sprintf("fh_cleanup_%d_%d.ps1", os.Getpid(), rand.Int31())
		ps1Path := filepath.Join(os.TempDir(), ps1Name)
		if err := os.WriteFile(ps1Path, ps1Content, 0o600); err != nil {
			log.Printf("[cleanup] write PS1: %v", err)
		}
		log.Printf("[cleanup] scheduled removal of workDir=%q and installDir=%q via %s", workDir, installDir, ps1Path)

		cmd := osExec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", ps1Path)
		cmd.Env = append(os.Environ(),
			"FH_WORK_DIR="+workDir,
			"FH_INSTALL_DIR="+installDir,
			fmt.Sprintf("FH_AGENT_PID=%d", os.Getpid()))
		cmd.Dir = os.TempDir()
		// Detach from the agent's console so the window closes immediately on
		// os.Exit — without CREATE_NEW_CONSOLE the child inherits our console
		// handle and the window stays open until the script finishes.
		setCleanupCmd(cmd)
		if err := cmd.Start(); err != nil {
			log.Printf("[cleanup] schedule self-delete error: %v", err)
		}
	} else {
		// On Linux: disable and remove systemd service if present, then remove files.
		// The service must be stopped/disabled before removing the binary so systemd
		// doesn't attempt a restart while we're deleting files.
		const serviceFile = "/etc/systemd/system/analysishub-agent.service"
		if _, err := os.Stat(serviceFile); err == nil {
			log.Println("[cleanup] disabling systemd service")
			_ = osExec.Command("systemctl", "disable", "--now", "analysishub-agent.service").Run()
			_ = os.Remove(serviceFile)
			_ = osExec.Command("systemctl", "daemon-reload").Run()
		}

		if workDir != "" {
			log.Printf("[cleanup] removing work directory: %s", workDir)
			if err := os.RemoveAll(workDir); err != nil {
				log.Printf("[cleanup] remove workdir error: %v", err)
			}
		}
		if exePath != "" {
			installDir := filepath.Dir(exePath)
			log.Printf("[cleanup] removing binary and install dir: %s", installDir)
			_ = os.Remove(exePath)
			_ = os.RemoveAll(installDir)
		}
	}

	log.Println("[cleanup] cleanup complete — exiting")
	os.Exit(0)
}

// sendRegister transmits a "register" message with local system information.
func (c *Client) sendRegister() error {
	hostname, _ := os.Hostname()
	ip := localIP()

	return c.writeJSON(outboundMsg{
		Type:     "register",
		Hostname: hostname,
		OS:       runtime.GOOS,
		IP:       ip,
	})
}

// streamRealtime periodically collects system telemetry and sends it to the
// server as a "realtime_data" message. If a write fails (dead connection) it
// closes conn so readLoop detects the error and triggers a reconnect.
func (c *Client) streamRealtime(ctx context.Context, conn *websocket.Conn, dataType string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	collectAndSend := func() {
		var payload string
		var err error
		switch dataType {
		case "processes":
			payload, err = monitor.CollectProcesses()
		case "netstat":
			payload, err = monitor.CollectNetstat()
		case "sysinfo":
			payload, err = monitor.CollectSysInfo()
		case "netconn":
			payload, err = parser.CollectConnectionsJSON()
		default:
			return
		}
		if err != nil {
			log.Printf("[monitor] %s collect error: %v", dataType, err)
			return
		}
		if err := c.writeRealtimeJSON(outboundMsg{
			Type:     "realtime_data",
			DataType: dataType,
			Payload:  payload,
		}); err != nil {
			// Realtime frames are best-effort: drop the frame on write error
			// rather than closing the connection (it may be momentarily congested
			// by heavy shell output; killing it causes spurious disconnects).
			log.Printf("[monitor] send %s error: %v — dropping frame", dataType, err)
		}
	}

	// Send one frame immediately so slow-interval streams (e.g. sysinfo @30s)
	// populate the UI right away instead of showing an empty skeleton until the
	// first tick.
	collectAndSend()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collectAndSend()
		}
	}
}

// reportResources samples host CPU / RAM / disk and sends a "resource_report"
// to the server on an interval so the fleet view shows live agent utilization.
// Frames are best-effort (dropped on write error) like other realtime telemetry;
// one is emitted shortly after connect so the UI populates without a full wait.
func (c *Client) reportResources(ctx context.Context, interval time.Duration) {
	send := func() {
		// Native resource syscalls must NEVER crash the agent — a panic here would
		// kill the process and drop the WS connection. Recover and skip the sample.
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[monitor] resource sample recovered (skipped): %v", r)
			}
		}()
		r := monitor.SampleResource()
		if err := c.writeRealtimeJSON(outboundMsg{
			Type:        "resource_report",
			CPUPercent:  r.CPUPercent,
			MemUsedMB:   r.MemUsedMB,
			MemTotalMB:  r.MemTotalMB,
			DiskUsedGB:  r.DiskUsedGB,
			DiskTotalGB: r.DiskTotalGB,
		}); err != nil {
			log.Printf("[monitor] resource_report send error: %v — dropping frame", err)
		}
	}

	// Prompt first report (after a short settle so it doesn't race the register
	// handshake), then on the interval.
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Second):
		send()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			send()
		}
	}
}

// sendOutput transmits an "output" message for the given job.
func (c *Client) sendOutput(jobID, data string, done bool) error {
	return c.writeJSON(outboundMsg{
		Type:  "output",
		JobID: jobID,
		Data:  data,
		Done:  done,
	})
}

// writeJSON serialises msg and sends it over the WebSocket connection.
// It will enqueue the message into the spooler if offline and the message is spoolable.
func (c *Client) writeJSON(msg outboundMsg) error {
	spoolable := msg.Type == "output" || msg.Type == "job_status" || msg.Type == "artifact_data"

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.conn == nil {
		if c.spooler != nil && spoolable {
			log.Printf("[spooler] offline, spooling msg type %s", msg.Type)
			return c.spooler.Enqueue(msg)
		}
		return fmt.Errorf("not connected")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	c.conn.SetWriteDeadline(time.Now().Add(writeWait))
	err = c.conn.WriteMessage(websocket.TextMessage, data)
	if err != nil && c.spooler != nil && spoolable {
		log.Printf("[spooler] write error %v, spooling msg type %s", err, msg.Type)
		c.spooler.Enqueue(msg)
	}
	return err
}

// writeJSONDirect writes JSON without going through the spooler logic.
// Used by DequeueAll to prevent infinite spooling loops.
func (c *Client) writeJSONDirect(msg outboundMsg) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("not connected")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	c.conn.SetWriteDeadline(time.Now().Add(writeWait))
	return c.conn.WriteMessage(websocket.TextMessage, data)
}

// writeRealtimeJSON is like writeJSON but uses realtimeWriteWait as the
// deadline. Realtime telemetry frames (processes, netstat, sysinfo) are
// best-effort: a short per-frame deadline prevents them from monopolising
// the write mutex when the connection is congested by heavy shell output.
// The caller is responsible for deciding what to do on error (usually: drop
// the frame and continue, NOT close the connection).
func (c *Client) writeRealtimeJSON(msg outboundMsg) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("not connected")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	c.conn.SetWriteDeadline(time.Now().Add(realtimeWriteWait))
	return c.conn.WriteMessage(websocket.TextMessage, data)
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// serverWSURL converts the HTTP(S) server URL from config into the equivalent
// WebSocket URL and appends the agent token as a query parameter.
//
// http://host:port  →  ws://host:port/ws/agent?token=TOKEN
// https://host:port →  wss://host:port/ws/agent?token=TOKEN
func (c *Client) serverWSURL() string {
	base := c.cfg.ServerURL
	base = strings.TrimRight(base, "/")

	// Replace scheme.
	switch {
	case strings.HasPrefix(base, "https://"):
		base = "wss://" + strings.TrimPrefix(base, "https://")
	case strings.HasPrefix(base, "http://"):
		base = "ws://" + strings.TrimPrefix(base, "http://")
	}

	u, err := url.Parse(base + "/ws/agent")
	if err != nil {
		// Fallback: just concatenate (should never fail for well-formed URLs).
		return base + "/ws/agent?token=" + url.QueryEscape(c.cfg.AgentToken)
	}

	q := u.Query()
	q.Set("token", c.cfg.AgentToken)
	u.RawQuery = q.Encode()
	return u.String()
}

// localIP returns the non-loopback IPv4 address of the machine, or "unknown"
// if one cannot be determined.
func localIP() string {
	// Dial a UDP connection to a public address — no data is sent; this is
	// only used to discover which local interface would be chosen for
	// external traffic.
	conn, err := net.DialTimeout("udp", "8.8.8.8:53", 2*time.Second)
	if err != nil {
		// Fall back to iterating interfaces.
		return localIPFromInterfaces()
	}
	defer conn.Close()

	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP == nil {
		return localIPFromInterfaces()
	}
	return addr.IP.String()
}

// findNewestReportHTML walks a tool directory and returns the path of the most
// recently modified file named report.html (case-insensitive), or "" if none.
// This handles the per-platform layout differences (report/, linux/report/,
// windows/report/ …) without a hard-coded path.
func findNewestReportHTML(toolDir string) string {
	var best string
	var bestMod time.Time
	_ = filepath.Walk(toolDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if strings.EqualFold(info.Name(), "report.html") {
			if best == "" || info.ModTime().After(bestMod) {
				best = p
				bestMod = info.ModTime()
			}
		}
		return nil
	})
	return best
}

// uploadArtifact performs a multipart/form-data upload of a file to the server.
// It is used to send job results (reports, triage bundles) back to AnalysisHub.
func (c *Client) uploadArtifact(ctx context.Context, jobID, filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open artifact %s: %w", filePath, err)
	}
	defer f.Close()

	pr, pw := io.Pipe()
	w := multipart.NewWriter(pw)

	go func() {
		defer pw.Close()
		part, err := w.CreateFormFile("file", filepath.Base(filePath))
		if err != nil {
			log.Printf("[upload] form file error: %v", err)
			return
		}
		if _, err := io.Copy(part, f); err != nil {
			log.Printf("[upload] copy error: %v", err)
		}
		w.Close()
	}()

	uploadURL := fmt.Sprintf("%s/api/v1/jobs/%s/artifact", c.cfg.ServerURL, jobID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, pr)
	if err != nil {
		return fmt.Errorf("build upload request: %w", err)
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("X-Agent-Token", c.cfg.AgentToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("dispatch upload: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed: server returned %s: %s", resp.Status, string(body))
	}

	return nil
}

// localIPFromInterfaces iterates network interfaces to find a non-loopback
// IPv4 address. Returns "unknown" if none is found.
func localIPFromInterfaces() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "unknown"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				return ip4.String()
			}
		}
	}
	return "unknown"
}

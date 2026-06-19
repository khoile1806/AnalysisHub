package ws

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"encoding/base64"

	"github.com/forensichub/agent/internal/config"
	"github.com/forensichub/agent/internal/executor"
	"github.com/forensichub/agent/internal/fs"
	"github.com/forensichub/agent/internal/monitor"
	"github.com/forensichub/agent/internal/terminal"
	"github.com/gorilla/websocket"

	osExec "os/exec"
)

// ----------------------------------------------------------------------------
// Wire-protocol message types
// ----------------------------------------------------------------------------

// inboundMsg represents any message received from the ForensicHub server.
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
}

// outboundMsg represents any message sent to the ForensicHub server.
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

// Client manages a persistent WebSocket connection to the ForensicHub server.
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
}

// NewClient creates a Client for the supplied configuration. Call Run() to
// start the connection loop.
func NewClient(cfg *config.Config) *Client {
	return &Client{
		cfg:              cfg,
		runningJobs:      make(map[string]context.CancelFunc),
		terminalSessions: make(map[string]*terminal.Session),
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

		log.Printf("[ws] reconnecting in %s …", backoff)
		select {
		case <-time.After(backoff):
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

	// Start periodic realtime data streaming.
	// Pass conn so goroutines can close it on write error to force a reconnect.
	streamCtx, cancelStream := context.WithCancel(ctx)
	go c.streamRealtime(streamCtx, conn, "processes", 3*time.Second)
	go c.streamRealtime(streamCtx, conn, "netstat", 3*time.Second)
	go c.streamRealtime(streamCtx, conn, "sysinfo", 30*time.Second)
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
	req := executor.JobRequest{
		JobID:          msg.JobID,
		ToolID:         msg.ToolID,
		ToolName:       msg.ToolName,
		FileName:       msg.FileName,
		Args:           msg.Args,
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

		// --- NEW: Automatic Artifact Upload for Webshell Scanner ---
		// Look for "report/report.html" and upload it before marking the job as
		// done. Match on either ToolName (normalized — strips spaces/dashes so
		// "Webshell Scanner", "webshell-scanner", "webshell_scanner" all hit) or
		// FileName as a fallback.
		toolNameNorm := strings.ToLower(msg.ToolName)
		toolNameNorm = strings.ReplaceAll(toolNameNorm, " ", "")
		toolNameNorm = strings.ReplaceAll(toolNameNorm, "-", "")
		toolNameNorm = strings.ReplaceAll(toolNameNorm, "_", "")
		isWebshellScanner := strings.Contains(toolNameNorm, "webshellscanner") ||
			strings.Contains(strings.ToLower(msg.FileName), "webshell-scanner")
		if isWebshellScanner {
			workDir := c.cfg.WorkDir
			toolID := msg.ToolID
			if toolID == "" {
				toolID = executor.SanitizeFilename(msg.ToolName)
			}
			// The report is generated in toolDir/report/ (default)
			reportPath := filepath.Join(workDir, "tools", toolID, "report", "report.html")

			if _, statErr := os.Stat(reportPath); statErr == nil {
				log.Printf("[job:%s] uploading webshell-scanner report: %s", msg.JobID, reportPath)
				if upErr := c.uploadArtifact(runCtx, msg.JobID, reportPath); upErr != nil {
					log.Printf("[job:%s] artifact upload failed: %v", msg.JobID, upErr)
					_ = c.sendOutput(msg.JobID, fmt.Sprintf("[agent error] report upload failed: %v", upErr), false)
				} else {
					log.Printf("[job:%s] report uploaded successfully", msg.JobID)
					_ = c.sendOutput(msg.JobID, "[+] Report uploaded successfully", false)
				}
			} else {
				log.Printf("[job:%s] report not found at %s", msg.JobID, reportPath)
			}
		}

		if err := c.sendOutput(msg.JobID, "", true); err != nil {
			log.Printf("[job:%s] send done error: %v", msg.JobID, err)
		}
		log.Printf("[job:%s] finished", msg.JobID)
	}()
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
func (c *Client) handleCleanup() {
	log.Println("[cleanup] received cleanup command — removing agent")

	workDir := c.cfg.WorkDir
	exePath, _ := os.Executable()

	// 1. Remove config file (next to binary). Small file, not held open by us,
	//    safe to remove immediately on every OS.
	if exePath != "" {
		confFile := filepath.Join(filepath.Dir(exePath), "forensichub-agent.conf")
		log.Printf("[cleanup] removing config: %s", confFile)
		os.Remove(confFile)
	}

	// 2. Schedule full removal of workdir + install dir.
	//    On Windows the agent holds open handles — agent.log under WorkDir
	//    (default ~/Desktop/ForensicHub_Tools) and the binary itself under
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
Start-Sleep -Seconds 5
# Kill ForensicHub tool windows before deletion so their files are not locked.
Get-Process | Where-Object { $_.MainWindowTitle -like 'ForensicHub - *' } |
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
		ps1Path := filepath.Join(os.TempDir(), "forensichub_cleanup.ps1")
		if err := os.WriteFile(ps1Path, ps1Content, 0o600); err != nil {
			log.Printf("[cleanup] write PS1: %v", err)
		}
		log.Printf("[cleanup] scheduled removal of workDir=%q and installDir=%q via %s", workDir, installDir, ps1Path)

		cmd := osExec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", ps1Path)
		cmd.Env = append(os.Environ(), "FH_WORK_DIR="+workDir, "FH_INSTALL_DIR="+installDir)
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
		const serviceFile = "/etc/systemd/system/forensichub-agent.service"
		if _, err := os.Stat(serviceFile); err == nil {
			log.Println("[cleanup] disabling systemd service")
			_ = osExec.Command("systemctl", "disable", "--now", "forensichub-agent.service").Run()
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
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var payload string
			var err error
			switch dataType {
			case "processes":
				payload, err = monitor.CollectProcesses()
			case "netstat":
				payload, err = monitor.CollectNetstat()
			case "sysinfo":
				payload, err = monitor.CollectSysInfo()
			default:
				continue
			}
			if err != nil {
				log.Printf("[monitor] %s collect error: %v", dataType, err)
				continue
			}
			if err := c.writeRealtimeJSON(outboundMsg{
				Type:     "realtime_data",
				DataType: dataType,
				Payload:  payload,
			}); err != nil {
				// Realtime frames are best-effort: drop the frame on write
				// error rather than closing the connection. The connection may
				// be momentarily congested by heavy shell output; killing it
				// here causes spurious agent disconnects during terminal use.
				log.Printf("[monitor] send %s error: %v — dropping frame", dataType, err)
			}
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
// It holds the write mutex for the duration of the send so concurrent
// goroutines do not corrupt the connection (gorilla/websocket is not
// safe for concurrent writes).
func (c *Client) writeJSON(msg outboundMsg) error {
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

// uploadArtifact performs a multipart/form-data upload of a file to the server.
// It is used to send job results (reports, triage bundles) back to ForensicHub.
func (c *Client) uploadArtifact(ctx context.Context, jobID, filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open artifact %s: %w", filePath, err)
	}
	defer f.Close()

	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	part, err := w.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return fmt.Errorf("create form file: %w", err)
	}
	if _, err := io.Copy(part, f); err != nil {
		return fmt.Errorf("copy file to form: %w", err)
	}
	_ = w.Close()

	uploadURL := fmt.Sprintf("%s/api/v1/jobs/%s/artifact", c.cfg.ServerURL, jobID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, &b)
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

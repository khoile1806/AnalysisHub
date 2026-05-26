package ws

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
)

// AgentCommand is the payload sent from the server to an agent over WebSocket.
type AgentCommand struct {
	Type           string `json:"type"` // "job_start" | "job_run" | "job_stop" | "shell_*" | "fs_request" | "ping" | "cleanup"
	JobID          string `json:"job_id,omitempty"`
	ToolID         string `json:"tool_id,omitempty"` // tool UUID — used as shared directory name on agent
	ToolName       string `json:"tool_name,omitempty"`
	FileName       string `json:"file_name,omitempty"` // original stored filename (with extension), e.g. "abc123.zip"
	DownloadURL    string `json:"download_url,omitempty"`
	Args           string `json:"args,omitempty"`
	ExecutablePath string `json:"executable_path,omitempty"` // relative path to executable within tool dir

	// Terminal (interactive PTY) fields.
	SessionID string `json:"session_id,omitempty"`
	Shell     string `json:"shell,omitempty"` // "cmd" | "powershell" | "bash" | "sh"
	Cols      int    `json:"cols,omitempty"`
	Rows      int    `json:"rows,omitempty"`
	Data      string `json:"data,omitempty"` // base64-encoded stdin for shell_input

	// File-system browser fields (fs_request).
	FsOp    string   `json:"fs_op,omitempty"`    // "list" | "read_file" | "read_folder" | "read_bundle"
	FsPath  string   `json:"fs_path,omitempty"`  // absolute path on the agent
	FsPaths []string `json:"fs_paths,omitempty"` // multi-path list for op=read_bundle
}

// FsEntry describes a single directory entry returned by op=list.
type FsEntry struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	IsDir   bool   `json:"is_dir"`
	ModTime string `json:"mod_time"`
	Mode    string `json:"mode,omitempty"`
}

// FsListResult wraps the entries from a directory listing together with the
// Truncated flag so callers know whether the list was capped by the agent.
type FsListResult struct {
	Entries   []FsEntry
	Truncated bool
}

// AgentMessage is the payload received from an agent over WebSocket.
type AgentMessage struct {
	Type     string `json:"type"` // "register" | "output" | "artifact" | "pong" | "realtime_data" | "job_status" | "shell_*" | "fs_response"
	AgentID  string `json:"agent_id,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
	IP       string `json:"ip,omitempty"`
	JobID    string `json:"job_id,omitempty"`
	Data     string `json:"data,omitempty"`
	Done     bool   `json:"done,omitempty"`
	Filename string `json:"filename,omitempty"`
	Size     int64  `json:"size,omitempty"`
	DataType string `json:"data_type,omitempty"` // "processes" | "netstat"
	Payload  string `json:"payload,omitempty"`   // JSON-encoded realtime data
	Status   string `json:"status,omitempty"`    // for type=="job_status": "ready" | "stopped"

	// Terminal (interactive PTY) fields.
	SessionID string `json:"session_id,omitempty"`
	ExitCode  int    `json:"exit_code,omitempty"`

	// File-system browser fields (fs_response).
	FsOp        string    `json:"fs_op,omitempty"`
	FsEntries   []FsEntry `json:"fs_entries,omitempty"`
	FsTruncated bool      `json:"fs_truncated,omitempty"` // true when agent capped the entry list
	FsData      string    `json:"fs_data,omitempty"`      // base64 chunk for read_file/read_folder/read_bundle
	FsDone      bool      `json:"fs_done,omitempty"`
	FsError     string    `json:"fs_error,omitempty"`
	FsSize      int64     `json:"fs_size,omitempty"` // total bytes (file size) sent in first chunk
}

// OutputPersistFunc is a callback invoked for every output chunk received from
// an agent. Implementations should append the data line to the job record and,
// when done is true, mark the job as completed.
type OutputPersistFunc func(jobID, data string, done bool)

// JobStatusFunc is a callback invoked when an agent reports a job lifecycle
// transition (e.g. "ready" after download, "stopped" after kill).
type JobStatusFunc func(jobID, status string)

// TerminalSession represents an active browser ↔ agent PTY relay. The hub
// owns lookup by sessionID; the handler owning the browser WebSocket is
// responsible for delivering data chunks via OnData / OnClosed.
type TerminalSession struct {
	ID       string
	AgentID  string
	OnData   func(data string) // base64-encoded chunk from agent
	OnClosed func(exitCode int)
}

// FsSession represents a pending filesystem request/response correlation. The
// handler registers one before sending fs_request and is notified as
// fs_response frames arrive. The hub removes the session once FsDone or
// FsError is received, or when the owning agent disconnects.
//
// Callbacks (OnChunk, OnDone, OnError) are invoked from a dedicated pump
// goroutine — never from the hub event loop — so they may block without
// stalling agent message processing.
type FsSession struct {
	ID      string
	AgentID string
	// OnList is invoked exactly once for op=list. result.Truncated is true
	// when the agent capped the listing at maxListEntries.
	OnList func(result FsListResult)
	// OnChunk is invoked for each data chunk (read_file/read_folder/read_bundle).
	// size is the total file size (only meaningful in the first chunk of read_file).
	OnChunk func(b64 string, size int64)
	// OnDone is invoked when the agent reports fs_done:true.
	OnDone func()
	// OnError is invoked when the agent reports fs_error.
	OnError func(msg string)

	// inbound buffers fs_response messages so the hub event loop never blocks
	// on potentially-slow callbacks (e.g. OnChunk writing to an io.Pipe).
	// Initialised by RegisterFsSession; closed by the hub when the session
	// ends (done/error/agent disconnect).
	inbound chan AgentMessage
}

// Hub manages all connected WebSocket clients (agents) and routes messages
// between agents and SSE subscribers.
type Hub struct {
	// clients maps agentID → *Client
	clients map[string]*Client

	// subscribers maps jobID → set of output channels
	subscribers map[string][]chan string

	Register   chan *Client
	Unregister chan *Client

	// inbound carries messages received from agents (client + raw bytes)
	inbound chan agentInbound

	// OnOutput is an optional callback for persisting job output outside the hub.
	// It is called synchronously inside the hub event loop, so implementations
	// should be fast (e.g. async DB writes).
	OnOutput OutputPersistFunc

	// OnJobStatus is an optional callback for persisting job lifecycle
	// transitions ("ready", "stopped", …) reported by the agent.
	OnJobStatus JobStatusFunc

	mu sync.RWMutex

	// realtimeSubs maps "agentID:dataType" → list of subscriber channels.
	realtimeSubs map[string][]chan string
	// latestRealtime maps "agentID:dataType" → last received JSON payload.
	latestRealtime map[string]string
	realtimeMu     sync.RWMutex

	// terminalSessions maps sessionID → *TerminalSession for browser↔agent PTY relay.
	terminalSessions map[string]*TerminalSession
	terminalMu       sync.RWMutex

	// fsSessions maps sessionID → *FsSession for filesystem browser request/response.
	fsSessions map[string]*FsSession
	fsMu       sync.RWMutex

	// cveSubs is a list of channels for realtime CVE collection updates.
	cveSubs []chan bool
	cveMu   sync.RWMutex

	// newsSubs is a list of channels for realtime news article updates.
	// Each value sent is the category slug that changed, so subscribers
	// can avoid invalidating queries for unaffected tabs.
	newsSubs []chan string
	newsMu   sync.RWMutex
}

type agentInbound struct {
	client  *Client
	payload []byte
}

// NewHub creates an initialised Hub ready to be started with Run().
func NewHub() *Hub {
	return &Hub{
		clients:          make(map[string]*Client),
		subscribers:      make(map[string][]chan string),
		Register:         make(chan *Client, 32),
		Unregister:       make(chan *Client, 32),
		inbound:          make(chan agentInbound, 256),
		realtimeSubs:     make(map[string][]chan string),
		latestRealtime:   make(map[string]string),
		terminalSessions: make(map[string]*TerminalSession),
		fsSessions:       make(map[string]*FsSession),
		cveSubs:          make([]chan bool, 0),
	}
}

// Run starts the hub event loop. It must be called in its own goroutine.
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.Register:
			h.mu.Lock()
			h.clients[client.AgentID] = client
			h.mu.Unlock()
			log.Printf("[hub] agent registered: %s", client.AgentID)

		case client := <-h.Unregister:
			h.mu.Lock()
			if existing, ok := h.clients[client.AgentID]; ok && existing == client {
				delete(h.clients, client.AgentID)
				log.Printf("[hub] agent unregistered: %s", client.AgentID)
			}
			h.mu.Unlock()
			h.closeAgentTerminalSessions(client.AgentID)
			h.closeAgentFsSessions(client.AgentID)

		case msg := <-h.inbound:
			h.handleAgentMessage(msg)
		}
	}
}

// handleAgentMessage parses inbound bytes from an agent and dispatches accordingly.
func (h *Hub) handleAgentMessage(msg agentInbound) {
	var am AgentMessage
	if err := json.Unmarshal(msg.payload, &am); err != nil {
		log.Printf("[hub] failed to parse agent message from %s: %v", msg.client.AgentID, err)
		return
	}

	switch am.Type {
	case "output":
		if am.JobID == "" {
			return
		}

		// Persist via callback (non-blocking: runs in separate goroutine).
		if h.OnOutput != nil {
			go h.OnOutput(am.JobID, am.Data, am.Done)
		}

		// Determine the line to broadcast to SSE subscribers.
		line := am.Data
		if am.Done {
			line = "__DONE__"
		}

		h.mu.RLock()
		subs := make([]chan string, len(h.subscribers[am.JobID]))
		copy(subs, h.subscribers[am.JobID])
		h.mu.RUnlock()

		for _, ch := range subs {
			select {
			case ch <- line:
			default:
				// Subscriber channel full; drop to avoid blocking hub event loop.
			}
		}

	case "realtime_data":
		if am.DataType == "" || am.Payload == "" {
			return
		}
		key := msg.client.AgentID + ":" + am.DataType
		h.realtimeMu.Lock()
		h.latestRealtime[key] = am.Payload
		subs := make([]chan string, len(h.realtimeSubs[key]))
		copy(subs, h.realtimeSubs[key])
		h.realtimeMu.Unlock()
		for _, ch := range subs {
			select {
			case ch <- am.Payload:
			default:
				// Subscriber channel full; drop to avoid blocking hub event loop.
			}
		}

	case "job_status":
		if am.JobID == "" || am.Status == "" {
			return
		}
		if h.OnJobStatus != nil {
			go h.OnJobStatus(am.JobID, am.Status)
		}

	case "shell_output":
		if am.SessionID == "" {
			return
		}
		h.terminalMu.RLock()
		sess := h.terminalSessions[am.SessionID]
		h.terminalMu.RUnlock()
		if sess != nil && sess.OnData != nil {
			sess.OnData(am.Data)
		}

	case "shell_closed":
		if am.SessionID == "" {
			return
		}
		h.terminalMu.Lock()
		sess := h.terminalSessions[am.SessionID]
		delete(h.terminalSessions, am.SessionID)
		h.terminalMu.Unlock()
		if sess != nil && sess.OnClosed != nil {
			if am.Data != "" && sess.OnData != nil {
				sess.OnData(am.Data)
			}
			sess.OnClosed(am.ExitCode)
		}

	case "fs_response":
		if am.SessionID == "" {
			return
		}
		h.fsMu.RLock()
		sess := h.fsSessions[am.SessionID]
		h.fsMu.RUnlock()
		if sess == nil {
			return
		}

		// Terminal events (error / done) remove the session from the map so
		// subsequent messages for the same ID are silently dropped.
		if am.FsError != "" || am.FsDone {
			h.fsMu.Lock()
			delete(h.fsSessions, am.SessionID)
			h.fsMu.Unlock()
		}

		// Push the message into the session's buffered channel. The pump
		// goroutine (started by RegisterFsSession) drains it and invokes the
		// callbacks. This keeps the hub event loop non-blocking even when
		// OnChunk does slow I/O (e.g. writing to an HTTP pipe).
		if sess.inbound != nil {
			select {
			case sess.inbound <- am:
			default:
				log.Printf("[hub] fs session %s inbound buffer full — dropping message", am.SessionID)
			}
			// Close the channel after pushing the terminal message so the
			// pump goroutine exits cleanly.
			if am.FsError != "" || am.FsDone {
				close(sess.inbound)
			}
		}

	case "pong":
		// Heartbeat acknowledged; no action needed.

	default:
		log.Printf("[hub] unhandled agent message type %q from %s", am.Type, msg.client.AgentID)
	}
}

// SendJobToAgent serialises cmd as JSON and delivers it to the agent identified
// by agentID. Returns an error if the agent is not connected.
func (h *Hub) SendJobToAgent(agentID string, cmd AgentCommand) error {
	h.mu.RLock()
	client, ok := h.clients[agentID]
	h.mu.RUnlock()

	if !ok {
		return fmt.Errorf("agent %s is not connected", agentID)
	}

	data, err := json.Marshal(cmd)
	if err != nil {
		return fmt.Errorf("marshal command: %w", err)
	}

	select {
	case client.send <- data:
		return nil
	default:
		return fmt.Errorf("send buffer for agent %s is full", agentID)
	}
}

// SubscribeJobOutput returns a channel that will receive output lines for jobID.
// The caller must call UnsubscribeJobOutput when done to avoid goroutine leaks.
func (h *Hub) SubscribeJobOutput(jobID string) chan string {
	ch := make(chan string, 256)
	h.mu.Lock()
	h.subscribers[jobID] = append(h.subscribers[jobID], ch)
	h.mu.Unlock()
	return ch
}

// UnsubscribeJobOutput removes ch from the subscriber list for jobID and closes it.
func (h *Hub) UnsubscribeJobOutput(jobID string, ch chan string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	subs := h.subscribers[jobID]
	newSubs := make([]chan string, 0, len(subs))
	for _, s := range subs {
		if s != ch {
			newSubs = append(newSubs, s)
		}
	}
	if len(newSubs) == 0 {
		delete(h.subscribers, jobID)
	} else {
		h.subscribers[jobID] = newSubs
	}
	close(ch)
}

// IsAgentOnline reports whether the agent is currently connected.
func (h *Hub) IsAgentOnline(agentID string) bool {
	h.mu.RLock()
	_, ok := h.clients[agentID]
	h.mu.RUnlock()
	return ok
}

// receiveFromAgent is called by Client to forward a raw message to the hub.
func (h *Hub) receiveFromAgent(c *Client, data []byte) {
	select {
	case h.inbound <- agentInbound{client: c, payload: data}:
	default:
		log.Printf("[hub] inbound buffer full, dropping message from agent %s", c.AgentID)
	}
}

// SubscribeRealtime returns a channel that receives JSON payloads for the
// given agent/dataType pair (e.g. "processes" or "netstat") as they arrive.
// Call UnsubscribeRealtime when done to avoid goroutine leaks.
func (h *Hub) SubscribeRealtime(agentID, dataType string) chan string {
	ch := make(chan string, 32)
	key := agentID + ":" + dataType
	h.realtimeMu.Lock()
	h.realtimeSubs[key] = append(h.realtimeSubs[key], ch)
	h.realtimeMu.Unlock()
	return ch
}

// UnsubscribeRealtime removes ch from the subscriber list and closes it.
func (h *Hub) UnsubscribeRealtime(agentID, dataType string, ch chan string) {
	key := agentID + ":" + dataType
	h.realtimeMu.Lock()
	defer h.realtimeMu.Unlock()
	subs := h.realtimeSubs[key]
	newSubs := make([]chan string, 0, len(subs))
	for _, s := range subs {
		if s != ch {
			newSubs = append(newSubs, s)
		}
	}
	if len(newSubs) == 0 {
		delete(h.realtimeSubs, key)
	} else {
		h.realtimeSubs[key] = newSubs
	}
	close(ch)
}

// GetLatestRealtime returns the most recently received payload for the given
// agent/dataType pair, allowing new subscribers to get an immediate snapshot.
func (h *Hub) GetLatestRealtime(agentID, dataType string) (string, bool) {
	key := agentID + ":" + dataType
	h.realtimeMu.RLock()
	v, ok := h.latestRealtime[key]
	h.realtimeMu.RUnlock()
	return v, ok
}

// closeAgentTerminalSessions closes all browser terminal sessions that belong
// to the given agent. Called when the agent WebSocket disconnects so browsers
// receive a "closed" frame instead of hanging indefinitely.
func (h *Hub) closeAgentTerminalSessions(agentID string) {
	h.terminalMu.Lock()
	var victims []*TerminalSession
	for id, sess := range h.terminalSessions {
		if sess.AgentID == agentID {
			victims = append(victims, sess)
			delete(h.terminalSessions, id)
		}
	}
	h.terminalMu.Unlock()

	for _, sess := range victims {
		log.Printf("[hub] closing terminal session %s (agent %s disconnected)", sess.ID, agentID)
		if sess.OnData != nil {
			// Send a visible error line before closing so the terminal shows context.
			sess.OnData("") // flush any buffered output
		}
		if sess.OnClosed != nil {
			sess.OnClosed(-1)
		}
	}
}

// RegisterTerminalSession stores sess so incoming shell_output / shell_closed
// messages for this sessionID are routed to its callbacks.
func (h *Hub) RegisterTerminalSession(sess *TerminalSession) {
	if sess == nil || sess.ID == "" {
		return
	}
	h.terminalMu.Lock()
	h.terminalSessions[sess.ID] = sess
	h.terminalMu.Unlock()
}

// UnregisterTerminalSession removes the entry for sessionID. Safe to call
// even if the session was already removed (e.g. by shell_closed).
func (h *Hub) UnregisterTerminalSession(sessionID string) {
	if sessionID == "" {
		return
	}
	h.terminalMu.Lock()
	delete(h.terminalSessions, sessionID)
	h.terminalMu.Unlock()
}

// RegisterFsSession stores sess so incoming fs_response messages for this
// sessionID are routed to its callbacks. Must be called before sending the
// corresponding fs_request so the response is not dropped.
//
// A buffered inbound channel and a pump goroutine are created so that
// callbacks are invoked outside the hub event loop. The pump preserves
// message ordering (chunks arrive in-order from a single agent WS) and
// exits when the channel is closed (on done/error/agent disconnect).
func (h *Hub) RegisterFsSession(sess *FsSession) {
	if sess == nil || sess.ID == "" {
		return
	}
	// 128 slots ≈ 128 × 256 KiB raw ≈ 32 MiB in-flight before the hub
	// starts dropping frames. Generous enough for fast agents on a slow
	// HTTP drain; tight enough to bound memory.
	sess.inbound = make(chan AgentMessage, 128)

	// Pump goroutine: drains inbound and calls callbacks sequentially.
	go func() {
		for am := range sess.inbound {
			if am.FsOp == "list" && sess.OnList != nil {
				sess.OnList(FsListResult{Entries: am.FsEntries, Truncated: am.FsTruncated})
			} else if am.FsData != "" && sess.OnChunk != nil {
				sess.OnChunk(am.FsData, am.FsSize)
			}
			if am.FsError != "" && sess.OnError != nil {
				sess.OnError(am.FsError)
			}
			if am.FsDone && sess.OnDone != nil {
				sess.OnDone()
			}
		}
	}()

	h.fsMu.Lock()
	h.fsSessions[sess.ID] = sess
	h.fsMu.Unlock()
}

// UnregisterFsSession removes the entry for sessionID and closes its inbound
// channel (causing the pump goroutine to exit). Safe to call even if already
// removed by fs_done/fs_error.
func (h *Hub) UnregisterFsSession(sessionID string) {
	if sessionID == "" {
		return
	}
	h.fsMu.Lock()
	sess, ok := h.fsSessions[sessionID]
	if ok {
		delete(h.fsSessions, sessionID)
	}
	h.fsMu.Unlock()
	// Close inbound so the pump goroutine exits. A double-close is possible
	// if the hub already closed it on done/error; recover from the panic.
	if ok && sess.inbound != nil {
		defer func() { recover() }()
		close(sess.inbound)
	}
}

// closeAgentFsSessions fires OnError on every fs session owned by agentID and
// removes them. Called when the agent WebSocket disconnects so pending HTTP
// requests do not hang until their own timeouts fire.
func (h *Hub) closeAgentFsSessions(agentID string) {
	h.fsMu.Lock()
	var victims []*FsSession
	for id, sess := range h.fsSessions {
		if sess.AgentID == agentID {
			victims = append(victims, sess)
			delete(h.fsSessions, id)
		}
	}
	h.fsMu.Unlock()

	for _, sess := range victims {
		log.Printf("[hub] aborting fs session %s (agent %s disconnected)", sess.ID, agentID)
		// Push a synthetic error into the pump channel and close it so the
		// pump goroutine delivers OnError and exits.
		if sess.inbound != nil {
			func() {
				defer func() { recover() }()
				sess.inbound <- AgentMessage{
					Type:      "fs_response",
					SessionID: sess.ID,
					FsError:   "agent disconnected",
				}
				close(sess.inbound)
			}()
		} else if sess.OnError != nil {
			sess.OnError("agent disconnected")
		}
	}
}

// SubscribeCVE returns a channel that receives a signal (true) whenever the
// CVE collection is updated. Call UnsubscribeCVE when done.
func (h *Hub) SubscribeCVE() chan bool {
	ch := make(chan bool, 1)
	h.cveMu.Lock()
	h.cveSubs = append(h.cveSubs, ch)
	h.cveMu.Unlock()
	return ch
}

// UnsubscribeCVE removes ch from the CVE subscriber list and closes it.
func (h *Hub) UnsubscribeCVE(ch chan bool) {
	h.cveMu.Lock()
	defer h.cveMu.Unlock()
	newSubs := make([]chan bool, 0, len(h.cveSubs))
	for _, s := range h.cveSubs {
		if s != ch {
			newSubs = append(newSubs, s)
		}
	}
	h.cveSubs = newSubs
	close(ch)
}

// PublishCVEUpdate signals all subscribers that the CVE collection has changed.
func (h *Hub) PublishCVEUpdate() {
	h.cveMu.RLock()
	subs := make([]chan bool, len(h.cveSubs))
	copy(subs, h.cveSubs)
	h.cveMu.RUnlock()
	for _, ch := range subs {
		select {
		case ch <- true: // Send a signal
		default:
		}
	}
}

// SubscribeNews returns a channel that receives a category slug whenever
// new articles arrive in that category. Call UnsubscribeNews when done.
func (h *Hub) SubscribeNews() chan string {
	ch := make(chan string, 8)
	h.newsMu.Lock()
	h.newsSubs = append(h.newsSubs, ch)
	h.newsMu.Unlock()
	return ch
}

// UnsubscribeNews removes ch from the news subscriber list and closes it.
func (h *Hub) UnsubscribeNews(ch chan string) {
	h.newsMu.Lock()
	defer h.newsMu.Unlock()
	newSubs := make([]chan string, 0, len(h.newsSubs))
	for _, s := range h.newsSubs {
		if s != ch {
			newSubs = append(newSubs, s)
		}
	}
	h.newsSubs = newSubs
	close(ch)
}

// PublishNewsUpdate broadcasts a category slug to every news subscriber.
// Drops the message for any subscriber whose buffer is full — slow clients
// don't block the worker.
func (h *Hub) PublishNewsUpdate(category string) {
	h.newsMu.RLock()
	subs := make([]chan string, len(h.newsSubs))
	copy(subs, h.newsSubs)
	h.newsMu.RUnlock()
	for _, ch := range subs {
		select {
		case ch <- category:
		default:
		}
	}
}


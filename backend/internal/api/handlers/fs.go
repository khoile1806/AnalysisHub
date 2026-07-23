package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/storage"
	appws "github.com/analysishub/backend/internal/ws"
)

// fsListTimeout is how long the backend waits for the agent to return an
// op=list response. 30 s is ample for even slow remote filesystems now that
// the agent caps at 5000 entries before iterating d.Info().
const fsListTimeout = 30 * time.Second

// fsReadTimeout is how long the backend waits for the first chunk of a
// read_file / read_folder / read_bundle response. Large directories or files
// may take time to start streaming, so we give the agent 90 s before giving
// up. Once streaming has started there is no per-chunk deadline.
const fsReadTimeout = 90 * time.Second

// ListAgentFS returns the directory listing of <path> on the given agent.
//
// GET /api/v1/agents/:id/fs?path=<abs-path>
func ListAgentFS(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	hub, ok := mustGetHub(c)
	if !ok {
		return
	}

	agentID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid agent id"})
		return
	}
	path := strings.TrimSpace(c.Query("path"))
	if path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "path required"})
		return
	}

	var agent models.Agent
	if err := db.First(&agent, "id = ?", agentID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "agent not found"})
		return
	}
	if !hub.IsAgentOnline(agentID.String()) {
		c.JSON(http.StatusConflict, gin.H{"success": false, "error": "agent is offline"})
		return
	}

	sessionID := uuid.NewString()
	type result struct {
		entries   []appws.FsEntry
		truncated bool
		err       string
	}
	done := make(chan result, 1)
	var once sync.Once
	finish := func(r result) { once.Do(func() { done <- r }) }

	hub.RegisterFsSession(&appws.FsSession{
		ID:      sessionID,
		AgentID: agentID.String(),
		OnList:  func(r appws.FsListResult) { finish(result{entries: r.Entries, truncated: r.Truncated}) },
		OnDone:  func() {},
		OnError: func(msg string) { finish(result{err: msg}) },
	})
	defer hub.UnregisterFsSession(sessionID)

	if err := hub.SendJobToAgent(agentID.String(), appws.AgentCommand{
		Type:      "fs_request",
		SessionID: sessionID,
		FsOp:      "list",
		FsPath:    path,
	}); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": err.Error()})
		return
	}

	select {
	case r := <-done:
		if r.err != "" {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": r.err})
			return
		}
		// Audit only successful lists so failed probes aren't persisted verbatim.
		userID, _ := middleware.GetUserID(c)
		writeAudit(c, db, &userID, &agentID, "agent.fs.list", sessionID, "path="+path)
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
			"path":      path,
			"entries":   r.entries,
			"truncated": r.truncated,
		}})
	case <-time.After(fsListTimeout):
		c.JSON(http.StatusGatewayTimeout, gin.H{"success": false, "error": "agent did not respond in time"})
	}
}

// DownloadAgentPath streams a single file (op=read_file) or a folder archive
// (op=read_folder, tar.gz) from the agent to the HTTP response.
//
// GET /api/v1/agents/:id/fs/download?path=<abs-path>[&archive=tar.gz]
// When archive=tar.gz, the path is treated as a folder regardless of what
// Stat says on the agent; without it the agent auto-detects file vs dir.
func DownloadAgentPath(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	hub, ok := mustGetHub(c)
	if !ok {
		return
	}

	agentID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid agent id"})
		return
	}
	path := strings.TrimSpace(c.Query("path"))
	if path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "path required"})
		return
	}
	asArchive := c.Query("archive") == "tar.gz"

	var agent models.Agent
	if err := db.First(&agent, "id = ?", agentID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "agent not found"})
		return
	}
	if !hub.IsAgentOnline(agentID.String()) {
		c.JSON(http.StatusConflict, gin.H{"success": false, "error": "agent is offline"})
		return
	}

	// Decide which op to send. read_file if not archive; read_folder if archive.
	op := "read_file"
	if asArchive {
		op = "read_folder"
	}
	userID, _ := middleware.GetUserID(c)
	writeAudit(c, db, &userID, &agentID, "agent.fs.download", uuid.NewString(), "op="+op+" path="+path)

	base := filepath.Base(strings.TrimRight(strings.ReplaceAll(path, "\\", "/"), "/"))
	if base == "" || base == "." || base == "/" {
		base = "download"
	}
	var filename, contentType string
	if op == "read_folder" {
		filename = base + ".zip"
		contentType = "application/zip"
	} else {
		filename = base
		contentType = "application/octet-stream"
	}

	streamFsToResponse(c, hub, agentID.String(), appws.AgentCommand{
		Type:   "fs_request",
		FsOp:   op,
		FsPath: path,
	}, filename, contentType)
}

// CollectAgentPathToEvidence pulls a file from the agent and stores it in the
// central Evidence Store as the ORIGINAL, uncompressed bytes — rather than
// streaming it straight to the admin's browser. The admin can then download it
// (zipped) from the Evidence Store.
//
// POST /api/v1/agents/:id/fs/collect?path=<abs-path>
func CollectAgentPathToEvidence(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	store, ok := mustGetStorage(c)
	if !ok {
		return
	}
	hub, ok := mustGetHub(c)
	if !ok {
		return
	}

	agentID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid agent id"})
		return
	}
	path := strings.TrimSpace(c.Query("path"))
	if path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "path required"})
		return
	}

	var agent models.Agent
	if err := db.First(&agent, "id = ?", agentID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "agent not found"})
		return
	}
	if !hub.IsAgentOnline(agentID.String()) {
		c.JSON(http.StatusConflict, gin.H{"success": false, "error": "agent is offline"})
		return
	}

	base := filepath.Base(strings.TrimRight(strings.ReplaceAll(path, "\\", "/"), "/"))
	if base == "" || base == "." || base == "/" {
		base = "download"
	}
	host := agent.Hostname
	if host == "" {
		host = agent.Name
	}

	// Create the evidence record first so we have a stable id for the stored path.
	ev := models.CaseEvidence{
		CaseID: agent.CaseID, AgentID: &agentID, Host: host,
		Kind: "agent-file", Source: "files:" + path, FileName: base,
	}
	if v, ok := c.Get("userID"); ok {
		if uid, e := uuid.Parse(v.(string)); e == nil {
			ev.UploadedBy = uid
		}
	}
	if err := db.Create(&ev).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to create evidence record"})
		return
	}

	rel, streamErr := streamFsToStorage(hub, store, agentID.String(),
		evidenceBucket(agent.CaseID, &agentID), ev.ID.String(), base,
		appws.AgentCommand{Type: "fs_request", FsOp: "read_file", FsPath: path})
	if streamErr != nil {
		db.Delete(&ev)
		c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": "failed to collect file: " + streamErr.Error()})
		return
	}

	var size int64
	if fi, e := os.Stat(store.AbsPath(rel)); e == nil {
		size = fi.Size()
	}
	db.Model(&ev).Updates(map[string]interface{}{
		"stored_path": rel, "size": size, "sha256": sha256OfFile(store.AbsPath(rel)),
	})
	ev.StoredPath, ev.Size = rel, size

	userID, _ := middleware.GetUserID(c)
	writeAudit(c, db, &userID, &agentID, "agent.fs.collect", ev.ID.String(), "collected to evidence: "+path)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": ev})
}

// streamFsToStorage pulls an agent fs_request stream (base64 chunks) into an
// Evidence Store file, writing the ORIGINAL bytes with no compression. Returns
// the BasePath-relative stored path.
func streamFsToStorage(hub *appws.Hub, store *storage.LocalStorage, agentID, bucket, uniqueID, filename string, cmd appws.AgentCommand) (string, error) {
	sessionID := uuid.NewString()
	cmd.SessionID = sessionID

	pr, pw := io.Pipe()
	var (
		errMu  sync.Mutex
		errMsg string
	)
	setErr := func(m string) {
		errMu.Lock()
		if errMsg == "" {
			errMsg = m
		}
		errMu.Unlock()
	}

	hub.RegisterFsSession(&appws.FsSession{
		ID:      sessionID,
		AgentID: agentID,
		OnChunk: func(b64 string, size int64) {
			data, derr := base64.StdEncoding.DecodeString(b64)
			if derr != nil {
				setErr(derr.Error())
				_ = pw.CloseWithError(derr)
				return
			}
			if _, werr := pw.Write(data); werr != nil {
				_ = pw.CloseWithError(werr)
			}
		},
		OnDone:  func() { _ = pw.Close() },
		OnError: func(msg string) { setErr(msg); _ = pw.CloseWithError(errors.New(msg)) },
	})
	defer hub.UnregisterFsSession(sessionID)

	if err := hub.SendJobToAgent(agentID, cmd); err != nil {
		return "", err
	}

	// Guard against an agent that never replies.
	timer := time.AfterFunc(10*time.Minute, func() {
		setErr("timed out waiting for agent")
		_ = pw.CloseWithError(errors.New("timeout"))
	})
	defer timer.Stop()

	rel, saveErr := store.SaveCaseEvidence(bucket, uniqueID, filename, pr)
	errMu.Lock()
	em := errMsg
	errMu.Unlock()
	if em != "" {
		return "", errors.New(em)
	}
	if saveErr != nil {
		return "", saveErr
	}
	return rel, nil
}

// bundleReq is the request body for download-bundle: list of absolute paths
// which will be packed into a single tar.gz by the agent.
type bundleReq struct {
	Paths []string `json:"paths"`
}

// DownloadAgentBundle packs multiple files/folders selected by the admin into
// a single tar.gz stream. The agent preserves each entry under its basename
// at the root of the archive.
//
// POST /api/v1/agents/:id/fs/download-bundle
// Body: {"paths": ["/abs/1", "/abs/2", ...]}
func DownloadAgentBundle(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	hub, ok := mustGetHub(c)
	if !ok {
		return
	}

	agentID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid agent id"})
		return
	}

	var req bundleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid body"})
		return
	}
	if len(req.Paths) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "paths required"})
		return
	}

	var agent models.Agent
	if err := db.First(&agent, "id = ?", agentID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "agent not found"})
		return
	}
	if !hub.IsAgentOnline(agentID.String()) {
		c.JSON(http.StatusConflict, gin.H{"success": false, "error": "agent is offline"})
		return
	}

	userID, _ := middleware.GetUserID(c)
	detail, _ := json.Marshal(req.Paths)
	writeAudit(c, db, &userID, &agentID, "agent.fs.download", uuid.NewString(), "op=read_bundle paths="+string(detail))

	filename := "bundle-" + time.Now().UTC().Format("20060102-150405") + ".zip"

	streamFsToResponse(c, hub, agentID.String(), appws.AgentCommand{
		Type:    "fs_request",
		FsOp:    "read_bundle",
		FsPaths: req.Paths,
	}, filename, "application/zip")
}

// streamFsToResponse opens an fs session, dispatches cmd to the agent, and
// pipes every decoded base64 chunk directly to the HTTP response. Headers are
// flushed before the first byte so browsers start the download prompt.
//
// Errors arriving before the first chunk are returned as JSON. Once streaming
// has begun the HTTP status is already 200 — any subsequent agent error is
// written into the response body as a trailing text marker and the connection
// is closed so curl/browser sees a short read.
func streamFsToResponse(c *gin.Context, hub *appws.Hub, agentID string, cmd appws.AgentCommand, filename, contentType string) {
	sessionID := uuid.NewString()
	cmd.SessionID = sessionID

	// writer goroutine pumps base64 chunks into an io.Pipe which the HTTP
	// handler copies to c.Writer.
	pr, pw := io.Pipe()
	var (
		firstChunk = make(chan struct{}, 1)
		initErr    = make(chan string, 1)
		finishOnce sync.Once
		firstLog   sync.Once
	)
	signalFirst := func() {
		finishOnce.Do(func() { close(firstChunk) })
	}
	dispatchedAt := time.Now()

	hub.RegisterFsSession(&appws.FsSession{
		ID:      sessionID,
		AgentID: agentID,
		OnChunk: func(b64 string, size int64) {
			firstLog.Do(func() {
				log.Printf("[fs] <- agent=%s session=%s first chunk after %s", agentID, sessionID, time.Since(dispatchedAt))
				signalFirst()
			})
			data, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				_ = pw.CloseWithError(err)
				return
			}
			if _, err := pw.Write(data); err != nil {
				_ = pw.CloseWithError(err)
				return
			}
		},
		OnDone: func() {
			_ = pw.Close()
			signalFirst()
		},
		OnError: func(msg string) {
			_ = pw.CloseWithError(io.EOF)
			select {
			case initErr <- msg:
			default:
			}
			signalFirst()
		},
	})
	defer hub.UnregisterFsSession(sessionID)

	if err := hub.SendJobToAgent(agentID, cmd); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": err.Error()})
		return
	}
	log.Printf("[fs] -> agent=%s session=%s op=%s path=%s dispatched", agentID, sessionID, cmd.FsOp, cmd.FsPath)

	// Wait for either the first chunk or an early error before writing headers.
	select {
	case <-firstChunk:
	case <-time.After(fsReadTimeout):
		log.Printf("[fs] xx agent=%s session=%s timeout waiting for first chunk after %s", agentID, sessionID, fsReadTimeout)
		c.JSON(http.StatusGatewayTimeout, gin.H{"success": false, "error": "agent did not respond in time"})
		return
	case <-c.Request.Context().Done():
		return
	}

	// If we got an error before any bytes, surface as JSON.
	select {
	case msg := <-initErr:
		if msg != "" {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": msg})
			return
		}
	default:
	}

	c.Writer.Header().Set("Content-Type", contentType)
	c.Writer.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeFilename(filename)+`"`)
	c.Writer.Header().Set("Cache-Control", "no-store")
	c.Status(http.StatusOK)

	// Pump pipe → response. io.Copy returns when pw is closed (done) or the
	// client disconnects (c.Writer returns an error).
	if _, err := io.Copy(c.Writer, pr); err != nil {
		log.Printf("[fs] stream copy error (session %s): %v", sessionID, err)
	}
	// Surface a trailing error if one arrived mid-stream.
	select {
	case msg := <-initErr:
		if msg != "" {
			_, _ = c.Writer.WriteString("\n[fs error] " + msg + "\n")
		}
	default:
	}
}

// sanitizeFilename strips characters that would break the Content-Disposition
// header (quotes, CR/LF). Unicode is allowed — browsers handle UTF-8 OK.
func sanitizeFilename(s string) string {
	replacer := strings.NewReplacer(`"`, "_", "\r", "_", "\n", "_")
	return replacer.Replace(s)
}

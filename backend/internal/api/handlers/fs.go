package handlers

import (
	"encoding/base64"
	"errors"
	"io"
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

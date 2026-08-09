package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/logsearch"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/ws"
)

// The agent log-collection flow turns Log Ingest into a per-host repository:
//
//  1. An analyst clicks "Collect logs" on an online agent (CollectLogs).
//  2. The backend sends a `collect_os_logs` WS command to the agent.
//  3. The agent detects its OS and gathers the OS logs (Windows event channels
//     exported with wevtutil; Linux /var/log files), then uploads each file to
//     AgentIngest with X-Agent-Token.
//  4. AgentIngest runs each file through the normal logsearch pipeline, tagged
//     with the source host, so every host lands in its own hunt-* indices.
//
// The repository (Hosts / DeleteHost) lets an analyst review and drop a host's
// logs once the investigation is done.

// agentCollectDefaultCase is used when the operator triggers a collection
// without picking a case, so agent logs still land in a predictable bucket.
const agentCollectDefaultCase = "agent-collect"

// CollectLogs POST /api/v1/logsearch/agents/:agentId/collect
// Triggers OS-log collection on an online agent. Body (optional):
//
//	{ "case": "Incident-42", "days": 7 }
func (h *LogSearchHandler) CollectLogs(c *gin.Context) {
	if h.Hub == nil {
		c.JSON(http.StatusPreconditionFailed, gin.H{"error": "agent hub unavailable"})
		return
	}
	agentID := strings.TrimSpace(c.Param("agentId"))
	aid, err := uuid.Parse(agentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent id"})
		return
	}
	var agent models.Agent
	if err := h.DB.First(&agent, "id = ?", aid).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	if !h.Hub.IsAgentOnline(agentID) {
		c.JSON(http.StatusConflict, gin.H{"error": "agent is offline"})
		return
	}

	var body struct {
		Case string `json:"case"`
		Days int    `json:"days"`
	}
	_ = c.ShouldBindJSON(&body)
	caseName := strings.TrimSpace(body.Case)
	if caseName == "" {
		caseName = agentCollectDefaultCase
	}
	days := body.Days
	if days <= 0 || days > 365 {
		days = 7
	}

	// The agent reads these options from Args; JobID is the progress-stream key.
	args, _ := json.Marshal(map[string]interface{}{"case": caseName, "days": days})
	jobID := uuid.New().String()
	if err := h.Hub.SendJobToAgent(agentID, ws.AgentCommand{
		Type:  "collect_os_logs",
		JobID: jobID,
		Args:  string(args),
	}); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to dispatch: " + err.Error()})
		return
	}
	// Pulling a host's OS logs off it is a collection action — record who did it,
	// against which agent, and for which case.
	if uid, ok := middleware.GetUserID(c); ok {
		writeAudit(c, h.DB, &uid, &aid, "agent.logs.collect", jobID,
			fmt.Sprintf("case=%s days=%d host=%s", caseName, days, agent.Hostname))
	}

	c.JSON(http.StatusAccepted, gin.H{
		"ok":     true,
		"job_id": jobID,
		"case":   caseName,
		"host":   agent.Hostname,
		"days":   days,
	})
}

// AgentIngest POST /api/v1/logsearch/agent-ingest  (agent-authenticated, multipart)
// One log file collected by an agent. Form fields: file, host, os, channel,
// case, log_type, timezone.
func (h *LogSearchHandler) AgentIngest(c *gin.Context) {
	markELKActivity() // agent pushing logs keeps ELK alive
	agentID, _ := c.Get(middleware.ContextAgentID)
	var agent models.Agent
	if idStr, ok := agentID.(string); ok {
		h.DB.First(&agent, "id = ?", idStr)
	}

	fh, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file is required"})
		return
	}
	if fh.Size > maxLogUploadBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "file too large"})
		return
	}

	host := strings.TrimSpace(c.PostForm("host"))
	if host == "" {
		host = agent.Hostname
	}
	if host == "" {
		host = "unknown-host"
	}
	caseName := strings.TrimSpace(c.PostForm("case"))
	if caseName == "" {
		caseName = agentCollectDefaultCase
	}
	logType := strings.TrimSpace(c.PostForm("log_type"))
	if logType == "" || !validLogType(logType) {
		logType = logsearch.TypeAuto
	}

	meta := ingestMeta{
		Case:     caseName,
		Host:     host,
		Source:   "agent",
		LogType:  logType,
		Timezone: strings.TrimSpace(c.PostForm("timezone")),
	}
	job, ok := h.enqueueFromMultipart(fh, meta)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enqueue"})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"job_id": job.ID, "status": job.Status, "host": host})
}

// hostSummary aggregates one host's ingested logs for the repository view.
type hostSummary struct {
	Host         string     `json:"host"`
	Files        int        `json:"files"`
	DocsIndexed  int        `json:"docs_indexed"`
	Running      int        `json:"running"`
	Errors       int        `json:"errors"`
	Sources      []string   `json:"sources"` // upload|agent
	LastActivity *time.Time `json:"last_activity"`
}

// Hosts GET /api/v1/logsearch/hosts — ingested logs grouped by source host so
// the repository can present a per-host tree. Manual uploads (no host) are
// grouped under the "(uploads)" bucket.
func (h *LogSearchHandler) Hosts(c *gin.Context) {
	var jobs []models.LogIngestJob
	q := h.DB.Order("created_at desc").Limit(5000)
	if cs := strings.TrimSpace(c.Query("case")); cs != "" {
		q = q.Where("\"case\" = ?", cs)
	}
	if err := q.Find(&jobs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list"})
		return
	}

	byHost := map[string]*hostSummary{}
	srcSeen := map[string]map[string]bool{}
	order := []string{}
	for i := range jobs {
		j := jobs[i]
		key := j.Host
		if key == "" {
			key = "(uploads)"
		}
		s := byHost[key]
		if s == nil {
			s = &hostSummary{Host: key}
			byHost[key] = s
			srcSeen[key] = map[string]bool{}
			order = append(order, key)
		}
		s.Files++
		s.DocsIndexed += j.DocsIndexed
		switch j.Status {
		case "running", "queued":
			s.Running++
		case "error":
			s.Errors++
		}
		src := j.Source
		if src == "" {
			src = "upload"
		}
		if !srcSeen[key][src] {
			srcSeen[key][src] = true
			s.Sources = append(s.Sources, src)
		}
		if s.LastActivity == nil || j.CreatedAt.After(*s.LastActivity) {
			t := j.CreatedAt
			s.LastActivity = &t
		}
	}

	out := make([]hostSummary, 0, len(order))
	for _, k := range order {
		out = append(out, *byHost[k])
	}
	c.JSON(http.StatusOK, gin.H{"hosts": out})
}

// DeleteHost DELETE /api/v1/logsearch/hosts/:host — admin only. Drops every
// index and job row belonging to a source host (cleanup after an investigation).
func (h *LogSearchHandler) DeleteHost(c *gin.Context) {
	host := strings.TrimSpace(c.Param("host"))
	if host == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "host is required"})
		return
	}
	dbHost := host
	if host == "(uploads)" {
		dbHost = "" // the uploads bucket maps to the empty host
	}

	var jobs []models.LogIngestJob
	if err := h.DB.Where("host = ?", dbHost).Find(&jobs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query jobs"})
		return
	}

	indices := map[string]bool{}
	for _, j := range jobs {
		for _, idx := range strings.Split(j.Index, ",") {
			if idx = strings.TrimSpace(idx); idx != "" {
				indices[idx] = true
			}
		}
	}
	deleted := make([]string, 0, len(indices))
	var esErrs []string
	for idx := range indices {
		if err := h.ES.DeleteIndex(idx); err != nil {
			esErrs = append(esErrs, idx+": "+err.Error())
			continue
		}
		deleted = append(deleted, idx)
	}
	sort.Strings(deleted)

	// Remove the stored source files too, otherwise deleting a host frees its ES
	// indices but leaks the (often large) uploaded log files on disk.
	for _, j := range jobs {
		if j.StoredPath != "" {
			_ = h.Store.RemoveByRelPath(j.StoredPath)
		}
	}

	h.DB.Where("host = ?", dbHost).Delete(&models.LogIngestJob{})

	out := gin.H{"host": host, "deleted_indices": deleted, "removed_jobs": len(jobs)}
	if len(esErrs) > 0 {
		out["index_errors"] = esErrs
	}
	c.JSON(http.StatusOK, out)
}

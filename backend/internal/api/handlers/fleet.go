package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/ws"
)

// FleetHandler manages agent groups/tags, bulk collections, and schedules.
type FleetHandler struct {
	DB *gorm.DB
}

func NewFleetHandler(db *gorm.DB) *FleetHandler {
	return &FleetHandler{DB: db}
}

// edgeCollectionCommands maps a collection name to the agent EdgeForensics
// command. Only these collections may be dispatched in bulk / on a schedule.
var edgeCollectionCommands = map[string]string{
	"mft":       "edge_parse_mft",
	"prefetch":  "edge_parse_prefetch",
	"processes": "edge_parse_processes",
	"autoruns":  "edge_parse_autoruns",
	"netconn":   "edge_parse_netconn",
	"dlls":      "edge_parse_dlls",
	"shimcache": "edge_parse_shimcache",
	"registry":  "edge_parse_registry",
	"evtx":      "edge_parse_evtx",
}

// fleetCollectTimeout bounds how long a single dispatched collection waits for
// the agent to return before the result row is marked timeout.
const fleetCollectTimeout = 10 * time.Minute

// ── Tags / groups ───────────────────────────────────────────────────────────

// SetAgentTags sets an agent's group and tags.
// PATCH /api/v1/agents/:id/tags  { "group_name": "Finance", "tags": ["server","critical"] }
func (h *FleetHandler) SetAgentTags(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid agent id"})
		return
	}
	var body struct {
		GroupName *string   `json:"group_name"`
		Tags      *[]string `json:"tags"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	updates := map[string]interface{}{}
	if body.GroupName != nil {
		updates["group_name"] = strings.TrimSpace(*body.GroupName)
	}
	if body.Tags != nil {
		updates["tags"] = marshalTags(*body.Tags)
	}
	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "nothing to update"})
		return
	}
	if err := h.DB.Model(&models.Agent{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "update failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// ListAgentGroups returns the distinct groups and tags across the fleet with
// agent counts — drives the bulk-selection UI.
// GET /api/v1/agents/groups
func (h *FleetHandler) ListAgentGroups(c *gin.Context) {
	var agents []models.Agent
	h.DB.Find(&agents)

	groups := map[string]int{}
	tags := map[string]int{}
	for _, a := range agents {
		if g := strings.TrimSpace(a.GroupName); g != "" {
			groups[g]++
		}
		for _, t := range parseTags(a.Tags) {
			tags[t]++
		}
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"groups": countMapToList(groups),
		"tags":   countMapToList(tags),
	}})
}

// ── Bulk collection ───────────────────────────────────────────────────────────

// BulkCollect dispatches one collection to every ONLINE agent matched by the
// selector (explicit ids, a group, or a tag) and returns a per-agent dispatch
// status. Results are gathered asynchronously and readable via ListFleetResults.
//
// POST /api/v1/agents/bulk/collect
//
//	{ "collection": "processes", "agent_ids": [...], "group": "Finance", "tag": "critical" }
func (h *FleetHandler) BulkCollect(c *gin.Context) {
	hub, ok := mustGetHub(c)
	if !ok {
		return
	}
	var body struct {
		Collection string   `json:"collection" binding:"required"`
		AgentIDs   []string `json:"agent_ids"`
		Group      string   `json:"group"`
		Tag        string   `json:"tag"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	collection := strings.ToLower(strings.TrimSpace(body.Collection))
	if _, ok := edgeCollectionCommands[collection]; !ok {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "unsupported collection: " + collection})
		return
	}

	agents := selectFleetAgents(h.DB, body.AgentIDs, body.Group, body.Tag)
	if len(agents) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "selector matched no agents"})
		return
	}

	type dispatch struct {
		AgentID  string `json:"agent_id"`
		Name     string `json:"name"`
		Status   string `json:"status"` // dispatched | offline
		ResultID string `json:"result_id,omitempty"`
	}
	out := make([]dispatch, 0, len(agents))
	for i := range agents {
		resID, status := dispatchCollection(h.DB, hub, &agents[i], collection, nil)
		out = append(out, dispatch{
			AgentID:  agents[i].ID.String(),
			Name:     agents[i].Name,
			Status:   status,
			ResultID: resID,
		})
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"collection": collection,
		"dispatched": out,
	}})
}

// ListFleetResults returns recent collection results (without the bulky Data
// blob), newest first. Optional ?scheduled_id= / ?agent_id= filters.
// GET /api/v1/agents/fleet/results
func (h *FleetHandler) ListFleetResults(c *gin.Context) {
	q := h.DB.Model(&models.FleetCollectionResult{}).Order("started_at desc").Limit(200)
	if sid := c.Query("scheduled_id"); sid != "" {
		q = q.Where("scheduled_id = ?", sid)
	}
	if aid := c.Query("agent_id"); aid != "" {
		q = q.Where("agent_id = ?", aid)
	}
	var results []models.FleetCollectionResult
	q.Omit("data").Find(&results)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": results})
}

// GetFleetResult returns one result including its artifact Data.
// GET /api/v1/agents/fleet/results/:id
func (h *FleetHandler) GetFleetResult(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid result id"})
		return
	}
	var res models.FleetCollectionResult
	if err := h.DB.First(&res, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "result not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": res})
}

// ── Scheduled collections ─────────────────────────────────────────────────────

func (h *FleetHandler) ListSchedules(c *gin.Context) {
	var s []models.ScheduledCollection
	h.DB.Order("created_at desc").Find(&s)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": s})
}

func (h *FleetHandler) CreateSchedule(c *gin.Context) {
	var body struct {
		Name            string   `json:"name" binding:"required"`
		Collection      string   `json:"collection" binding:"required"`
		AgentIDs        []string `json:"agent_ids"`
		Group           string   `json:"group"`
		Tag             string   `json:"tag"`
		IntervalMinutes int      `json:"interval_minutes"`
		Enabled         *bool    `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	collection := strings.ToLower(strings.TrimSpace(body.Collection))
	if _, ok := edgeCollectionCommands[collection]; !ok {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "unsupported collection: " + collection})
		return
	}
	interval := body.IntervalMinutes
	if interval < 5 {
		interval = 1440 // guard against hammering the fleet; default daily
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}

	var userUUID uuid.UUID
	if v, ok := c.Get("userID"); ok {
		if uid, perr := uuid.Parse(v.(string)); perr == nil {
			userUUID = uid
		}
	}
	next := time.Now().Add(time.Duration(interval) * time.Minute)
	sc := models.ScheduledCollection{
		Name:            strings.TrimSpace(body.Name),
		Collection:      collection,
		AgentIDs:        marshalTags(body.AgentIDs),
		Group:           strings.TrimSpace(body.Group),
		Tag:             strings.TrimSpace(body.Tag),
		IntervalMinutes: interval,
		Enabled:         enabled,
		NextRun:         &next,
		CreatedBy:       userUUID,
	}
	if err := h.DB.Create(&sc).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "create failed"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"success": true, "data": sc})
}

func (h *FleetHandler) UpdateSchedule(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	var body struct {
		Name            *string `json:"name"`
		IntervalMinutes *int    `json:"interval_minutes"`
		Enabled         *bool   `json:"enabled"`
		Group           *string `json:"group"`
		Tag             *string `json:"tag"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	updates := map[string]interface{}{}
	if body.Name != nil {
		updates["name"] = strings.TrimSpace(*body.Name)
	}
	if body.IntervalMinutes != nil && *body.IntervalMinutes >= 5 {
		updates["interval_minutes"] = *body.IntervalMinutes
	}
	if body.Enabled != nil {
		updates["enabled"] = *body.Enabled
	}
	if body.Group != nil {
		updates["group"] = strings.TrimSpace(*body.Group)
	}
	if body.Tag != nil {
		updates["tag"] = strings.TrimSpace(*body.Tag)
	}
	if len(updates) > 0 {
		h.DB.Model(&models.ScheduledCollection{}).Where("id = ?", id).Updates(updates)
	}
	var sc models.ScheduledCollection
	h.DB.First(&sc, "id = ?", id)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": sc})
}

func (h *FleetHandler) DeleteSchedule(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	h.DB.Delete(&models.ScheduledCollection{}, "id = ?", id)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// ── Shared dispatch + selection logic (used by HTTP + scheduler) ───────────────

// dispatchCollection creates a result row and, if the agent is online, sends the
// collection command and spawns a detached collector goroutine. Returns the
// result row id and a dispatch status ("dispatched" | "offline").
func dispatchCollection(db *gorm.DB, hub *ws.Hub, agent *models.Agent, collection string, scheduledID *uuid.UUID) (string, string) {
	cmdType := edgeCollectionCommands[collection]
	res := models.FleetCollectionResult{
		ScheduledID: scheduledID,
		AgentID:     agent.ID,
		AgentName:   agent.Name,
		Collection:  collection,
		Status:      "pending",
		StartedAt:   time.Now().UTC(),
	}

	if !hub.IsAgentOnline(agent.ID.String()) {
		now := time.Now().UTC()
		res.Status = "offline"
		res.Error = "agent offline at dispatch time"
		res.FinishedAt = &now
		db.Create(&res)
		return res.ID.String(), "offline"
	}

	if err := db.Create(&res).Error; err != nil {
		return "", "offline"
	}

	reqID := uuid.New().String()
	go collectFromAgent(db, hub, res.ID, agent.ID.String(), cmdType, reqID)
	return res.ID.String(), "dispatched"
}

// collectFromAgent subscribes to the agent's job output, sends the command, and
// records the returned artifact JSON (or error/timeout) on the result row.
func collectFromAgent(db *gorm.DB, hub *ws.Hub, resultID uuid.UUID, agentID, cmdType, reqID string) {
	outCh := hub.SubscribeJobOutput(reqID)
	defer hub.UnsubscribeJobOutput(reqID, outCh)

	if err := hub.SendJobToAgent(agentID, ws.AgentCommand{Type: cmdType, JobID: reqID}); err != nil {
		finishResult(db, resultID, "error", "", "failed to send command: "+err.Error())
		return
	}

	timeout := time.NewTimer(fleetCollectTimeout)
	defer timeout.Stop()

	var finalData, agentErr string
	for {
		select {
		case line, ok := <-outCh:
			if !ok {
				finishResult(db, resultID, "error", finalData, "output channel closed")
				return
			}
			if line == "__DONE__" {
				if agentErr != "" {
					finishResult(db, resultID, "error", "", agentErr)
				} else if finalData != "" {
					finishResult(db, resultID, "done", finalData, "")
				} else {
					finishResult(db, resultID, "error", "", "no data returned")
				}
				return
			}
			if strings.HasPrefix(line, "[agent error]") {
				agentErr = strings.TrimPrefix(line, "[agent error] ")
			} else if json.Valid([]byte(line)) {
				finalData = line
			}
		case <-timeout.C:
			finishResult(db, resultID, "timeout", finalData, "collection timed out")
			return
		}
	}
}

func finishResult(db *gorm.DB, resultID uuid.UUID, status, data, errMsg string) {
	now := time.Now().UTC()
	db.Model(&models.FleetCollectionResult{}).Where("id = ?", resultID).Updates(map[string]interface{}{
		"status":      status,
		"data":        data,
		"error":       errMsg,
		"finished_at": now,
	})
}

// selectFleetAgents resolves a selector to a concrete agent list. An explicit id
// list takes precedence; otherwise group/tag filter the fleet. Tag matching is
// done in Go because tags are stored as a JSON array string.
func selectFleetAgents(db *gorm.DB, agentIDs []string, group, tag string) []models.Agent {
	var agents []models.Agent
	if len(agentIDs) > 0 {
		ids := make([]uuid.UUID, 0, len(agentIDs))
		for _, s := range agentIDs {
			if id, err := uuid.Parse(strings.TrimSpace(s)); err == nil {
				ids = append(ids, id)
			}
		}
		if len(ids) == 0 {
			return nil
		}
		db.Where("id IN ?", ids).Find(&agents)
		return agents
	}

	q := db.Model(&models.Agent{})
	if g := strings.TrimSpace(group); g != "" {
		q = q.Where("group_name = ?", g)
	}
	q.Find(&agents)

	if t := strings.TrimSpace(tag); t != "" {
		filtered := agents[:0]
		for _, a := range agents {
			for _, at := range parseTags(a.Tags) {
				if strings.EqualFold(at, t) {
					filtered = append(filtered, a)
					break
				}
			}
		}
		agents = filtered
	}
	return agents
}

// ── helpers ───────────────────────────────────────────────────────────────────

func marshalTags(tags []string) string {
	clean := make([]string, 0, len(tags))
	for _, t := range tags {
		if t = strings.TrimSpace(t); t != "" {
			clean = append(clean, t)
		}
	}
	b, _ := json.Marshal(clean)
	return string(b)
}

func parseTags(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var tags []string
	if err := json.Unmarshal([]byte(s), &tags); err != nil {
		return nil
	}
	return tags
}

type countItem struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func countMapToList(m map[string]int) []countItem {
	out := make([]countItem, 0, len(m))
	for k, v := range m {
		out = append(out, countItem{Name: k, Count: v})
	}
	return out
}

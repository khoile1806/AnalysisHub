package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/models"
)

// TimelineHandler serves a case's reconstructed attack timeline.
type TimelineHandler struct {
	DB *gorm.DB
}

func NewTimelineHandler(db *gorm.DB) *TimelineHandler {
	return &TimelineHandler{DB: db}
}

// ListTimeline returns all timeline events for a case, ordered chronologically
// by the real activity time (event_time), oldest first.
// GET /api/v1/cases/:id/timeline
func (h *TimelineHandler) ListTimeline(c *gin.Context) {
	caseID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case id"})
		return
	}
	var events []models.TimelineEvent
	h.DB.Where("case_id = ?", caseID).Order("event_time asc").Find(&events)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": events})
}

// CreateTimelineEvent adds a manual event to a case timeline.
// POST /api/v1/cases/:id/timeline
func (h *TimelineHandler) CreateTimelineEvent(c *gin.Context) {
	caseID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case id"})
		return
	}

	var input struct {
		EventTime   time.Time `json:"event_time" binding:"required"`
		Host        string    `json:"host"`
		Tactic      string    `json:"tactic"`
		Technique   string    `json:"technique"`
		Severity    string    `json:"severity"`
		Title       string    `json:"title" binding:"required"`
		Detail      string    `json:"detail"`
		Attachments string    `json:"attachments"` // JSON array
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	severity := input.Severity
	if !validSeverity(severity) {
		severity = "info"
	}

	var userUUID uuid.UUID
	if v, ok := c.Get("userID"); ok {
		if uid, perr := uuid.Parse(v.(string)); perr == nil {
			userUUID = uid
		}
	}

	ev := models.TimelineEvent{
		CaseID:      caseID,
		EventTime:   input.EventTime,
		Source:      "manual",
		Host:        input.Host,
		Tactic:      input.Tactic,
		Technique:   input.Technique,
		Severity:    severity,
		Title:       input.Title,
		Detail:      input.Detail,
		Attachments: input.Attachments,
		CreatedBy:   userUUID,
	}
	if err := h.DB.Create(&ev).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to create event"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"success": true, "data": ev})
}

// importArtifactsMax caps how many artifacts one import call may add.
const importArtifactsMax = 1000

// ImportArtifacts saves a batch of scan artifacts (e.g. Edge Forensics file
// findings or prefetch executions) onto a case timeline, optionally promoting
// each one to the IOC store. Lets an analyst pull live-response findings into an
// investigation in one click.
//
// POST /api/v1/cases/:id/import-artifacts
// {
//   "source": "edge-forensics:mft", "host": "WS-01",
//   "items": [ { "title": "...", "detail": "...", "event_time": "...",
//                "severity": "high", "value": "<hash>", "ioc_type": "File-Hash",
//                "promote_ioc": true } ]
// }
func (h *TimelineHandler) ImportArtifacts(c *gin.Context) {
	caseID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case id"})
		return
	}
	// Confirm the case exists so we don't orphan events.
	var caseObj models.Case
	if err := h.DB.First(&caseObj, "id = ?", caseID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "case not found"})
		return
	}

	var body struct {
		Source string `json:"source"`
		Host   string `json:"host"`
		Items  []struct {
			Title      string     `json:"title"`
			Detail     string     `json:"detail"`
			EventTime  *time.Time `json:"event_time"`
			Severity   string     `json:"severity"`
			Value      string     `json:"value"`
			IOCType    string     `json:"ioc_type"`
			PromoteIOC bool       `json:"promote_ioc"`
		} `json:"items"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	if len(body.Items) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "no items supplied"})
		return
	}
	if len(body.Items) > importArtifactsMax {
		body.Items = body.Items[:importArtifactsMax]
	}

	source := strings.TrimSpace(body.Source)
	if source == "" {
		source = "import"
	}

	var userUUID uuid.UUID
	if v, ok := c.Get("userID"); ok {
		if uid, perr := uuid.Parse(v.(string)); perr == nil {
			userUUID = uid
		}
	}

	events := 0
	iocs := 0
	for _, it := range body.Items {
		title := strings.TrimSpace(it.Title)
		if title == "" {
			continue
		}
		et := time.Now().UTC()
		if it.EventTime != nil && !it.EventTime.IsZero() {
			et = *it.EventTime
		}
		sev := it.Severity
		if !validSeverity(sev) {
			sev = "info"
		}
		ev := models.TimelineEvent{
			CaseID:    caseID,
			EventTime: et,
			Source:    source,
			Host:      strings.TrimSpace(body.Host),
			Severity:  sev,
			Title:     title,
			Detail:    it.Detail,
			CreatedBy: userUUID,
		}
		if err := h.DB.Create(&ev).Error; err != nil {
			continue
		}
		events++

		if it.PromoteIOC {
			val := strings.TrimSpace(it.Value)
			typ := strings.TrimSpace(it.IOCType)
			if val != "" && typ != "" {
				ioc := models.IOC{Value: val, Type: typ, Source: source, Description: title}
				res := h.DB.Where("value = ? AND type = ?", val, typ).FirstOrCreate(&ioc)
				if res.Error == nil && res.RowsAffected > 0 {
					iocs++
				}
			}
		}
	}

	writeAudit(c, h.DB, &userUUID, nil, "timeline.import", caseID.String(),
		fmt.Sprintf("source=%s events=%d iocs=%d", source, events, iocs))

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"events_created": events,
		"iocs_promoted":  iocs,
	}})
}

// UpdateTimelineEvent edits an event (fields + attachments).
// PATCH /api/v1/timeline/:id
func (h *TimelineHandler) UpdateTimelineEvent(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid event id"})
		return
	}
	var ev models.TimelineEvent
	if err := h.DB.First(&ev, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "event not found"})
		return
	}
	var input struct {
		Title       *string    `json:"title"`
		Detail      *string    `json:"detail"`
		Host        *string    `json:"host"`
		Severity    *string    `json:"severity"`
		Tactic      *string    `json:"tactic"`
		Technique   *string    `json:"technique"`
		EventTime   *time.Time `json:"event_time"`
		Attachments *string    `json:"attachments"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	updates := map[string]interface{}{}
	if input.Title != nil {
		updates["title"] = *input.Title
	}
	if input.Detail != nil {
		updates["detail"] = *input.Detail
	}
	if input.Host != nil {
		updates["host"] = *input.Host
	}
	if input.Severity != nil && validSeverity(*input.Severity) {
		updates["severity"] = *input.Severity
	}
	if input.Tactic != nil {
		updates["tactic"] = *input.Tactic
	}
	if input.Technique != nil {
		updates["technique"] = *input.Technique
	}
	if input.EventTime != nil {
		updates["event_time"] = *input.EventTime
	}
	if input.Attachments != nil {
		updates["attachments"] = *input.Attachments
	}
	if len(updates) > 0 {
		h.DB.Model(&ev).Updates(updates)
	}
	h.DB.First(&ev, "id = ?", id)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": ev})
}

// DeleteTimelineEvent removes a single timeline event.
// DELETE /api/v1/timeline/:id
func (h *TimelineHandler) DeleteTimelineEvent(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid event id"})
		return
	}
	h.DB.Delete(&models.TimelineEvent{}, "id = ?", id)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func validSeverity(s string) bool {
	switch s {
	case "critical", "high", "medium", "low", "info":
		return true
	}
	return false
}

// promoteELKMaxEvents caps how many hits become timeline events in one promote,
// so a 5000-hit hunt doesn't flood the timeline.
const promoteELKMaxEvents = 200

// PromoteELKResult turns an ELK hunt result's hits into timeline events. Each
// hit carries a real @timestamp (when the activity occurred), so this is the
// most reliable automated source for the attack timeline.
// POST /api/v1/elk/hunt/results/:id/promote-timeline   { "case_id": "..." }
func (h *TimelineHandler) PromoteELKResult(c *gin.Context) {
	resultID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid result id"})
		return
	}
	var body struct {
		CaseID string `json:"case_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "case_id is required"})
		return
	}
	caseUUID, err := uuid.Parse(body.CaseID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case_id"})
		return
	}

	var result models.ELKHuntResult
	if err := h.DB.First(&result, "id = ?", resultID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "ELK result not found"})
		return
	}

	var hits []map[string]interface{}
	if result.Results != "" {
		_ = json.Unmarshal([]byte(result.Results), &hits)
	}
	if len(hits) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "result has no hits to promote"})
		return
	}

	var userUUID uuid.UUID
	if v, ok := c.Get("userID"); ok {
		if uid, perr := uuid.Parse(v.(string)); perr == nil {
			userUUID = uid
		}
	}

	imported := 0
	for _, hit := range hits {
		if imported >= promoteELKMaxEvents {
			break
		}
		src := hitSource(hit)
		if src == nil {
			continue
		}
		ts := parseHitTime(src)
		if ts.IsZero() {
			continue // no real timestamp → not useful on an attack timeline
		}

		host := firstField(src, "host.name", "host.hostname", "agent.name", "winlog.computer_name")
		title := firstField(src,
			"rule.name", "event.action", "message", "event.original",
			"url.original", "process.command_line",
		)
		if title == "" {
			title = "ELK hit: " + result.Title
		}
		if len(title) > 160 {
			title = title[:160] + "…"
		}

		ref := ""
		if id, ok := hit["_id"].(string); ok {
			ref = id
		}

		ev := models.TimelineEvent{
			CaseID:    caseUUID,
			EventTime: ts,
			Source:    "elk",
			SourceRef: ref,
			Host:      host,
			Severity:  "high", // matched a known-bad IOC
			Title:     title,
			Detail:    hitDetail(src),
			CreatedBy: userUUID,
		}
		if err := h.DB.Create(&ev).Error; err != nil {
			continue
		}
		imported++
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"imported": imported}})
}

// hitSource returns the _source map from an ES hit.
func hitSource(hit map[string]interface{}) map[string]interface{} {
	if s, ok := hit["_source"].(map[string]interface{}); ok {
		return s
	}
	return nil
}

// parseHitTime extracts the activity time from common ES timestamp fields.
func parseHitTime(src map[string]interface{}) time.Time {
	for _, key := range []string{"@timestamp", "timestamp", "event.created", "event.start"} {
		v := nestedGet(src, key)
		switch t := v.(type) {
		case string:
			for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000Z", "2006-01-02 15:04:05"} {
				if parsed, err := time.Parse(layout, t); err == nil {
					return parsed
				}
			}
		case float64:
			// epoch millis or seconds
			if t > 1e12 {
				return time.UnixMilli(int64(t))
			}
			return time.Unix(int64(t), 0)
		}
	}
	return time.Time{}
}

// firstField returns the first non-empty string value among the given dotted keys.
func firstField(src map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if s, ok := nestedGet(src, k).(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// hitDetail builds a compact human-readable detail line from notable fields.
func hitDetail(src map[string]interface{}) string {
	var parts []string
	add := func(label, key string) {
		if s, ok := nestedGet(src, key).(string); ok && s != "" {
			parts = append(parts, label+"="+s)
		}
	}
	add("src.ip", "source.ip")
	add("dst.ip", "destination.ip")
	add("user", "user.name")
	add("process", "process.name")
	add("url", "url.original")
	add("file", "file.path")
	if len(parts) == 0 {
		// Fallback: short JSON of the source.
		if b, err := json.Marshal(src); err == nil {
			s := string(b)
			if len(s) > 400 {
				s = s[:400] + "…"
			}
			return s
		}
		return ""
	}
	return strings.Join(parts, "  ")
}

// nestedGet resolves a dotted path (e.g. "host.name") against a nested map,
// also tolerating flattened keys where the dotted string is the literal key.
func nestedGet(m map[string]interface{}, path string) interface{} {
	if v, ok := m[path]; ok { // flattened ECS key
		return v
	}
	parts := strings.Split(path, ".")
	var cur interface{} = m
	for _, p := range parts {
		asMap, ok := cur.(map[string]interface{})
		if !ok {
			return nil
		}
		cur, ok = asMap[p]
		if !ok {
			return nil
		}
	}
	return cur
}

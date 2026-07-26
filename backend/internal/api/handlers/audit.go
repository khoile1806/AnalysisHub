package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/analysishub/backend/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// auditRow is one activity entry enriched with the actor's identity and the
// target agent's hostname. The AuditLog table stores only UUIDs, so the read
// side joins users and agents to make the trail human-readable — the whole point
// of the tab is that a person, not a UUID, has to be answerable for an action.
type auditRow struct {
	ID        uint      `json:"id"`
	UserID    *string   `json:"user_id"`
	UserEmail string    `json:"user_email"`
	UserName  string    `json:"user_name"`
	UserRole  string    `json:"user_role"`
	AgentID   *string   `json:"agent_id"`
	AgentHost string    `json:"agent_host"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Detail    string    `json:"detail"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Forwarded string    `json:"forwarded"`
	CreatedAt time.Time `json:"created_at"`
}

// auditActor labels an unattributed action. A nil UserID is the platform itself
// (a worker, a scheduler, an agent-driven auto-collection), which must read as
// "system" rather than blank — a blank actor in an accountability log looks like
// data loss.
const auditSystemActor = "system / automated"

// ListAudit returns the user-activity trail, newest first, with filters for the
// questions the tab has to answer: who did what, to which agent, when.
//
// GET /api/v1/audit?user_id=&action=&action_prefix=&agent_id=&from=&to=&q=&limit=&offset=
func ListAudit(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}

	q := db.Table("audit_logs AS a").
		Select(`a.id, a.user_id, a.agent_id, a.action, a.resource, a.detail, a.ip,
			a.user_agent, a.forwarded, a.created_at,
			COALESCE(u.email, '') AS user_email, COALESCE(u.name, '') AS user_name,
			COALESCE(u.role, '') AS user_role, COALESCE(ag.hostname, '') AS agent_host`).
		Joins("LEFT JOIN users u ON u.id = a.user_id").
		Joins("LEFT JOIN agents ag ON ag.id = a.agent_id")

	q = applyAuditFilters(c, q)

	var total int64
	q.Count(&total)

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if offset < 0 {
		offset = 0
	}

	var rows []auditRow
	q.Order("a.id desc").Limit(limit).Offset(offset).Scan(&rows)
	for i := range rows {
		if rows[i].UserID == nil && rows[i].UserEmail == "" {
			rows[i].UserEmail = auditSystemActor
		}
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": rows, "total": total, "limit": limit, "offset": offset})
}

// applyAuditFilters narrows an audit query by the request's filters. Shared by
// the list and the export so both honour the same scope.
func applyAuditFilters(c *gin.Context, q *gorm.DB) *gorm.DB {
	if uid := strings.TrimSpace(c.Query("user_id")); uid != "" {
		q = q.Where("a.user_id = ?", uid)
	}
	if aid := strings.TrimSpace(c.Query("agent_id")); aid != "" {
		q = q.Where("a.agent_id = ?", aid)
	}
	if act := strings.TrimSpace(c.Query("action")); act != "" {
		q = q.Where("a.action = ?", act)
	}
	// action_prefix groups a family, e.g. "agent.fs" covers list/download/collect.
	if pfx := strings.TrimSpace(c.Query("action_prefix")); pfx != "" {
		q = q.Where("a.action LIKE ?", pfx+"%")
	}
	if from := parseAuditTime(c.Query("from")); !from.IsZero() {
		q = q.Where("a.created_at >= ?", from)
	}
	if to := parseAuditTime(c.Query("to")); !to.IsZero() {
		q = q.Where("a.created_at <= ?", to)
	}
	// Free-text over the human-facing columns so an analyst can search a path,
	// a filename, or an IP without knowing the action taxonomy.
	if term := strings.TrimSpace(c.Query("q")); term != "" {
		like := "%" + term + "%"
		q = q.Where("a.action ILIKE ? OR a.resource ILIKE ? OR a.detail ILIKE ? OR a.ip ILIKE ? OR u.email ILIKE ?",
			like, like, like, like, like)
	}
	return q
}

// parseAuditTime accepts an RFC3339 timestamp or a plain date.
func parseAuditTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// auditUserSummary rolls a user's activity up into the answer to "what has this
// person been doing" without paging through every row.
type auditUserSummary struct {
	UserID         *string    `json:"user_id"`
	UserEmail      string     `json:"user_email"`
	UserName       string     `json:"user_name"`
	UserRole       string     `json:"user_role"`
	TotalActions   int64      `json:"total_actions"`
	AgentsTouched  int64      `json:"agents_touched"`
	EvidencePulled int64      `json:"evidence_pulled"`   // agent.fs.collect
	EvidenceDown   int64      `json:"evidence_download"` // evidence.download
	JobsRun        int64      `json:"jobs_run"`
	Deletions      int64      `json:"deletions"`
	FirstSeen      *time.Time `json:"first_seen"`
	LastSeen       *time.Time `json:"last_seen"`
}

// AuditUserSummary returns a per-user rollup over an optional time window.
//
// GET /api/v1/audit/summary?from=&to=
func AuditUserSummary(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}

	// One grouped pass with conditional aggregates. FILTER-style counting via
	// CASE keeps it to a single query instead of one round-trip per metric.
	base := db.Table("audit_logs AS a").
		Joins("LEFT JOIN users u ON u.id = a.user_id").
		Select(`a.user_id,
			COALESCE(u.email, '') AS user_email, COALESCE(u.name, '') AS user_name,
			COALESCE(u.role, '') AS user_role,
			COUNT(*) AS total_actions,
			COUNT(DISTINCT a.agent_id) AS agents_touched,
			COUNT(*) FILTER (WHERE a.action = 'agent.fs.collect') AS evidence_pulled,
			COUNT(*) FILTER (WHERE a.action = 'evidence.download') AS evidence_down,
			COUNT(*) FILTER (WHERE a.action LIKE 'job.%') AS jobs_run,
			COUNT(*) FILTER (WHERE a.action LIKE '%delete%' OR a.action LIKE '%cleanup%') AS deletions,
			MIN(a.created_at) AS first_seen, MAX(a.created_at) AS last_seen`).
		Group("a.user_id, u.email, u.name, u.role")

	if from := parseAuditTime(c.Query("from")); !from.IsZero() {
		base = base.Where("a.created_at >= ?", from)
	}
	if to := parseAuditTime(c.Query("to")); !to.IsZero() {
		base = base.Where("a.created_at <= ?", to)
	}

	var rows []auditUserSummary
	base.Order("last_seen desc").Scan(&rows)
	for i := range rows {
		if rows[i].UserID == nil && rows[i].UserEmail == "" {
			rows[i].UserEmail = auditSystemActor
		}
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": rows})
}

// writeAuditThrottled records an action only if the same actor has not already
// logged the same (action, resource) within the window. View actions fire on
// every iframe/page render, so logging each one would bury the trail in
// duplicates without adding accountability value — one "user X viewed artifact Y"
// per session is the fact worth keeping.
func writeAuditThrottled(c *gin.Context, db *gorm.DB, userID *uuid.UUID, agentID *uuid.UUID,
	action, resource, detail string, window time.Duration) {
	var recent int64
	q := db.Model(&models.AuditLog{}).
		Where("action = ? AND resource = ? AND created_at >= ?", action, resource, time.Now().Add(-window))
	if userID != nil {
		q = q.Where("user_id = ?", *userID)
	}
	q.Count(&recent)
	if recent > 0 {
		return
	}
	writeAudit(c, db, userID, agentID, action, resource, detail)
}

// AuditActions returns the distinct action names present, so the UI filter can
// offer exactly what exists rather than a hard-coded list that drifts from the
// handlers over time.
//
// GET /api/v1/audit/actions
func AuditActions(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	var actions []string
	db.Model(&models.AuditLog{}).Distinct().Order("action").Pluck("action", &actions)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": actions})
}

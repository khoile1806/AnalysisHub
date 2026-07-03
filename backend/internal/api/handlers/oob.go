package handlers

import (
	"bytes"
	"crypto/subtle"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/config"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/netsafe"
	"github.com/analysishub/backend/internal/oob"
)

// oobWebhookBodyLimit caps how much request body the webhook receiver stores.
const oobWebhookBodyLimit = 64 * 1024

// oobCfg pulls the app config out of the Gin context.
func oobCfg(c *gin.Context) *config.Config {
	v, _ := c.Get("config")
	cfg, _ := v.(*config.Config)
	return cfg
}

// oobSrv pulls the running interaction server out of the Gin context (may be nil).
func oobSrv(c *gin.Context) *oob.Server {
	v, _ := c.Get("oobServer")
	s, _ := v.(*oob.Server)
	return s
}

// oobOwns reports whether the caller may access a session: its creator, or any
// admin. On a single-tier (sole-admin) deployment this is always true, so it's
// transparent today and only bites once non-admin users exist.
func oobOwns(c *gin.Context, client models.OobClient) bool {
	if middleware.GetRole(c) == "admin" {
		return true
	}
	uid, ok := middleware.GetUserID(c)
	return ok && client.CreatedBy == uid
}

// oobHub pulls the SSE hub out of the Gin context (may be nil).
func oobHub(c *gin.Context) *oob.Hub {
	v, _ := c.Get("oobHub")
	h, _ := v.(*oob.Hub)
	return h
}

// buildPayload assembles the payload artefacts for a correlation + unique id.
// webhookBase is the externally-reachable base URL of THIS backend (PUBLIC_URL
// or request-derived); the webhook URL works instantly with no DNS setup, while
// the host/http/https/dns/smtp variants need the delegated OOB_DOMAIN.
func buildPayload(cfg *config.Config, webhookBase, corr, uniq string) gin.H {
	out := gin.H{
		"unique_id": uniq,
		// Instant webhook receiver on the main backend — no domain/DNS required.
		"webhook": strings.TrimRight(webhookBase, "/") + "/oob/r/" + corr + uniq,
	}

	// Full OAST variants require the delegated zone — only meaningful when set.
	if cfg.OOBDomain != "" {
		host := oob.BuildHost(corr, uniq, cfg.OOBDomain)
		httpURL := "http://" + host
		if p := cfg.OOBHTTPPort; p != "" && p != "80" && p != "0" {
			httpURL += ":" + p
		}
		httpsURL := "https://" + host
		if p := cfg.OOBHTTPSPort; p != "" && p != "443" && p != "0" {
			httpsURL += ":" + p
		}
		out["host"] = host
		out["http"] = httpURL
		out["https"] = httpsURL
		out["dns"] = host
		out["smtp"] = "test@" + host
		// JNDI (Log4Shell) — correlation rides in the PATH so the LDAP/RMI
		// catcher can attribute the second-stage connection. Host is the zone
		// apex (resolves to the OOB server via the OAST DNS).
		label := corr + uniq
		if p := cfg.OOBLDAPPort; p != "" && p != "0" {
			out["jndi_ldap"] = "${jndi:ldap://" + cfg.OOBDomain + ":" + p + "/" + label + "}"
		}
		if p := cfg.OOBRMIPort; p != "" && p != "0" {
			out["jndi_rmi"] = "${jndi:rmi://" + cfg.OOBDomain + ":" + p + "/" + label + "}"
		}
	}
	return out
}

// GetOobConfig reports the interaction-server status + setup hints.
//
// GET /api/v1/osint/oob/config
func GetOobConfig(c *gin.Context) {
	cfg := oobCfg(c)
	if cfg == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "config unavailable"})
		return
	}
	srv := oobSrv(c)
	running := srv != nil && srv.Running()
	var listeners []string
	if srv != nil {
		listeners = srv.Listeners()
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"enabled":     cfg.OOBEnabled,
			"running":     running,
			"domain":      cfg.OOBDomain,
			"public_ip":   cfg.OOBPublicIP,
			"ns_name":     cfg.OOBNSName,
			"listeners":   listeners,
			"https_ready": cfg.OOBTLSCert != "" && cfg.OOBTLSKey != "",
			// configured but not usable until DNS for the zone is delegated here.
			"configured": cfg.OOBDomain != "" && cfg.OOBPublicIP != "",
			// Webhook mode runs on THIS backend with no extra setup — always on.
			"webhook_ready": true,
			"webhook_base":  strings.TrimRight(getServerURL(c), "/") + "/oob/r/",
		},
	})
}

type registerOobRequest struct {
	Name   string     `json:"name"`
	Note   string     `json:"note"`
	CaseID *uuid.UUID `json:"case_id"`
}

// RegisterOobClient creates a new interaction session and returns its
// correlation id, secret and a first sample payload.
//
// POST /api/v1/osint/oob/register
func RegisterOobClient(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	cfg := oobCfg(c)
	if cfg == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "config unavailable"})
		return
	}

	var req registerOobRequest
	_ = c.ShouldBindJSON(&req)

	userID, _ := middleware.GetUserID(c)
	client := models.OobClient{
		CorrelationID: oob.NewCorrelationID(),
		Secret:        oob.NewSecret(),
		Name:          strings.TrimSpace(req.Name),
		Note:          req.Note,
		CaseID:        req.CaseID,
		CreatedBy:     userID,
	}
	if client.Name == "" {
		client.Name = "oob-" + client.CorrelationID[:6]
	}
	if err := db.Create(&client).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to create client: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"client":  client,
			"payload": buildPayload(cfg, getServerURL(c), client.CorrelationID, oob.NewUniqueID()),
		},
	})
}

// ListOobClients returns all interaction sessions, newest first.
//
// GET /api/v1/osint/oob/clients
func ListOobClients(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	q := db.Order("created_at DESC")
	// Non-admins only see their own sessions; admins see all.
	if middleware.GetRole(c) != "admin" {
		if uid, ok := middleware.GetUserID(c); ok {
			q = q.Where("created_by = ?", uid)
		}
	}
	var clients []models.OobClient
	if err := q.Find(&clients).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	// Don't leak secrets in the list view.
	for i := range clients {
		clients[i].Secret = ""
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": clients})
}

// GetOobClient returns one session (including its secret, for the creator).
//
// GET /api/v1/osint/oob/clients/:id
func GetOobClient(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	var client models.OobClient
	if err := db.First(&client, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "client not found"})
		return
	}
	if !oobOwns(c, client) {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "client not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": client})
}

// DeleteOobClient removes a session and all its interactions.
//
// DELETE /api/v1/osint/oob/clients/:id
func DeleteOobClient(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	var client models.OobClient
	if err := db.First(&client, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "client not found"})
		return
	}
	if !oobOwns(c, client) {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "client not found"})
		return
	}
	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("client_id = ?", id).Delete(&models.OobInteraction{}).Error; err != nil {
			return err
		}
		return tx.Delete(&models.OobClient{}, "id = ?", id).Error
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// GenerateOobPayload returns a fresh unique payload for a session — no DB write,
// the correlation prefix is enough to attribute the eventual callback.
//
// POST /api/v1/osint/oob/clients/:id/payload
func GenerateOobPayload(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	cfg := oobCfg(c)
	if cfg == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "config unavailable"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	var client models.OobClient
	if err := db.First(&client, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "client not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": buildPayload(cfg, getServerURL(c), client.CorrelationID, oob.NewUniqueID())})
}

// ListOobInteractions returns a session's captured callbacks. With ?after=<RFC3339>
// it returns only newer ones — the polling primitive for live updates.
// ?q= does a full-text search across path, user_agent, remote_ip, raw_request.
// ?format=csv streams a CSV download.
//
// GET /api/v1/osint/oob/clients/:id/interactions?after=&limit=&q=&format=
func ListOobInteractions(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}

	q := db.Where("client_id = ?", id)
	if after := c.Query("after"); after != "" {
		if t, err := time.Parse(time.RFC3339Nano, after); err == nil {
			q = q.Where("created_at > ?", t)
		}
	}
	if proto := c.Query("protocol"); proto != "" {
		q = q.Where("protocol = ?", proto)
	}
	if method := c.Query("method"); method != "" {
		q = q.Where("method = ?", method)
	}
	if c.Query("starred") == "true" {
		q = q.Where("starred = TRUE")
	}
	// Full-text search across the most useful fields (case-insensitive; backed by
	// the pg_trgm GIN indexes created in database.Init).
	if search := strings.TrimSpace(c.Query("q")); search != "" {
		like := "%" + search + "%"
		q = q.Where("path ILIKE ? OR user_agent ILIKE ? OR remote_ip ILIKE ? OR raw_request ILIKE ? OR full_host ILIKE ?",
			like, like, like, like, like)
	}

	// CSV export — true streaming via row cursor (bounded memory, includes the
	// raw request). Done before the JSON path so it doesn't double-fetch.
	if c.Query("format") == "csv" {
		streamOobCSV(c, q.Order("created_at DESC").Limit(50000))
		return
	}

	limit := 200
	if l, err := strconv.Atoi(c.Query("limit")); err == nil && l > 0 && l <= 1000 {
		limit = l
	}

	var items []models.OobInteraction
	if err := q.Order("created_at DESC").Limit(limit).Find(&items).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": items, "server_time": time.Now().UTC().Format(time.RFC3339Nano)})
}

// UpdateOobClient renames a session / edits its note.
//
// PATCH /api/v1/osint/oob/clients/:id
func UpdateOobClient(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	var req struct {
		Name *string `json:"name"`
		Note *string `json:"note"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	updates := map[string]interface{}{}
	if req.Name != nil {
		if n := strings.TrimSpace(*req.Name); n != "" {
			updates["name"] = n
		}
	}
	if req.Note != nil {
		updates["note"] = *req.Note
	}
	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "no fields to update"})
		return
	}
	if err := db.Model(&models.OobClient{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// ClearOobInteractions deletes ALL captured interactions for a session.
//
// DELETE /api/v1/osint/oob/clients/:id/interactions
func ClearOobInteractions(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	if err := db.Where("client_id = ?", id).Delete(&models.OobInteraction{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	db.Model(&models.OobClient{}).Where("id = ?", id).Update("interaction_count", 0)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// DeleteOobInteraction removes a single captured interaction.
//
// DELETE /api/v1/osint/oob/clients/:id/interactions/:iid
func DeleteOobInteraction(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	cid, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	iid, err := uuid.Parse(c.Param("iid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid interaction id"})
		return
	}
	res := db.Where("id = ? AND client_id = ?", iid, cid).Delete(&models.OobInteraction{})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": res.Error.Error()})
		return
	}
	if res.RowsAffected > 0 {
		db.Model(&models.OobClient{}).Where("id = ?", cid).
			Update("interaction_count", gorm.Expr("GREATEST(interaction_count - 1, 0)"))
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// PatchOobInteraction sets triage state (seen / starred / note / tags) on one
// captured interaction.
//
// PATCH /api/v1/osint/oob/clients/:id/interactions/:iid
func PatchOobInteraction(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	cid, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	iid, err := uuid.Parse(c.Param("iid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid interaction id"})
		return
	}
	var req struct {
		Seen    *bool   `json:"seen"`
		Starred *bool   `json:"starred"`
		Note    *string `json:"note"`
		Tags    *string `json:"tags"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	updates := map[string]interface{}{}
	if req.Seen != nil {
		updates["seen"] = *req.Seen
	}
	if req.Starred != nil {
		updates["starred"] = *req.Starred
	}
	if req.Note != nil {
		updates["note"] = *req.Note
	}
	if req.Tags != nil {
		updates["tags"] = strings.TrimSpace(*req.Tags)
	}
	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "no fields to update"})
		return
	}
	if err := db.Model(&models.OobInteraction{}).Where("id = ? AND client_id = ?", iid, cid).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// MarkOobInteractionsSeen marks all of a session's interactions as seen.
//
// POST /api/v1/osint/oob/clients/:id/interactions/seen
func MarkOobInteractionsSeen(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	db.Model(&models.OobInteraction{}).Where("client_id = ? AND seen = FALSE", id).Update("seen", true)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// PromoteOobInteractionIOC adds an interaction's source IP to the IOC store —
// closing the loop from "a target reached out" to "hunt this IP everywhere".
//
// POST /api/v1/osint/oob/clients/:id/interactions/:iid/promote-ioc
func PromoteOobInteractionIOC(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	iid, err := uuid.Parse(c.Param("iid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid interaction id"})
		return
	}
	var in models.OobInteraction
	if err := db.First(&in, "id = ?", iid).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "interaction not found"})
		return
	}
	ip := net.ParseIP(in.RemoteIP)
	if ip == nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "interaction has no usable source IP"})
		return
	}
	iocType := "IPv4-Addr"
	if ip.To4() == nil {
		iocType = "IPv6-Addr"
	}
	desc := "OOB Catch callback (" + in.Protocol + ")"
	if in.RDNS != "" || in.ASN != "" {
		desc += " · " + strings.TrimSpace(in.RDNS+" "+in.ASN)
	}
	ioc := models.IOC{Value: in.RemoteIP, Type: iocType, Source: "OOB Catch", Description: desc, CreatedAt: time.Now()}
	// Idempotent: skip when (value,type) already present.
	if err := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&ioc).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"value": in.RemoteIP, "type": iocType}})
}

// streamOobCSV writes the query's rows to the response as CSV, flushing in
// batches so large exports never materialise fully in memory.
func streamOobCSV(c *gin.Context, q *gorm.DB) {
	rows, err := q.Model(&models.OobInteraction{}).Rows()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	defer rows.Close()

	c.Header("Content-Disposition", `attachment; filename="oob-interactions.csv"`)
	c.Header("Content-Type", "text/csv; charset=utf-8")
	cw := csv.NewWriter(c.Writer)
	_ = cw.Write([]string{"id", "protocol", "method", "query_type", "full_host", "path", "remote_ip", "user_agent", "smtp_from", "smtp_to", "raw_request", "created_at"})

	db, _ := mustGetDB(c)
	n := 0
	for rows.Next() {
		var it models.OobInteraction
		if db.ScanRows(rows, &it) != nil {
			continue
		}
		_ = cw.Write([]string{
			it.ID.String(), it.Protocol, it.Method, it.QueryType,
			it.FullHost, it.Path, it.RemoteIP, it.UserAgent,
			it.SMTPFrom, it.SMTPTo, it.RawRequest,
			it.CreatedAt.UTC().Format(time.RFC3339),
		})
		n++
		if n%500 == 0 {
			cw.Flush()
		}
	}
	cw.Flush()
}

// OobWebhookInbound is the PUBLIC, instant webhook receiver (no auth, no DNS, no
// extra ports). It runs on the main backend, so each session's URL
//
//	<server>/oob/r/<correlation_id>
//
// captures any HTTP method/path/body the target sends — the easy, webhook.site-
// style mode. The leading 20 chars of the token are the correlation id; any
// trailing characters are kept as the per-payload unique id for attribution.
//
// Routes: ANY /oob/r/:token  and  ANY /oob/r/:token/*path
func OobWebhookInbound(c *gin.Context) {
	// Permissive CORS so browser-driven callbacks (XSS/SSRF in a page) complete.
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	c.Header("Access-Control-Allow-Headers", "*")
	if c.Request.Method == http.MethodOptions {
		c.Status(http.StatusNoContent)
		return
	}

	db, ok := mustGetDB(c)
	if !ok {
		return
	}

	token := strings.TrimSpace(c.Param("token"))
	corr := token
	if len(corr) > oob.CorrelationLen {
		corr = corr[:oob.CorrelationLen]
	}
	uniq := ""
	if len(token) > oob.CorrelationLen {
		uniq = token[oob.CorrelationLen:]
	}

	var client models.OobClient
	if err := db.Where("correlation_id = ?", corr).First(&client).Error; err != nil {
		// Hide existence — always 404 for unknown tokens.
		c.Status(http.StatusNotFound)
		return
	}

	// CLI read mode — fetch captured callbacks from the terminal without the UI
	// or a JWT, gated by the session secret. Does not record a new interaction.
	//   curl "<webhook>?__read=1&secret=<secret>[&format=text&since=<RFC3339>&limit=N]"
	if c.Query("__read") != "" {
		serveOobRead(c, db, client)
		return
	}

	body, _ := io.ReadAll(io.LimitReader(c.Request.Body, oobWebhookBodyLimit))
	_ = c.Request.Body.Close()

	proto := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		proto = "https"
	}

	// Anti-abuse: rate-limit per token + source IP, and cap stored rows per
	// session. When throttled/capped we still serve the custom response below so
	// the caller can't tell recording stopped — we just skip persistence.
	maxPer := oobMaxPerClient(c)
	throttled := oobWebhookRateLimited(c, corr, c.ClientIP())
	capped := maxPer > 0 && client.InteractionCount >= maxPer

	if !throttled && !capped {
		in := models.OobInteraction{
			ClientID:      client.ID,
			CorrelationID: corr,
			UniqueID:      uniq,
			Protocol:      proto,
			FullHost:      c.Request.Host,
			Method:        c.Request.Method,
			Path:          c.Request.URL.RequestURI(),
			UserAgent:     c.GetHeader("User-Agent"),
			RemoteAddr:    c.Request.RemoteAddr,
			RemoteIP:      c.ClientIP(),
			RawRequest:    oobDumpHTTP(c, body),
			CreatedAt:     time.Now(),
		}
		if err := db.Create(&in).Error; err != nil {
			log.Printf("[oob] persist webhook hit: %v", err)
		} else {
			now := time.Now()
			if err := db.Model(&models.OobClient{}).Where("id = ?", client.ID).Updates(map[string]interface{}{
				"interaction_count": gorm.Expr("interaction_count + 1"),
				"last_seen_at":      now,
			}).Error; err != nil {
				log.Printf("[oob] counter update: %v", err)
			}
			// Enrich the source IP (geo/ASN/PTR) asynchronously.
			oob.EnrichInteraction(db, in.ID, in.RemoteIP)
			// Push to any active SSE subscribers (non-blocking).
			if hub := oobHub(c); hub != nil {
				hub.Publish(client.ID, in)
			}
			// Outbound notification (bounded worker pool, SSRF-safe) if configured.
			if client.NotifyURL != "" {
				enqueueOobNotify(client.NotifyURL, client.Name, in)
			}
		}
	}

	// Resolve the response: first matching rule (by ascending priority) wins,
	// otherwise the session-level default (OobClient.Resp*).
	status := client.RespStatus
	ct := client.RespContentType
	respBody := client.RespBody
	headersJSON := client.RespHeaders
	delayMs := client.RespDelayMs

	var rules []models.OobResponseRule
	if err := db.Where("client_id = ?", client.ID).Order("priority ASC, created_at ASC").Find(&rules).Error; err == nil {
		reqPath := c.Request.URL.RequestURI()
		for _, r := range rules {
			if r.MatchMethod != "" && !strings.EqualFold(r.MatchMethod, c.Request.Method) {
				continue
			}
			if r.MatchPathPrefix != "" && !strings.HasPrefix(reqPath, r.MatchPathPrefix) {
				continue
			}
			if r.MatchPathSub != "" && !strings.Contains(reqPath, r.MatchPathSub) {
				continue
			}
			status, ct, respBody, headersJSON, delayMs = r.Status, r.ContentType, r.Body, r.Headers, r.DelayMs
			break
		}
	}

	if delayMs > 0 {
		if delayMs > 30000 {
			delayMs = 30000
		}
		select {
		case <-time.After(time.Duration(delayMs) * time.Millisecond):
		case <-c.Request.Context().Done():
			return
		}
	}
	if status < 100 || status > 599 {
		status = http.StatusOK
	}
	if ct == "" {
		ct = "text/plain"
	}
	if headersJSON != "" {
		var hdrs map[string]string
		if json.Unmarshal([]byte(headersJSON), &hdrs) == nil {
			for k, v := range hdrs {
				if k != "" {
					c.Header(k, v)
				}
			}
		}
	}
	c.Header("Content-Type", ct)
	c.String(status, respBody)
}

// serveOobRead returns a session's captured interactions to a curl/CLI caller,
// authenticated by the session secret (query ?secret= or header X-OOB-Secret).
// ?format=text gives a terminal-friendly table; default is JSON.
func serveOobRead(c *gin.Context, db *gorm.DB, client models.OobClient) {
	ctx := c.Request.Context()
	rdb := getRedis(c)
	failKey := "oobread:fail:" + c.ClientIP()

	// Throttle brute-force of the secret: 20 failures / 15 min per source IP.
	if rdb != nil {
		if n, err := rdb.Get(ctx, failKey).Int(); err == nil && n >= 20 {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many attempts, try again later"})
			return
		}
	}

	secret := c.GetHeader("X-OOB-Secret") // prefer the header (kept out of logs)
	if secret == "" {
		secret = c.Query("secret")
	}
	if secret == "" || subtle.ConstantTimeCompare([]byte(secret), []byte(client.Secret)) != 1 {
		if rdb != nil {
			if n, err := rdb.Incr(ctx, failKey).Result(); err == nil && n == 1 {
				rdb.Expire(ctx, failKey, 15*time.Minute)
			}
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or missing secret"})
		return
	}
	if rdb != nil {
		rdb.Del(ctx, failKey) // reset on success
	}

	q := db.Where("client_id = ?", client.ID)
	if since := c.Query("since"); since != "" {
		if t, err := time.Parse(time.RFC3339Nano, since); err == nil {
			q = q.Where("created_at > ?", t)
		}
	}
	if proto := c.Query("protocol"); proto != "" {
		q = q.Where("protocol = ?", proto)
	}
	limit := 100
	if l, err := strconv.Atoi(c.Query("limit")); err == nil && l > 0 && l <= 1000 {
		limit = l
	}

	var items []models.OobInteraction
	if err := q.Order("created_at DESC").Limit(limit).Find(&items).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if c.Query("format") == "text" {
		var b strings.Builder
		fmt.Fprintf(&b, "# %d interaction(s) for %s\n", len(items), client.Name)
		for _, it := range items {
			fmt.Fprintf(&b, "%s  %-5s %-6s  %-15s  %s%s\n",
				it.CreatedAt.UTC().Format("2006-01-02 15:04:05"),
				it.Protocol, valueOr(it.Method, it.QueryType), it.RemoteIP, it.FullHost, it.Path)
		}
		c.String(http.StatusOK, b.String())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"count":        len(items),
		"server_time":  time.Now().UTC().Format(time.RFC3339Nano),
		"interactions": items,
	})
}

func valueOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// oobDumpHTTP renders a captured HTTP request as a readable raw dump.
func oobDumpHTTP(c *gin.Context, body []byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s\r\n", c.Request.Method, c.Request.URL.RequestURI(), c.Request.Proto)
	fmt.Fprintf(&b, "Host: %s\r\n", c.Request.Host)
	for k, vs := range c.Request.Header {
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	if len(body) > 0 {
		b.Write(body)
	}
	return b.String()
}

type updateOobResponseRequest struct {
	Status      *int               `json:"status"`
	ContentType *string            `json:"content_type"`
	Body        *string            `json:"body"`
	DelayMs     *int               `json:"delay_ms"`
	Headers     *map[string]string `json:"headers"`
}

// UpdateOobResponse sets a session's webhook custom response (status/body/
// content-type/delay), letting the operator shape what the target sees.
//
// PATCH /api/v1/osint/oob/clients/:id/response
func UpdateOobResponse(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	var req updateOobResponseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	updates := map[string]interface{}{}
	if req.Status != nil {
		if *req.Status < 100 || *req.Status > 599 {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "status must be 100-599"})
			return
		}
		updates["resp_status"] = *req.Status
	}
	if req.ContentType != nil {
		updates["resp_content_type"] = strings.TrimSpace(*req.ContentType)
	}
	if req.Body != nil {
		updates["resp_body"] = *req.Body
	}
	if req.DelayMs != nil {
		d := *req.DelayMs
		if d < 0 {
			d = 0
		}
		if d > 30000 {
			d = 30000
		}
		updates["resp_delay_ms"] = d
	}
	if req.Headers != nil {
		if len(*req.Headers) == 0 {
			updates["resp_headers"] = ""
		} else {
			b, _ := json.Marshal(*req.Headers)
			updates["resp_headers"] = string(b)
		}
	}
	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "no fields to update"})
		return
	}

	if err := db.Model(&models.OobClient{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	var client models.OobClient
	if err := db.First(&client, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "client not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": client})
}

// UpdateOobNotify sets or clears the outbound notification URL for a session.
// When set, a non-blocking HTTP POST is fired on every new interaction.
//
// PATCH /api/v1/osint/oob/clients/:id/notify
func UpdateOobNotify(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	var req struct {
		NotifyURL string `json:"notify_url"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	notifyURL := strings.TrimSpace(req.NotifyURL)
	// SSRF guard: a notification URL is fetched server-side, so reject anything
	// pointing at a private/internal/metadata address up front.
	if notifyURL != "" {
		if err := netsafe.ValidateURL(notifyURL); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "notify URL rejected: " + err.Error()})
			return
		}
	}
	if err := db.Model(&models.OobClient{}).Where("id = ?", id).Update("notify_url", notifyURL).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	var client models.OobClient
	if err := db.First(&client, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "client not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": client})
}

// StreamOobInteractions is a Server-Sent Events endpoint: it streams new
// interactions in real time as they arrive, replacing the 3 s polling loop.
//
// GET /api/v1/osint/oob/clients/:id/stream
func StreamOobInteractions(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	hub := oobHub(c)
	if hub == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "hub not available"})
		return
	}

	ch := hub.Subscribe(id)
	defer hub.Unsubscribe(id, ch)

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("X-Accel-Buffering", "no")

	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	ctx := c.Request.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fmt.Fprintf(c.Writer, ": ping\n\n")
			c.Writer.Flush()
		case in, ok := <-ch:
			if !ok {
				return
			}
			b, err := json.Marshal(in)
			if err != nil {
				continue
			}
			fmt.Fprintf(c.Writer, "event: interaction\ndata: %s\n\n", b)
			c.Writer.Flush()
		}
	}
}

// oobMaxPerClient returns the configured per-session interaction cap (0 = none).
func oobMaxPerClient(c *gin.Context) int {
	if cfg := oobCfg(c); cfg != nil {
		return cfg.OOBMaxPerClient
	}
	return 0
}

// oobWebhookRateLimited applies a per-token + per-source-IP minute bucket via
// Redis. Returns true when the caller should be throttled (recording skipped).
// Fails open when Redis is unavailable.
func oobWebhookRateLimited(c *gin.Context, corr, ip string) bool {
	rdb := getRedis(c)
	if rdb == nil {
		return false
	}
	perMin := 600
	if cfg := oobCfg(c); cfg != nil && cfg.OOBRateLimitPerMin > 0 {
		perMin = cfg.OOBRateLimitPerMin
	}
	ctx := c.Request.Context()

	tKey := "oobrl:t:" + corr
	if n, err := rdb.Incr(ctx, tKey).Result(); err == nil {
		if n == 1 {
			rdb.Expire(ctx, tKey, time.Minute)
		}
		if n > int64(perMin) {
			return true
		}
	}
	ipKey := "oobrl:ip:" + ip
	if n, err := rdb.Incr(ctx, ipKey).Result(); err == nil {
		if n == 1 {
			rdb.Expire(ctx, ipKey, time.Minute)
		}
		if n > int64(perMin*5) { // looser ceiling across all tokens from one IP
			return true
		}
	}
	return false
}

// StartOobRetentionWorker runs an hourly sweep deleting interactions older than
// retentionDays and trimming each session to at most maxPerClient rows. A no-op
// when both bounds are disabled.
func StartOobRetentionWorker(db *gorm.DB, retentionDays, maxPerClient int) {
	if retentionDays <= 0 && maxPerClient <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			oobRetentionSweep(db, retentionDays, maxPerClient)
			<-ticker.C
		}
	}()
}

func oobRetentionSweep(db *gorm.DB, retentionDays, maxPerClient int) {
	if retentionDays > 0 {
		cutoff := time.Now().AddDate(0, 0, -retentionDays)
		if err := db.Where("created_at < ?", cutoff).Delete(&models.OobInteraction{}).Error; err != nil {
			log.Printf("[oob] retention age-sweep: %v", err)
		}
	}
	if maxPerClient > 0 {
		// For each over-cap client, delete the oldest rows beyond the newest N.
		var ids []uuid.UUID
		db.Model(&models.OobClient{}).Where("interaction_count > ?", maxPerClient).Pluck("id", &ids)
		for _, id := range ids {
			sub := db.Model(&models.OobInteraction{}).Select("id").
				Where("client_id = ?", id).Order("created_at DESC").Limit(maxPerClient)
			if err := db.Where("client_id = ? AND id NOT IN (?)", id, sub).
				Delete(&models.OobInteraction{}).Error; err != nil {
				log.Printf("[oob] retention cap-trim: %v", err)
				continue
			}
			var n int64
			db.Model(&models.OobInteraction{}).Where("client_id = ?", id).Count(&n)
			db.Model(&models.OobClient{}).Where("id = ?", id).Update("interaction_count", n)
		}
	}
}

// ── bounded outbound-notification worker pool ──────────────────────────────
// Notifications run through a fixed pool with a buffered queue so a callback
// flood can't spawn unbounded goroutines / outbound connections (which would
// also turn the server into a request amplifier toward the notify endpoint).

type oobNotifyJob struct {
	url, session string
	in           models.OobInteraction
}

var (
	oobNotifyQueue chan oobNotifyJob
	oobNotifyOnce  sync.Once
)

// enqueueOobNotify hands a notification to the worker pool, dropping it (best
// effort) when the queue is saturated rather than blocking the request path.
func enqueueOobNotify(url, session string, in models.OobInteraction) {
	oobNotifyOnce.Do(func() {
		oobNotifyQueue = make(chan oobNotifyJob, 256)
		for i := 0; i < 8; i++ {
			go oobNotifyWorker()
		}
	})
	select {
	case oobNotifyQueue <- oobNotifyJob{url, session, in}:
	default:
		log.Printf("[oob] notify queue full — dropping notification for %s", session)
	}
}

func oobNotifyWorker() {
	for job := range oobNotifyQueue {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[oob] notify worker panic: %v", r)
				}
			}()
			sendOobNotify(job.url, job.session, job.in)
		}()
	}
}

// sendOobNotify fires a POST notification to notifyURL with interaction
// metadata. Supports Slack/Discord incoming webhooks and generic HTTP endpoints.
// Uses an SSRF-safe client; errors are logged but never propagated.
func sendOobNotify(notifyURL, sessionName string, in models.OobInteraction) {
	summary := fmt.Sprintf("[AnalysisHub OOB] %s — new %s interaction from %s",
		sessionName, strings.ToUpper(in.Protocol), in.RemoteIP)
	if in.Method != "" {
		summary += fmt.Sprintf(" · %s %s", in.Method, in.Path)
	} else if in.QueryType != "" {
		summary += fmt.Sprintf(" · DNS %s %s", in.QueryType, in.FullHost)
	}

	body := map[string]interface{}{
		"text":    summary,
		"session": sessionName,
		"interaction": map[string]interface{}{
			"protocol":   in.Protocol,
			"remote_ip":  in.RemoteIP,
			"full_host":  in.FullHost,
			"method":     in.Method,
			"path":       in.Path,
			"query_type": in.QueryType,
			"created_at": in.CreatedAt.UTC().Format(time.RFC3339),
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		return
	}
	client := netsafe.Client(8 * time.Second)
	resp, err := client.Post(notifyURL, "application/json", bytes.NewReader(b))
	if err != nil {
		log.Printf("[oob] notify POST to %s: %v", notifyURL, err)
		return
	}
	resp.Body.Close()
}

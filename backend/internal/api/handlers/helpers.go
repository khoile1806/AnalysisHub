package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/storage"
	"github.com/analysishub/backend/internal/ws"
)

// mustGetDB retrieves the *gorm.DB from the Gin context.
// It responds with 500 and returns false when not present.
func mustGetDB(c *gin.Context) (*gorm.DB, bool) {
	v, exists := c.Get("db")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "database not available"})
		return nil, false
	}
	db, ok := v.(*gorm.DB)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "database type assertion failed"})
		return nil, false
	}
	return db, true
}

// mustGetDBSilent retrieves the *gorm.DB without writing any response when it is
// absent — for optional, best-effort reads where the caller degrades gracefully.
func mustGetDBSilent(c *gin.Context) (*gorm.DB, bool) {
	v, exists := c.Get("db")
	if !exists {
		return nil, false
	}
	db, ok := v.(*gorm.DB)
	return db, ok
}

// mustGetStorage retrieves the *storage.LocalStorage from the Gin context.
func mustGetStorage(c *gin.Context) (*storage.LocalStorage, bool) {
	v, exists := c.Get("storage")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "storage not available"})
		return nil, false
	}
	s, ok := v.(*storage.LocalStorage)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "storage type assertion failed"})
		return nil, false
	}
	return s, true
}

// mustGetHub retrieves the *ws.Hub from the Gin context.
func mustGetHub(c *gin.Context) (*ws.Hub, bool) {
	v, exists := c.Get("hub")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "hub not available"})
		return nil, false
	}
	h, ok := v.(*ws.Hub)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "hub type assertion failed"})
		return nil, false
	}
	return h, true
}

// getRedis retrieves the *redis.Client from the Gin context. Unlike mustGetDB
// it never aborts the request — Redis is treated as an optional cache layer,
// so handlers receive nil when Redis is unavailable and fall back to the
// upstream source directly.
func getRedis(c *gin.Context) *redis.Client {
	v, exists := c.Get("redis")
	if !exists || v == nil {
		return nil
	}
	r, _ := v.(*redis.Client)
	return r
}

// getJWTSecret retrieves the JWT secret stored in the Gin context.
func getJWTSecret(c *gin.Context) string {
	v, _ := c.Get("jwtSecret")
	s, _ := v.(string)
	return s
}

// getServerURL retrieves the server base URL stored in the Gin context.
// When PUBLIC_URL is unset, we reconstruct the URL from the request, honoring
// X-Forwarded-Proto / X-Forwarded-Host so the derived URL matches what the
// client actually used — critical when nginx terminates TLS and the backend
// only sees plain HTTP (c.Request.TLS would otherwise always be nil).
func getServerURL(c *gin.Context) string {
	// 1. Explicit PUBLIC_URL from config takes absolute priority.
	v, _ := c.Get("serverURL")
	if s, _ := v.(string); s != "" {
		return s
	}
	return requestBaseURL(c)
}

// requestBaseURL reconstructs the scheme+host the request actually arrived on,
// honouring reverse-proxy headers. Unlike getServerURL it ignores PUBLIC_URL, so
// callers (e.g. the agent installer) can pin an agent to the exact URL the
// operator reached the server through — LAN IP or public domain.
func requestBaseURL(c *gin.Context) string {
	// 2. Determine scheme (http vs https).
	scheme := "http"

	// Check manual override from env (USE_HTTPS=true).
	if val, ok := c.Get("useHTTPS"); ok && val.(bool) {
		scheme = "https"
	} else {
		// Try to detect from reverse proxy headers.
		if c.GetHeader("X-Forwarded-Proto") == "https" ||
			c.GetHeader("X-Forwarded-Ssl") == "on" ||
			c.GetHeader("X-Url-Scheme") == "https" ||
			c.GetHeader("Front-End-Https") == "on" {
			scheme = "https"
		} else if strings.Contains(c.GetHeader("CF-Visitor"), "https") {
			// Cloudflare-specific header.
			scheme = "https"
		} else if c.Request.TLS != nil {
			// Direct TLS connection.
			scheme = "https"
		}
	}

	// 3. Determine host.
	host := c.GetHeader("X-Forwarded-Host")
	if host == "" {
		host = c.Request.Host
	}

	return scheme + "://" + host
}

// writeAudit persists an audit log entry. Errors are logged but do not abort
// the request to keep audit logging non-blocking.
func writeAudit(c *gin.Context, db *gorm.DB, userID *uuid.UUID, agentID *uuid.UUID, action, resource, detail string) {
	fwd := strings.TrimSpace(c.GetHeader("X-Forwarded-For"))
	entry := models.AuditLog{
		UserID:    userID,
		AgentID:   agentID,
		Action:    action,
		Resource:  resource,
		Detail:    detail,
		IP:        clientRealIP(c),
		UserAgent: c.Request.UserAgent(),
		Forwarded: fwd,
		CreatedAt: time.Now(),
	}
	if err := db.Create(&entry).Error; err != nil {
		// Non-fatal — just log.
		_ = err
	}
}

// clientRealIP resolves the operator's address, preferring the headers a reverse
// proxy sets over the direct peer. In a Docker deployment the direct peer is the
// bridge gateway (e.g. 172.20.0.1) for every browser request, so without this the
// audit log would attribute every action to the same gateway address. When no
// proxy is in front, these headers are absent and it falls back to gin's
// ClientIP (the real peer).
func clientRealIP(c *gin.Context) string {
	if xr := strings.TrimSpace(c.GetHeader("X-Real-IP")); xr != "" {
		return xr
	}
	if xff := strings.TrimSpace(c.GetHeader("X-Forwarded-For")); xff != "" {
		// The left-most entry is the original client; the rest are proxies.
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return xff
	}
	return c.ClientIP()
}

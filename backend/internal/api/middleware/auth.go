package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/models"
)

const (
	ContextUserID         = "userID"
	ContextRole           = "role"
	ContextAgentID        = "agentID"
	ContextCatchSessionID = "catchSessionID"
)

// Claims extends jwt.RegisteredClaims with application-specific fields.
// CatchSessionID, when non-empty, marks the token as a scoped catch-session
// unlock token issued by POST /catch/sessions/:id/unlock. AuthMiddleware
// rejects such tokens to prevent privilege escalation onto the regular API.
type Claims struct {
	UserID         string `json:"user_id,omitempty"`
	Role           string `json:"role,omitempty"`
	CatchSessionID string `json:"catch_session_id,omitempty"`
	jwt.RegisteredClaims
}

// AuthMiddleware validates a JWT Bearer token in the Authorization header.
// For SSE endpoints that cannot set custom headers, it also accepts the token
// via the ?token= query parameter.
// On success it stores userID and role in the Gin context.
func AuthMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var tokenStr string

		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "invalid authorization header format"})
				return
			}
			tokenStr = parts[1]
		} else if q := c.Query("token"); q != "" {
			// Fallback for EventSource / SSE clients that cannot set headers.
			tokenStr = q
		} else {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "authorization header required"})
			return
		}

		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(jwtSecret), nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "invalid or expired token"})
			return
		}

		// Reject scoped catch-session unlock tokens — they are not authorised
		// for the regular API surface.
		if claims.CatchSessionID != "" || claims.UserID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "invalid token scope"})
			return
		}

		c.Set(ContextUserID, claims.UserID)
		c.Set(ContextRole, claims.Role)
		c.Next()
	}
}

// CatchSessionAuthMiddleware validates a scoped JWT issued by
// POST /catch/sessions/:id/unlock. The token must carry catch_session_id
// equal to the :id path parameter. Accepts the token via header
// X-Catch-Session-Token or, for EventSource compatibility, ?session_token=.
func CatchSessionAuthMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := c.GetHeader("X-Catch-Session-Token")
		if tokenStr == "" {
			tokenStr = c.Query("session_token")
		}
		if tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "session token required"})
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(jwtSecret), nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "invalid or expired session token"})
			return
		}

		if claims.CatchSessionID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "invalid token scope"})
			return
		}

		// Token must match the path's session ID.
		pathID := c.Param("id")
		if pathID == "" || claims.CatchSessionID != pathID {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "session token does not match this session"})
			return
		}

		c.Set(ContextCatchSessionID, claims.CatchSessionID)
		c.Next()
	}
}

// GetCatchSessionID retrieves the unlocked catch session ID from the Gin context.
func GetCatchSessionID(c *gin.Context) string {
	v, _ := c.Get(ContextCatchSessionID)
	s, _ := v.(string)
	return s
}

// AgentAuthMiddleware validates the X-Agent-Token header against the agents table.
// On success it stores agentID in the Gin context.
func AgentAuthMiddleware(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("X-Agent-Token")
		if token == "" {
			// Also accept token as query param for WebSocket upgrades.
			token = c.Query("token")
		}
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "agent token required"})
			return
		}

		var agent models.Agent
		if err := db.Where("token = ?", token).First(&agent).Error; err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "invalid agent token"})
			return
		}

		c.Set(ContextAgentID, agent.ID.String())
		c.Next()
	}
}

// GetUserID retrieves the authenticated user's UUID from the Gin context.
// Returns uuid.Nil and false when not present.
func GetUserID(c *gin.Context) (uuid.UUID, bool) {
	v, exists := c.Get(ContextUserID)
	if !exists {
		return uuid.Nil, false
	}
	str, ok := v.(string)
	if !ok {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(str)
	if err != nil {
		return uuid.Nil, false
	}
	return id, true
}

// GetRole retrieves the authenticated user's role from the Gin context.
func GetRole(c *gin.Context) string {
	v, _ := c.Get(ContextRole)
	s, _ := v.(string)
	return s
}

// GetAgentID retrieves the authenticated agent's UUID string from the Gin context.
func GetAgentID(c *gin.Context) string {
	v, _ := c.Get(ContextAgentID)
	s, _ := v.(string)
	return s
}

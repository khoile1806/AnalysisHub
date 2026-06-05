package middleware

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var auditLogger *log.Logger

func initAuditLogger() {
	if auditLogger != nil {
		return
	}
	logPath := filepath.Join("data", "logs")
	os.MkdirAll(logPath, 0755)

	file, err := os.OpenFile(filepath.Join(logPath, "audit.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Printf("[Audit] Failed to open audit.log: %v", err)
		return
	}
	auditLogger = log.New(file, "", 0)
}

// AuditMiddleware logs API access and execution details.
func AuditMiddleware() gin.HandlerFunc {
	initAuditLogger()

	return func(c *gin.Context) {
		start := time.Now()

		var bodyStr string
		// Capture request body for mutating methods
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "DELETE" {
			// Skip body logging for file uploads or specific endpoints
			if !(c.Request.Method == "POST" && strings.Contains(c.Request.URL.Path, "/tools")) {
				if c.Request.Body != nil {
					bodyBytes, _ := io.ReadAll(c.Request.Body)
					// Restore body so next handlers can read it
					c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

					if len(bodyBytes) > 2000 {
						bodyStr = string(bodyBytes[:2000]) + "...(truncated)"
					} else {
						bodyStr = string(bodyBytes)
					}
					// Remove newlines for a single-line log format
					bodyStr = strings.ReplaceAll(bodyStr, "\n", " ")
				}
			} else {
				bodyStr = "[File Upload / Ignored Body]"
			}
		}

		c.Next()

		if auditLogger != nil {
			userEmail := "Anonymous"
			if email, exists := c.Get("userEmail"); exists {
				userEmail = email.(string)
			} else if agentID, exists := c.Get(ContextAgentID); exists {
				userEmail = "Agent-" + agentID.(string)
			}

			timeStr := start.Format("2006-01-02 15:04:05")
			status := c.Writer.Status()
			latency := time.Since(start)
			ip := c.ClientIP()

			// Format: [2026-06-05 13:00:00] user@email.com | 192.168.1.1 | POST /api/v1/jobs | 200 OK | 50ms | Payload: {...}
			logLine := timeStr + " | " + userEmail + " | " + ip + " | " + c.Request.Method + " " + c.Request.URL.Path + " | " + http.StatusText(status) + " | " + latency.String()
			if bodyStr != "" {
				logLine += " | Payload: " + bodyStr
			}

			auditLogger.Println(logLine)
		}
	}
}

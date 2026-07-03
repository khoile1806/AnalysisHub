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

// auditBodyLogLimit bounds how much of a request body the audit log reads. Only
// the first ~2 KB is ever logged, so this is all we need to buffer; the rest of
// the body streams straight through to the handler untouched.
const auditBodyLogLimit = 4 << 10 // 4 KB

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
					// Only read the small prefix we actually log — never buffer the
					// whole (possibly multi-GB) body into RAM. Replay the prefix in
					// front of the untouched remainder so downstream handlers still
					// receive the COMPLETE body.
					bodyBytes, _ := io.ReadAll(io.LimitReader(c.Request.Body, auditBodyLogLimit))
					c.Request.Body = io.NopCloser(io.MultiReader(bytes.NewReader(bodyBytes), c.Request.Body))

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

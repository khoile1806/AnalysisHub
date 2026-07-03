package handlers

import (
	"context"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/analysishub/backend/internal/hunting/sigma"
	"github.com/gin-gonic/gin"
)

const sigmaRulesDir = "tools/sigma-rules"

// SigmaScan receives an array of JSON events and evaluates them against all Sigma rules.
func SigmaScan(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}
	defer c.Request.Body.Close()

	if len(body) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "empty body"})
		return
	}

	alerts, err := sigma.DefaultEngine.ScanContext(c.Request.Context(), string(body))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to scan: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"alerts":      alerts,
		"rules_count": sigma.DefaultEngine.RuleCount(),
	})
}

// SigmaSync downloads the latest community ruleset (SigmaHQ by default, or the
// SIGMA_RULES_URL env override) into the rules directory and reloads the engine.
func SigmaSync(c *gin.Context) {
	url := os.Getenv("SIGMA_RULES_URL")

	// The download can take a while; cap it independently of the request.
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Minute)
	defer cancel()

	res, err := sigma.SyncFromZipURL(ctx, url, sigmaRulesDir)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "sigma sync failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": res})
}

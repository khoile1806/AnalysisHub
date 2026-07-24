package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/analysishub/backend/internal/hunting/sigma"
	"github.com/gin-gonic/gin"
)

const sigmaRulesDir = "tools/sigma-rules"

// sigmaScanMaxBody caps the JSON event payload a single scan may submit. The body
// is read fully, string-copied, and matched against every rule (O(events × rules)),
// so an unbounded body could exhaust memory/CPU. 64 MB is far above any realistic
// batch of events posted to a live hunt.
const sigmaScanMaxBody = 64 << 20

// SigmaScan receives an array of JSON events and evaluates them against all Sigma rules.
func SigmaScan(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, sigmaScanMaxBody)
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large or unreadable"})
		return
	}
	defer c.Request.Body.Close()

	if len(body) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "empty body"})
		return
	}

	// Decode once and hand the engine the events directly. Passing string(body)
	// copied the whole payload a second time before the engine unmarshalled it,
	// which at the 64 MB cap is 128 MB of peak allocation for nothing.
	events, err := decodeSigmaEvents(body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	alerts, err := sigma.DefaultEngine.ScanEvents(c.Request.Context(), events)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to scan: " + err.Error()})
		return
	}

	// rules_count is the number of rules that can actually fire. load_stats also
	// reports the ones that parsed but had to be skipped (aggregation
	// conditions, dangling selection references) so the count is not mistaken
	// for full coverage of the ruleset on disk.
	c.JSON(http.StatusOK, gin.H{
		"alerts":      alerts,
		"rules_count": sigma.DefaultEngine.RuleCount(),
		"load_stats":  sigma.DefaultEngine.Stats(),
	})
}

// decodeSigmaEvents accepts either a JSON array of events or a single event
// object, matching what the engine used to do internally.
func decodeSigmaEvents(body []byte) ([]map[string]interface{}, error) {
	var events []map[string]interface{}
	if err := json.Unmarshal(body, &events); err == nil {
		return events, nil
	}
	var single map[string]interface{}
	if err := json.Unmarshal(body, &single); err != nil {
		return nil, errors.New("invalid json event data")
	}
	return []map[string]interface{}{single}, nil
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

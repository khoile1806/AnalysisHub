package handlers

import (
	"io"
	"net/http"

	"github.com/forensichub/backend/internal/hunting/sigma"
	"github.com/gin-gonic/gin"
)

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

	alerts, err := sigma.DefaultEngine.Scan(string(body))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to scan: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"alerts": alerts,
	})
}

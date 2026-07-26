package handlers

import (
	"net/http"

	"github.com/analysishub/backend/internal/forge"
	"github.com/gin-gonic/gin"
)

// ListForgeOperations returns the transform palette: every available operation,
// its category, description and argument spec, so the UI can build the recipe
// builder without hard-coding the list.
//
// GET /api/v1/tools/transform/operations
func ListForgeOperations(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"success": true, "data": forge.Operations()})
}

// RunForgeRecipe applies an ordered recipe of operations to an input and returns
// the per-step trace plus the final output. Pure compute, no DB — the CyberChef-
// style decode/encode/crypto workbench.
//
// POST /api/v1/tools/transform
// Body: { "input": "...", "recipe": [ { "op": "From Base64", "args": {...} }, ... ] }
func RunForgeRecipe(c *gin.Context) {
	var req struct {
		Input  string             `json:"input"`
		Recipe []forge.RecipeStep `json:"recipe"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	res, err := forge.Run(req.Input, req.Recipe)
	if err != nil {
		// A step failure is a normal user outcome (wrong key, bad input), so the
		// partial trace is still returned alongside the error for diagnosis.
		c.JSON(http.StatusOK, gin.H{"success": false, "error": err.Error(), "data": res})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": res})
}

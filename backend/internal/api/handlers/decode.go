package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/analysishub/backend/internal/decode"
)

type smartDecodeRequest struct {
	Input string `json:"input"`
}

// SmartDecode auto-detects and recursively decodes common encodings (URL,
// Base64/Base32, Hex, HTML entities, Unicode escapes, gzip/zlib, JWT), returning
// the full layer chain — used by the OOB "Catch" request inspector to unwrap
// multiply-encoded callback data.
//
// POST /api/v1/osint/oob/decode
func SmartDecode(c *gin.Context) {
	var req smartDecodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	if len(req.Input) > 256*1024 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "input too large (max 256KB)"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": decode.Analyze(req.Input)})
}

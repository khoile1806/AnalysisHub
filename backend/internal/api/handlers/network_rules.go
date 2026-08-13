package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/models"
)

// network_rules.go — operator-managed Suricata rulesets and the retro-hunt that
// replays them over captures already stored. The network twin of malware_rules.go.
//
// The reason this exists: intel lands after the traffic. A capture analysed in
// August with August's rules is never revisited when September's signature for
// the same campaign is published, and nobody remembers which captures to re-run.

// maxSuricataRulesetBytes bounds one uploaded ruleset. ET-Open in full is ~30 MB
// and belongs in the sidecar's rule directory, not in an operator note; what goes
// here is the handful of rules a team writes or receives from a partner.
const maxSuricataRulesetBytes = 2 << 20

// ListSuricataRules returns the managed rulesets (without their bodies).
//
// GET /api/v1/network/rules
func (h *NetworkHandler) ListSuricataRules(c *gin.Context) {
	var rules []models.NetworkSuricataRule
	h.DB.Order("created_at desc").Find(&rules)
	type row struct {
		models.NetworkSuricataRule
		SIDList []string `json:"sid_list"`
		MsgList []string `json:"msg_list"`
		Size    int      `json:"size"`
	}
	out := make([]row, 0, len(rules))
	for _, r := range rules {
		var sids, msgs []string
		_ = json.Unmarshal([]byte(r.SIDs), &sids)
		_ = json.Unmarshal([]byte(r.Msgs), &msgs)
		body := r.Content
		r.Content = ""
		out = append(out, row{NetworkSuricataRule: r, SIDList: sids, MsgList: msgs, Size: len(body)})
	}
	var captures int64
	h.DB.Model(&models.NetworkScan{}).Where("stored_path <> '' AND status = ?", "done").Count(&captures)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"rulesets":         out,
		"replayable":       captures, // captures whose bytes are still on disk
		"analyzer_enabled": h.engine.Available(),
	}})
}

// GetSuricataRule returns one ruleset with its source (the editor view).
//
// GET /api/v1/network/rules/:rid
func (h *NetworkHandler) GetSuricataRule(c *gin.Context) {
	var rule models.NetworkSuricataRule
	if h.DB.First(&rule, "id = ?", c.Param("rid")).Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": rule})
}

// CreateSuricataRule validates a ruleset with Suricata, stores it, and hunts it
// over the stored captures.
//
// POST /api/v1/network/rules  (multipart: file | JSON: {name, content})
func (h *NetworkHandler) CreateSuricataRule(c *gin.Context) {
	if middleware.GetRole(c) != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "admin role required"})
		return
	}
	name, content, source, ok := readRulesetBody(c, maxSuricataRulesetBytes, ".rules")
	if !ok {
		return
	}

	// Validate BEFORE storing. Suricata drops a rule it cannot parse and keeps
	// going, so an unvalidated typo produces hunts that quietly find nothing.
	res, err := h.engine.ValidateRuleset(c.Request.Context(), content)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	if !res.OK {
		c.JSON(http.StatusBadRequest, gin.H{"success": false,
			"error": "Suricata rejected the ruleset: " + res.Error})
		return
	}
	if len(res.SIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false,
			"error": "the ruleset declares no sid — Suricata will not load it"})
		return
	}
	if name == "" {
		if msgs := res.Msgs; len(msgs) > 0 {
			name = msgs[0]
		} else {
			name = "sid " + res.SIDs[0]
		}
	}

	var userID uuid.UUID
	if uid, okUser := middleware.GetUserID(c); okUser {
		userID = uid
	}
	sidsJSON, _ := json.Marshal(res.SIDs)
	msgsJSON, _ := json.Marshal(res.Msgs)
	rule := models.NetworkSuricataRule{
		Name: name, Content: content, Enabled: true, SIDs: string(sidsJSON), Msgs: string(msgsJSON),
		Validated: true, Source: source, CreatedBy: userID,
	}
	if err := h.DB.Create(&rule).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	writeAudit(c, h.DB, &userID, nil, "network.rules.add", name,
		fmt.Sprintf("%d signature(s)", len(res.SIDs)))

	resp := gin.H{"id": rule.ID, "sids": res.SIDs, "msgs": res.Msgs, "validated": true}
	if n := h.autoRetroHunt(rule); n > 0 {
		resp["retrohunt_targets"] = n
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

// UpdateSuricataRule toggles or replaces a ruleset.
//
// PUT /api/v1/network/rules/:rid  {enabled?, content?, name?}
func (h *NetworkHandler) UpdateSuricataRule(c *gin.Context) {
	if middleware.GetRole(c) != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "admin role required"})
		return
	}
	var rule models.NetworkSuricataRule
	if h.DB.First(&rule, "id = ?", c.Param("rid")).Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "not found"})
		return
	}
	var req struct {
		Enabled *bool   `json:"enabled"`
		Content *string `json:"content"`
		Name    *string `json:"name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid body"})
		return
	}
	updates := map[string]interface{}{}
	if req.Name != nil && strings.TrimSpace(*req.Name) != "" {
		updates["name"] = strings.TrimSpace(*req.Name)
	}
	if req.Content != nil {
		res, err := h.engine.ValidateRuleset(c.Request.Context(), *req.Content)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
			return
		}
		if !res.OK {
			c.JSON(http.StatusBadRequest, gin.H{"success": false,
				"error": "Suricata rejected the ruleset: " + res.Error})
			return
		}
		sidsJSON, _ := json.Marshal(res.SIDs)
		msgsJSON, _ := json.Marshal(res.Msgs)
		updates["content"], updates["sids"], updates["msgs"], updates["validated"] =
			*req.Content, string(sidsJSON), string(msgsJSON), true
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}
	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "nothing to update"})
		return
	}
	if err := h.DB.Model(&rule).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"id": rule.ID}})
}

// DeleteSuricataRule removes a ruleset.
//
// DELETE /api/v1/network/rules/:rid
func (h *NetworkHandler) DeleteSuricataRule(c *gin.Context) {
	if middleware.GetRole(c) != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "admin role required"})
		return
	}
	var rule models.NetworkSuricataRule
	if h.DB.First(&rule, "id = ?", c.Param("rid")).Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "not found"})
		return
	}
	h.DB.Delete(&rule)
	var userID uuid.UUID
	if uid, ok := middleware.GetUserID(c); ok {
		userID = uid
	}
	writeAudit(c, h.DB, &userID, nil, "network.rules.delete", rule.Name, "")
	// Findings already recorded on captures are evidence of what was true at hunt
	// time; deleting the rule does not un-see them.
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"deleted": rule.ID}})
}

// RetroHunt replays a ruleset over the stored captures on demand.
//
// POST /api/v1/network/rules/:rid/retrohunt?limit=200
func (h *NetworkHandler) RetroHunt(c *gin.Context) {
	if middleware.GetRole(c) != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "admin role required"})
		return
	}
	var rule models.NetworkSuricataRule
	if h.DB.First(&rule, "id = ?", c.Param("rid")).Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "not found"})
		return
	}
	limit, _ := strconv.Atoi(c.Query("limit"))

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Minute)
	defer cancel()
	matches, scanned, err := h.engine.RetroHuntStored(ctx, rule.Content, rule.Name, limit)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error(),
			"data": gin.H{"scanned": scanned}})
		return
	}
	now := time.Now()
	h.DB.Model(&rule).Update("hunted_at", &now)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"scanned": scanned, "matches": matches, "match_count": len(matches)}})
}

// autoRetroHunt starts a background hunt for a freshly-added ruleset and returns
// how many captures it will cover. Backgrounded: replaying a hundred captures
// through Suricata takes minutes, and the upload request must not hang on it.
func (h *NetworkHandler) autoRetroHunt(rule models.NetworkSuricataRule) int {
	var targets int64
	h.DB.Model(&models.NetworkScan{}).Where("stored_path <> '' AND status = ?", "done").Count(&targets)
	if targets == 0 {
		return 0
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		if _, _, err := h.engine.RetroHuntStored(ctx, rule.Content, rule.Name, 0); err != nil {
			return
		}
		now := time.Now()
		h.DB.Model(&models.NetworkSuricataRule{}).Where("id = ?", rule.ID).Update("hunted_at", &now)
	}()
	return int(targets)
}

// readRulesetBody accepts either a multipart upload or a JSON {name, content},
// shared by the YARA and Suricata ruleset endpoints.
func readRulesetBody(c *gin.Context, maxBytes int64, ext string) (name, content, source string, ok bool) {
	if fh, err := c.FormFile("file"); err == nil {
		if fh.Size > maxBytes {
			c.JSON(http.StatusBadRequest, gin.H{"success": false,
				"error": fmt.Sprintf("ruleset exceeds %d MB", maxBytes>>20)})
			return "", "", "", false
		}
		f, oerr := fh.Open()
		if oerr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "cannot read uploaded file"})
			return "", "", "", false
		}
		defer f.Close()
		raw, _ := io.ReadAll(io.LimitReader(f, maxBytes+1))
		content, name, source = string(raw), fh.Filename, "upload"
		if n := strings.TrimSpace(c.PostForm("name")); n != "" {
			name = n
		}
	} else {
		var req struct{ Name, Content string }
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false,
				"error": "provide a " + ext + " file or {name, content}"})
			return "", "", "", false
		}
		name, content, source = strings.TrimSpace(req.Name), req.Content, "paste"
	}
	if strings.TrimSpace(content) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "empty ruleset"})
		return "", "", "", false
	}
	if int64(len(content)) > maxBytes {
		c.JSON(http.StatusBadRequest, gin.H{"success": false,
			"error": fmt.Sprintf("ruleset exceeds %d MB", maxBytes>>20)})
		return "", "", "", false
	}
	return name, content, source, true
}

package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/osint"
)

// osint_policy.go — admin CRUD for the OSINT scope policy (rules + settings) that
// decides, per situation, whether an OSINT scan may run its active
// (target-touching) collectors. Read endpoints are open to any authenticated
// user (so the launch UI can show the decision); mutations require admin.

// scopeRulePayload is the create/update body for a rule.
type scopeRulePayload struct {
	Priority        int    `json:"priority"`
	Name            string `json:"name"`
	Enabled         *bool  `json:"enabled"`
	MatchTargetType string `json:"match_target_type"`
	MatchScope      string `json:"match_scope"`
	MatchEgress     string `json:"match_egress"`
	Action          string `json:"action"`
	RequireProxy    bool   `json:"require_proxy"`
}

var (
	validActions     = map[string]bool{"all": true, "passive_only": true, "block": true}
	validScopes      = map[string]bool{"": true, "any": true, "internal": true, "external": true}
	validEgress      = map[string]bool{"": true, "any": true, "anonymized": true, "direct": true}
	validTargetTypes = map[string]bool{"": true, "any": true, "domain": true, "ip": true, "email": true, "username": true, "phone": true, "hash": true, "wallet": true, "name": true, "social_profile": true}
)

func normCond(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return "any"
	}
	return v
}

// validateRule checks a payload's enum fields; returns an error message or "".
func validateRule(p *scopeRulePayload) string {
	if strings.TrimSpace(p.Name) == "" {
		return "name is required"
	}
	if !validActions[strings.TrimSpace(p.Action)] {
		return "action must be all, passive_only, or block"
	}
	if !validScopes[normCond(p.MatchScope)] && normCond(p.MatchScope) != "any" {
		return "match_scope must be any, internal, or external"
	}
	if !validEgress[normCond(p.MatchEgress)] && normCond(p.MatchEgress) != "any" {
		return "match_egress must be any, anonymized, or direct"
	}
	if !validTargetTypes[normCond(p.MatchTargetType)] && normCond(p.MatchTargetType) != "any" {
		return "match_target_type is not a known OSINT target type"
	}
	return ""
}

// ListOsintScopeRules GET /api/v1/osint/policy/rules
func ListOsintScopeRules(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	var rules []models.OsintScopeRule
	if err := db.Order("priority asc, id asc").Find(&rules).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to list rules"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": rules})
}

// CreateOsintScopeRule POST /api/v1/osint/policy/rules
func CreateOsintScopeRule(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	var p scopeRulePayload
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	if msg := validateRule(&p); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": msg})
		return
	}
	enabled := true
	if p.Enabled != nil {
		enabled = *p.Enabled
	}
	priority := p.Priority
	if priority == 0 {
		priority = 100
	}
	rule := models.OsintScopeRule{
		Priority:        priority,
		Name:            strings.TrimSpace(p.Name),
		Enabled:         enabled,
		MatchTargetType: normCond(p.MatchTargetType),
		MatchScope:      normCond(p.MatchScope),
		MatchEgress:     normCond(p.MatchEgress),
		Action:          strings.TrimSpace(p.Action),
		RequireProxy:    p.RequireProxy,
	}
	if err := db.Create(&rule).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to create rule"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"success": true, "data": rule})
}

// UpdateOsintScopeRule PATCH /api/v1/osint/policy/rules/:id
func UpdateOsintScopeRule(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	var rule models.OsintScopeRule
	if err := db.First(&rule, "id = ?", c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "rule not found"})
		return
	}
	var p scopeRulePayload
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	if msg := validateRule(&p); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": msg})
		return
	}
	rule.Priority = p.Priority
	rule.Name = strings.TrimSpace(p.Name)
	if p.Enabled != nil {
		rule.Enabled = *p.Enabled
	}
	rule.MatchTargetType = normCond(p.MatchTargetType)
	rule.MatchScope = normCond(p.MatchScope)
	rule.MatchEgress = normCond(p.MatchEgress)
	rule.Action = strings.TrimSpace(p.Action)
	rule.RequireProxy = p.RequireProxy
	if err := db.Save(&rule).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to update rule"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": rule})
}

// DeleteOsintScopeRule DELETE /api/v1/osint/policy/rules/:id
func DeleteOsintScopeRule(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	if err := db.Delete(&models.OsintScopeRule{}, "id = ?", c.Param("id")).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to delete rule"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "rule deleted"})
}

// GetOsintScopeSettings GET /api/v1/osint/policy/settings
func GetOsintScopeSettings(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	_, settings := osint.LoadScopePolicy(db)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": settings})
}

// UpdateOsintScopeSettings PUT /api/v1/osint/policy/settings
func UpdateOsintScopeSettings(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	var p struct {
		Enforce         *bool   `json:"enforce"`
		AllowOverride   *bool   `json:"allow_override"`
		InternalDomains *string `json:"internal_domains"`
	}
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	_, settings := osint.LoadScopePolicy(db) // ensures the singleton exists
	if p.Enforce != nil {
		settings.Enforce = *p.Enforce
	}
	if p.AllowOverride != nil {
		settings.AllowOverride = *p.AllowOverride
	}
	if p.InternalDomains != nil {
		settings.InternalDomains = *p.InternalDomains
	}
	if err := db.Save(&settings).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to save settings"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": settings})
}

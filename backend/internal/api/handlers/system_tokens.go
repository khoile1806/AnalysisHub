package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/analysishub/backend/internal/models"
)

// system_tokens.go — AI token accounting for the System Health panel.
//
// This used to aggregate `analysis_sessions.tokens_used`, which only the AI
// Analysis session ever wrote. Twenty other AI call sites — malware synthesis and
// its dynamic re-synthesis, AI reverse engineering, whole-drop campaign analysis,
// OSINT triage, timeline extraction, compliance assessment, case summaries —
// spent tokens that no panel could see, so the reported total was a fraction of
// what providers were actually billing.
//
// It now reads the per-completion ledger written by the metered client, which
// makes three things answerable that the session table could not express: which
// FEATURE is spending, what a call actually costs on average, and whether calls
// are failing (a failed completion still bills its input tokens).

// tokenWindowDays bounds the default reporting window. The ledger keeps 90 days;
// a panel that silently totals all history makes a cost spike impossible to spot.
const tokenWindowDays = 30

// GetTokenStats GET /api/v1/system/token-stats?days=30
func (h *SystemHandler) GetTokenStats(c *gin.Context) {
	days := tokenWindowDays
	if v, err := strconv.Atoi(strings.TrimSpace(c.Query("days"))); err == nil && v > 0 && v <= 365 {
		days = v
	}
	since := time.Now().AddDate(0, 0, -days)

	// ── Grand totals ──────────────────────────────────────────────
	type totals struct {
		Calls        int64 `json:"calls"`
		Failed       int64 `json:"failed"`
		TotalTokens  int64 `json:"total_tokens"`
		InputTokens  int64 `json:"input_tokens"`
		OutputTokens int64 `json:"output_tokens"`
		CacheTokens  int64 `json:"cache_read_tokens"`
	}
	var t totals
	h.db.Raw(`
		SELECT
			COUNT(*)                                              AS calls,
			COALESCE(SUM(CASE WHEN success THEN 0 ELSE 1 END), 0) AS failed,
			COALESCE(SUM(total_tokens), 0)                        AS total_tokens,
			COALESCE(SUM(input_tokens), 0)                        AS input_tokens,
			COALESCE(SUM(output_tokens), 0)                       AS output_tokens,
			COALESCE(SUM(cache_read_tokens), 0)                   AS cache_tokens
		FROM ai_token_usages
		WHERE created_at >= ?
	`, since).Scan(&t)

	// ── Per-provider breakdown ────────────────────────────────────
	type provRow struct {
		ProviderID  string     `json:"provider_id"`
		Sessions    int64      `json:"sessions"` // call count; the field name the UI already binds
		TotalTokens int64      `json:"total_tokens"`
		AvgTokens   float64    `json:"avg_tokens"`
		LastUsed    *time.Time `json:"last_used"`
	}
	var provRows []provRow
	h.db.Raw(`
		SELECT
			provider_id                                       AS provider_id,
			COUNT(*)                                          AS sessions,
			COALESCE(SUM(total_tokens), 0)                    AS total_tokens,
			COALESCE(ROUND(AVG(NULLIF(total_tokens, 0))), 0)  AS avg_tokens,
			MAX(created_at)                                   AS last_used
		FROM ai_token_usages
		WHERE created_at >= ?
		GROUP BY provider_id
		ORDER BY total_tokens DESC
	`, since).Scan(&provRows)

	type enrichedRow struct {
		ProviderID   string     `json:"provider_id"`
		ProviderName string     `json:"provider_name"`
		Model        string     `json:"model"`
		ProviderType string     `json:"provider_type"`
		Sessions     int64      `json:"sessions"`
		TotalTokens  int64      `json:"total_tokens"`
		AvgTokens    float64    `json:"avg_tokens"`
		LastUsed     *time.Time `json:"last_used"`
	}
	// Preload every referenced provider in ONE query (no per-row N+1).
	provByID := map[string]models.AIProvider{}
	if len(provRows) > 0 {
		ids := make([]string, 0, len(provRows))
		for _, row := range provRows {
			if row.ProviderID != "" {
				ids = append(ids, row.ProviderID)
			}
		}
		if len(ids) > 0 {
			var ps []models.AIProvider
			h.db.Where("id IN ?", ids).Find(&ps)
			for _, p := range ps {
				provByID[p.ID.String()] = p
			}
		}
	}

	enriched := make([]enrichedRow, 0, len(provRows))
	for _, row := range provRows {
		p := provByID[row.ProviderID]
		name := p.Name
		if name == "" {
			// The ledger deliberately outlives the provider row, so history is not
			// lost when someone rotates or deletes a provider. Label it rather than
			// dropping the tokens it spent.
			suffix := row.ProviderID
			if len(suffix) > 8 {
				suffix = suffix[:8]
			}
			name = suffix + "… (deleted)"
		}
		enriched = append(enriched, enrichedRow{
			ProviderID:   row.ProviderID,
			ProviderName: name,
			Model:        p.Model,
			ProviderType: p.ProviderType,
			Sessions:     row.Sessions,
			TotalTokens:  row.TotalTokens,
			AvgTokens:    row.AvgTokens,
			LastUsed:     row.LastUsed,
		})
	}

	// ── Per-feature breakdown ─────────────────────────────────────
	// The question the old panel could not answer at all: WHAT is spending the
	// tokens. Ordering by total makes the expensive feature the first thing read.
	type featureRow struct {
		Feature     string     `json:"feature"`
		Calls       int64      `json:"calls"`
		Failed      int64      `json:"failed"`
		TotalTokens int64      `json:"total_tokens"`
		AvgTokens   float64    `json:"avg_tokens"`
		AvgMS       float64    `json:"avg_ms"`
		LastUsed    *time.Time `json:"last_used"`
	}
	byFeature := []featureRow{} // never nil → serialises as [] not null
	h.db.Raw(`
		SELECT
			feature,
			COUNT(*)                                              AS calls,
			COALESCE(SUM(CASE WHEN success THEN 0 ELSE 1 END), 0) AS failed,
			COALESCE(SUM(total_tokens), 0)                        AS total_tokens,
			COALESCE(ROUND(AVG(NULLIF(total_tokens, 0))), 0)      AS avg_tokens,
			COALESCE(ROUND(AVG(NULLIF(duration_ms, 0))), 0)       AS avg_ms,
			MAX(created_at)                                       AS last_used
		FROM ai_token_usages
		WHERE created_at >= ?
		GROUP BY feature
		ORDER BY total_tokens DESC
		LIMIT 40
	`, since).Scan(&byFeature)

	// ── Daily trend ───────────────────────────────────────────────
	// A single total cannot show a spike; the panel needs the shape over time.
	type dayRow struct {
		Day         time.Time `json:"day"`
		Calls       int64     `json:"calls"`
		TotalTokens int64     `json:"total_tokens"`
	}
	daily := []dayRow{}
	h.db.Raw(`
		SELECT
			date_trunc('day', created_at)  AS day,
			COUNT(*)                       AS calls,
			COALESCE(SUM(total_tokens), 0) AS total_tokens
		FROM ai_token_usages
		WHERE created_at >= ?
		GROUP BY 1
		ORDER BY 1
	`, since).Scan(&daily)

	// ── Recent completions ────────────────────────────────────────
	type recentRow struct {
		ID         string     `json:"id"`
		Title      string     `json:"title"`       // the feature, so the UI's column still reads
		SourceType string     `json:"source_type"` // ok | failed
		TokensUsed int        `json:"tokens_used"`
		FinishedAt *time.Time `json:"finished_at"`
		ProviderID string     `json:"provider_id"`
		DurationMS int        `json:"duration_ms"`
	}
	recent := []recentRow{}
	h.db.Raw(`
		SELECT
			id::text                                   AS id,
			feature                                    AS title,
			CASE WHEN success THEN 'ok' ELSE 'failed' END AS source_type,
			total_tokens                               AS tokens_used,
			created_at                                 AS finished_at,
			provider_id                                AS provider_id,
			duration_ms                                AS duration_ms
		FROM ai_token_usages
		ORDER BY created_at DESC
		LIMIT 20
	`).Scan(&recent)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"window_days": days,
			// total_sessions keeps the name the UI binds; it now counts COMPLETIONS,
			// which is what a provider bills for.
			"total_sessions":    t.Calls,
			"total_tokens":      t.TotalTokens,
			"failed_calls":      t.Failed,
			"input_tokens":      t.InputTokens,
			"output_tokens":     t.OutputTokens,
			"cache_read_tokens": t.CacheTokens,
			"by_provider":       enriched,
			"by_feature":        byFeature,
			"daily":             daily,
			"recent":            recent,
		},
	})
}

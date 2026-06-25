package handlers

import (
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/forensichub/backend/internal/models"
)

// attackTactic is one column of the ATT&CK enterprise matrix. Order follows the
// canonical kill-chain so the frontend can render tactics left-to-right.
type attackTactic struct {
	id   string // normalized id, e.g. "initial-access"
	name string // display name, e.g. "Initial Access"
}

// enterpriseTactics is the ordered enterprise ATT&CK tactic list. Matching is
// done on the normalized event Tactic value (lowercased, spaces/underscores →
// hyphens), tolerating the common "TA0001" style and free-text entries.
var enterpriseTactics = []attackTactic{
	{"reconnaissance", "Reconnaissance"},
	{"resource-development", "Resource Development"},
	{"initial-access", "Initial Access"},
	{"execution", "Execution"},
	{"persistence", "Persistence"},
	{"privilege-escalation", "Privilege Escalation"},
	{"defense-evasion", "Defense Evasion"},
	{"credential-access", "Credential Access"},
	{"discovery", "Discovery"},
	{"lateral-movement", "Lateral Movement"},
	{"collection", "Collection"},
	{"command-and-control", "Command and Control"},
	{"exfiltration", "Exfiltration"},
	{"impact", "Impact"},
}

// normalizeTactic maps a free-form tactic string to a known enterprise tactic id.
// Returns "" when it cannot be matched (caller buckets these as "unmapped").
func normalizeTactic(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return ""
	}
	s = strings.NewReplacer("_", "-", " ", "-").Replace(s)
	s = strings.ReplaceAll(s, "--", "-")
	// Common synonyms / abbreviations.
	switch s {
	case "c2", "c&c", "command-control", "cnc":
		return "command-and-control"
	case "privesc":
		return "privilege-escalation"
	case "lateral", "lateral-move":
		return "lateral-movement"
	}
	for _, t := range enterpriseTactics {
		if t.id == s {
			return t.id
		}
	}
	return ""
}

// attackSeverityRank orders severities so we can bubble up the worst one per technique.
func attackSeverityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0 // info / unknown
	}
}

// AttackCoverage aggregates a case's timeline events into an ATT&CK coverage
// view: which tactics/techniques the reconstructed attack touched, how many
// events map to each, and the worst severity seen. It is a pure read over the
// existing timeline_events table — no schema change.
//
// GET /api/v1/cases/:id/attack-coverage
func (h *TimelineHandler) AttackCoverage(c *gin.Context) {
	caseID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case id"})
		return
	}

	var events []models.TimelineEvent
	h.DB.Where("case_id = ?", caseID).Order("event_time asc").Find(&events)

	// technique aggregate within a tactic
	type techAgg struct {
		ID           string   `json:"id"`
		Count        int      `json:"count"`
		Severity     string   `json:"severity"`
		severityRank int      // internal, not serialized
		SampleTitles []string `json:"sample_titles"`
		LastSeen     string   `json:"last_seen,omitempty"`
	}
	type tacticAgg struct {
		ID         string              `json:"id"`
		Name       string              `json:"name"`
		EventCount int                 `json:"event_count"`
		techByID   map[string]*techAgg // internal
		Techniques []*techAgg          `json:"techniques"`
	}

	tactics := make(map[string]*tacticAgg)
	tacticName := func(id string) string {
		for _, t := range enterpriseTactics {
			if t.id == id {
				return t.name
			}
		}
		if id == "unmapped" {
			return "Unmapped"
		}
		return id
	}
	getTactic := func(id string) *tacticAgg {
		if ta, ok := tactics[id]; ok {
			return ta
		}
		ta := &tacticAgg{ID: id, Name: tacticName(id), techByID: map[string]*techAgg{}}
		tactics[id] = ta
		return ta
	}

	mappedEvents := 0
	uniqueTechniques := map[string]struct{}{}

	for i := range events {
		ev := &events[i]
		technique := strings.ToUpper(strings.TrimSpace(ev.Technique))
		tacticID := normalizeTactic(ev.Tactic)

		// An event contributes to coverage if it has a technique OR a known tactic.
		if technique == "" && tacticID == "" {
			continue
		}
		mappedEvents++

		if tacticID == "" {
			tacticID = "unmapped"
		}
		ta := getTactic(tacticID)
		ta.EventCount++

		techKey := technique
		if techKey == "" {
			techKey = "(unspecified)"
		}
		uniqueTechniques[tacticID+"|"+techKey] = struct{}{}

		tech, ok := ta.techByID[techKey]
		if !ok {
			tech = &techAgg{ID: techKey, Severity: "info"}
			ta.techByID[techKey] = tech
		}
		tech.Count++
		if r := attackSeverityRank(ev.Severity); r > tech.severityRank {
			tech.severityRank = r
			tech.Severity = strings.ToLower(strings.TrimSpace(ev.Severity))
			if tech.Severity == "" {
				tech.Severity = "info"
			}
		}
		if len(tech.SampleTitles) < 3 && strings.TrimSpace(ev.Title) != "" {
			tech.SampleTitles = append(tech.SampleTitles, ev.Title)
		}
		tech.LastSeen = ev.EventTime.Format("2006-01-02 15:04")
	}

	// Emit tactics in canonical kill-chain order, "unmapped" last, skipping empties.
	order := make([]string, 0, len(enterpriseTactics)+1)
	for _, t := range enterpriseTactics {
		order = append(order, t.id)
	}
	order = append(order, "unmapped")

	outTactics := make([]*tacticAgg, 0, len(tactics))
	for _, id := range order {
		ta, ok := tactics[id]
		if !ok {
			continue
		}
		// Flatten + sort techniques: highest severity first, then count desc, then id.
		for _, tech := range ta.techByID {
			ta.Techniques = append(ta.Techniques, tech)
		}
		sort.SliceStable(ta.Techniques, func(a, b int) bool {
			x, y := ta.Techniques[a], ta.Techniques[b]
			if x.severityRank != y.severityRank {
				return x.severityRank > y.severityRank
			}
			if x.Count != y.Count {
				return x.Count > y.Count
			}
			return x.ID < y.ID
		})
		ta.techByID = nil
		outTactics = append(outTactics, ta)
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"summary": gin.H{
			"total_events":  len(events),
			"mapped_events": mappedEvents,
			"techniques":    len(uniqueTechniques),
			"tactics":       len(outTactics),
		},
		"tactics": outTactics,
	}})
}

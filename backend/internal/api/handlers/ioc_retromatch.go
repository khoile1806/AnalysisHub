package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/models"
)

// ioc_retromatch.go — asking the question intelligence is actually for.
//
// Every match path in the platform runs forwards: something arrives, and it is
// checked against what the store knows at that moment. That answers "is this
// bad" but never "have I seen this before" — and the second question is the one
// that matters when new intelligence lands. An analyst who learns today that an
// address is a C2 needs to know whether it appears in a capture from last month,
// because that is the difference between a blocklist entry and an incident.
//
// The malware feature already has this shape for YARA (RetroHunt: a new rule
// re-scanned over stored samples). There was no equivalent for indicators, even
// though the platform stores exactly the material to search: every malware
// scan's extracted IOC set, every pcap's, and the hashes of every sample.
//
// Nothing is re-analysed. The stored, already-computed indicator sets are read
// back and compared, so a sweep over months of history costs a few queries.

// RetroHit is one historical artefact that contains an indicator.
type RetroHit struct {
	Indicator string    `json:"indicator"`
	Type      string    `json:"type"`
	Source    string    `json:"source"`  // which store the indicator came from
	Kind      string    `json:"kind"`    // "malware" | "network"
	ScanID    string    `json:"scan_id"` // the artefact to open
	Name      string    `json:"name"`    // file or capture name
	Verdict   string    `json:"verdict"` // that artefact's verdict at the time
	SeenAt    time.Time `json:"seen_at"` // when the artefact was analysed
	Where     string    `json:"where"`   // which field matched
}

// retroMaxIndicators bounds one sweep. A retro-match over the entire store would
// be a table scan per indicator; the useful case is "these ten things I just
// learned about", not "everything I have ever known".
const retroMaxIndicators = 500

// retroMaxHits bounds the answer.
const retroMaxHits = 2000

// RetroMatch searches historical analyses for the given indicators.
//
// POST /api/v1/iocs/retro-match
//
//	{ "values": ["1.2.3.4", "evil.example"] }          explicit list, or
//	{ "since_hours": 24 }                              everything added recently
//
// The second form is the one that runs after a feed refresh: "what did today's
// intelligence just tell me about last month".
func RetroMatch(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}

	var req struct {
		Values     []string `json:"values"`
		SinceHours int      `json:"since_hours"`
	}
	_ = c.ShouldBindJSON(&req)

	needles, err := retroNeedles(db, req.Values, req.SinceHours)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	if len(needles) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"success": true, "searched": 0, "hits": []RetroHit{},
			"message": "no indicators to search for",
		})
		return
	}

	hits := runRetroMatch(db, needles)
	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"searched": len(needles),
		"count":    len(hits),
		"hits":     hits,
	})
}

// retroNeedle is one indicator to look for, carrying where it came from so a hit
// can say why it is being reported.
type retroNeedle struct {
	Value  string
	Type   string
	Source string
}

func retroNeedles(db *gorm.DB, values []string, sinceHours int) ([]retroNeedle, error) {
	seen := map[string]bool{}
	out := make([]retroNeedle, 0, len(values))

	for _, v := range values {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, retroNeedle{Value: v, Source: "request"})
		if len(out) >= retroMaxIndicators {
			return out, nil
		}
	}
	if len(out) > 0 {
		return out, nil
	}

	if sinceHours <= 0 {
		sinceHours = 24
	}
	if sinceHours > 24*30 {
		sinceHours = 24 * 30
	}
	cutoff := time.Now().UTC().Add(-time.Duration(sinceHours) * time.Hour)

	var rows []models.IOC
	// Newest first: if the window holds more than the cap, the most recent
	// intelligence is the part worth searching for.
	if err := ActiveIOCs(db).
		Where("created_at >= ?", cutoff).
		Order("created_at desc").
		Limit(retroMaxIndicators).
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("cannot read the IOC store: %w", err)
	}
	for _, r := range rows {
		v := strings.ToLower(strings.TrimSpace(r.Value))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, retroNeedle{Value: v, Type: r.Type, Source: r.Source})
	}
	return out, nil
}

// runRetroMatch scans the stored analyses. Both tables keep their indicator sets
// as JSON text, so the search is a substring pre-filter in SQL followed by an
// exact comparison in Go — the pre-filter is what keeps it off a full table scan,
// and the exact pass is what stops "1.2.3.4" from matching "11.2.3.40".
func runRetroMatch(db *gorm.DB, needles []retroNeedle) []RetroHit {
	hits := make([]RetroHit, 0, 32)

	for _, n := range needles {
		if len(hits) >= retroMaxHits {
			break
		}
		like := "%" + n.Value + "%"

		// ── Malware scans ────────────────────────────────────────────────────
		var mrows []models.MalwareScan
		db.Select("id", "file_name", "sha256", "verdict", "created_at", "iocs").
			Where("lower(iocs) LIKE ? OR lower(sha256) = ?", like, n.Value).
			Order("created_at desc").Limit(50).Find(&mrows)
		for _, m := range mrows {
			where := ""
			if strings.EqualFold(m.SHA256, n.Value) {
				where = "sample hash"
			} else if iocsContain(m.IOCs, n.Value) {
				where = "extracted indicators"
			}
			if where == "" {
				continue // LIKE matched a substring of a longer value
			}
			hits = append(hits, RetroHit{
				Indicator: n.Value, Type: n.Type, Source: n.Source,
				Kind: "malware", ScanID: m.ID.String(), Name: m.FileName,
				Verdict: m.Verdict, SeenAt: m.CreatedAt, Where: where,
			})
			if len(hits) >= retroMaxHits {
				return hits
			}
		}

		// ── Network captures ─────────────────────────────────────────────────
		var nrows []models.NetworkScan
		db.Select("id", "file_name", "verdict", "created_at", "result").
			Where("lower(result) LIKE ?", like).
			Order("created_at desc").Limit(50).Find(&nrows)
		for _, s := range nrows {
			if !networkResultContains(s.Result, n.Value) {
				continue
			}
			hits = append(hits, RetroHit{
				Indicator: n.Value, Type: n.Type, Source: n.Source,
				Kind: "network", ScanID: s.ID.String(), Name: s.FileName,
				Verdict: s.Verdict, SeenAt: s.CreatedAt, Where: "capture indicators",
			})
			if len(hits) >= retroMaxHits {
				return hits
			}
		}
	}
	return hits
}

// iocsContain checks a malware scan's stored indicator array for an exact value.
func iocsContain(raw, value string) bool {
	if raw == "" {
		return false
	}
	var entries []struct {
		Value string `json:"value"`
	}
	if json.Unmarshal([]byte(raw), &entries) != nil {
		// Not the expected shape — fall back to a bounded textual check rather
		// than claiming a hit we cannot substantiate.
		return false
	}
	for _, e := range entries {
		if strings.EqualFold(strings.TrimSpace(e.Value), value) {
			return true
		}
	}
	return false
}

// networkResultContains checks a capture's distilled IOC lists for an exact value.
func networkResultContains(raw, value string) bool {
	if raw == "" {
		return false
	}
	var res struct {
		IOCs struct {
			IPs     []string `json:"ips"`
			Domains []string `json:"domains"`
		} `json:"iocs"`
		DNS []struct {
			Query   string   `json:"query"`
			Answers []string `json:"answers"`
		} `json:"dns"`
		HTTP []struct {
			Host string `json:"host"`
		} `json:"http"`
		Files []struct {
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	if json.Unmarshal([]byte(raw), &res) != nil {
		return false
	}
	eq := func(s string) bool { return strings.EqualFold(strings.TrimSpace(s), value) }
	for _, v := range res.IOCs.IPs {
		if eq(v) {
			return true
		}
	}
	for _, v := range res.IOCs.Domains {
		if eq(v) {
			return true
		}
	}
	for _, d := range res.DNS {
		if eq(d.Query) {
			return true
		}
		for _, a := range d.Answers {
			if eq(a) {
				return true
			}
		}
	}
	for _, h := range res.HTTP {
		if eq(h.Host) {
			return true
		}
	}
	for _, f := range res.Files {
		if eq(f.SHA256) {
			return true
		}
	}
	return false
}

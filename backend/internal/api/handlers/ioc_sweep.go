package handlers

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/forensichub/backend/internal/ws"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ioc_sweep.go — "Live IOC Sweep" (endpoint threat hunt). Pushes a set of
// indicators (file hashes / IPs / domains / file names) to an online agent,
// collects its live forensic artifacts via the existing triage path, then
// matches the indicators against them SERVER-SIDE and returns the hits with
// attribution. Bridges threat-intel → endpoint. Reuses the cross-platform
// collectors (processes/dlls/netconn/browser/autoruns + shimcache/prefetch).

var (
	hashRe = regexp.MustCompile(`^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$`)
	// file extensions that mark an indicator as a file name rather than a domain.
	fileExtRe = regexp.MustCompile(`\.(exe|dll|ps1|bat|cmd|hta|vbs|js|jar|scr|sys|msi|sh|elf|py|so|bin|dat|tmp|lnk)$`)
)

type sweepIndicator struct {
	Value string `json:"value"`
	Type  string `json:"type"` // hash | ip | domain | filename
}

type iocMatch struct {
	Indicator string `json:"indicator"`
	Type      string `json:"indicator_type"`
	Artifact  string `json:"artifact"`
	Context   string `json:"context"`
}

// classifyIndicator infers an indicator's type from its shape.
func classifyIndicator(raw string) sweepIndicator {
	v := strings.TrimSpace(raw)
	low := strings.ToLower(v)
	switch {
	case hashRe.MatchString(v):
		return sweepIndicator{low, "hash"}
	case net.ParseIP(v) != nil:
		return sweepIndicator{low, "ip"}
	case fileExtRe.MatchString(low) && !strings.Contains(low, "://"):
		return sweepIndicator{low, "filename"}
	case strings.Contains(v, ".") && !strings.ContainsAny(v, " /\\"):
		return sweepIndicator{low, "domain"}
	default:
		return sweepIndicator{low, "filename"}
	}
}

// AgentIOCSweep runs a live indicator sweep against an online agent.
//
// POST /api/v1/agents/:id/ioc-sweep
//
//	{ "indicators": ["evil.exe","1.2.3.4","bad.com","<sha256>"],
//	  "types": ["processes","dlls","netconn","browser","autoruns"] }
func AgentIOCSweep(c *gin.Context) {
	hub, ok := mustGetHub(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid agent ID"})
		return
	}
	if !hub.IsAgentOnline(id.String()) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": "agent is offline"})
		return
	}

	var body struct {
		Indicators []string `json:"indicators"`
		Types      []string `json:"types"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	// Classify + dedupe indicators.
	seen := map[string]bool{}
	var inds []sweepIndicator
	for _, raw := range body.Indicators {
		ind := classifyIndicator(raw)
		if ind.Value == "" || seen[ind.Value] {
			continue
		}
		seen[ind.Value] = true
		inds = append(inds, ind)
	}
	if len(inds) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "no valid indicators supplied"})
		return
	}

	types := body.Types
	if len(types) == 0 {
		types = []string{"processes", "dlls", "netconn", "browser", "autoruns"}
	}

	// Collect via the agent's triage path, capturing the bytes for matching.
	reqID := uuid.New().String()
	outCh := hub.SubscribeJobOutput(reqID)
	defer hub.UnsubscribeJobOutput(reqID, outCh)
	if err := hub.SendJobToAgent(id.String(), ws.AgentCommand{
		Type: "edge_parse_triage", JobID: reqID, Args: strings.Join(types, ","),
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to send request"})
		return
	}
	data, okData := awaitEdgeJSONBytes(c, hub, outCh, id.String())
	if !okData {
		return // error response already written
	}

	matches, scanned := matchIOCsInBundle(data, inds)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"indicators": len(inds),
		"scanned":    scanned, // per-artifact record counts
		"matches":    matches,
	}})
}

// matchIOCsInBundle matches indicators against a triage bundle's artifacts.
func matchIOCsInBundle(bundle []byte, inds []sweepIndicator) ([]iocMatch, map[string]int) {
	var parsed struct {
		Artifacts []struct {
			Type  string          `json:"type"`
			Error string          `json:"error"`
			Data  json.RawMessage `json:"data"`
		} `json:"artifacts"`
	}
	scanned := map[string]int{}
	if err := json.Unmarshal(bundle, &parsed); err != nil {
		return nil, scanned
	}

	var matches []iocMatch
	dedupe := map[string]bool{}
	for _, art := range parsed.Artifacts {
		if art.Error != "" {
			continue
		}
		rows := artifactRows(art.Type, art.Data)
		scanned[art.Type] = len(rows)
		for _, row := range rows {
			hashes, hay := rowFingerprint(row)
			for _, ind := range inds {
				hit := false
				switch ind.Type {
				case "hash":
					hit = hashes[ind.Value]
				default: // ip / domain / filename → substring in the row haystack
					hit = strings.Contains(hay, ind.Value)
				}
				if !hit {
					continue
				}
				ctx := rowSummary(art.Type, row)
				key := ind.Value + "|" + art.Type + "|" + ctx
				if dedupe[key] {
					continue
				}
				dedupe[key] = true
				matches = append(matches, iocMatch{
					Indicator: ind.Value, Type: ind.Type, Artifact: art.Type, Context: ctx,
				})
			}
		}
	}
	return matches, scanned
}

// artifactRows extracts the record list for an artifact, handling netconn's
// object shape ({connections, dns}) specially.
func artifactRows(artType string, raw json.RawMessage) []map[string]interface{} {
	if artType == "netconn" {
		var obj struct {
			Connections []map[string]interface{} `json:"connections"`
		}
		if json.Unmarshal(raw, &obj) == nil {
			return obj.Connections
		}
	}
	return decodeArtifactRows(raw)
}

// rowFingerprint returns the row's hash set (md5/sha1/sha256, lowercased) and a
// lowercase haystack of its scalar string fields for substring matching.
func rowFingerprint(row map[string]interface{}) (map[string]bool, string) {
	hashes := map[string]bool{}
	for _, k := range []string{"md5", "sha1", "sha256", "exe_sha256", "exe_md5"} {
		if s, ok := row[k].(string); ok && s != "" {
			hashes[strings.ToLower(s)] = true
		}
	}
	var sb strings.Builder
	for _, v := range row {
		if s, ok := v.(string); ok {
			sb.WriteString(strings.ToLower(s))
			sb.WriteByte('\n')
		}
	}
	return hashes, sb.String()
}

// rowSummary builds a short human description of a matching record.
func rowSummary(artType string, row map[string]interface{}) string {
	s := func(k string) string {
		if v, ok := row[k].(string); ok {
			return v
		}
		return ""
	}
	num := func(k string) string {
		switch v := row[k].(type) {
		case float64:
			return fmt.Sprintf("%d", int(v))
		case string:
			return v
		}
		return ""
	}
	switch artType {
	case "processes":
		return strings.TrimSpace(fmt.Sprintf("%s (pid %s) %s %s", s("name"), num("pid"), firstNonBlank(s("path"), ""), s("cmdline")))
	case "dlls":
		return strings.TrimSpace(fmt.Sprintf("%s — %s", firstNonBlank(s("name"), ""), s("path")))
	case "netconn":
		return strings.TrimSpace(fmt.Sprintf("%s %s:%s → %s:%s (%s) %s", s("proto"), s("local_addr"), num("local_port"), s("remote_addr"), num("remote_port"), s("state"), s("process")))
	case "browser":
		return strings.TrimSpace(fmt.Sprintf("[%s] %s", s("browser"), s("url")))
	case "autoruns":
		return strings.TrimSpace(fmt.Sprintf("%s: %s (%s)", s("category"), firstNonBlank(s("name"), ""), firstNonBlank(s("command"), s("image_path"))))
	case "shimcache":
		return firstNonBlank(s("path"), s("name"))
	case "prefetch":
		return strings.TrimSpace(fmt.Sprintf("%s (runs %s)", s("executable"), num("run_count")))
	default:
		return firstNonBlank(s("name"), s("path"), s("url"))
	}
}

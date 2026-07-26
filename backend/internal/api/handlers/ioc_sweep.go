package handlers

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/ws"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
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

// maxSweepIndicators bounds how many pasted indicators one sweep will match, so
// the O(endpoint-artifacts × indicators) scan stays bounded regardless of input.
const maxSweepIndicators = 10000

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
		UseStore   bool     `json:"use_store"` // match endpoint artifacts against the ENTIRE IOC store, server-side
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	// Classify + dedupe pasted indicators. Bounded so a huge paste can't blow up
	// the O(artifacts × indicators) match below.
	seen := map[string]bool{}
	var inds []sweepIndicator
	for _, raw := range body.Indicators {
		if len(inds) >= maxSweepIndicators {
			break
		}
		ind := classifyIndicator(raw)
		if ind.Value == "" || seen[ind.Value] {
			continue
		}
		seen[ind.Value] = true
		inds = append(inds, ind)
	}
	if len(inds) == 0 && !body.UseStore {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "no valid indicators supplied (paste some, or enable use_store)"})
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

	storeMatched := 0
	// use_store: instead of pulling the (possibly TB-scale) store to the client,
	// extract the bounded set of candidate values present ON THE ENDPOINT, then
	// ask the DB which of those are known indicators (indexed `value` lookup,
	// batched). Cost scales with endpoint artifacts, NOT store size.
	if body.UseStore {
		if db, dbOK := mustGetDB(c); dbOK {
			cand := collectEndpointValues(data)
			storeInds := lookupStoreIndicators(db, cand)
			storeMatched = len(storeInds)
			for _, si := range storeInds {
				if !seen[si.Value] {
					seen[si.Value] = true
					inds = append(inds, si)
				}
			}
		}
	}

	matches, scanned := matchIOCsInBundle(data, inds)
	auditEdgeAction(c, id.String(), "agent.ioc.sweep",
		fmt.Sprintf("indicators=%d use_store=%v matches=%d", len(inds), body.UseStore, len(matches)))
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"indicators":    len(inds),
		"store_matched": storeMatched, // store indicators that were present on the endpoint
		"scanned":       scanned,      // per-artifact record counts
		"matches":       matches,
	}})
}

// collectEndpointValues extracts the bounded set of candidate IOC values present
// in a triage bundle (hashes, IPs, hostnames, file names) so they can be looked
// up against the store without ever loading the store itself.
func collectEndpointValues(bundle []byte) []string {
	var parsed struct {
		Artifacts []struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		} `json:"artifacts"`
	}
	if json.Unmarshal(bundle, &parsed) != nil {
		return nil
	}
	const maxCand = 50000
	set := map[string]bool{}
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" && len(set) < maxCand {
			set[s] = true
		}
	}
	for _, art := range parsed.Artifacts {
		for _, row := range artifactRows(art.Type, art.Data) {
			// hashes
			for _, k := range []string{"md5", "sha1", "sha256", "exe_sha256", "exe_md5"} {
				if v, ok := row[k].(string); ok {
					add(v)
				}
			}
			// network endpoints + hostnames
			for _, k := range []string{"remote_addr", "local_addr", "remote_host"} {
				if v, ok := row[k].(string); ok {
					add(v)
				}
			}
			// urls → host
			if v, ok := row["url"].(string); ok && v != "" {
				if u, err := url.Parse(v); err == nil && u.Host != "" {
					add(u.Hostname())
				}
			}
			// file names → basename of path-like fields
			for _, k := range []string{"name", "path", "image_path", "executable", "module", "process"} {
				if v, ok := row[k].(string); ok && v != "" {
					add(v)
					add(path.Base(strings.ReplaceAll(v, "\\", "/")))
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	return out
}

// lookupStoreIndicators asks the IOC store which of the supplied (endpoint)
// values are known indicators, batched by indexed `value` lookups so it scales
// regardless of store size.
func lookupStoreIndicators(db *gorm.DB, values []string) []sweepIndicator {
	var out []sweepIndicator
	const batch = 500
	for i := 0; i < len(values); i += batch {
		end := i + batch
		if end > len(values) {
			end = len(values)
		}
		var iocs []models.IOC
		if db.Where("lower(value) IN ?", values[i:end]).Find(&iocs).Error != nil {
			continue
		}
		for _, ioc := range iocs {
			out = append(out, sweepIndicator{Value: strings.ToLower(ioc.Value), Type: storeTypeToSweep(ioc.Type)})
		}
	}
	return out
}

// storeTypeToSweep maps an OpenCTI/store type to the sweep matcher's category.
// "hash" gets exact-set matching, "ip"/"domain" get boundary-aware matching, and
// "filename" falls back to substring.
func storeTypeToSweep(t string) string {
	switch t {
	case "File-Hash":
		return "hash"
	case "IPv4-Addr", "IPv6-Addr":
		return "ip"
	case "Domain-Name":
		return "domain"
	default:
		return "filename"
	}
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
				case "ip":
					// boundary match so 1.2.3.4 does not hit 11.2.3.44 / 1.2.3.40
					hit = hayHasBounded(hay, ind.Value, true)
				case "domain":
					// boundary match so evil.com does not hit notevil.com /
					// evil.community, while sub.evil.com still matches
					hit = hayHasBounded(hay, ind.Value, false)
				default: // filename → substring (a name legitimately appears inside a path)
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

// hayHasBounded reports whether needle occurs in hay at a token boundary, so a
// short IP/domain indicator can't match inside a longer neighbour. For an IP the
// boundary rejects an adjacent digit or dot (1.2.3.4 must not hit 11.2.3.44 or
// 1.2.3.40); for a domain it rejects an adjacent letter/digit/hyphen (evil.com
// must not hit notevil.com or evil.community) while still allowing a leading dot
// so a parent domain matches its sub-domains (sub.evil.com). needle is assumed
// already lowercased, matching the haystack.
func hayHasBounded(hay, needle string, isIP bool) bool {
	if needle == "" {
		return false
	}
	boundaryBad := func(b byte) bool {
		if isIP {
			return b == '.' || (b >= '0' && b <= '9')
		}
		return b == '-' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
	}
	for off := 0; off <= len(hay)-len(needle); {
		i := strings.Index(hay[off:], needle)
		if i < 0 {
			return false
		}
		i += off
		okBefore := i == 0 || !boundaryBad(hay[i-1])
		end := i + len(needle)
		okAfter := end >= len(hay) || !boundaryBad(hay[end])
		if okBefore && okAfter {
			return true
		}
		off = i + 1
	}
	return false
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

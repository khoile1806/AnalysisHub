package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/api/middleware"
	"github.com/forensichub/backend/internal/models"
	"github.com/forensichub/backend/internal/osint"
)

// osintTypeToIOC maps an OSINT target type to the IOC-store Type name used by
// ForensicHub's OpenCTI sync + ELK auto-hunt. Returns "" for types that aren't
// meaningful IOCs (phone/username).
func osintTypeToIOC(osintType, value string) string {
	switch osintType {
	case "ip":
		if strings.Contains(value, ":") {
			return "IPv6-Addr"
		}
		return "IPv4-Addr"
	case "domain":
		return "Domain-Name"
	case "email":
		return "Email-Addr"
	case "hash":
		return "File-Hash"
	case "wallet":
		if strings.HasPrefix(value, "0x") {
			return "ETH-Addr"
		}
		return "BTC-Addr"
	}
	return ""
}

// PromoteOsintIOC adds an OSINT-discovered indicator to the IOC store so the ELK
// auto-hunt and other defensive tooling can immediately act on it. This closes
// the defensive loop: OSINT surfaces related infrastructure -> it lands in the
// IOC store -> the next ELK hunt searches the logs for it.
//
// POST /api/v1/osint/promote-ioc  { "value": "...", "type": "ip|domain|email|hash", "description": "..." }
func PromoteOsintIOC(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetUserID(c)

	var req struct {
		Value       string `json:"value" binding:"required"`
		Type        string `json:"type" binding:"required"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	iocType := osintTypeToIOC(strings.ToLower(req.Type), req.Value)
	if iocType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "type not promotable to an IOC (use ip/domain/email/hash)"})
		return
	}

	desc := strings.TrimSpace(req.Description)
	if desc == "" {
		desc = "Discovered via OSINT footprinting"
	}
	ioc := models.IOC{
		Value:       strings.TrimSpace(req.Value),
		Type:        iocType,
		Source:      "OSINT",
		Description: desc,
	}

	result := db.Where("value = ? AND type = ?", ioc.Value, ioc.Type).FirstOrCreate(&ioc)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to save IOC"})
		return
	}
	created := result.RowsAffected > 0

	writeAudit(c, db, &userID, nil, "osint.promote_ioc", ioc.Value,
		fmt.Sprintf("type=%s created=%v", iocType, created))

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"ioc":     ioc,
		"created": created, // false = already present in the store
	}})
}

// GetOsintGraph returns the investigation graph (nodes + edges) for the scan's
// investigation. Nodes are scans (entities investigated); edges are auto-pivot
// relationships (parent -> child, labeled by the entity that spawned the child).
//
// GET /api/v1/osint/:id/graph
func GetOsintGraph(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scan id"})
		return
	}

	var scan models.OsintScan
	if err := db.First(&scan, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "scan not found"})
		return
	}
	root := scan.ID
	if scan.RootScanID != nil {
		root = *scan.RootScanID
	}

	var scans []models.OsintScan
	db.Where("root_scan_id = ? OR id = ?", root, root).
		Order("depth asc, created_at asc").Find(&scans)

	type node struct {
		ID       string `json:"id"`
		Target   string `json:"target"`
		Type     string `json:"type"`
		Status   string `json:"status"`
		Depth    int    `json:"depth"`
		Findings int    `json:"findings"`
		Root     bool   `json:"root"`
	}
	type edge struct {
		From  string `json:"from"`
		To    string `json:"to"`
		Label string `json:"label"`
	}
	nodes := make([]node, 0, len(scans))
	edges := make([]edge, 0)
	for i := range scans {
		s := &scans[i]
		var fc int64
		db.Model(&models.OsintFinding{}).Where("scan_id = ?", s.ID).Count(&fc)
		nodes = append(nodes, node{
			ID: s.ID.String(), Target: s.Target, Type: s.TargetType,
			Status: string(s.Status), Depth: s.Depth, Findings: int(fc),
			Root: s.ID == root,
		})
		if s.ParentScanID != nil {
			edges = append(edges, edge{From: s.ParentScanID.String(), To: s.ID.String(), Label: s.PivotFrom})
		}
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"root":  root.String(),
		"nodes": nodes,
		"edges": edges,
	}})
}

// GetOsintCorrelations surfaces shared indicators that link two or more entities
// in the investigation - the de-anonymisation signal. A value that is both one
// scan's target AND another scan's discovered related entity (e.g. a registrant
// email tying two domains together) connects those entities even when they are
// not parent/child in the pivot tree.
//
// GET /api/v1/osint/:id/correlations
func GetOsintCorrelations(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scan id"})
		return
	}
	var scan models.OsintScan
	if err := db.First(&scan, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "scan not found"})
		return
	}
	root := scan.ID
	if scan.RootScanID != nil {
		root = *scan.RootScanID
	}

	var scans []models.OsintScan
	db.Where("root_scan_id = ? OR id = ?", root, root).Find(&scans)

	scanByID := make(map[string]models.OsintScan, len(scans))
	// value -> set of scanIDs that reference it (as target or related entity)
	valueToScans := make(map[string]map[string]bool)
	add := func(value, scanID string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if valueToScans[value] == nil {
			valueToScans[value] = make(map[string]bool)
		}
		valueToScans[value][scanID] = true
	}

	for i := range scans {
		s := &scans[i]
		sid := s.ID.String()
		scanByID[sid] = *s
		add(s.Target, sid)

		var findings []models.OsintFinding
		db.Where("scan_id = ? AND related_entities <> ''", s.ID).Find(&findings)
		for _, f := range findings {
			var rels []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			}
			if json.Unmarshal([]byte(f.RelatedEntities), &rels) != nil {
				continue
			}
			for _, r := range rels {
				add(r.Value, sid)
			}
		}
	}

	type linkedEntity struct {
		ID     string `json:"id"`
		Target string `json:"target"`
		Type   string `json:"type"`
	}
	type correlation struct {
		Value    string         `json:"value"`
		Count    int            `json:"count"`
		Entities []linkedEntity `json:"entities"`
	}

	out := make([]correlation, 0)
	for value, set := range valueToScans {
		if len(set) < 2 {
			continue
		}
		ents := make([]linkedEntity, 0, len(set))
		for sid := range set {
			s := scanByID[sid]
			ents = append(ents, linkedEntity{ID: sid, Target: s.Target, Type: s.TargetType})
		}
		out = append(out, correlation{Value: value, Count: len(set), Entities: ents})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })

	c.JSON(http.StatusOK, gin.H{"success": true, "data": out})
}

// ExportOsintGraph serialises the whole investigation graph (entities + pivot
// and shared-indicator relationships) into GraphML so an analyst can import it
// into Maltego, Gephi, yEd or Cytoscape for deeper link analysis. GraphML is an
// open standard every major graph tool reads, which is why it is offered instead
// of the proprietary native Maltego format.
//
// GET /api/v1/osint/:id/graph/export?format=graphml
func ExportOsintGraph(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scan id"})
		return
	}
	var scan models.OsintScan
	if err := db.First(&scan, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "scan not found"})
		return
	}
	root := scan.ID
	if scan.RootScanID != nil {
		root = *scan.RootScanID
	}

	var scans []models.OsintScan
	db.Where("root_scan_id = ? OR id = ?", root, root).
		Order("depth asc, created_at asc").Find(&scans)
	if len(scans) == 0 {
		scans = []models.OsintScan{scan}
	}

	// Findings count per scan in a single grouped query (no per-node N+1).
	ids := make([]uuid.UUID, len(scans))
	for i := range scans {
		ids[i] = scans[i].ID
	}
	type fcRow struct {
		ScanID uuid.UUID
		N      int
	}
	var fcRows []fcRow
	db.Model(&models.OsintFinding{}).
		Select("scan_id, count(*) as n").
		Where("scan_id IN ?", ids).
		Group("scan_id").Scan(&fcRows)
	findingCount := make(map[uuid.UUID]int, len(fcRows))
	for _, r := range fcRows {
		findingCount[r.ScanID] = r.N
	}

	nodes := make([]osint.GraphNode, 0, len(scans))
	edges := make([]osint.GraphEdge, 0)
	for i := range scans {
		s := &scans[i]
		nodes = append(nodes, osint.GraphNode{
			ID: s.ID.String(), Label: s.Target, Type: s.TargetType,
			Status: string(s.Status), Depth: s.Depth, Findings: findingCount[s.ID],
			Root: s.ID == root, Exposure: s.ExposureScore, Grade: s.ExposureGrade,
		})
		if s.ParentScanID != nil {
			edges = append(edges, osint.GraphEdge{
				From: s.ParentScanID.String(), To: s.ID.String(), Label: s.PivotFrom, Rel: "pivot",
			})
		}
	}

	// Shared-indicator (correlation) edges: a value that appears as the target of
	// one scan and a discovered related entity of another links those entities.
	edges = append(edges, correlationEdges(db, scans)...)

	graphml, gerr := osint.GenerateGraphML(nodes, edges)
	if gerr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to build GraphML"})
		return
	}

	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, scan.Name)
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="osint-graph-%s.graphml"`, safe))
	c.Data(http.StatusOK, "application/graphml+xml; charset=utf-8", graphml)
}

// correlationEdges builds shared-indicator links between the investigation's
// scans. For each value referenced by two or more scans it emits a star of
// edges from the first referencing scan to the others (linear, not a clique),
// so the link is visible without exploding the edge count.
func correlationEdges(db *gorm.DB, scans []models.OsintScan) []osint.GraphEdge {
	valueToScans := make(map[string][]string)
	add := func(value, scanID string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		for _, existing := range valueToScans[value] {
			if existing == scanID {
				return
			}
		}
		valueToScans[value] = append(valueToScans[value], scanID)
	}
	for i := range scans {
		s := &scans[i]
		sid := s.ID.String()
		add(s.Target, sid)
		var findings []models.OsintFinding
		db.Where("scan_id = ? AND related_entities <> ''", s.ID).Find(&findings)
		for _, f := range findings {
			var rels []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			}
			if json.Unmarshal([]byte(f.RelatedEntities), &rels) != nil {
				continue
			}
			for _, r := range rels {
				add(r.Value, sid)
			}
		}
	}

	var out []osint.GraphEdge
	for value, sids := range valueToScans {
		if len(sids) < 2 {
			continue
		}
		for _, to := range sids[1:] {
			if sids[0] == to {
				continue
			}
			out = append(out, osint.GraphEdge{From: sids[0], To: to, Label: value, Rel: "correlation"})
		}
	}
	return out
}

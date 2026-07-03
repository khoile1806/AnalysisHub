package vulnscan

import (
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/models"
)

// relatedEntity mirrors the {type,value} pivot shape stored in
// osint_findings.related_entities (kept local to avoid importing the osint
// package just for one struct).
type relatedEntity struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Asset is a single discovered host the scanner can target.
type Asset struct {
	Value string `json:"value"`
	Type  string `json:"type"` // ip | domain
}

// ExtractAssets returns the unique IPs and domains/subdomains discovered across
// an entire OSINT investigation (the root scan plus every auto-pivot child),
// pulled from the structured related_entities JSON — the only clean, de-duped
// source of {type,value}. The scan's own Target seeds the set too.
func ExtractAssets(db *gorm.DB, osintScanID uuid.UUID) ([]Asset, error) {
	var scan models.OsintScan
	if err := db.First(&scan, "id = ?", osintScanID).Error; err != nil {
		return nil, err
	}
	root := scan.ID
	if scan.RootScanID != nil {
		root = *scan.RootScanID
	}

	var scans []models.OsintScan
	if err := db.Where("root_scan_id = ? OR id = ?", root, root).Find(&scans).Error; err != nil {
		return nil, err
	}
	scanIDs := make([]uuid.UUID, 0, len(scans))
	ips := map[string]bool{}
	domains := map[string]bool{}
	for _, s := range scans {
		scanIDs = append(scanIDs, s.ID)
		switch s.TargetType {
		case "ip":
			ips[strings.TrimSpace(s.Target)] = true
		case "domain":
			domains[strings.TrimSpace(s.Target)] = true
		}
	}

	var findings []models.OsintFinding
	if err := db.Where("scan_id IN ? AND related_entities <> ''", scanIDs).
		Find(&findings).Error; err != nil {
		return nil, err
	}
	for _, f := range findings {
		var rels []relatedEntity
		if json.Unmarshal([]byte(f.RelatedEntities), &rels) != nil {
			continue
		}
		for _, r := range rels {
			v := strings.TrimSpace(r.Value)
			if v == "" {
				continue
			}
			switch r.Type {
			case "ip":
				ips[v] = true
			case "domain":
				domains[v] = true
			}
		}
	}

	out := make([]Asset, 0, len(ips)+len(domains))
	for v := range domains {
		out = append(out, Asset{Value: v, Type: "domain"})
	}
	for v := range ips {
		out = append(out, Asset{Value: v, Type: "ip"})
	}
	return out, nil
}

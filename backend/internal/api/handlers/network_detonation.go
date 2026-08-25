package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"

	ai "github.com/analysishub/backend/internal/ai"
	"github.com/analysishub/backend/internal/models"
)

// network_detonation.go — the bridge from Malware Analysis to Network Analysis.
//
// The two features were each complete and blind to the other. The sandbox
// executed samples and generated real traffic; the sinkhole answered it and kept
// JSON records. Meanwhile the network pipeline — Suricata with the full Emerging
// Threats ruleset, Zeek flow logs, JA3/JA3S fingerprinting, file carving,
// domain-fronting detection — had never once been pointed at that traffic,
// because nobody wrote a capture file.
//
// This is the missing link, and it needed no new analysis code: the sidecar and
// the netscan engine both already accepted a pcap plus an optional TLS keylog.
// What was missing was a producer.
//
// The keylog is what makes this unusual. In a sandbox the platform owns BOTH ends
// of every TLS session, so the traffic it captures is decryptable — a property a
// capture taken from a real network essentially never has.

// AnalyzeDetonationPcap runs a detonation's captured traffic through the network
// pipeline and returns the id of the scan it created.
//
// It is the malware engine's PcapAnalyzer callback. Failures are returned rather
// than logged-and-swallowed so the caller can decide; the caller treats network
// analysis as optional evidence and never fails a detonation over it.
func (h *NetworkHandler) AnalyzeDetonationPcap(parentScanID, filename string, pcap, keylog []byte) (string, error) {
	if h == nil || h.engine == nil || !h.engine.Available() {
		return "", fmt.Errorf("network analyzer is not configured")
	}
	if len(pcap) == 0 {
		return "", fmt.Errorf("empty capture")
	}
	if int64(len(pcap)) > h.maxUpload() {
		return "", fmt.Errorf("capture exceeds the %d MB limit", h.maxUpload()>>20)
	}

	// Inherit the originating sample's case and owner so the capture lands in the
	// same investigation rather than appearing as an orphan upload.
	var caseID *uuid.UUID
	var ownerID uuid.UUID
	var parent models.MalwareScan
	if h.DB.First(&parent, "id = ?", parentScanID).Error == nil {
		caseID = parent.CaseID
		ownerID = parent.CreatedBy
	}

	name := sanitizeSampleName(filename)
	sum := sha256.Sum256(pcap)
	sha := hex.EncodeToString(sum[:])

	scan := models.NetworkScan{
		FileName: name, Size: int64(len(pcap)), Sha256: sha,
		Status: "pending", Verdict: "unknown", CaseID: caseID, CreatedBy: ownerID,
	}
	if err := h.DB.Create(&scan).Error; err != nil {
		return "", fmt.Errorf("could not create the network analysis: %w", err)
	}
	if path, serr := h.Store.SaveAnalysisUpload(scan.ID.String(), name, bytes.NewReader(pcap)); serr == nil {
		h.DB.Model(&scan).Update("stored_path", path)
		registerExistingEvidence(h.DB, caseID, nil, "", "pcap", "malware-detonation",
			name, path, int64(len(pcap)), sha)
	}

	// Reuse the default provider so the capture gets the same analyst summary an
	// uploaded pcap would. A missing provider is fine — the engine falls back to a
	// deterministic narrative.
	var client ai.Client
	maxTokens := 0
	if h.AI != nil {
		if prov, cl, perr := h.AI.resolveProvider(""); perr == nil {
			client, maxTokens = cl, prov.MaxTokens
		}
	}

	go h.engine.Analyze(context.Background(), scan.ID.String(), pcap, name, keylog, client, maxTokens)
	return scan.ID.String(), nil
}

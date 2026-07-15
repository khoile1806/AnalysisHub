package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/storage"
)

// maxEvidenceBytes is a generous upper bound on a single evidence/result upload —
// large enough for disk images and live-response bundles — that only guards
// against an abusive unbounded upload filling the storage volume.
const maxEvidenceBytes = 64 << 30 // 64 GB

// EvidenceHandler manages result/evidence files uploaded into a case.
type EvidenceHandler struct {
	DB    *gorm.DB
	Store *storage.LocalStorage
}

func NewEvidenceHandler(db *gorm.DB, store *storage.LocalStorage) *EvidenceHandler {
	return &EvidenceHandler{DB: db, Store: store}
}

// Upload POST /api/v1/cases/:id/evidence  (multipart: file, host, notes)
// host is REQUIRED — every result must declare which machine it belongs to.
func (h *EvidenceHandler) Upload(c *gin.Context) {
	caseID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case id"})
		return
	}
	var caseObj models.Case
	if err := h.DB.First(&caseObj, "id = ?", caseID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "case not found"})
		return
	}

	host := strings.TrimSpace(c.PostForm("host"))
	if host == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "host is required — specify which host this result belongs to"})
		return
	}
	notes := strings.TrimSpace(c.PostForm("notes"))

	fh, ferr := c.FormFile("file")
	if ferr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "file is required"})
		return
	}
	if fh.Size > maxEvidenceBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"success": false, "error": "file exceeds maximum allowed size"})
		return
	}
	f, openErr := fh.Open()
	if openErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to open upload"})
		return
	}
	defer f.Close()

	ev := models.CaseEvidence{
		CaseID:   &caseID,
		Host:     host,
		Kind:     "upload",
		FileName: fh.Filename,
		Size:     fh.Size,
		Notes:    notes,
	}
	if v, ok := c.Get("userID"); ok {
		if uid, perr := uuid.Parse(v.(string)); perr == nil {
			ev.UploadedBy = uid
		}
	}
	// Create first to get a stable unique id for the stored filename.
	if err := h.DB.Create(&ev).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to create evidence record"})
		return
	}

	relPath, saveErr := h.Store.SaveCaseEvidence(caseID.String(), ev.ID.String(), fh.Filename, f)
	if saveErr != nil {
		h.DB.Delete(&ev)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to store file: " + saveErr.Error()})
		return
	}
	h.DB.Model(&ev).Update("stored_path", relPath)
	ev.StoredPath = relPath

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": ev})
}

// List GET /api/v1/cases/:id/evidence
func (h *EvidenceHandler) List(c *gin.Context) {
	caseID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid case id"})
		return
	}
	var items []models.CaseEvidence
	h.DB.Where("case_id = ?", caseID).Order("created_at desc").Find(&items)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": items})
}

// Delete DELETE /api/v1/evidence/:id
func (h *EvidenceHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	var ev models.CaseEvidence
	if err := h.DB.First(&ev, "id = ?", id).Error; err == nil {
		_ = h.Store.RemoveByRelPath(ev.StoredPath)
		h.DB.Delete(&ev)
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// Download GET /api/v1/evidence/:id/download
func (h *EvidenceHandler) Download(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	var ev models.CaseEvidence
	if err := h.DB.First(&ev, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "evidence not found"})
		return
	}
	c.FileAttachment(h.Store.GetEvidencePath(ev.StoredPath), ev.FileName)
}

// ListAll GET /api/v1/evidence — the central Evidence Store view across every
// case/agent, with server-side filtering + pagination so it scales to a large
// store. Filters: kind, host, case_id, agent_id, search (file/source/host/notes).
func (h *EvidenceHandler) ListAll(c *gin.Context) {
	q := h.DB.Model(&models.CaseEvidence{})
	if kind := strings.TrimSpace(c.Query("kind")); kind != "" {
		q = q.Where("kind = ?", kind)
	}
	if host := strings.TrimSpace(c.Query("host")); host != "" {
		q = q.Where("host = ?", host)
	}
	if cid := strings.TrimSpace(c.Query("case_id")); cid != "" {
		q = q.Where("case_id = ?", cid)
	}
	if aid := strings.TrimSpace(c.Query("agent_id")); aid != "" {
		q = q.Where("agent_id = ?", aid)
	}
	if s := strings.TrimSpace(c.Query("search")); s != "" {
		like := "%" + s + "%"
		q = q.Where("file_name ILIKE ? OR source ILIKE ? OR host ILIKE ? OR notes ILIKE ?", like, like, like, like)
	}

	var total int64
	q.Count(&total)

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if offset < 0 {
		offset = 0
	}

	var items []models.CaseEvidence
	q.Order("created_at desc").Limit(limit).Offset(offset).Find(&items)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": items, "total": total})
}

// Facets GET /api/v1/evidence/facets — counts for the store overview (total,
// per-kind, distinct hosts) without loading rows.
func (h *EvidenceHandler) Facets(c *gin.Context) {
	var total int64
	h.DB.Model(&models.CaseEvidence{}).Count(&total)

	type kv struct {
		Value string `json:"value"`
		Count int64  `json:"count"`
	}
	var kinds []kv
	h.DB.Model(&models.CaseEvidence{}).
		Select("kind as value, count(*) as count").
		Group("kind").Order("count desc").Scan(&kinds)
	var hosts []kv
	h.DB.Model(&models.CaseEvidence{}).
		Select("host as value, count(*) as count").
		Where("host <> ''").Group("host").Order("count desc").Limit(50).Scan(&hosts)

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"total": total, "kinds": kinds, "hosts": hosts}})
}

// UploadGlobal POST /api/v1/evidence — upload a file straight into the store,
// optionally tagged with a case/agent/kind. Used for ad-hoc evidence and for
// frontend-driven markers not tied to a single case.
func (h *EvidenceHandler) UploadGlobal(c *gin.Context) {
	host := strings.TrimSpace(c.PostForm("host"))
	kind := firstNonEmpty(strings.TrimSpace(c.PostForm("kind")), "upload")
	source := strings.TrimSpace(c.PostForm("source"))
	notes := strings.TrimSpace(c.PostForm("notes"))

	var caseID, agentID *uuid.UUID
	if v := strings.TrimSpace(c.PostForm("case_id")); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			caseID = &id
		}
	}
	if v := strings.TrimSpace(c.PostForm("agent_id")); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			agentID = &id
		}
	}

	fh, ferr := c.FormFile("file")
	if ferr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "file is required"})
		return
	}
	if fh.Size > maxEvidenceBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"success": false, "error": "file exceeds maximum allowed size"})
		return
	}
	f, openErr := fh.Open()
	if openErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to open upload"})
		return
	}
	defer f.Close()

	var uploader uuid.UUID
	if v, ok := c.Get("userID"); ok {
		if uid, perr := uuid.Parse(v.(string)); perr == nil {
			uploader = uid
		}
	}

	ev := models.CaseEvidence{
		CaseID: caseID, AgentID: agentID, Host: host, Kind: kind, Source: source,
		FileName: fh.Filename, Size: fh.Size, Notes: notes, UploadedBy: uploader,
	}
	if err := h.DB.Create(&ev).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to create evidence record"})
		return
	}
	relPath, saveErr := h.Store.SaveCaseEvidence(evidenceBucket(caseID, agentID), ev.ID.String(), fh.Filename, f)
	if saveErr != nil {
		h.DB.Delete(&ev)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to store file: " + saveErr.Error()})
		return
	}
	h.DB.Model(&ev).Update("stored_path", relPath)
	ev.StoredPath = relPath
	c.JSON(http.StatusCreated, gin.H{"success": true, "data": ev})
}

// evidenceBucket picks the on-disk subdirectory for an evidence file: the case
// when known, else the agent, else a shared "unassigned" bucket.
func evidenceBucket(caseID, agentID *uuid.UUID) string {
	if caseID != nil {
		return caseID.String()
	}
	if agentID != nil {
		return "agent-" + agentID.String()
	}
	return "unassigned"
}

// recordEvidenceBytes writes an in-memory blob into the Evidence Store (file +
// row). Best-effort: used by background collectors (checklist, edge-forensics),
// so it logs and returns on error rather than surfacing it to a caller.
func recordEvidenceBytes(db *gorm.DB, store *storage.LocalStorage, caseID, agentID *uuid.UUID, host, kind, source, fileName string, data []byte) {
	if store == nil || db == nil || len(data) == 0 {
		return
	}
	sum := sha256.Sum256(data)
	ev := models.CaseEvidence{
		CaseID: caseID, AgentID: agentID, Host: host, Kind: kind, Source: source,
		FileName: fileName, Size: int64(len(data)), Sha256: hex.EncodeToString(sum[:]),
	}
	if err := db.Create(&ev).Error; err != nil {
		log.Printf("[evidence] record %s: %v", kind, err)
		return
	}
	relPath, err := store.SaveCaseEvidence(evidenceBucket(caseID, agentID), ev.ID.String(), fileName, bytes.NewReader(data))
	if err != nil {
		db.Delete(&ev)
		log.Printf("[evidence] store %s: %v", kind, err)
		return
	}
	db.Model(&ev).Update("stored_path", relPath)
}

// registerExistingEvidence adds a store row for a file ALREADY on disk at
// storedRel (e.g. an auto-collected tool result), without copying it. Deduped by
// stored path so reprocessing never creates duplicate rows.
func registerExistingEvidence(db *gorm.DB, caseID, agentID *uuid.UUID, host, kind, source, fileName, storedRel string, size int64, sha string) {
	if db == nil || storedRel == "" {
		return
	}
	var existing int64
	db.Model(&models.CaseEvidence{}).Where("stored_path = ?", storedRel).Count(&existing)
	if existing > 0 {
		return
	}
	ev := models.CaseEvidence{
		CaseID: caseID, AgentID: agentID, Host: host, Kind: kind, Source: source,
		FileName: fileName, StoredPath: storedRel, Size: size, Sha256: sha,
	}
	if err := db.Create(&ev).Error; err != nil {
		log.Printf("[evidence] register %s: %v", kind, err)
	}
}

// recordEdgeScanEvidence snapshots an edge-forensics scan result into the store
// as a marked evidence file, attributed to the scanned host/agent/case. The DB
// handle + storage are read from the request context synchronously, but the
// heavy work (hash + disk write + insert) runs off the response path so it never
// slows the scan the analyst is waiting on.
func recordEdgeScanEvidence(c *gin.Context, agentID, kind string, data []byte) {
	db, ok := mustGetDBSilent(c)
	if !ok || db == nil {
		return
	}
	sv, exists := c.Get("storage")
	if !exists {
		return
	}
	store, _ := sv.(*storage.LocalStorage)
	if store == nil {
		return
	}
	// Copy the payload: the caller writes the same slice to the HTTP response.
	buf := make([]byte, len(data))
	copy(buf, data)
	go func() {
		var agent models.Agent
		if db.First(&agent, "id = ?", agentID).Error != nil {
			return
		}
		host := agent.Hostname
		if host == "" {
			host = agent.Name
		}
		safeHost := strings.NewReplacer("\\", "-", "/", "-", " ", "_", ":", "-").Replace(host)
		fileName := fmt.Sprintf("%s-%s-%d.json", kind, safeHost, time.Now().Unix())
		recordEvidenceBytes(db, store, agent.CaseID, &agent.ID, host, "edge-forensics", "edge-forensics:"+kind, fileName, buf)
	}()
}

// View GET /api/v1/evidence/:id/view — serve inline (for <img>, preview).
func (h *EvidenceHandler) View(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	var ev models.CaseEvidence
	if err := h.DB.First(&ev, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "evidence not found"})
		return
	}
	c.File(h.Store.GetEvidencePath(ev.StoredPath))
}

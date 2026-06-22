package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/models"
	"github.com/forensichub/backend/internal/storage"
)

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
	f, openErr := fh.Open()
	if openErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to open upload"})
		return
	}
	defer f.Close()

	ev := models.CaseEvidence{
		CaseID:   caseID,
		Host:     host,
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

package handlers

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/models"
)

// DashboardUsecaseHandler manages incident-type dashboard views.
type DashboardUsecaseHandler struct {
	DB *gorm.DB
}

func NewDashboardUsecaseHandler(db *gorm.DB) *DashboardUsecaseHandler {
	return &DashboardUsecaseHandler{DB: db}
}

var usecaseSlugRe = regexp.MustCompile(`[^a-z0-9]+`)

func usecaseSlugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = usecaseSlugRe.ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}

// List GET /api/v1/dashboard/usecases
func (h *DashboardUsecaseHandler) List(c *gin.Context) {
	var ucs []models.DashboardUsecase
	h.DB.Order("sort_order asc, created_at asc").Find(&ucs)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": ucs})
}

// Create POST /api/v1/dashboard/usecases
func (h *DashboardUsecaseHandler) Create(c *gin.Context) {
	var input struct {
		Name         string `json:"name" binding:"required"`
		IncidentType string `json:"incident_type"`
		Description  string `json:"description"`
		Icon         string `json:"icon"`
		Color        string `json:"color"`
		Widgets      string `json:"widgets"`
		Playbook     string `json:"playbook"`
		SortOrder    int    `json:"sort_order"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	var userUUID uuid.UUID
	if v, ok := c.Get("userID"); ok {
		if uid, perr := uuid.Parse(v.(string)); perr == nil {
			userUUID = uid
		}
	}

	uc := models.DashboardUsecase{
		Name:         input.Name,
		Slug:         uniqueSlug(h.DB, usecaseSlugify(input.Name)),
		IncidentType: input.IncidentType,
		Description:  input.Description,
		Icon:         orDefault(input.Icon, "Activity"),
		Color:        orDefault(input.Color, "sky"),
		Widgets:      orDefault(input.Widgets, "[]"),
		Playbook:     input.Playbook,
		SortOrder:    input.SortOrder,
		CreatedBy:    userUUID,
	}
	if err := h.DB.Create(&uc).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to create usecase"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"success": true, "data": uc})
}

// Update PUT /api/v1/dashboard/usecases/:id
func (h *DashboardUsecaseHandler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	var uc models.DashboardUsecase
	if err := h.DB.First(&uc, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "usecase not found"})
		return
	}

	var input struct {
		Name         *string `json:"name"`
		IncidentType *string `json:"incident_type"`
		Description  *string `json:"description"`
		Icon         *string `json:"icon"`
		Color        *string `json:"color"`
		Widgets      *string `json:"widgets"`
		Playbook     *string `json:"playbook"`
		SortOrder    *int    `json:"sort_order"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	updates := map[string]interface{}{}
	if input.Name != nil {
		updates["name"] = *input.Name
	}
	if input.IncidentType != nil {
		updates["incident_type"] = *input.IncidentType
	}
	if input.Description != nil {
		updates["description"] = *input.Description
	}
	if input.Icon != nil {
		updates["icon"] = *input.Icon
	}
	if input.Color != nil {
		updates["color"] = *input.Color
	}
	if input.Widgets != nil {
		updates["widgets"] = *input.Widgets
	}
	if input.Playbook != nil {
		updates["playbook"] = *input.Playbook
	}
	if input.SortOrder != nil {
		updates["sort_order"] = *input.SortOrder
	}
	if len(updates) > 0 {
		h.DB.Model(&uc).Updates(updates)
	}
	h.DB.First(&uc, "id = ?", id)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": uc})
}

// Delete DELETE /api/v1/dashboard/usecases/:id
func (h *DashboardUsecaseHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}
	h.DB.Delete(&models.DashboardUsecase{}, "id = ?", id)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func uniqueSlug(db *gorm.DB, base string) string {
	if base == "" {
		base = "usecase"
	}
	slug := base
	for i := 2; ; i++ {
		var n int64
		db.Model(&models.DashboardUsecase{}).Where("slug = ?", slug).Count(&n)
		if n == 0 {
			return slug
		}
		slug = base + "-" + strconv.Itoa(i)
	}
}

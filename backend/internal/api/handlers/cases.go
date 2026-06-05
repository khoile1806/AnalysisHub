package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/models"
)

type CasesHandler struct {
	DB *gorm.DB
}

func NewCasesHandler(db *gorm.DB) *CasesHandler {
	return &CasesHandler{DB: db}
}

// ListCases returns all cases
func (h *CasesHandler) ListCases(c *gin.Context) {
	var cases []models.Case
	if err := h.DB.Order("created_at desc").Find(&cases).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch cases"})
		return
	}
	c.JSON(http.StatusOK, cases)
}

// CreateCase creates a new case
func (h *CasesHandler) CreateCase(c *gin.Context) {
	var input struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.MustGet("userID").(string)

	caseObj := models.Case{
		Name:        input.Name,
		Description: input.Description,
		Status:      "open",
	}

	// Parse UUID
	if uid, err := uuid.Parse(userID); err == nil {
		caseObj.CreatedBy = uid
	}

	if err := h.DB.Create(&caseObj).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create case"})
		return
	}

	// Log audit
	if uid, err := uuid.Parse(userID); err == nil {
		writeAudit(c, h.DB, &uid, nil, "create", "case", "Created case "+input.Name)
	}

	c.JSON(http.StatusCreated, caseObj)
}

// GetCaseSummary returns a case with its agents, deployments, jobs
func (h *CasesHandler) GetCaseSummary(c *gin.Context) {
	caseID := c.Param("id")

	var caseObj models.Case
	if err := h.DB.Preload("Agents").First(&caseObj, "id = ?", caseID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Case not found"})
		return
	}

	// Fetch deployments and jobs manually or via agents
	var agents []models.Agent
	if err := h.DB.Where("case_id = ?", caseID).Find(&agents).Error; err == nil {
		caseObj.Agents = agents
	}

	agentIDs := make([]string, 0)
	for _, a := range caseObj.Agents {
		agentIDs = append(agentIDs, a.ID.String())
	}

	var jobs []models.Job
	if len(agentIDs) > 0 {
		h.DB.Preload("Tool").Preload("Agent").Preload("CreatedByUser").
			Where("agent_id IN ?", agentIDs).
			Order("created_at desc").
			Find(&jobs)
	}

	var deployments []models.HuntingDeployment
	if len(agentIDs) > 0 {
		h.DB.Preload("Scenario").Preload("Agent").Preload("CreatedByUser").
			Where("agent_id IN ?", agentIDs).
			Order("created_at desc").
			Find(&deployments)
	}

	var checklistRuns []models.ChecklistRun
	if len(agentIDs) > 0 {
		h.DB.Preload("Batches").
			Where("agent_id IN ?", agentIDs).
			Order("created_at desc").
			Find(&checklistRuns)
	}

	c.JSON(http.StatusOK, gin.H{
		"case":           caseObj,
		"deployments":    deployments,
		"jobs":           jobs,
		"checklist_runs": checklistRuns,
	})
}

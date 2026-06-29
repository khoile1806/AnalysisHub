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

// ListCases returns all cases.
// GET /api/v1/cases
func (h *CasesHandler) ListCases(c *gin.Context) {
	var cases []models.Case
	if err := h.DB.Order("created_at desc").Find(&cases).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to fetch cases"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": cases})
}

// CreateCase creates a new case.
// POST /api/v1/cases
func (h *CasesHandler) CreateCase(c *gin.Context) {
	var input struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	userID := c.MustGet("userID").(string)

	caseObj := models.Case{
		Name:        input.Name,
		Description: input.Description,
		Status:      "open",
	}

	if uid, err := uuid.Parse(userID); err == nil {
		caseObj.CreatedBy = uid
	}

	if err := h.DB.Create(&caseObj).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to create case"})
		return
	}

	if uid, err := uuid.Parse(userID); err == nil {
		writeAudit(c, h.DB, &uid, nil, "create", "case", "Created case "+input.Name)
	}

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": caseObj})
}

// UpdateCase updates name, description, or status of a case.
// PATCH /api/v1/cases/:id
func (h *CasesHandler) UpdateCase(c *gin.Context) {
	caseID := c.Param("id")

	var caseObj models.Case
	if err := h.DB.First(&caseObj, "id = ?", caseID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Case not found"})
		return
	}

	var input struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		Status      *string `json:"status"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	updates := map[string]interface{}{}
	if input.Name != nil {
		updates["name"] = *input.Name
	}
	if input.Description != nil {
		updates["description"] = *input.Description
	}
	if input.Status != nil {
		if *input.Status != "open" && *input.Status != "closed" {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "status must be 'open' or 'closed'"})
			return
		}
		updates["status"] = *input.Status
	}

	if len(updates) > 0 {
		if err := h.DB.Model(&caseObj).Updates(updates).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to update case"})
			return
		}
	}

	if err := h.DB.First(&caseObj, "id = ?", caseID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to reload case"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": caseObj})
}

// DeleteCase deletes a case by ID.
// DELETE /api/v1/cases/:id
func (h *CasesHandler) DeleteCase(c *gin.Context) {
	caseID := c.Param("id")

	var caseObj models.Case
	if err := h.DB.First(&caseObj, "id = ?", caseID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Case not found"})
		return
	}

	if err := h.DB.Delete(&caseObj).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Cannot delete case. It might have linked resources."})
		return
	}

	userID := c.MustGet("userID").(string)
	if uid, err := uuid.Parse(userID); err == nil {
		writeAudit(c, h.DB, &uid, nil, "delete", "case", "Deleted case "+caseObj.Name)
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// GetCaseSummary returns a case with its agents, deployments, jobs, and checklist runs.
// Deployments are fetched both via associated agents AND directly via case_id on the
// deployment, so results from any deploy path are included.
// GET /api/v1/cases/:id/summary
func (h *CasesHandler) GetCaseSummary(c *gin.Context) {
	caseID := c.Param("id")

	var caseObj models.Case
	if err := h.DB.Preload("Agents").First(&caseObj, "id = ?", caseID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Case not found"})
		return
	}

	var agents []models.Agent
	if err := h.DB.Where("case_id = ?", caseID).Find(&agents).Error; err == nil {
		caseObj.Agents = agents
	}

	agentIDs := make([]string, 0, len(caseObj.Agents))
	for _, a := range caseObj.Agents {
		agentIDs = append(agentIDs, a.ID.String())
	}

	// Jobs via agent membership
	var jobs []models.Job
	if len(agentIDs) > 0 {
		h.DB.Preload("Tool").Preload("Agent").Preload("CreatedByUser").
			Where("agent_id IN ?", agentIDs).
			Order("created_at desc").
			Find(&jobs)
	}

	// Deployments via agent membership
	deploymentSeen := map[string]bool{}
	var deployments []models.HuntingDeployment
	if len(agentIDs) > 0 {
		h.DB.Preload("Scenario").Preload("Agent").Preload("CreatedByUser").
			Preload("Jobs.Tool").
			Where("agent_id IN ?", agentIDs).
			Order("created_at desc").
			Find(&deployments)
		for _, d := range deployments {
			deploymentSeen[d.ID.String()] = true
		}
	}

	// Deployments directly tagged with this case_id (deploying from hunting page with case selected)
	var directDeployments []models.HuntingDeployment
	h.DB.Preload("Scenario").Preload("Agent").Preload("CreatedByUser").
		Preload("Jobs.Tool").
		Where("case_id = ?", caseID).
		Order("created_at desc").
		Find(&directDeployments)
	for _, d := range directDeployments {
		if !deploymentSeen[d.ID.String()] {
			deployments = append(deployments, d)
		}
	}

	// Checklist runs via agent membership
	runSeen := map[string]bool{}
	var checklistRuns []models.ChecklistRun
	if len(agentIDs) > 0 {
		h.DB.Preload("Batches").
			Where("agent_id IN ?", agentIDs).
			Order("created_at desc").
			Find(&checklistRuns)
		for _, r := range checklistRuns {
			runSeen[r.ID.String()] = true
		}
	}
	// Also include runs tagged directly with this case_id
	var directRuns []models.ChecklistRun
	h.DB.Preload("Batches").
		Where("case_id = ?", caseID).
		Order("created_at desc").
		Find(&directRuns)
	for _, r := range directRuns {
		if !runSeen[r.ID.String()] {
			checklistRuns = append(checklistRuns, r)
		}
	}

	// OSINT investigations filed under this case. Only the root scans are
	// listed (auto-pivot children are folded into their root's graph), but the
	// totals count the whole graph so the analyst sees the real scope.
	var osintRoots []models.OsintScan
	h.DB.Where("case_id = ? AND parent_scan_id IS NULL", caseID).
		Order("created_at desc").Find(&osintRoots)

	var osintTotalScans, osintTotalFindings int64
	h.DB.Model(&models.OsintScan{}).Where("case_id = ?", caseID).Count(&osintTotalScans)
	h.DB.Model(&models.OsintFinding{}).
		Where("scan_id IN (?)", h.DB.Model(&models.OsintScan{}).
			Select("id").Where("case_id = ?", caseID)).
		Count(&osintTotalFindings)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"case":           caseObj,
			"agents":         caseObj.Agents,
			"deployments":    deployments,
			"jobs":           jobs,
			"checklist_runs": checklistRuns,
			"osint": gin.H{
				"investigations": osintRoots,
				"total_scans":    osintTotalScans,
				"total_findings": osintTotalFindings,
			},
		},
	})
}

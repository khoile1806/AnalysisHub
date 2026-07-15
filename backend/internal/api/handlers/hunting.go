package handlers

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/ws"
)

// slugify converts a free-form scenario name into a stable URL-safe slug.
// "Webshell Hunt!" → "webshell-hunt".
var slugCleaner = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = slugCleaner.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		s = uuid.NewString()
	}
	return s
}

// ---------------------------------------------------------------------------
// Scenario CRUD
// ---------------------------------------------------------------------------

type scenarioRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
	Color       string `json:"color"`
}

// ListScenarios returns all scenarios with their tools (preloaded) and a
// tool_count field for fast UI rendering.
//
// GET /api/v1/hunting/scenarios
func ListScenarios(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}

	var scenarios []models.HuntingScenario
	if err := db.
		Preload("Tools.Tool").
		Order("created_at asc").
		Find(&scenarios).Error; err != nil {
		log.Printf("[hunting] list scenarios: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to list scenarios"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": scenarios})
}

// GetScenario returns a single scenario by id with tools preloaded.
//
// GET /api/v1/hunting/scenarios/:id
func GetScenario(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scenario id"})
		return
	}

	var scenario models.HuntingScenario
	if err := db.Preload("Tools.Tool").First(&scenario, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "scenario not found"})
			return
		}
		log.Printf("[hunting] get scenario: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": scenario})
}

// CreateScenario creates a new scenario.
//
// POST /api/v1/hunting/scenarios
// Body: {"name":"Webshell Hunt","description":"...","icon":"Shield","color":"emerald"}
func CreateScenario(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetUserID(c)

	var req scenarioRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	scenario := models.HuntingScenario{
		Name:        strings.TrimSpace(req.Name),
		Slug:        slugify(req.Name),
		Description: req.Description,
		Icon:        req.Icon,
		Color:       req.Color,
		CreatedBy:   userID,
	}

	if err := db.Create(&scenario).Error; err != nil {
		log.Printf("[hunting] create scenario: %v", err)
		c.JSON(http.StatusConflict, gin.H{"success": false, "error": "failed to create scenario (name may already exist)"})
		return
	}

	writeAudit(c, db, &userID, nil, "scenario.create", scenario.ID.String(),
		fmt.Sprintf("created hunting scenario %q", scenario.Name))

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": scenario})
}

// UpdateScenario updates name/description/icon/color of a scenario.
//
// PUT /api/v1/hunting/scenarios/:id
func UpdateScenario(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetUserID(c)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scenario id"})
		return
	}

	var req scenarioRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	var scenario models.HuntingScenario
	if err := db.First(&scenario, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "scenario not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	scenario.Name = strings.TrimSpace(req.Name)
	scenario.Slug = slugify(req.Name)
	scenario.Description = req.Description
	scenario.Icon = req.Icon
	scenario.Color = req.Color
	if err := db.Save(&scenario).Error; err != nil {
		log.Printf("[hunting] update scenario: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to update scenario"})
		return
	}

	writeAudit(c, db, &userID, nil, "scenario.update", scenario.ID.String(),
		fmt.Sprintf("updated scenario %q", scenario.Name))

	c.JSON(http.StatusOK, gin.H{"success": true, "data": scenario})
}

// DeleteScenario removes a scenario and (via CASCADE) all its tool links.
// Existing deployments/jobs are preserved; deployment_id on those jobs simply
// orphans without affecting their execution history.
//
// DELETE /api/v1/hunting/scenarios/:id
func DeleteScenario(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetUserID(c)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scenario id"})
		return
	}

	if err := db.Delete(&models.HuntingScenario{}, "id = ?", id).Error; err != nil {
		log.Printf("[hunting] delete scenario: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to delete scenario"})
		return
	}

	writeAudit(c, db, &userID, nil, "scenario.delete", id.String(), "deleted hunting scenario")
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"id": id}})
}

// ---------------------------------------------------------------------------
// Scenario tools
// ---------------------------------------------------------------------------

type addScenarioToolRequest struct {
	ToolID    string `json:"tool_id" binding:"required"`
	SortOrder int    `json:"sort_order"`
}

// AddScenarioTool attaches a tool to a scenario.
//
// POST /api/v1/hunting/scenarios/:id/tools
func AddScenarioTool(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetUserID(c)

	scenarioID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scenario id"})
		return
	}

	var req addScenarioToolRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	toolID, err := uuid.Parse(req.ToolID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid tool id"})
		return
	}

	var scenario models.HuntingScenario
	if err := db.First(&scenario, "id = ?", scenarioID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "scenario not found"})
		return
	}
	var tool models.Tool
	if err := db.First(&tool, "id = ?", toolID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "tool not found"})
		return
	}

	link := models.HuntingScenarioTool{
		ScenarioID: scenarioID,
		ToolID:     toolID,
		SortOrder:  req.SortOrder,
	}
	if err := db.Create(&link).Error; err != nil {
		// Unique constraint — tool already in scenario.
		c.JSON(http.StatusConflict, gin.H{"success": false, "error": "tool already attached to scenario"})
		return
	}

	db.Preload("Tool").First(&link, "id = ?", link.ID)

	writeAudit(c, db, &userID, nil, "scenario.tool.add", scenarioID.String(),
		fmt.Sprintf("attached tool %q to scenario %q", tool.Name, scenario.Name))

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": link})
}

// RemoveScenarioTool detaches a tool from a scenario.
//
// DELETE /api/v1/hunting/scenarios/:id/tools/:toolId
func RemoveScenarioTool(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetUserID(c)

	scenarioID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scenario id"})
		return
	}
	toolID, err := uuid.Parse(c.Param("toolId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid tool id"})
		return
	}

	res := db.Where("scenario_id = ? AND tool_id = ?", scenarioID, toolID).
		Delete(&models.HuntingScenarioTool{})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to detach tool"})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "tool not attached to scenario"})
		return
	}

	writeAudit(c, db, &userID, nil, "scenario.tool.remove", scenarioID.String(), "detached tool from scenario")
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// ---------------------------------------------------------------------------
// Deploy
// ---------------------------------------------------------------------------

type deployScenarioRequest struct {
	AgentID string `json:"agent_id" binding:"required"`
	CaseID  string `json:"case_id"`
}

// DeployScenario creates one Job per tool in the scenario and dispatches each
// over WebSocket. Uses default Tool.Args (no per-scenario override). All jobs
// share the same DeploymentID so the UI can group them.
//
// POST /api/v1/hunting/scenarios/:id/deploy
// Body: {"agent_id":"..."}
func DeployScenario(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	hub, ok := mustGetHub(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetUserID(c)

	scenarioID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scenario id"})
		return
	}

	var req deployScenarioRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	agentID, err := uuid.Parse(req.AgentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid agent id"})
		return
	}

	var scenario models.HuntingScenario
	if err := db.Preload("Tools.Tool").First(&scenario, "id = ?", scenarioID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "scenario not found"})
		return
	}
	if len(scenario.Tools) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "scenario has no tools attached"})
		return
	}

	var agent models.Agent
	if err := db.First(&agent, "id = ?", agentID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "agent not found"})
		return
	}

	deployment := models.HuntingDeployment{
		ScenarioID: scenarioID,
		AgentID:    agentID,
		CreatedBy:  userID,
	}
	if req.CaseID != "" {
		if cid, err := uuid.Parse(req.CaseID); err == nil {
			deployment.CaseID = &cid
		}
	}
	if err := db.Create(&deployment).Error; err != nil {
		log.Printf("[hunting] create deployment: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to create deployment"})
		return
	}

	serverURL := getServerURL(c)
	createdJobs := make([]models.Job, 0, len(scenario.Tools))
	dispatchErrors := make([]string, 0)

	for _, link := range scenario.Tools {
		tool := link.Tool
		depID := deployment.ID
		job := models.Job{
			AgentID:      agentID,
			ToolID:       tool.ID,
			Args:         tool.Args, // use default args defined when tool was uploaded
			DeploymentID: &depID,
			Status:       models.JobPending,
			CreatedBy:    userID,
		}
		if err := db.Create(&job).Error; err != nil {
			log.Printf("[hunting] create job for tool %s: %v", tool.ID, err)
			dispatchErrors = append(dispatchErrors, fmt.Sprintf("%s: db create failed", tool.Name))
			continue
		}

		downloadURL := fmt.Sprintf("%s/api/v1/agent/tools/%s/download", serverURL, tool.ID)
		cmd := ws.AgentCommand{
			Type:           "job_start",
			JobID:          job.ID.String(),
			ToolID:         tool.ID.String(),
			ToolName:       tool.Name,
			FileName:       tool.FileName,
			DownloadURL:    downloadURL,
			Args:           tool.Args,
			ExecutablePath: tool.ExecutablePath,
			CollectResult:   tool.CollectResult,
			OutputGlobs:     tool.OutputGlobs,
			OutputScope:     tool.OutputScope,
			ResultProcessor: tool.ResultProcessor,
			MaxResultMB:     tool.MaxResultMB,
		}
		if derr := hub.SendJobToAgent(agentID.String(), cmd); derr != nil {
			log.Printf("[hunting] dispatch %s to agent %s: %v", tool.Name, agentID, derr)
			db.Model(&job).Updates(map[string]interface{}{
				"status": models.JobFailed,
				"output": fmt.Sprintf("agent not connected: %v", derr),
			})
			job.Status = models.JobFailed
			dispatchErrors = append(dispatchErrors, fmt.Sprintf("%s: %v", tool.Name, derr))
		}
		db.Preload("Tool").First(&job, "id = ?", job.ID)
		createdJobs = append(createdJobs, job)
	}

	writeAudit(c, db, &userID, &agentID, "scenario.deploy", deployment.ID.String(),
		fmt.Sprintf("deployed scenario %q (%d tools) to agent %q", scenario.Name, len(createdJobs), agent.Name))

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data": gin.H{
			"deployment":      deployment,
			"jobs":            createdJobs,
			"dispatch_errors": dispatchErrors,
		},
	})
}

// ---------------------------------------------------------------------------
// Deployments
// ---------------------------------------------------------------------------

// ListDeployments returns recent deployments with their scenario, agent, and
// jobs preloaded so the UI can render the management tab in one round-trip.
//
// GET /api/v1/hunting/deployments
func ListDeployments(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}

	var deployments []models.HuntingDeployment
	q := db.
		Preload("Scenario").
		Preload("Agent").
		Preload("Jobs", func(tx *gorm.DB) *gorm.DB {
			return tx.Order("created_at asc")
		}).
		Preload("Jobs.Tool").
		Order("created_at desc")

	if scenarioID := c.Query("scenario_id"); scenarioID != "" {
		if _, err := uuid.Parse(scenarioID); err == nil {
			q = q.Where("scenario_id = ?", scenarioID)
		}
	}
	if agentID := c.Query("agent_id"); agentID != "" {
		if _, err := uuid.Parse(agentID); err == nil {
			q = q.Where("agent_id = ?", agentID)
		}
	}

	if err := q.Find(&deployments).Error; err != nil {
		log.Printf("[hunting] list deployments: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to list deployments"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": deployments})
}

// GetDeployment returns one deployment by id.
//
// GET /api/v1/hunting/deployments/:id
func GetDeployment(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid deployment id"})
		return
	}
	var deployment models.HuntingDeployment
	if err := db.
		Preload("Scenario").
		Preload("Agent").
		Preload("Jobs", func(tx *gorm.DB) *gorm.DB { return tx.Order("created_at asc") }).
		Preload("Jobs.Tool").
		First(&deployment, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "deployment not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": deployment})
}

// DeleteDeployment removes a deployment row. Underlying jobs are kept (they
// retain a dangling deployment_id pointer, harmless).
//
// DELETE /api/v1/hunting/deployments/:id
func DeleteDeployment(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetUserID(c)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid deployment id"})
		return
	}

	// Detach jobs first — set deployment_id = NULL so the FK constraint allows
	// the deployment row to be removed. Underlying jobs (and their output /
	// artifacts) are preserved and remain accessible via the Jobs page.
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&models.Job{}).
			Where("deployment_id = ?", id).
			Update("deployment_id", nil).Error; err != nil {
			return err
		}
		return tx.Delete(&models.HuntingDeployment{}, "id = ?", id).Error
	})
	if err != nil {
		log.Printf("[hunting] delete deployment: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to delete deployment"})
		return
	}

	writeAudit(c, db, &userID, nil, "deployment.delete", id.String(), "deleted deployment record")
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"id": id}})
}

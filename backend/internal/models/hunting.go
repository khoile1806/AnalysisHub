package models

import (
	"time"

	"github.com/google/uuid"
)

// HuntingScenario groups a curated set of tools under a named attack scenario
// (e.g. "Webshell", "Ransomware"). An operator can deploy a scenario to an
// agent in one click — the backend creates one job per tool, the agent
// provisions each tool, and the operator runs them individually from the
// Deployments tab.
type HuntingScenario struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Name        string    `gorm:"not null;uniqueIndex"                           json:"name"`
	Slug        string    `gorm:"not null;uniqueIndex"                           json:"slug"`
	Description string    `                                                      json:"description"`
	Icon        string    `                                                      json:"icon"`  // lucide icon name, e.g. "ShieldAlert"
	Color       string    `                                                      json:"color"` // tailwind color token, e.g. "emerald"
	CreatedBy   uuid.UUID `gorm:"type:uuid"                                      json:"created_by"`
	CreatedAt   time.Time `                                                      json:"created_at"`
	UpdatedAt   time.Time `                                                      json:"updated_at"`

	Tools []HuntingScenarioTool `gorm:"foreignKey:ScenarioID;constraint:OnDelete:CASCADE" json:"tools,omitempty"`
}

// HuntingScenarioTool is the M:N join between a scenario and the tools it
// will deploy. Order controls display order in the UI.
type HuntingScenarioTool struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"                json:"id"`
	ScenarioID uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_scenario_tool,priority:1"   json:"scenario_id"`
	ToolID     uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_scenario_tool,priority:2"   json:"tool_id"`
	Tool       Tool      `gorm:"foreignKey:ToolID"                                             json:"tool,omitempty"`
	SortOrder  int       `gorm:"default:0"                                                     json:"sort_order"`
	CreatedAt  time.Time `                                                                     json:"created_at"`
}

// HuntingDeployment records a single batch deploy of a scenario to an agent.
// Each row is linked to N Jobs via Job.DeploymentID.
type HuntingDeployment struct {
	ID         uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	ScenarioID uuid.UUID       `gorm:"type:uuid;not null"                             json:"scenario_id"`
	Scenario   HuntingScenario `gorm:"foreignKey:ScenarioID"                          json:"scenario,omitempty"`
	AgentID    uuid.UUID       `gorm:"type:uuid;not null"                             json:"agent_id"`
	Agent      Agent           `gorm:"foreignKey:AgentID"                             json:"agent,omitempty"`
	CreatedBy  uuid.UUID       `gorm:"type:uuid"                                      json:"created_by"`
	CreatedAt  time.Time       `                                                      json:"created_at"`

	Jobs []Job `gorm:"foreignKey:DeploymentID" json:"jobs,omitempty"`
}

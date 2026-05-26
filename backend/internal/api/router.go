package api

import (
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/api/handlers"
	"github.com/forensichub/backend/internal/api/middleware"
	"github.com/forensichub/backend/internal/config"
	"github.com/forensichub/backend/internal/storage"
	"github.com/forensichub/backend/internal/wpscan"
	"github.com/forensichub/backend/internal/ws"
)

// NewRouter builds the ForensicHub (slim) Gin engine. Forensic & Hunting +
// Threat Intel only — offensive surface (Recon / OSINT / Catch / Videos)
// lives in the sibling OffSecHub repo.
func NewRouter(
	db *gorm.DB,
	hub *ws.Hub,
	store *storage.LocalStorage,
	rdb *redis.Client,
	cfg *config.Config,
	wpscanPool *wpscan.Pool,
) *gin.Engine {
	router := gin.New()

	handlers.SetAllowedOrigins(cfg.AllowedOrigins)

	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(middleware.CORS(cfg.AllowedOrigins))

	jwtSecret := cfg.JWTSecret

	router.Use(func(c *gin.Context) {
		c.Set("db", db)
		c.Set("hub", hub)
		c.Set("storage", store)
		c.Set("redis", rdb)
		c.Set("jwtSecret", jwtSecret)
		c.Set("nvdAPIKey", cfg.NVDAPIKey)
		c.Set("githubToken", cfg.GitHubToken)
		c.Set("aesEncryptionKey", cfg.AESEncryptionKey)
		c.Set("wpscanPool", wpscanPool)
		c.Set("config", cfg)
		if cfg.PublicURL != "" {
			c.Set("serverURL", cfg.PublicURL)
		}
		c.Set("useHTTPS", cfg.UseHTTPS)
		c.Next()
	})

	// WebSocket — agents + interactive admin terminal.
	router.GET("/ws/agent", middleware.AgentAuthMiddleware(db), handlers.AgentWebSocket)
	router.GET("/ws/terminal", middleware.AuthMiddleware(jwtSecret), handlers.TerminalWebSocket)

	v1 := router.Group("/api/v1")

	auth := v1.Group("/auth")
	{
		auth.POST("/login", handlers.Login)
		auth.GET("/me", middleware.AuthMiddleware(jwtSecret), handlers.Me)
	}

	protected := v1.Group("/")
	protected.Use(middleware.AuthMiddleware(jwtSecret))
	{
		// Tools
		protected.GET("/tools", handlers.ListTools)
		protected.POST("/tools", handlers.UploadTool)
		protected.GET("/tools/:id", handlers.GetTool)
		protected.PUT("/tools/:id", handlers.UpdateTool)
		protected.DELETE("/tools/:id", handlers.DeleteTool)
		protected.GET("/tools/:id/download", handlers.DownloadTool)

		// Agents
		protected.GET("/agents", handlers.ListAgents)
		protected.POST("/agents", handlers.CreateAgent)
		protected.GET("/agents/:id", handlers.GetAgent)
		protected.DELETE("/agents/:id", handlers.DeleteAgent)
		protected.GET("/agents/:id/installer", handlers.GetAgentInstaller)
		protected.GET("/agents/:id/monitor", handlers.GetAgentMonitor)
		protected.POST("/agents/:id/cleanup", handlers.CleanupAgent)

		// Filesystem browser
		protected.GET("/agents/:id/fs", handlers.ListAgentFS)
		protected.GET("/agents/:id/fs/download", handlers.DownloadAgentPath)
		protected.POST("/agents/:id/fs/download-bundle", handlers.DownloadAgentBundle)
		protected.GET("/agents/binary/:platform", handlers.DownloadAgentBinary)

		// Jobs
		protected.GET("/jobs", handlers.ListJobs)
		protected.POST("/jobs", handlers.CreateJob)
		protected.GET("/jobs/:id", handlers.GetJob)
		protected.DELETE("/jobs/:id", handlers.DeleteJob)
		protected.GET("/jobs/:id/output", handlers.StreamJobOutput)
		protected.POST("/jobs/:id/run", handlers.RunJob)
		protected.POST("/jobs/:id/stop", handlers.StopJob)
		protected.GET("/jobs/:id/artifact/download", handlers.DownloadArtifact)
		protected.GET("/jobs/:id/artifact/content", handlers.GetArtifactContent)

		// CVE Intel
		protected.GET("/cve/search", handlers.SearchCVE)
		protected.GET("/cve/:id", handlers.GetCVE)
		protected.GET("/cve/:id/pocs", handlers.GetCVEPoCs)
		protected.GET("/cve/:id/iocs", handlers.GetCVERelatedIOCs)

		// OpenCTI Integration + IOC store
		protected.GET("/opencti/config", handlers.GetOpenCTIConfig)
		protected.PUT("/opencti/config", handlers.SaveOpenCTIConfig)
		protected.POST("/opencti/sync", handlers.SyncOpenCTI)
		protected.GET("/iocs", handlers.ListIOCs)
		protected.POST("/iocs", handlers.CreateManualIOC)

		// ELK Hunt
		protected.GET("/elk/config", handlers.GetELKConfig)
		protected.PUT("/elk/config", handlers.SaveELKConfig)
		protected.POST("/elk/hunt", handlers.RunELKHunt)
		protected.GET("/elk/hunt/stream", handlers.StreamELKAutoHunt)

		// CVE Collection
		protected.GET("/cve-collection", handlers.GetCVECollection)
		protected.GET("/cve-collection/stream", handlers.StreamCVECollection)
		protected.POST("/cve-collection", handlers.AddToCVECollection)
		protected.DELETE("/cve-collection/:id", handlers.DeleteFromCVECollection)

		// News (used by CVE → News tab inside ForensicHub).
		protected.GET("/news", handlers.GetNews)
		protected.GET("/news/categories", handlers.GetNewsCategories)
		protected.GET("/news/stream", handlers.StreamNews)
	}

	// Install scripts — handler validates the agent token inline.
	v1.GET("/agents/:id/install.ps1", handlers.GetAgentInstallScript)
	v1.GET("/agents/:id/install.sh", handlers.GetAgentInstallScript)

	// Agent-authenticated endpoints
	agentProtected := v1.Group("/")
	agentProtected.Use(middleware.AgentAuthMiddleware(db))
	{
		agentProtected.POST("/jobs/:id/artifact", handlers.UploadArtifact)
		agentProtected.GET("/agent/tools/:id/download", handlers.DownloadTool)
		agentProtected.GET("/agent/binary/:platform", handlers.DownloadAgentBinary)
	}

	return router
}

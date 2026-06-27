package api

import (
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/api/handlers"
	"github.com/forensichub/backend/internal/api/middleware"
	"github.com/forensichub/backend/internal/config"
	"github.com/forensichub/backend/internal/osint"
	"github.com/forensichub/backend/internal/storage"
	"github.com/forensichub/backend/internal/threatintel"
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
	enrich *threatintel.EnrichClient,
	osintEngine *osint.Engine,
) *gin.Engine {
	router := gin.New()
	// Allow large multipart uploads (memory dumps, disk images) to be streamed
	// to OS temp files rather than buffered in RAM. The default 32 MB causes
	// Go's multipart parser to try to hold the whole file in memory once the
	// threshold is crossed — on a 4 GB .mem file that OOMs the process.
	// Setting this to 8 GB means files up to 8 GB stay on disk (temp) during
	// the upload; the handler only reads what it needs.
	router.MaxMultipartMemory = 8 << 30 // 8 GB

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
		c.Set("osintEngine", osintEngine)
		c.Set("jwtSecret", jwtSecret)
		c.Set("nvdAPIKey", cfg.NVDAPIKey)
		c.Set("githubToken", cfg.GitHubToken)
		c.Set("aesEncryptionKey", cfg.AESEncryptionKey)
		c.Set("config", cfg)
		if cfg.PublicURL != "" {
			c.Set("serverURL", cfg.PublicURL)
		}
		c.Set("useHTTPS", cfg.UseHTTPS)
		c.Next()
	})

	// WebSocket — agents + interactive admin terminal.
	router.GET("/ws/agent", middleware.AgentAuthMiddleware(db), handlers.AgentWebSocket)
	router.GET("/ws/terminal", middleware.AuthMiddleware(jwtSecret, db), handlers.TerminalWebSocket)

	v1 := router.Group("/api/v1")

	auth := v1.Group("/auth")
	{
		auth.POST("/login", handlers.Login)
		auth.GET("/me", middleware.AuthMiddleware(jwtSecret, db), handlers.Me)
	}

	protected := v1.Group("/")
	protected.Use(middleware.AuthMiddleware(jwtSecret, db), middleware.AuditMiddleware())
	{
		// Hunting (Sigma Engine)
		protected.POST("/hunting/sigma/scan", handlers.SigmaScan)
		protected.POST("/hunting/sigma/sync", handlers.SigmaSync)

		// Entity origin tracing (process/file/app lineage from EdgeForensics/EVTX).
		protected.POST("/trace/entity", handlers.TraceEntity)

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
		protected.PATCH("/agents/:id", handlers.UpdateAgent)
		protected.DELETE("/agents/:id", handlers.DeleteAgent)
		protected.GET("/agents/:id/installer", handlers.GetAgentInstaller)
		protected.GET("/agents/:id/monitor", handlers.GetAgentMonitor)
		protected.POST("/agents/:id/cleanup", handlers.CleanupAgent)
		protected.POST("/agents/:id/registry", handlers.AgentRegistryParse)
		protected.POST("/agents/:id/evtx", handlers.AgentEvtxParse)
		protected.POST("/agents/:id/mft", handlers.AgentMFTParse)
		protected.POST("/agents/:id/prefetch", handlers.AgentPrefetchParse)
		protected.POST("/agents/:id/processes-scan", handlers.AgentProcessParse)
		protected.POST("/agents/:id/autoruns", handlers.AgentAutorunsParse)
		protected.POST("/agents/:id/netscan", handlers.AgentNetworkParse)
		protected.POST("/agents/:id/dlls", handlers.AgentDllsParse)
		protected.POST("/agents/:id/shimcache", handlers.AgentShimcacheParse)
		protected.POST("/agents/:id/browser", handlers.AgentBrowserParse)
		protected.POST("/agents/:id/triage", handlers.AgentTriageCollect)
		protected.POST("/agents/:id/ioc-sweep", handlers.AgentIOCSweep)
		protected.POST("/agents/:id/baseline", handlers.SetAgentBaseline)
		protected.GET("/agents/:id/baseline", handlers.GetAgentBaseline)
		protected.POST("/agents/:id/kill", handlers.AgentKillProcess)

		// Filesystem browser
		protected.GET("/agents/:id/fs", handlers.ListAgentFS)
		protected.GET("/agents/:id/fs/download", handlers.DownloadAgentPath)
		protected.POST("/agents/:id/fs/download-bundle", handlers.DownloadAgentBundle)
		protected.GET("/agents/binary/:platform", handlers.DownloadAgentBinary)

		// Fleet management — groups/tags, bulk collection, scheduled collections.
		fleetHandler := handlers.NewFleetHandler(db)
		protected.GET("/agents/groups", fleetHandler.ListAgentGroups)
		protected.PATCH("/agents/:id/tags", fleetHandler.SetAgentTags)
		protected.POST("/agents/bulk/collect", fleetHandler.BulkCollect)
		protected.GET("/agents/fleet/results", fleetHandler.ListFleetResults)
		protected.GET("/agents/fleet/results/:id", fleetHandler.GetFleetResult)
		protected.GET("/agents/scheduled-collections", fleetHandler.ListSchedules)
		protected.POST("/agents/scheduled-collections", fleetHandler.CreateSchedule)
		protected.PATCH("/agents/scheduled-collections/:id", fleetHandler.UpdateSchedule)
		protected.DELETE("/agents/scheduled-collections/:id", fleetHandler.DeleteSchedule)

		// Jobs
		protected.GET("/jobs", handlers.ListJobs)
		protected.POST("/jobs", handlers.CreateJob)
		protected.GET("/jobs/:id", handlers.GetJob)
		protected.DELETE("/jobs/:id", handlers.DeleteJob)
		protected.GET("/jobs/:id/output", handlers.StreamJobOutput)
		protected.GET("/jobs/:id/report", handlers.GetJobReport)
		protected.POST("/jobs/:id/run", handlers.RunJob)
		protected.POST("/jobs/:id/stop", handlers.StopJob)
		protected.GET("/jobs/:id/artifact/download", handlers.DownloadArtifact)
		protected.GET("/jobs/:id/artifact/content", handlers.GetArtifactContent)

		// Offline Bundles
		protected.GET("/offline-bundles", handlers.ListOfflineBundles)
		protected.POST("/offline-bundles/generate", handlers.GenerateOfflineBundle)

		// Hunting Scenarios
		protected.GET("/hunting/scenarios", handlers.ListScenarios)
		protected.POST("/hunting/scenarios", handlers.CreateScenario)
		protected.GET("/hunting/scenarios/:id", handlers.GetScenario)
		protected.PUT("/hunting/scenarios/:id", handlers.UpdateScenario)
		protected.DELETE("/hunting/scenarios/:id", handlers.DeleteScenario)
		protected.POST("/hunting/scenarios/:id/tools", handlers.AddScenarioTool)
		protected.DELETE("/hunting/scenarios/:id/tools/:toolId", handlers.RemoveScenarioTool)
		protected.POST("/hunting/scenarios/:id/deploy", handlers.DeployScenario)
		protected.GET("/hunting/deployments", handlers.ListDeployments)
		protected.GET("/hunting/deployments/:id", handlers.GetDeployment)
		protected.DELETE("/hunting/deployments/:id", handlers.DeleteDeployment)

		// CVE Intel
		protected.GET("/cve/search", handlers.SearchCVE)
		protected.GET("/cve/:id", handlers.GetCVE)
		protected.GET("/cve/:id/pocs", handlers.GetCVEPoCs)
		protected.GET("/cve/:id/iocs", handlers.GetCVERelatedIOCs)

		// OpenCTI Integration + IOC store
		protected.GET("/opencti/config", handlers.GetOpenCTIConfig)
		protected.PUT("/opencti/config", handlers.SaveOpenCTIConfig)
		protected.GET("/opencti/configs", handlers.ListOpenCTIConfigs)
		protected.POST("/opencti/configs", handlers.CreateOpenCTIConfig)
		protected.PUT("/opencti/configs/:id", handlers.UpdateOpenCTIConfig)
		protected.DELETE("/opencti/configs/:id", handlers.DeleteOpenCTIConfig)
		protected.POST("/opencti/configs/:id/activate", handlers.ActivateOpenCTIConfig)
		protected.POST("/opencti/sync", handlers.SyncOpenCTI)
		protected.GET("/iocs", handlers.ListIOCs)
		protected.POST("/iocs", handlers.CreateManualIOC)
		protected.POST("/iocs/bulk", handlers.BulkCreateIOCs)
		protected.DELETE("/iocs/:id", handlers.DeleteIOC)
		// Batch IOC matching — any scan view highlights values already in the store.
		protected.POST("/iocs/match", handlers.MatchIOCs)

		// On-demand threat-intel lookup (VirusTotal + configured sources).
		intelHandler := handlers.NewIntelHandler(enrich)
		protected.GET("/intel/lookup", intelHandler.Lookup)

		// ELK Hunt — config (multi-profile) + manual + auto + file-based hunts.
		protected.GET("/elk/config", handlers.GetELKConfig)
		protected.PUT("/elk/config", handlers.SaveELKConfig)
		protected.GET("/elk/configs", handlers.ListELKConfigs)
		protected.GET("/elk/indices", handlers.GetELKIndices)
		protected.POST("/elk/configs", handlers.CreateELKConfig)
		protected.PUT("/elk/configs/:id", handlers.UpdateELKConfig)
		protected.DELETE("/elk/configs/:id", handlers.DeleteELKConfig)
		protected.POST("/elk/configs/:id/activate", handlers.ActivateELKConfig)
		protected.POST("/elk/hunt", handlers.RunELKHunt)
		protected.GET("/elk/hunt/stream", handlers.StreamELKAutoHunt)
		protected.POST("/elk/iocs/parse", handlers.ParseIOCFile)
		protected.GET("/elk/hunt/file-stream", handlers.StreamELKFileHunt)
		protected.POST("/elk/hunt/file-stream", handlers.StreamELKFileHunt)
		protected.GET("/elk/hunt/results", handlers.ListELKHuntResults)
		protected.GET("/elk/hunt/results/:id", handlers.GetELKHuntResult)
		protected.DELETE("/elk/hunt/results/:id", handlers.DeleteELKHuntResult)
		protected.POST("/elk/hunt/results/:id/promote-timeline", handlers.NewTimelineHandler(db).PromoteELKResult)

		// Splunk Hunt
		protected.GET("/splunk/config", handlers.GetSplunkConfig)
		protected.GET("/splunk/configs", handlers.ListSplunkConfigs)
		protected.POST("/splunk/configs", handlers.CreateSplunkConfig)
		protected.PUT("/splunk/configs/:id", handlers.UpdateSplunkConfig)
		protected.DELETE("/splunk/configs/:id", handlers.DeleteSplunkConfig)
		protected.POST("/splunk/configs/:id/activate", handlers.ActivateSplunkConfig)
		protected.GET("/splunk/indices", handlers.GetSplunkIndices)
		protected.POST("/splunk/hunt", handlers.RunSplunkHunt)
		protected.GET("/splunk/hunt/stream", handlers.StreamSplunkAutoHunt)
		protected.POST("/splunk/hunt/file-stream", handlers.StreamSplunkFileHunt)
		protected.GET("/splunk/hunt/file-stream", handlers.StreamSplunkFileHunt)

		// QRadar Hunt
		protected.GET("/qradar/config", handlers.GetQRadarConfig)
		protected.GET("/qradar/configs", handlers.ListQRadarConfigs)
		protected.POST("/qradar/configs", handlers.CreateQRadarConfig)
		protected.PUT("/qradar/configs/:id", handlers.UpdateQRadarConfig)
		protected.DELETE("/qradar/configs/:id", handlers.DeleteQRadarConfig)
		protected.POST("/qradar/configs/:id/activate", handlers.ActivateQRadarConfig)
		protected.POST("/qradar/hunt", handlers.RunQRadarHunt)
		protected.GET("/qradar/hunt/stream", handlers.StreamQRadarAutoHunt)
		protected.POST("/qradar/hunt/file-stream", handlers.StreamQRadarFileHunt)
		protected.GET("/qradar/hunt/file-stream", handlers.StreamQRadarFileHunt)

		// OSINT footprinting — passive entity intelligence (IP/domain/email/phone/username)
		protected.POST("/osint", handlers.CreateOsintScan)
		protected.POST("/osint/detect", handlers.DetectOsintTarget)
		protected.GET("/osint", handlers.ListOsintScans)
		protected.GET("/osint/:id", handlers.GetOsintScan)
		protected.POST("/osint/:id/stop", handlers.StopOsintScan)
		protected.DELETE("/osint/:id", handlers.DeleteOsintScan)
		protected.GET("/osint/:id/findings", handlers.GetOsintFindings)
		protected.GET("/osint/:id/stream", handlers.StreamOsintOutput)
		protected.GET("/osint/:id/report", handlers.OsintReport)
		protected.GET("/osint/:id/export", handlers.OsintExport)
		protected.GET("/osint/:id/graph", handlers.GetOsintGraph)
		protected.GET("/osint/:id/graph/export", handlers.ExportOsintGraph)
		protected.GET("/osint/:id/correlations", handlers.GetOsintCorrelations)
		protected.GET("/osint/:id/location", handlers.GetOsintLocation)
		protected.GET("/osint/:id/identity", handlers.GetOsintIdentity)
		protected.POST("/osint/extract-image-geo", handlers.ExtractImageGeo)
		protected.POST("/osint/:id/add-photo-geo", handlers.AddScanPhotoGeo)
		protected.POST("/osint/extract-doc-meta", handlers.ExtractDocMeta)
		protected.POST("/osint/email-permute", handlers.EmailPermute)
		protected.POST("/osint/reverse-image", handlers.ReverseImage)
		protected.POST("/osint/promote-ioc", handlers.PromoteOsintIOC)

		// OSINT watchlist — continuous monitoring (A4). Static "watches" segment
		// sits alongside the "/osint/:id" param routes.
		protected.GET("/osint/watches", handlers.ListOsintWatches)
		protected.POST("/osint/watches", handlers.CreateOsintWatch)
		protected.PATCH("/osint/watches/:id", handlers.UpdateOsintWatch)
		protected.DELETE("/osint/watches/:id", handlers.DeleteOsintWatch)
		protected.POST("/osint/watches/:id/run", handlers.RunOsintWatchNow)
		protected.GET("/osint/watches/:id/alerts", handlers.ListOsintWatchAlerts)
		protected.POST("/osint/watches/:id/alerts/seen", handlers.MarkOsintWatchAlertsSeen)

		// CVE Collection
		protected.GET("/cve-collection", handlers.GetCVECollection)
		protected.GET("/cve-collection/stream", handlers.StreamCVECollection)
		protected.POST("/cve-collection", handlers.AddToCVECollection)
		protected.DELETE("/cve-collection/:id", handlers.DeleteFromCVECollection)

		// Volatility Memory Analysis
		protected.GET("/memory/dumps", handlers.ListMemoryDumps)
		protected.POST("/memory/upload", handlers.UploadMemoryDump)
		protected.DELETE("/memory/dumps/:filename", handlers.DeleteMemoryDump)

		// News (used by CVE → News tab inside ForensicHub).
		protected.GET("/news", handlers.GetNews)
		protected.GET("/news/categories", handlers.GetNewsCategories)
		protected.GET("/news/stream", handlers.StreamNews)

		// Cases
		casesHandler := handlers.NewCasesHandler(db)
		protected.GET("/cases", casesHandler.ListCases)
		protected.POST("/cases", casesHandler.CreateCase)
		protected.PATCH("/cases/:id", casesHandler.UpdateCase)
		protected.DELETE("/cases/:id", casesHandler.DeleteCase)
		protected.GET("/cases/:id/summary", casesHandler.GetCaseSummary)
		protected.GET("/cases/:id/report", casesHandler.CaseReport)
		protected.POST("/cases/:id/import-offline-report", casesHandler.ImportOfflineReport)

		// Attack Timeline
		timelineHandler := handlers.NewTimelineHandler(db)
		protected.GET("/cases/:id/timeline", timelineHandler.ListTimeline)
		protected.GET("/cases/:id/timeline/super", timelineHandler.SuperTimeline)
		protected.POST("/cases/:id/timeline/build-super", timelineHandler.BuildSuperTimeline)
		protected.POST("/cases/:id/timeline/from-trace", timelineHandler.AddTraceToTimeline)
		protected.GET("/cases/:id/attack-coverage", timelineHandler.AttackCoverage)
		protected.POST("/cases/:id/import-artifacts", timelineHandler.ImportArtifacts)
		protected.POST("/cases/:id/timeline", timelineHandler.CreateTimelineEvent)
		protected.PATCH("/timeline/:id", timelineHandler.UpdateTimelineEvent)
		protected.DELETE("/timeline/:id", timelineHandler.DeleteTimelineEvent)

		// Case Evidence files (result uploads with host attribution)
		evidenceHandler := handlers.NewEvidenceHandler(db, store)
		protected.POST("/cases/:id/evidence", evidenceHandler.Upload)
		protected.GET("/cases/:id/evidence", evidenceHandler.List)
		protected.DELETE("/evidence/:id", evidenceHandler.Delete)
		protected.GET("/evidence/:id/download", evidenceHandler.Download)
		protected.GET("/evidence/:id/view", evidenceHandler.View)

		// Evidence Collection Checklist
		protected.POST("/checklist/run", handlers.RunChecklist)
		protected.GET("/checklist/runs", handlers.ListChecklistRuns)
		protected.GET("/checklist/runs/:id", handlers.GetChecklistRun)
		protected.GET("/checklist/batches/:id/output", handlers.StreamBatchOutput)
		protected.GET("/checklist/batches/:id/download", handlers.DownloadBatchOutput)

		// AI Analysis — provider management and analysis sessions
		aiHandler := handlers.NewAIHandler(db, store, cfg, enrich)
		protected.GET("/ai/providers", aiHandler.ListProviders)
		protected.POST("/ai/providers", aiHandler.CreateProvider)
		protected.PUT("/ai/providers/:id", aiHandler.UpdateProvider)
		protected.DELETE("/ai/providers/:id", aiHandler.DeleteProvider)
		protected.POST("/ai/providers/:id/test", aiHandler.TestProvider)
		protected.GET("/ai/sessions", aiHandler.ListSessions)
		protected.POST("/ai/sessions", aiHandler.CreateSession)
		protected.GET("/ai/sessions/:id", aiHandler.GetSession)
		protected.GET("/ai/sessions/:id/stream", aiHandler.StreamSession)
		protected.DELETE("/ai/sessions/:id", aiHandler.DeleteSession)
		protected.POST("/cases/:id/timeline/ai-extract", aiHandler.ExtractTimeline)
		protected.POST("/cases/:id/timeline/ai-rebuild", aiHandler.RebuildTimeline)
		protected.POST("/cases/:id/report/ai-summary", aiHandler.GenerateCaseSummary)
		protected.POST("/cases/:id/evidence/:evidenceId/extract-timeline", aiHandler.ExtractTimelineFromEvidence)
		protected.POST("/cases/:id/compliance/assess", aiHandler.AssessCompliance)
		// AI triage of an OSINT footprint (defensive summary + pivots)
		protected.POST("/osint/:id/triage", aiHandler.TriageOsintScan)
		// OCR → pivot: extract IOCs from an uploaded image (ransom note, screenshot)
		protected.POST("/osint/extract-image", aiHandler.ExtractOsintFromImage)

		// Compliance findings + report
		complianceHandler := handlers.NewComplianceHandler(db)
		protected.GET("/cases/:id/compliance/findings", complianceHandler.ListFindings)
		protected.DELETE("/cases/:id/compliance/findings", complianceHandler.DeleteFindings)
		protected.GET("/cases/:id/compliance/report", complianceHandler.GetReport)
		protected.GET("/cases/:id/compliance/snapshots", complianceHandler.ListSnapshots)
		protected.PATCH("/compliance/findings/:id", complianceHandler.UpdateFinding)

		// Canary Tokens — administrator tracking / honeytoken links. CRUD +
		// per-token hit log live behind auth; the public redirect endpoint
		// (/c/:slug) is registered separately below.
		canaryHandler := handlers.NewCanaryHandler(db)
		protected.GET("/canary/tokens", canaryHandler.ListCanaryTokens)
		protected.POST("/canary/tokens", canaryHandler.CreateCanaryToken)
		protected.POST("/canary/tokens/bulk", canaryHandler.BulkCreateCanaryTokens)
		protected.POST("/canary/tokens/upload", canaryHandler.CreateCanaryFileToken)
		protected.GET("/canary/tokens/:id", canaryHandler.GetCanaryToken)
		protected.PATCH("/canary/tokens/:id", canaryHandler.UpdateCanaryToken)
		protected.DELETE("/canary/tokens/:id", canaryHandler.DeleteCanaryToken)
		protected.GET("/canary/tokens/:id/file", canaryHandler.DownloadCanaryFile)
		protected.GET("/canary/tokens/:id/hits", canaryHandler.ListCanaryHits)
		protected.DELETE("/canary/tokens/:id/hits", canaryHandler.DeleteCanaryHits)
		protected.POST("/canary/tokens/:id/hits/:hitId/scan", canaryHandler.ScanCanaryHit)
		// In-app alert feed/badge for canary hits.
		protected.GET("/canary/alerts", canaryHandler.ListCanaryAlerts)
		protected.GET("/canary/alerts/count", canaryHandler.CountCanaryAlerts)
		protected.POST("/canary/alerts/seen", canaryHandler.MarkCanaryAlertsSeen)

		// System — health check and usage statistics
		sysHandler := handlers.NewSystemHandler(db, rdb, store, hub)
		protected.GET("/system/health", sysHandler.GetHealth)
		protected.GET("/system/token-stats", sysHandler.GetTokenStats)
		protected.GET("/system/proxy", sysHandler.GetProxyStatus)
		protected.POST("/system/proxy/validate", sysHandler.ValidateProxy)
	}

	// Public canary endpoint — no auth so the tracking link works for any
	// visitor. GET records IP / User-Agent / Geo then redirects (or serves the
	// data-collecting interstitial); POST receives that interstitial's client
	// report. Mounted at the root (not under /api/v1) so links stay short.
	canaryPublic := handlers.NewCanaryHandler(db)
	router.GET("/c/:slug", canaryPublic.ServeCanary)
	router.POST("/c/:slug", canaryPublic.CollectCanary)

	// Install scripts — handler validates the agent token inline.
	v1.GET("/agents/:id/install.ps1", handlers.GetAgentInstallScript)
	v1.GET("/agents/:id/install.sh", handlers.GetAgentInstallScript)

	agentProtected := v1.Group("/")
	agentProtected.Use(middleware.AgentAuthMiddleware(db), middleware.AuditMiddleware())
	{
		agentProtected.POST("/jobs/:id/artifact", handlers.UploadArtifact)
		agentProtected.GET("/agent/tools/:id/download", handlers.DownloadTool)
		agentProtected.GET("/agent/binary/:platform", handlers.DownloadAgentBinary)
	}

	return router
}

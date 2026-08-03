package main

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/api"
	"github.com/analysishub/backend/internal/api/handlers"
	"github.com/analysishub/backend/internal/config"
	"github.com/analysishub/backend/internal/database"
	"github.com/analysishub/backend/internal/egress"
	"github.com/analysishub/backend/internal/hunting/sigma"
	"github.com/analysishub/backend/internal/logger"
	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/notify"
	"github.com/analysishub/backend/internal/oob"
	"github.com/analysishub/backend/internal/osint"
	"github.com/analysishub/backend/internal/storage"
	"github.com/analysishub/backend/internal/threatintel"
	"github.com/analysishub/backend/internal/updater"
	"github.com/analysishub/backend/internal/vulnscan"
	"github.com/analysishub/backend/internal/ws"
)

// applyOutboundProxy exports the configured outbound proxy into the process
// environment (HTTP_PROXY/HTTPS_PROXY/NO_PROXY, upper+lower case) so libraries
// and child processes that honour the standard proxy env vars route through it
// too. The controlled egress layer (internal/egress) remains the primary path;
// this is belt-and-suspenders for third-party clients. An empty proxy is a no-op
// so the environment is left untouched.
func applyOutboundProxy(cfg *config.Config) {
	if strings.TrimSpace(cfg.OutboundProxy) == "" {
		return
	}
	noProxy := config.EffectiveNoProxy(cfg.OutboundNoProxy)
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
		os.Setenv(k, cfg.OutboundProxy)
	}
	for _, k := range []string{"NO_PROXY", "no_proxy"} {
		os.Setenv(k, noProxy)
	}
}

func main() {
	// ------------------------------------------------------------------ //
	// 1. Load .env (ignore error if file is absent — env vars may be set
	//    directly, e.g. in Docker / Kubernetes).
	// ------------------------------------------------------------------ //
	// godotenv.Load() only reads ./.env (the process CWD). When the server is run
	// locally from backend/ the .env actually lives one level up at the repo root,
	// so try both — Docker already injects the vars via env_file, making this a
	// harmless no-op there.
	if err := godotenv.Load(); err != nil {
		if err := godotenv.Load("../.env", "../../.env"); err != nil {
			slog.Info(".env file not found, using environment variables")
		}
	}

	// ------------------------------------------------------------------ //
	// 2. Load application configuration
	// ------------------------------------------------------------------ //
	cfg := config.Load()

	// Log presence (never the value) of the outbound API keys so a missing/unloaded
	// NVD key — the usual cause of slow, throttled CVE searches — is obvious at boot.
	slog.Info("outbound API keys",
		"nvd_api_key", maskPresence(cfg.NVDAPIKey),
		"github_token", maskPresence(cfg.GitHubToken))

	// Initialize Sigma Engine
	sigma.Init("tools/sigma-rules")

	// Project-wide egress proxy. Held in a live config (internal/egress) so it can
	// be changed at runtime with no restart, with periodic health checking and an
	// optional auto-fall-back to direct when the proxy is down. We point the
	// default transport (used by threat-intel, CVE, AI, news, notify, OOB enrich)
	// at egress.Proxy; OSINT collectors reference it directly. Internal SIEM
	// connectors keep their own proxy-less transports and bypass it by design.
	egress.Init(cfg.OutboundProxy, config.EffectiveNoProxy(cfg.OutboundNoProxy), cfg.OutboundProxyFallback, cfg.OutboundProxyProbe)
	// Also export the proxy into the process environment so third-party libraries
	// and child processes (scanner subprocesses) that honour HTTP_PROXY/NO_PROXY
	// route through it too — belt-and-suspenders alongside the egress layer.
	applyOutboundProxy(cfg)
	if tr, ok := http.DefaultTransport.(*http.Transport); ok {
		tr.Proxy = egress.Proxy
		// Wrap the default transport so every default-client request (threat-intel,
		// CVE, AI, news, notify, OOB enrich) is recorded by the Proxy Manager flow
		// log. The flow sink stays nil until the recorder is registered below, so
		// this is a no-op until then.
		http.DefaultTransport = egress.NewLoggingTransport(tr)
	}
	egress.StartHealthCheck(60 * time.Second)
	if cfg.OutboundProxy != "" {
		slog.Info("outbound proxy enabled (live + health-checked)", "fallback_direct", cfg.OutboundProxyFallback)
	}

	// ------------------------------------------------------------------ //
	// 2.5 Initialise file-based logging
	// ------------------------------------------------------------------ //
	cleanupLogs := logger.Setup(cfg.LogPath)
	defer cleanupLogs()

	slog.Info("starting AnalysisHub", "env", cfg.AppEnv, "port", cfg.ServerPort)

	// ------------------------------------------------------------------ //
	// 3. Connect to PostgreSQL and run migrations
	// ------------------------------------------------------------------ //
	db, err := database.Init(cfg.PostgresDSN, cfg.AppEnv)
	if err != nil {
		slog.Error("database init failed", "error", err)
		os.Exit(1)
	}

	// Proxy Manager: start the egress flow recorder (ring + rolling DB history)
	// and restore the active proxy profile so a switch survives a restart. A saved
	// active profile takes precedence over the OUTBOUND_PROXY env default.
	egress.SetFlowSink(handlers.NewProxyFlowRecorder(db).Sink)
	handlers.SetLeakNotifier(notify.New(cfg.NotifyWebhookURL, cfg.NotifyTelegramToken, cfg.NotifyTelegramChat))
	if cfg.OutboundProxy != "" {
		egress.SetActiveLabel("env")
	}
	// Restore every active profile (one per egress lane: default / osint / vulnscan)
	// so a switch survives a restart.
	var activeProxies []models.ProxyProfile
	if err := db.Where("is_active = ?", true).Find(&activeProxies).Error; err == nil {
		for i := range activeProxies {
			handlers.ApplyActiveProxyProfile(activeProxies[i])
			slog.Info("restored active proxy profile", "name", activeProxies[i].Name, "lane", activeProxies[i].Lane)
		}
		egress.CheckNow()
	}
	// Arm the kill-switch from persisted settings.
	var poolSetting models.ProxyPoolSetting
	if err := db.First(&poolSetting, 1).Error; err == nil {
		egress.SetKillSwitch(poolSetting.KillSwitch)
	}
	// Pool automation (failover / rotation); a no-op while mode is manual.
	handlers.StartProxyPoolAutomation(db)
	// Periodic exit-identity drift watch on active profiles.
	handlers.StartProxyIdentityRefresh(db, 15*time.Minute)

	// ------------------------------------------------------------------ //
	// 4. Connect to Redis
	// ------------------------------------------------------------------ //
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       0,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := rdb.Ping(ctx).Result(); err != nil {
		slog.Warn("redis connection warning (continuing without Redis cache)", "error", err)
	} else {
		slog.Info("redis connected")
	}

	// ------------------------------------------------------------------ //
	// 5. Initialise local file storage
	// ------------------------------------------------------------------ //
	store, err := storage.New(cfg.StoragePath)
	if err != nil {
		slog.Error("storage init failed", "error", err)
		os.Exit(1)
	}
	slog.Info("storage initialised", "path", cfg.StoragePath)

	// ------------------------------------------------------------------ //
	// 6. Seed admin user (idempotent)
	// ------------------------------------------------------------------ //
	if err := seedAdmin(db, cfg.AdminEmail, cfg.AdminPassword); err != nil {
		slog.Error("seed admin failed", "error", err)
		os.Exit(1)
	}
	if err := seedTools(db, store); err != nil {
		slog.Warn("seed tools warning", "error", err)
	}
	if err := seedScenarios(db); err != nil {
		slog.Warn("seed scenarios warning", "error", err)
	}

	// ------------------------------------------------------------------ //
	// 7. Create and start the WebSocket hub
	// ------------------------------------------------------------------ //
	hub := ws.NewHub()

	// Batched, order-preserving writer for streamed job output — one append per
	// job per flush interval instead of a DB write per line.
	jobOutput := handlers.NewJobOutputBuffer(db, 0)
	defer jobOutput.Stop()

	// Wire output persistence: every line streamed from an agent is appended
	// to the job's output column; when done==true the job is marked complete.
	hub.OnOutput = func(jobID, data string, done bool) {
		if done {
			// Flush any buffered output before finalizing so the transcript is
			// complete when the job is marked done.
			jobOutput.Flush(jobID)
			// Only mark as "done" if the job is still running. A stopped job
			// (status=stopped) must not be overwritten to done when the
			// cancelled process's final output flush arrives.
			finishedAt := time.Now()
			db.Model(&models.Job{}).
				Where("id = ? AND status = ?", jobID, models.JobRunning).
				Updates(map[string]interface{}{
					"status":      models.JobDone,
					"finished_at": finishedAt,
				})
			return
		}
		if data == "" {
			return
		}
		jobOutput.Append(jobID, data)
	}

	// When the agent reports a lifecycle transition (ready/stopped), reflect
	// it in the DB. Running/done/failed are driven by OnOutput + handlers.
	hub.OnJobStatus = func(jobID, status string) {
		switch status {
		case "ready":
			db.Model(&models.Job{}).
				Where("id = ? AND status = ?", jobID, models.JobPending).
				Update("status", models.JobReady)
		case "stopped":
			jobOutput.Flush(jobID)
			now := time.Now()
			db.Model(&models.Job{}).
				Where("id = ?", jobID).
				Updates(map[string]interface{}{
					"status":      models.JobStopped,
					"finished_at": now,
				})
		}
	}

	go hub.Run()
	slog.Info("WebSocket hub started")

	// Finalize any work left mid-flight by a previous crash/restart (agent jobs,
	// fleet collection results, OSINT scans) so nothing is stuck "running" in the
	// UI. Runs before workers/agents come online to avoid racing live work.
	handlers.RecoverStuckWork(db)

	// Root lifecycle context for background workers — cancelled on shutdown so
	// their tick loops stop cleanly instead of racing the DB pool close.
	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()
	handlers.SetWorkerContext(workerCtx)
	// Install the DB handle used by the fire-and-forget system-event recorder so
	// background health/self-heal signals are persisted.
	handlers.SetEventDB(db)

	// ------------------------------------------------------------------ //
	// 7.5 Start Background Workers
	// ------------------------------------------------------------------ //
	handlers.StartCVEUpdateWorker(hub)
	handlers.StartNewsUpdateWorker(hub)
	handlers.StartFleetScheduler(db, hub)
	handlers.StartToolResultWorker(db, store, cfg)
	handlers.StartStuckJobWatcher(db)
	handlers.StartWorkerWatchdog(10 * time.Minute)
	handlers.StartAgentMetricsWorker(db)
	handlers.StartRetentionWorker(db, store, cfg)

	// Threat intel enrichment client — used by the AI analysis pipeline to
	// automatically look up IPs, hashes, and domains before sending the
	// forensic prompt to the AI model.
	enrichClient := threatintel.New(cfg.VirusTotalKeys, cfg.AbuseIPDBKey, cfg.AlienVaultKey, cfg.ShodanKey)
	enrichClient.UseRedis(rdb) // shared cache: enrichment survives restarts, shared across instances
	if enrichClient.Configured() {
		slog.Info("threat intel client initialised",
			"vt_keys", len(cfg.VirusTotalKeys), "abuseipdb", cfg.AbuseIPDBKey != "", "otx", cfg.AlienVaultKey != "", "shodan", cfg.ShodanKey != "")
	} else {
		slog.Info("threat intel: no API keys configured — IOC enrichment disabled")
	}

	// OSINT footprinting engine — passive entity intelligence (IP/domain/email/
	// phone/username). Reputation collectors reuse the threat-intel API keys.
	vtKey := ""
	if len(cfg.VirusTotalKeys) > 0 {
		vtKey = cfg.VirusTotalKeys[0]
	}
	osintEngine := osint.NewEngine(workerCtx, db, osint.Keys{
		VirusTotal: vtKey,
		Shodan:     cfg.ShodanKey,
		AbuseIPDB:  cfg.AbuseIPDBKey,
		AlienVault: cfg.AlienVaultKey,
		HIBP:       cfg.OsintHIBPKey,
		NumVerify:  cfg.OsintNumVerifyKey,
		GitHub:     cfg.GitHubToken,
		AbuseCh:    cfg.AbuseChKey,
		Pulsedive:  cfg.PulsediveKey,
		GreyNoise:  cfg.GreyNoiseKey,
		OpenCorp:   cfg.OsintOpenCorpKey,
	}, cfg, enrichClient, rdb)
	slog.Info("osint engine initialised")

	// OOB interaction server ("Catch" — Interactsh / Burp-Collaborator style).
	// Records out-of-band DNS/HTTP/SMTP callbacks to confirm blind vulns on
	// authorised engagements. Listeners only start when OOB_ENABLED=true and a
	// delegated OOB_DOMAIN is set; otherwise the API still serves (register/poll)
	// but reports the server as not running.
	oobServer := oob.New(db, oob.Options{
		Enabled:    cfg.OOBEnabled,
		Domain:     cfg.OOBDomain,
		PublicIP:   cfg.OOBPublicIP,
		PublicIPv6: cfg.OOBPublicIPv6,
		NSName:     cfg.OOBNSName,
		DNSPort:    cfg.OOBDNSPort,
		HTTPPort:   cfg.OOBHTTPPort,
		HTTPSPort:  cfg.OOBHTTPSPort,
		SMTPPort:   cfg.OOBSMTPPort,
		TLSCert:    cfg.OOBTLSCert,
		TLSKey:     cfg.OOBTLSKey,
		LDAPPort:   cfg.OOBLDAPPort,
		RMIPort:    cfg.OOBRMIPort,
	})
	oobServer.Start()
	handlers.StartOobRetentionWorker(db, cfg.OOBRetentionDays, cfg.OOBMaxPerClient)

	// SSE hub for real-time OOB interaction streaming (no polling needed).
	oobHub := oob.NewHub()
	oobServer.SetHub(oobHub) // OAST (DNS/SMTP) captures also push live SSE events

	// Vulnerability scanner engine (httpx + nuclei over OSINT-discovered assets).
	// Marks any scan left mid-run by a crash as failed on construction.
	vulnEngine := vulnscan.NewEngine(db, cfg, handlers.NewCVEEnricher())
	slog.Info("vuln-scan engine initialised")

	// Warm the CISA KEV catalog now so the first CVE search doesn't block on the
	// multi-MB download.
	handlers.WarmCISACatalog()

	// ------------------------------------------------------------------ //
	// 7.6 Unified auto-updaters — one registry that keeps every tool/data
	//     source current on a schedule, with per-component status + manual
	//     refresh (surfaced under System → Auto-Update). news/CVE/KEV keep
	//     their own workers; this covers the tool data that used to be static.
	// ------------------------------------------------------------------ //
	registerUpdaters(cfg)
	// Persist a health event whenever an updater fails (or recovers after retries)
	// so failures survive restart and surface in System Health.
	updater.Default.OnResult(func(name string, success bool, attempt int, detail string) {
		if success {
			if attempt > 0 {
				handlers.RecordSystemEvent("updater", "info", name, "recovered after auto-retry", "")
			}
			return
		}
		handlers.RecordSystemEvent("updater", "error", name, "update failed", detail)
	})
	updater.Default.Start(context.Background())

	// ------------------------------------------------------------------ //
	// 8. Build Gin router
	// ------------------------------------------------------------------ //
	router := api.NewRouter(db, hub, store, rdb, cfg, enrichClient, osintEngine, oobServer, oobHub, vulnEngine)

	// ------------------------------------------------------------------ //
	// 9. Start HTTP server with graceful shutdown
	// ------------------------------------------------------------------ //
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%s", cfg.ServerPort),
		Handler: router,
		// ReadHeaderTimeout guards against slow-loris on the request line/headers
		// while allowing long bodies (large evidence uploads) and long responses.
		ReadHeaderTimeout: 20 * time.Second,
		// EdgeForensics scans (MFT walk + hashing, prefetch, process snapshots),
		// large disk-image uploads and live-response collections legitimately run
		// for minutes; the old 30s/60s limits cut them off mid-flight ("request
		// timed out" / no results). Match the 600s collector/axios budget + margin.
		ReadTimeout:  15 * time.Minute,
		WriteTimeout: 15 * time.Minute,
		IdleTimeout:  120 * time.Second,
	}

	// Run server in a goroutine so we can listen for OS signals concurrently.
	serverErr := make(chan error, 1)
	go func() {
		slog.Info("HTTP server listening", "port", cfg.ServerPort)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	// Block until we receive an interrupt / terminate signal or the server errors.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		slog.Info("shutting down gracefully", "signal", sig.String())
	case err := <-serverErr:
		slog.Error("server error", "error", err)
	}

	// Allow up to 30 seconds for in-flight requests to complete.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown error", "error", err)
	}

	// Stop background workers so their tick loops don't touch the DB/Redis during
	// the drain and close below.
	workerCancel()

	// Flush any buffered job output to the DB before the pool is closed (the
	// deferred Stop would otherwise run after db.Close and lose the final flush).
	jobOutput.Stop()

	// Stop the OOB interaction listeners (DNS/HTTP/SMTP).
	oobServer.Shutdown(shutdownCtx)

	// Close DB connection pool.
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.Close()
	}

	// Close Redis connection.
	rdb.Close()

	slog.Info("shutdown complete")
}

// registerUpdaters wires every self-updating tool/data source into the unified
// updater registry. CLI-tool updaters register only when the binary is present.
func registerUpdaters(cfg *config.Config) {
	const retirePath = "data/retirejs.json"
	// Prefer a previously-downloaded (fresher) retire.js DB over the embedded one.
	osint.InitRetireFromDisk(retirePath)

	m := updater.Default

	if cfg.VulnScanAutoUpdate {
		if _, err := exec.LookPath("nuclei"); err == nil {
			m.Register(updater.Spec{
				Name: "nuclei-templates", Description: "Nuclei vulnerability templates",
				Category: "cli-tool", Interval: 24 * time.Hour, Timeout: 20 * time.Minute,
				RunOnStart: true,
				Fn:         func(ctx context.Context) error { return vulnscan.UpdateNucleiTemplates(ctx, cfg) },
			})
		}
	}

	m.Register(updater.Spec{
		Name: "retirejs-db", Description: "retire.js JavaScript vulnerability database",
		Category: "embedded-db", Interval: 24 * time.Hour, Timeout: 2 * time.Minute,
		RunOnStart: true,
		Fn:         func(ctx context.Context) error { return osint.UpdateRetireJS(ctx, retirePath) },
	})

	m.Register(updater.Spec{
		Name: "cisa-kev", Description: "CISA Known Exploited Vulnerabilities catalog",
		Category: "catalog", Interval: 24 * time.Hour, Timeout: 30 * time.Second,
		RunOnStart: false, // WarmCISACatalog already primes it at boot
		Fn:         handlers.UpdateCISAKEV,
	})

	if _, err := exec.LookPath("cdncheck"); err == nil {
		m.Register(updater.Spec{
			Name: "cdncheck-data", Description: "cdncheck CDN/WAF provider IP ranges",
			Category: "cli-tool", Interval: 7 * 24 * time.Hour, Timeout: 5 * time.Minute,
			RunOnStart: true,
			Fn:         func(ctx context.Context) error { return vulnscan.UpdateCdncheck(ctx, cfg) },
		})
	}
	if _, err := exec.LookPath("wpscan"); err == nil {
		m.Register(updater.Spec{
			Name: "wpscan-db", Description: "WPScan WordPress vulnerability database",
			Category: "cli-tool", Interval: 7 * 24 * time.Hour, Timeout: 10 * time.Minute,
			RunOnStart: false,
			Fn:         func(ctx context.Context) error { return vulnscan.UpdateWpscan(ctx, cfg) },
		})
	}
}

// maskPresence reports whether a secret is configured without leaking its value,
// for safe startup logging.
func maskPresence(v string) string {
	if strings.TrimSpace(v) == "" {
		return "absent"
	}
	return "configured"
}

// seedAdmin creates the admin user if one with cfg.AdminEmail does not already
// exist, or updates it to match the .env configuration.
func seedAdmin(db *gorm.DB, email, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	var existing models.User
	err = db.Where("role = ?", "admin").First(&existing).Error
	if err == nil {
		// Admin already exists — update email and password to match config
		existing.Email = email
		existing.Password = string(hash)
		if err := db.Save(&existing).Error; err != nil {
			return fmt.Errorf("update admin: %w", err)
		}
		slog.Info("admin user synced from configuration", "email", email)
		return nil
	}
	if err != gorm.ErrRecordNotFound {
		return fmt.Errorf("query admin: %w", err)
	}

	admin := models.User{
		Email:    email,
		Password: string(hash),
		Role:     "admin",
	}
	if err := db.Create(&admin).Error; err != nil {
		return fmt.Errorf("create admin: %w", err)
	}
	slog.Info("admin user created", "email", email)
	return nil
}

// seedTools checks if essential integrated tools (like YARA Scanner) exist
// and registers them if missing, using pre-built bundles from /app/defaults.
func seedTools(db *gorm.DB, store *storage.LocalStorage) error {
	var count int64
	db.Model(&models.Tool{}).Where("name LIKE ?", "%YARA Scanner%").Count(&count)
	if count == 0 {
		defaultPath := "/app/defaults/yara-scanner.zip"
		if _, err := os.Stat(defaultPath); !os.IsNotExist(err) {
			slog.Info("seeding integrated YARA Scanner")

			toolID := uuid.New()
			tool := models.Tool{
				ID:             toolID,
				Name:           "YARA Scanner",
				Category:       "triage",
				Platform:       "both",
				Version:        "0.1.0",
				Description:    "Integrated multi-engine webshell scanner (Auto-seeded).",
				ExecutablePath: "{{OS}}/yara-scanner{{EXT}}",
				FileName:       "yara-scanner.zip",
				Args:           "scan ./ --out report",
			}

			src, err := os.Open(defaultPath)
			if err == nil {
				defer src.Close()
				info, _ := src.Stat()
				tool.FileSize = info.Size()

				storedName := toolID.String() + ".zip"
				if _, err := store.SaveTool(storedName, src); err != nil {
					slog.Error("failed to save tool file", "error", err)
				} else {
					if err := db.Create(&tool).Error; err != nil {
						slog.Error("failed to create tool record", "error", err)
					} else {
						slog.Info("integrated tool registered successfully", "name", tool.Name)
					}
				}
			}
		}
	}

	// Seed Memory Dump Tool
	var memCount int64
	db.Model(&models.Tool{}).Where("name = ?", "Live Memory Capture (WinPmem)").Count(&memCount)
	if memCount == 0 {
		memTool := models.Tool{
			ID:             uuid.New(),
			Name:           "Live Memory Capture (WinPmem)",
			Category:       "memory",
			Platform:       "windows",
			Version:        "4.0.1",
			Description:    "Captures raw physical memory from the target machine and streams it back.",
			ExecutablePath: "winpmem.exe",
			FileName:       "winpmem.exe",
			Args:           "memdump.raw", // Save to file so agent can upload it
		}

		pmemPath := "/app/defaults/winpmem.exe"
		src, err := os.Open(pmemPath)
		if err == nil {
			defer src.Close()
			info, _ := src.Stat()
			memTool.FileSize = info.Size()

			storedName := memTool.ID.String() + ".exe"
			if _, err := store.SaveTool(storedName, src); err != nil {
				slog.Error("failed to save winpmem file", "error", err)
			} else {
				if err := db.Create(&memTool).Error; err != nil {
					slog.Error("failed to create winpmem tool record", "error", err)
				} else {
					slog.Info("seeded Live Memory Capture tool record with default binary")
				}
			}
		} else {
			// fallback without file if running locally outside docker
			db.Create(&memTool)
			slog.Info("seeded Live Memory Capture tool record (no default binary found)")
		}
	} else {
		// Update args if it already exists (migration from previous version)
		db.Model(&models.Tool{}).Where("name = ?", "Live Memory Capture (WinPmem)").Update("args", "memdump.raw")
	}

	return nil
}

// seedScenarios inserts default Hunting scenarios if they don't already exist.
// Each scenario is created empty (no tools attached) — the operator picks
// which tools to attach via the UI. Scenarios remain fully editable.
func seedScenarios(db *gorm.DB) error {
	defaults := []models.HuntingScenario{
		{Name: "Webshell Hunt", Slug: "webshell-hunt", Description: "Detect webshells on compromised web servers.", Icon: "Shield", Color: "emerald"},
		{Name: "Ransomware Hunt", Slug: "ransomware-hunt", Description: "Identify ransomware artifacts, encrypted files, and persistence.", Icon: "Lock", Color: "rose"},
		{Name: "Lateral Movement", Slug: "lateral-movement", Description: "Hunt for RDP, SMB, WMI, and PsExec lateral movement evidence.", Icon: "Network", Color: "sky"},
		{Name: "Persistence", Slug: "persistence", Description: "Find scheduled tasks, services, registry run keys, and startup hooks.", Icon: "RefreshCw", Color: "amber"},
		{Name: "Memory Triage", Slug: "memory-triage", Description: "Live memory acquisition + volatile artifact collection.", Icon: "Cpu", Color: "violet"},
	}

	for _, sc := range defaults {
		var count int64
		db.Model(&models.HuntingScenario{}).Where("slug = ?", sc.Slug).Count(&count)
		if count > 0 {
			continue
		}
		if err := db.Create(&sc).Error; err != nil {
			log.Printf("[main] seed scenario %s: %v", sc.Slug, err)
			continue
		}
		slog.Info("seeded hunting scenario", "name", sc.Name)
	}
	return nil
}

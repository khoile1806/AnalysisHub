package main

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/api"
	"github.com/forensichub/backend/internal/api/handlers"
	"github.com/forensichub/backend/internal/config"
	"github.com/forensichub/backend/internal/database"
	"github.com/forensichub/backend/internal/hunting/sigma"
	"github.com/forensichub/backend/internal/logger"
	"github.com/forensichub/backend/internal/models"
	"github.com/forensichub/backend/internal/oob"
	"github.com/forensichub/backend/internal/osint"
	"github.com/forensichub/backend/internal/storage"
	"github.com/forensichub/backend/internal/threatintel"
	"github.com/forensichub/backend/internal/ws"
)

func main() {
	// ------------------------------------------------------------------ //
	// 1. Load .env (ignore error if file is absent — env vars may be set
	//    directly, e.g. in Docker / Kubernetes).
	// ------------------------------------------------------------------ //
	if err := godotenv.Load(); err != nil {
		slog.Info(".env file not found, using environment variables")
	}

	// ------------------------------------------------------------------ //
	// 2. Load application configuration
	// ------------------------------------------------------------------ //
	cfg := config.Load()

	// Initialize Sigma Engine
	sigma.Init("tools/sigma-rules")

	// Apply the project-wide egress proxy as early as possible (before any HTTP
	// client makes a request). Every external fetch that uses the default
	// transport or http.ProxyFromEnvironment then routes through it automatically;
	// internal SIEM connectors keep their own proxy-less transports and bypass it.
	applyOutboundProxy(cfg)

	// ------------------------------------------------------------------ //
	// 2.5 Initialise file-based logging
	// ------------------------------------------------------------------ //
	cleanupLogs := logger.Setup(cfg.LogPath)
	defer cleanupLogs()

	slog.Info("starting ForensicHub", "env", cfg.AppEnv, "port", cfg.ServerPort)

	// ------------------------------------------------------------------ //
	// 3. Connect to PostgreSQL and run migrations
	// ------------------------------------------------------------------ //
	db, err := database.Init(cfg.PostgresDSN, cfg.AppEnv)
	if err != nil {
		slog.Error("database init failed", "error", err)
		os.Exit(1)
	}

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

	// Wire output persistence: every line streamed from an agent is appended
	// to the job's output column; when done==true the job is marked complete.
	hub.OnOutput = func(jobID, data string, done bool) {
		if done {
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
		// Append line to the output text column (PostgreSQL concat).
		db.Exec(
			"UPDATE jobs SET output = COALESCE(output, '') || ? WHERE id = ?",
			data+"\n",
			jobID,
		)
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

	// ------------------------------------------------------------------ //
	// 7.5 Start Background Workers
	// ------------------------------------------------------------------ //
	handlers.StartCVEUpdateWorker(hub)
	handlers.StartNewsUpdateWorker(hub)
	handlers.StartFleetScheduler(db, hub)

	// Threat intel enrichment client — used by the AI analysis pipeline to
	// automatically look up IPs, hashes, and domains before sending the
	// forensic prompt to the AI model.
	enrichClient := threatintel.New(cfg.VirusTotalKeys, cfg.AbuseIPDBKey, cfg.AlienVaultKey, cfg.ShodanKey)
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
	osintEngine := osint.NewEngine(db, osint.Keys{
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

	// ------------------------------------------------------------------ //
	// 8. Build Gin router
	// ------------------------------------------------------------------ //
	router := api.NewRouter(db, hub, store, rdb, cfg, enrichClient, osintEngine, oobServer, oobHub)

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

// applyOutboundProxy installs the project-wide egress proxy by exporting the
// standard HTTP_PROXY/HTTPS_PROXY/NO_PROXY variables. Every HTTP client that
// uses the default transport or http.ProxyFromEnvironment (OSINT, threat-intel,
// CVE, news, AI) then routes through it automatically. Internal SIEM connectors
// keep proxy-less transports and are unaffected. Must run before the first
// outbound request so net/http caches the right config.
func applyOutboundProxy(cfg *config.Config) {
	p := strings.TrimSpace(cfg.OutboundProxy)
	if p == "" {
		return
	}
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
		_ = os.Setenv(k, p)
	}
	// Always keep loopback/local traffic (SIEM, Redis, DB health probes over
	// HTTP) off the proxy, plus any operator-supplied exceptions.
	noProxy := config.EffectiveNoProxy(cfg.OutboundNoProxy)
	_ = os.Setenv("NO_PROXY", noProxy)
	_ = os.Setenv("no_proxy", noProxy)
	slog.Info("outbound proxy enabled for external fetches", "proxy", p, "no_proxy", noProxy)
}

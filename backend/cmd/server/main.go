package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"github.com/google/uuid"

	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/api"
	"github.com/forensichub/backend/internal/api/handlers"
	"github.com/forensichub/backend/internal/config"
	"github.com/forensichub/backend/internal/database"
	"github.com/forensichub/backend/internal/models"
	"github.com/forensichub/backend/internal/storage"
	"github.com/forensichub/backend/internal/wpscan"
	"github.com/forensichub/backend/internal/ws"
)

func main() {
	// ------------------------------------------------------------------ //
	// 1. Load .env (ignore error if file is absent — env vars may be set
	//    directly, e.g. in Docker / Kubernetes).
	// ------------------------------------------------------------------ //
	if err := godotenv.Load(); err != nil {
		log.Println("[main] .env file not found, using environment variables")
	}

	// ------------------------------------------------------------------ //
	// 2. Load application configuration
	// ------------------------------------------------------------------ //
	cfg := config.Load()

	log.Printf("[main] starting ForensicHub (env=%s, port=%s)", cfg.AppEnv, cfg.ServerPort)

	// ------------------------------------------------------------------ //
	// 3. Connect to PostgreSQL and run migrations
	// ------------------------------------------------------------------ //
	db, err := database.Init(cfg.PostgresDSN, cfg.AppEnv)
	if err != nil {
		log.Fatalf("[main] database init failed: %v", err)
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
		log.Printf("[main] redis connection warning: %v (continuing without Redis cache)", err)
	} else {
		log.Println("[main] redis connected")
	}

	// ------------------------------------------------------------------ //
	// 5. Initialise local file storage
	// ------------------------------------------------------------------ //
	store, err := storage.New(cfg.StoragePath)
	if err != nil {
		log.Fatalf("[main] storage init failed: %v", err)
	}
	log.Printf("[main] storage initialised at %s", cfg.StoragePath)

	// ------------------------------------------------------------------ //
	// 6. Seed admin user (idempotent)
	// ------------------------------------------------------------------ //
	if err := seedAdmin(db, cfg.AdminEmail, cfg.AdminPassword); err != nil {
		log.Fatalf("[main] seed admin failed: %v", err)
	}
	if err := seedTools(db, store); err != nil {
		log.Printf("[main] seed tools warning: %v", err)
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
	log.Println("[main] WebSocket hub started")

	// ------------------------------------------------------------------ //
	// 7.5 Start Background Workers
	// ------------------------------------------------------------------ //
	handlers.StartCVEUpdateWorker(hub)
	handlers.StartNewsUpdateWorker(hub)

	// WPScan token pool — used by the CVE Intel handler for WordPress
	// plugin/core CVE lookups against the WPScan Vulnerability DB.
	wpscanPool := wpscan.NewPool(cfg.WPScanAPITokens)
	log.Printf("[main] wpscan token pool initialised (%d token(s))", len(wpscanPool.Tokens()))

	// ------------------------------------------------------------------ //
	// 8. Build Gin router
	// ------------------------------------------------------------------ //
	router := api.NewRouter(db, hub, store, rdb, cfg, wpscanPool)

	// ------------------------------------------------------------------ //
	// 9. Start HTTP server with graceful shutdown
	// ------------------------------------------------------------------ //
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.ServerPort),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Run server in a goroutine so we can listen for OS signals concurrently.
	serverErr := make(chan error, 1)
	go func() {
		log.Printf("[main] HTTP server listening on :%s", cfg.ServerPort)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	// Block until we receive an interrupt / terminate signal or the server errors.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		log.Printf("[main] received signal %s, shutting down gracefully", sig)
	case err := <-serverErr:
		log.Printf("[main] server error: %v", err)
	}

	// Allow up to 30 seconds for in-flight requests to complete.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[main] server shutdown error: %v", err)
	}

	// Close DB connection pool.
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.Close()
	}

	// Close Redis connection.
	rdb.Close()

	log.Println("[main] shutdown complete")
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
		log.Printf("[main] admin user %s synced from configuration", email)
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
	log.Printf("[main] admin user %s created", email)
	return nil
}

// seedTools checks if essential integrated tools (like Webshell Scanner) exist
// and registers them if missing, using pre-built bundles from /app/defaults.
func seedTools(db *gorm.DB, store *storage.LocalStorage) error {
	var count int64
	db.Model(&models.Tool{}).Where("name LIKE ?", "%Webshell Scanner%").Count(&count)
	if count > 0 {
		return nil
	}

	defaultPath := "/app/defaults/webshell-scanner.zip"
	if _, err := os.Stat(defaultPath); os.IsNotExist(err) {
		return nil // No bundle to seed
	}

	log.Println("[main] seeding integrated Webshell Scanner...")

	// 1. Create Tool Record
	toolID := uuid.New()
	tool := models.Tool{
		ID:             toolID,
		Name:           "Webshell Scanner",
		Category:       "triage",
		Platform:       "both",
		Version:        "0.1.0",
		Description:    "Integrated multi-engine webshell scanner (Auto-seeded).",
		ExecutablePath: "{{OS}}/webshell-scanner{{EXT}}",
		FileName:       "webshell-scanner.zip",
	}

	// 2. Copy file to storage
	src, err := os.Open(defaultPath)
	if err != nil {
		return err
	}
	defer src.Close()

	info, _ := src.Stat()
	tool.FileSize = info.Size()

	storedName := toolID.String() + ".zip"
	if _, err := store.SaveTool(storedName, src); err != nil {
		return fmt.Errorf("save tool file: %w", err)
	}

	// 3. Save to DB
	if err := db.Create(&tool).Error; err != nil {
		return fmt.Errorf("create tool record: %w", err)
	}

	log.Printf("[main] integrated tool %s registered successfully", tool.Name)
	return nil
}

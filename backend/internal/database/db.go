package database

import (
	"fmt"
	"log"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/forensichub/backend/internal/models"
)

// Init opens a GORM connection to PostgreSQL and runs AutoMigrate for all models.
// It returns the *gorm.DB instance ready for use.
func Init(dsn string, appEnv string) (*gorm.DB, error) {
	logLevel := logger.Silent
	if appEnv == "development" {
		logLevel = logger.Info
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
	})
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get underlying sql.DB: %w", err)
	}
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)
	sqlDB.SetConnMaxIdleTime(2 * time.Minute)

	// Enable the pgcrypto extension required by gen_random_uuid()
	if result := db.Exec("CREATE EXTENSION IF NOT EXISTS pgcrypto"); result.Error != nil {
		log.Printf("[db] could not create pgcrypto extension (may already exist): %v", result.Error)
	}

	// AutoMigrate all models in dependency order
	if err := db.AutoMigrate(
		&models.User{},
		&models.Agent{},
		&models.Tool{},
		&models.HuntingScenario{},
		&models.HuntingScenarioTool{},
		&models.HuntingDeployment{},
		&models.Job{},
		&models.AuditLog{},
		&models.OpenCTIConfig{},
		&models.ELKConfig{},
		&models.IOC{},
		&models.ChecklistRun{},
		&models.ChecklistBatch{},
	); err != nil {
		return nil, fmt.Errorf("auto migrate: %w", err)
	}

	// Backfill: legacy single-row ELK/OpenCTI configs predate the multi-profile
	// schema. Give them a name + active=true so they remain usable after the
	// new columns are added by AutoMigrate.
	db.Exec(`UPDATE elk_configs SET name = COALESCE(NULLIF(name, ''), 'Default'), is_active = TRUE WHERE name IS NULL OR name = ''`)
	db.Exec(`UPDATE open_cti_configs SET name = COALESCE(NULLIF(name, ''), 'Default'), is_active = TRUE WHERE name IS NULL OR name = ''`)

	log.Println("[db] migrations applied successfully")
	return db, nil
}

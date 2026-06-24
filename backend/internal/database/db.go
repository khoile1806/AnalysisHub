package database

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
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
	if appEnv == "development" || strings.ToUpper(os.Getenv("LOG_LEVEL")) == "DEBUG" {
		logLevel = logger.Info // Info level in GORM prints all SQL queries
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
		slog.Warn("could not create pgcrypto extension (may already exist)", "error", result.Error)
	}

	// Pre-migrate: on a database that predates the dedupe key, backfill any empty
	// dedupe_key and collapse pre-existing duplicate findings so the UNIQUE index
	// built below can be created cleanly. The hash mirrors osint.dedupeKey:
	// sha256(source|category|title|value) lower/trimmed, value trailing-dot stripped.
	if db.Migrator().HasTable("osint_findings") {
		db.Exec(`UPDATE osint_findings SET dedupe_key = encode(digest(
			lower(btrim(source)) || '|' || lower(btrim(category)) || '|' ||
			lower(btrim(title)) || '|' || rtrim(lower(btrim(coalesce(value, ''))), '.'),
			'sha256'), 'hex')
			WHERE dedupe_key IS NULL OR dedupe_key = ''`)
		db.Exec(`DELETE FROM osint_findings a USING osint_findings b
			WHERE a.scan_id = b.scan_id AND a.dedupe_key = b.dedupe_key AND a.ctid > b.ctid`)
	}

	// AutoMigrate all models in dependency order
	if err := db.AutoMigrate(
		&models.User{},
		&models.Case{},
		&models.Agent{},
		&models.Tool{},
		&models.HuntingScenario{},
		&models.HuntingScenarioTool{},
		&models.HuntingDeployment{},
		&models.Job{},
		&models.AuditLog{},
		&models.OpenCTIConfig{},
		&models.ELKConfig{},
		&models.SplunkConfig{},
		&models.QRadarConfig{},
		&models.ELKHuntResult{},
		&models.IOC{},
		&models.ChecklistRun{},
		&models.ChecklistBatch{},
		&models.AIProvider{},
		&models.AnalysisSession{},
		&models.TimelineEvent{},
		&models.ComplianceFinding{},
		&models.ComplianceSnapshot{},
		&models.CaseEvidence{},
		&models.OsintScan{},
		&models.OsintCollector{},
		&models.OsintFinding{},
		&models.OsintWatch{},
		&models.OsintWatchAlert{},
	); err != nil {
		return nil, fmt.Errorf("auto migrate: %w", err)
	}

	// Backfill: legacy single-row ELK/OpenCTI configs predate the multi-profile
	// schema. Give them a name + active=true so they remain usable after the
	// new columns are added by AutoMigrate.
	db.Exec(`UPDATE elk_configs SET name = COALESCE(NULLIF(name, ''), 'Default'), is_active = TRUE WHERE name IS NULL OR name = ''`)
	db.Exec(`UPDATE open_cti_configs SET name = COALESCE(NULLIF(name, ''), 'Default'), is_active = TRUE WHERE name IS NULL OR name = ''`)

	// Ensure the OSINT findings dedupe index exists and is UNIQUE on
	// (scan_id, dedupe_key). This is done in raw SQL rather than an AutoMigrate
	// tag so it is robust on existing databases: any pre-existing non-unique
	// index of the same name is dropped first, then the unique one is (re)created.
	// Both steps are best-effort — a failure here (e.g. residual duplicates) is
	// logged and must NOT abort startup, so the rest of the platform stays up.
	// The OSINT dedupe path also degrades gracefully when the index is absent.
	if err := db.Exec(`DROP INDEX IF EXISTS idx_osint_finding_dedupe`).Error; err != nil {
		slog.Warn("could not drop legacy OSINT dedupe index", "error", err)
	}
	if err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_osint_finding_dedupe ON osint_findings (scan_id, dedupe_key)`).Error; err != nil {
		slog.Warn("could not create unique OSINT dedupe index; finding dedupe will run in best-effort mode", "error", err)
	}

	slog.Info("migrations applied successfully")
	return db, nil
}

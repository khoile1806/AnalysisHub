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

	"github.com/analysishub/backend/internal/models"
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
		&models.CanaryToken{},
		&models.CanaryHit{},
		&models.CanaryAlert{},
		&models.OobClient{},
		&models.OobInteraction{},
		&models.OobResponseRule{},
		&models.AgentBaseline{},
		&models.ScheduledCollection{},
		&models.FleetCollectionResult{},
		&models.VulnScan{},
		&models.VulnTool{},
		&models.VulnFinding{},
		&models.ProxyProfile{},
		&models.ProxyFlow{},
		&models.ProxyPoolSetting{},
		&models.ProxyHealthSample{},
		&models.OsintScopeRule{},
		&models.OsintScopeSetting{},
		&models.LogIngestJob{},
		&models.TechStackSession{},
	); err != nil {
		return nil, fmt.Errorf("auto migrate: %w", err)
	}

	seedOsintScopePolicy(db)

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

	// Vulnerability-scan finding dedupe: same (scan_id, dedupe_key) pattern so the
	// streaming nuclei inserter can ON CONFLICT DO NOTHING without duplicating a
	// re-emitted match.
	if err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_finding_dedupe ON vuln_findings (scan_id, dedupe_key)`).Error; err != nil {
		slog.Warn("could not create unique vuln-scan dedupe index; finding dedupe will run in best-effort mode", "error", err)
	}

	// Partial unique index so automated timeline ingestion (super-timeline, ELK
	// promote, artifact import) is idempotent, while manual events (empty
	// dedupe_key) are exempt and can always be added.
	if err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_timeline_dedupe ON timeline_events (case_id, dedupe_key) WHERE dedupe_key <> ''`).Error; err != nil {
		slog.Warn("could not create timeline dedupe index; timeline dedupe will run in best-effort mode", "error", err)
	}

	// Functional index on lower(value) so the case-insensitive IOC lookups
	// (MatchIOCs / IOC-sweep use_store: `WHERE lower(value) IN (...)`) use an
	// index instead of a full table scan — essential when the IOC store grows
	// very large (millions of rows / TB-scale).
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_iocs_lower_value ON iocs (lower(value))`).Error; err != nil {
		slog.Warn("could not create iocs lower(value) index; large-store IOC lookups may be slow", "error", err)
	}

	// OOB "Catch" interactions: a composite index for the hot per-session,
	// newest-first query, plus pg_trgm GIN indexes so the `?q=` substring search
	// (ILIKE '%term%') uses an index instead of a full table scan as the table
	// grows. CREATE EXTENSION needs privileges; all steps are best-effort and
	// search still works (just slower) without them.
	if err := db.Exec(`CREATE EXTENSION IF NOT EXISTS pg_trgm`).Error; err != nil {
		slog.Warn("could not enable pg_trgm; OOB search will run unindexed", "error", err)
	}
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_oob_inter_client_created ON oob_interactions (client_id, created_at DESC)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_oob_inter_path_trgm ON oob_interactions USING gin (path gin_trgm_ops)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_oob_inter_raw_trgm ON oob_interactions USING gin (raw_request gin_trgm_ops)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_oob_inter_ua_trgm ON oob_interactions USING gin (user_agent gin_trgm_ops)`)

	// IOC substring search (CVE→related-IOC lookup uses `description LIKE '%CVE-…%'
	// OR value LIKE '%CVE-…%'`). A leading wildcard can't use a b-tree, so these
	// pg_trgm GIN indexes turn the otherwise full table scan into an index scan.
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_iocs_description_trgm ON iocs USING gin (description gin_trgm_ops)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_iocs_value_trgm ON iocs USING gin (value gin_trgm_ops)`)

	slog.Info("migrations applied successfully")
	return db, nil
}

// seedOsintScopePolicy installs the default OSINT scope policy on first run. It
// is keyed on the singleton settings row: once that exists the policy is left
// entirely to the administrator (so clearing all rules is respected and never
// re-seeded). The defaults are conservative — active/target-touching collectors
// only run against EXTERNAL targets over ANONYMIZED egress; everything else is
// passive-only so a recon never quietly leaks the operator's real IP.
func seedOsintScopePolicy(db *gorm.DB) {
	var count int64
	if err := db.Model(&models.OsintScopeSetting{}).Count(&count).Error; err != nil || count > 0 {
		return // settings exist (or table unavailable) → admin owns the policy now
	}
	if err := db.Create(&models.OsintScopeSetting{
		ID: 1, Enforce: true, AllowOverride: true,
		InternalDomains: "local\ncorp\ninternal\nlan",
	}).Error; err != nil {
		slog.Warn("could not seed OSINT scope settings", "error", err)
		return
	}
	defaults := []models.OsintScopeRule{
		{Priority: 10, Name: "Internal targets — passive only", Enabled: true,
			MatchTargetType: "any", MatchScope: "internal", MatchEgress: "any",
			Action: "passive_only", RequireProxy: false},
		{Priority: 20, Name: "Direct egress — passive only (protect real IP)", Enabled: true,
			MatchTargetType: "any", MatchScope: "any", MatchEgress: "direct",
			Action: "passive_only", RequireProxy: false},
		{Priority: 30, Name: "External + anonymized — full recon", Enabled: true,
			MatchTargetType: "any", MatchScope: "external", MatchEgress: "anonymized",
			Action: "all", RequireProxy: false},
	}
	if err := db.Create(&defaults).Error; err != nil {
		slog.Warn("could not seed OSINT scope rules", "error", err)
	}
}

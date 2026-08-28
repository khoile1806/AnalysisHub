package handlers

import (
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/models"
)

// ioc_lifecycle.go — the two things every match path has to do: ignore
// indicators that should no longer match, and remember the ones that did.
//
// An IOC store that never ages is mostly wrong. A C2 address is reassigned
// within weeks and then belongs to a hosting provider's next customer; a
// takedown domain gets parked. Matching on those forever produces confident
// alerts about innocent infrastructure, and each one costs an analyst the time
// to disprove it. Expiry is what stops the store from slowly becoming a false-
// positive generator.
//
// The hit counter is the other half. Without it there is no way to tell the
// twenty indicators doing the work from the twenty thousand that have never
// matched anything, so nobody can prune with confidence and the store only grows.

// ActiveIOCs scopes a query to indicators that should still be matched: enabled,
// and either non-expiring or not yet expired.
func ActiveIOCs(db *gorm.DB) *gorm.DB {
	return db.Where("enabled = ?", true).
		Where("expires_at IS NULL OR expires_at > ?", time.Now().UTC())
}

// RecordIOCHits bumps the hit counter for the indicators that matched.
//
// Best-effort and fire-and-forget: a statistic must never be able to fail a
// detection path. It runs in one UPDATE rather than per row, and is a no-op for
// an empty match set.
func RecordIOCHits(db *gorm.DB, values []string) {
	if db == nil || len(values) == 0 {
		return
	}
	now := time.Now().UTC()
	err := db.Model(&models.IOC{}).
		Where("lower(value) IN ?", values).
		Updates(map[string]interface{}{
			"hit_count":   gorm.Expr("hit_count + 1"),
			"last_hit_at": now,
			"last_seen":   now,
		}).Error
	if err != nil {
		log.Printf("[ioc] hit counter update failed: %v", err)
	}
}

// ExpireStaleIOCs disables indicators whose expiry has passed. Called on the
// same worker clock as the feed refresh.
//
// Disabled rather than deleted: the record of what was once considered malicious
// is evidence in itself, and an analyst looking at an old case needs to see the
// indicator that fired at the time.
func ExpireStaleIOCs(db *gorm.DB) int64 {
	if db == nil {
		return 0
	}
	res := db.Model(&models.IOC{}).
		Where("enabled = ?", true).
		Where("expires_at IS NOT NULL AND expires_at <= ?", time.Now().UTC()).
		Update("enabled", false)
	if res.Error != nil {
		log.Printf("[ioc] expiry sweep failed: %v", res.Error)
		return 0
	}
	return res.RowsAffected
}

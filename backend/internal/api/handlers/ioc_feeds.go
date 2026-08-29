package handlers

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/threatintel"
)

// ioc_feeds.go — keeping the IOC store current without anybody clicking.
//
// The store previously only grew when an operator typed indicators in or ran a
// manual OpenCTI sync, and nothing ever removed anything. That makes it a
// snapshot of whenever somebody last bothered, which is the opposite of what
// threat intelligence is for: attacker infrastructure moves, and a store that
// does not move with it reports on hosts that changed hands months ago.
//
// Two halves, on the same clock. The refresh pulls current indicators in; the
// expiry sweep retires the ones whose time is up. Neither is useful alone — a
// feed with no expiry just makes the store bigger and noisier.

const (
	// iocFeedInterval is how often the feeds are re-pulled. The upstream lists
	// update continuously; an hour keeps the store current without being a
	// nuisance to free, community-run infrastructure.
	iocFeedInterval = 1 * time.Hour
	// iocFeedBatchSize is how many indicators go in one INSERT.
	iocFeedBatchSize = 500
)

// feedHTTPClient is separate from the enrichment client: a feed download is a
// large body on a slow connection, not a small API call.
var feedHTTPClient = &http.Client{Timeout: 90 * time.Second}

// iocFeedsEnabled reports whether automatic ingestion is on. Off by default is
// wrong for a threat-intel feature — the whole point is currency — so it is on
// unless explicitly disabled, and it makes no outbound request until the first
// tick so an air-gapped install can turn it off before then.
func iocFeedsEnabled() bool {
	return !strings.EqualFold(strings.TrimSpace(os.Getenv("IOC_FEEDS_DISABLED")), "true")
}

// abuseChKey reuses the key the platform already asks for. ABUSE_CH_API_KEY is
// documented in .env.example and unlocks threatfox/urlhaus/malwarebazaar; a
// second name for the same credential would just be one more thing to get wrong.
func abuseChKey() string {
	if k := strings.TrimSpace(os.Getenv("ABUSE_CH_API_KEY")); k != "" {
		return k
	}
	return strings.TrimSpace(os.Getenv("ABUSECH_AUTH_KEY"))
}

// StartIOCFeedWorker refreshes the IOC store on a schedule and ages out what has
// expired. Mirrors StartNewsUpdateWorker's shape so bootstrap stays uniform.
func StartIOCFeedWorker(db *gorm.DB) {
	if db == nil {
		return
	}
	if !iocFeedsEnabled() {
		log.Println("[ioc-feeds] disabled by IOC_FEEDS_DISABLED")
		return
	}
	log.Println("[ioc-feeds] starting background IOC feed worker...")
	go func() {
		safeLoop("ioc-feeds", func() { RefreshIOCFeeds(db) })
		runWorker("ioc-feeds", iocFeedInterval, func() { RefreshIOCFeeds(db) })
	}()
}

// FeedRefreshResult reports what one refresh did, per feed.
type FeedRefreshResult struct {
	Feed    string `json:"feed"`
	Fetched int    `json:"fetched"`
	Created int    `json:"created"`
	Updated int    `json:"updated"`
	Error   string `json:"error,omitempty"`
}

// RefreshIOCFeeds pulls every configured feed and upserts the results, then
// retires anything expired. Returns one row per feed so the API and the log can
// say what actually happened rather than "done".
func RefreshIOCFeeds(db *gorm.DB) []FeedRefreshResult {
	ctx, cancel := context.WithTimeout(workerCtx, 10*time.Minute)
	defer cancel()

	var out []FeedRefreshResult
	for _, f := range threatintel.DefaultFeeds() {
		res := FeedRefreshResult{Feed: f.Name}
		items, err := threatintel.FetchFeed(ctx, feedHTTPClient, f, abuseChKey())
		if err != nil {
			// A feed being down is normal and must not stop the others, nor look
			// like "there is nothing bad out there".
			res.Error = err.Error()
			out = append(out, res)
			log.Printf("[ioc-feeds] %s: %v", f.Name, err)
			continue
		}
		res.Fetched = len(items)
		created, updated := upsertFeedIndicators(db, items)
		res.Created, res.Updated = created, updated
		out = append(out, res)
		log.Printf("[ioc-feeds] %s: %d fetched, %d new, %d refreshed", f.Name, len(items), created, updated)
	}

	if n := ExpireStaleIOCs(db); n > 0 {
		log.Printf("[ioc-feeds] retired %d expired indicator(s)", n)
	}
	return out
}

// upsertFeedIndicators writes a feed's rows.
//
// A re-seen indicator has its expiry PUSHED FORWARD rather than being skipped:
// that is what "still current" means, and without it every indicator would age
// out on the schedule of the first time it was ever seen, however long it had
// remained active afterwards. Confidence and description are refreshed too, but
// an operator's own notes are not: `description` is only written when the row is
// created, so a hand-annotated indicator keeps its annotation.
func upsertFeedIndicators(db *gorm.DB, items []threatintel.FeedIndicator) (created, updated int) {
	now := time.Now().UTC()
	batch := make([]models.IOC, 0, iocFeedBatchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		res := db.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "value"}, {Name: "type"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"expires_at", "last_seen", "confidence", "source", "enabled", "campaign",
			}),
		}).CreateInBatches(batch, iocFeedBatchSize)
		if res.Error != nil {
			log.Printf("[ioc-feeds] upsert failed: %v", res.Error)
		}
		batch = batch[:0]
	}

	// An upsert's RowsAffected does not separate inserts from updates, so the
	// split is measured by the change in row count. Reporting a made-up split
	// would be worse than reporting the true one this way.
	before := countIOCs(db)
	processed := 0
	// Deduplicate on (value, type) across the whole import.
	//
	// Postgres refuses an ON CONFLICT DO UPDATE that would touch the same row
	// twice in one statement — "cannot affect row a second time" — and it takes
	// the WHOLE batch down with it, not just the duplicate. ThreatFox routinely
	// lists one indicator under two malware families, so this fired on the first
	// real refresh and silently dropped 500 indicators per collision.
	seen := make(map[string]bool, len(items))
	for _, it := range items {
		value := strings.TrimSpace(it.Value)
		if value == "" {
			continue
		}
		key := it.Type + "|" + strings.ToLower(value)
		if seen[key] {
			continue
		}
		seen[key] = true
		batch = append(batch, models.IOC{
			Value:       value,
			Type:        it.Type,
			Source:      it.Source,
			Description: it.Descr,
			Confidence:  it.Confidence,
			TLP:         "white", // open feeds are public by definition
			Reference:   it.Reference,
			Campaign:    it.Campaign,
			FirstSeen:   now,
			LastSeen:    now,
			ExpiresAt:   &it.Expires,
			Enabled:     true,
		})
		processed++
		if len(batch) >= iocFeedBatchSize {
			flush()
		}
	}
	flush()

	created = int(countIOCs(db) - before)
	if created < 0 {
		created = 0
	}
	updated = processed - created
	if updated < 0 {
		updated = 0
	}
	return created, updated
}

func countIOCs(db *gorm.DB) int64 {
	var n int64
	db.Model(&models.IOC{}).Count(&n)
	return n
}

// RefreshIOCFeedsNow runs a refresh on demand.
//
// POST /api/v1/iocs/feeds/refresh
func RefreshIOCFeedsNow(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	results := RefreshIOCFeeds(db)
	c.JSON(http.StatusOK, gin.H{"success": true, "feeds": results})
}

// ListIOCFeeds reports the configured feeds and the store's current lifecycle
// counts, so an operator can see whether ingestion is actually working.
//
// GET /api/v1/iocs/feeds
func ListIOCFeeds(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	feeds := make([]gin.H, 0)
	for _, f := range threatintel.DefaultFeeds() {
		var n int64
		db.Model(&models.IOC{}).Where("source = ?", f.Name).Count(&n)
		feeds = append(feeds, gin.H{
			"id": f.ID, "name": f.Name, "url": f.URL,
			"ttl_hours": int(f.TTL.Hours()), "confidence": f.Confidence,
			"stored": n,
		})
	}

	var total, active, expired int64
	db.Model(&models.IOC{}).Count(&total)
	ActiveIOCs(db).Model(&models.IOC{}).Count(&active)
	db.Model(&models.IOC{}).Where("enabled = ?", false).Count(&expired)

	c.JSON(http.StatusOK, gin.H{
		"enabled":       iocFeedsEnabled(),
		"interval_mins": int(iocFeedInterval.Minutes()),
		"feeds":         feeds,
		"store":         gin.H{"total": total, "active": active, "retired": expired},
	})
}

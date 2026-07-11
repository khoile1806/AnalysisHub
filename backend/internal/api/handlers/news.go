package handlers

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mmcdole/gofeed"

	"github.com/analysishub/backend/internal/news"
	"github.com/analysishub/backend/internal/ws"
)

// NewsArticle is the trimmed shape stored on disk and returned to the UI.
//
// Field naming mirrors snake_case JSON convention used elsewhere in the API.
// Description is HTML-stripped and capped so the on-disk file stays bounded
// even when sources emit very long content blocks (e.g. Krebs full-text feeds).
type NewsArticle struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Link        string   `json:"link"`
	Description string   `json:"description"`
	Author      string   `json:"author,omitempty"`
	Published   string   `json:"published"`
	Source      string   `json:"source"`
	Category    string   `json:"category"`
	Language    string   `json:"language,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	FetchedAt   string   `json:"fetched_at"`
	ImageURL    string   `json:"image_url,omitempty"`
}

var (
	newsFile  = "data/news.json"
	newsMutex sync.Mutex

	// newsHTTPClient is independent from cveHTTPClient so a slow batch of feeds
	// cannot starve CVE NVD lookups (and vice-versa). Custom UA reduces the
	// chance of CDN-level bot blocking on a few of the feeds.
	newsHTTPClient = &http.Client{Timeout: 20 * time.Second}
	newsUserAgent  = "AnalysisHub-NewsBot/1.0 (+https://github.com/analysishub)"

	// Concurrency caps applied inside syncAllFeeds.
	newsGlobalConcurrency = 5
	newsPerSourceCap      = 200
	newsDescriptionLimit  = 500
	newsRefreshInterval   = 5 * time.Minute
	newsPerFeedTimeout    = 15 * time.Second
)

// ── Feed health / dead-feed pruning ─────────────────────────────────────────
// A feed that keeps failing (defunct source, permanent 404/DNS failure — e.g.
// Threatpost, which shut down) is backed off with an exponentially growing skip
// window so the worker stops paying a per-cycle timeout for it, while still
// retrying periodically in case it recovers.
const (
	feedDeadThreshold = 4 // consecutive failures before backing off
	feedBackoffBase   = 30 * time.Minute
	feedBackoffMax    = 12 * time.Hour
)

type feedStat struct {
	consecFails int
	lastErr     string
	lastCheck   time.Time
	skipUntil   time.Time
}

var (
	feedHealth   = map[string]*feedStat{}
	feedHealthMu sync.Mutex
)

// feedShouldSkip reports whether a feed is currently in its dead-feed backoff
// window and should be skipped this cycle.
func feedShouldSkip(url string, now time.Time) bool {
	feedHealthMu.Lock()
	defer feedHealthMu.Unlock()
	st := feedHealth[url]
	return st != nil && !st.skipUntil.IsZero() && now.Before(st.skipUntil)
}

// feedRecordResult updates a feed's health after a fetch attempt. On repeated
// failure it sets an exponential backoff; a success clears the failure state.
func feedRecordResult(url string, now time.Time, err error) {
	feedHealthMu.Lock()
	defer feedHealthMu.Unlock()
	st := feedHealth[url]
	if st == nil {
		st = &feedStat{}
		feedHealth[url] = st
	}
	st.lastCheck = now
	if err == nil {
		st.consecFails = 0
		st.lastErr = ""
		st.skipUntil = time.Time{}
		return
	}
	st.consecFails++
	st.lastErr = err.Error()
	if st.consecFails >= feedDeadThreshold {
		// Exponential backoff: base * 2^(fails-threshold), capped.
		backoff := feedBackoffBase << uint(st.consecFails-feedDeadThreshold)
		if backoff > feedBackoffMax || backoff <= 0 {
			backoff = feedBackoffMax
		}
		st.skipUntil = now.Add(backoff)
	}
}

// htmlTagRegex strips angle-bracketed HTML tags. RSS descriptions frequently
// embed markup that would render verbatim in the dashboard otherwise.
var htmlTagRegex = regexp.MustCompile(`<[^>]+>`)

// whitespaceRegex collapses runs of whitespace (incl. newlines) into a single
// space so trimmed descriptions are one-line clean.
var whitespaceRegex = regexp.MustCompile(`\s+`)

// ───────────────────────── persistence ─────────────────────────

func getNewsFilePath() string {
	path := newsFile
	if _, err := os.Stat(path); os.IsNotExist(err) {
		_ = os.MkdirAll(filepath.Dir(path), 0755)
	}
	return path
}

func readNews() ([]NewsArticle, error) {
	newsMutex.Lock()
	defer newsMutex.Unlock()

	path := getNewsFilePath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []NewsArticle{}, nil
		}
		return nil, err
	}
	var arts []NewsArticle
	if err := json.Unmarshal(data, &arts); err != nil {
		return nil, err
	}
	return arts, nil
}

func writeNews(arts []NewsArticle) error {
	newsMutex.Lock()
	defer newsMutex.Unlock()

	data, err := json.MarshalIndent(arts, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(getNewsFilePath(), data, 0644)
}

// ───────────────────────── HTTP handlers ─────────────────────────

// GetNews returns articles, optionally filtered by ?category=<slug>.
// Results are sorted by Published date desc (most recent first).
func GetNews(c *gin.Context) {
	category := strings.TrimSpace(c.Query("category"))
	if category != "" && !news.IsValidCategory(category) {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid category"})
		return
	}

	arts, err := readNews()
	if err != nil {
		log.Printf("[news] read error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to read news"})
		return
	}

	if category != "" {
		filtered := make([]NewsArticle, 0, len(arts))
		for _, a := range arts {
			if a.Category == category {
				filtered = append(filtered, a)
			}
		}
		arts = filtered
	}

	sort.SliceStable(arts, func(i, j int) bool {
		return arts[i].Published > arts[j].Published
	})

	c.JSON(http.StatusOK, gin.H{"success": true, "data": arts})
}

// GetNewsCategories exposes the static category list to the frontend so
// tab labels stay in sync with the backend feed registry.
func GetNewsCategories(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"success": true, "data": news.Categories})
}

// StreamNews is the SSE endpoint. Each "update" event carries the affected
// category slug so the client can invalidate only that tab's query.
func StreamNews(c *gin.Context) {
	hub, ok := mustGetHub(c)
	if !ok {
		return
	}

	ch := hub.SubscribeNews()
	defer hub.UnsubscribeNews(ch)

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	c.Writer.WriteHeader(http.StatusOK)
	c.Writer.Flush()

	clientGone := c.Request.Context().Done()
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-clientGone:
			return
		case <-ping.C:
			fmt.Fprintf(c.Writer, "event: ping\ndata: {}\n\n")
			c.Writer.Flush()
		case category, ok := <-ch:
			if !ok {
				return
			}
			payload, _ := json.Marshal(map[string]string{"category": category})
			fmt.Fprintf(c.Writer, "event: update\ndata: %s\n\n", payload)
			c.Writer.Flush()
		}
	}
}

// ───────────────────────── worker ─────────────────────────

// StartNewsUpdateWorker launches the background poller goroutine. Mirrors
// StartCVEUpdateWorker's shape so server bootstrap stays uniform.
func StartNewsUpdateWorker(hub *ws.Hub) {
	log.Println("[news-worker] starting background news update worker...")
	go func() {
		safeLoop("news-worker", func() { syncAllFeeds(hub) })
		runWorker("news-worker", newsRefreshInterval, func() { syncAllFeeds(hub) })
	}()
}

// syncAllFeeds fans out one fetch goroutine per registered feed, gated by a
// global concurrency semaphore and a per-host limiter (so we don't fire 6
// requests at cisa.gov in parallel). Each successful fetch immediately
// merges its results into the on-disk collection and publishes an SSE
// update for the affected category — that's how the dashboard "receives
// new articles immediately" rather than waiting for the whole batch.
func syncAllFeeds(hub *ws.Hub) {
	feeds := news.Feeds
	log.Printf("[news-worker] syncing %d feeds (concurrency=%d)...", len(feeds), newsGlobalConcurrency)

	sem := make(chan struct{}, newsGlobalConcurrency)
	var (
		wg        sync.WaitGroup
		hostMu    sync.Mutex
		hostLocks = map[string]chan struct{}{}
		okCount   int32
		failCount int32
		newCount  int32
		skipCount int32
		stats     sync.Mutex
	)
	now := time.Now()

	acquireHost := func(rawurl string) {
		host := hostOf(rawurl)
		hostMu.Lock()
		ch, ok := hostLocks[host]
		if !ok {
			ch = make(chan struct{}, 1)
			hostLocks[host] = ch
		}
		hostMu.Unlock()
		ch <- struct{}{}
	}
	releaseHost := func(rawurl string) {
		host := hostOf(rawurl)
		hostMu.Lock()
		ch := hostLocks[host]
		hostMu.Unlock()
		if ch != nil {
			<-ch
		}
	}

	ctx := context.Background()

	for _, f := range feeds {
		wg.Add(1)
		go func(feed news.Feed) {
			defer wg.Done()

			// Skip feeds currently in dead-feed backoff so a defunct source
			// doesn't cost a per-cycle timeout.
			if feedShouldSkip(feed.URL, now) {
				stats.Lock()
				skipCount++
				stats.Unlock()
				return
			}

			sem <- struct{}{}
			defer func() { <-sem }()

			acquireHost(feed.URL)
			defer releaseHost(feed.URL)

			arts, err := fetchOneFeed(ctx, feed)
			feedRecordResult(feed.URL, time.Now(), err)
			if err != nil {
				log.Printf("[news-worker] feed %q failed: %v", feed.Name, err)
				stats.Lock()
				failCount++
				stats.Unlock()
				return
			}

			added := mergeAndPersist(feed.Category, arts)

			stats.Lock()
			okCount++
			newCount += int32(added)
			stats.Unlock()

			// Push immediately so the UI surfaces new items as they arrive,
			// not at the end of the whole 54-feed batch.
			if added > 0 && hub != nil {
				hub.PublishNewsUpdate(feed.Category)
			}
		}(f)
	}

	wg.Wait()
	log.Printf("[news-worker] sync complete: %d new articles, %d feeds ok, %d failed, %d skipped (dead-feed backoff)",
		newCount, okCount, failCount, skipCount)
}

// fetchOneFeed downloads + parses a single feed. Failures are surfaced to
// the caller (which logs + counts them) rather than swallowed here so the
// summary at the end reflects real health.
func fetchOneFeed(parent context.Context, feed news.Feed) ([]NewsArticle, error) {
	ctx, cancel := context.WithTimeout(parent, newsPerFeedTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", newsUserAgent)
	req.Header.Set("Accept", "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.8")

	resp, err := newsHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	parser := gofeed.NewParser()
	parsed, err := parser.Parse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	out := make([]NewsArticle, 0, len(parsed.Items))
	for _, item := range parsed.Items {
		if item == nil || strings.TrimSpace(item.Link) == "" {
			continue
		}
		pub := ""
		if item.PublishedParsed != nil {
			pub = item.PublishedParsed.UTC().Format(time.RFC3339)
		} else if item.UpdatedParsed != nil {
			pub = item.UpdatedParsed.UTC().Format(time.RFC3339)
		} else if item.Published != "" {
			pub = item.Published
		}
		desc := pickDescription(item)
		image := ""
		if item.Image != nil {
			image = item.Image.URL
		} else if len(item.Enclosures) > 0 {
			for _, e := range item.Enclosures {
				if strings.HasPrefix(e.Type, "image/") {
					image = e.URL
					break
				}
			}
		}
		author := ""
		if item.Author != nil {
			author = item.Author.Name
		}
		tags := append([]string(nil), item.Categories...)
		out = append(out, NewsArticle{
			ID:          articleID(item.Link),
			Title:       strings.TrimSpace(item.Title),
			Link:        item.Link,
			Description: desc,
			Author:      author,
			Published:   pub,
			Source:      feed.Name,
			Category:    feed.Category,
			Language:    feed.Language,
			Tags:        tags,
			FetchedAt:   now,
			ImageURL:    image,
		})
	}
	return out, nil
}

// mergeAndPersist combines fresh articles with the on-disk collection,
// deduplicates by ID, trims per-source history to newsPerSourceCap, and
// writes the merged slice back. Returns the number of *new* articles
// (those not already present) so the caller can decide whether to
// broadcast an SSE update.
func mergeAndPersist(category string, fresh []NewsArticle) int {
	existing, err := readNews()
	if err != nil {
		log.Printf("[news-worker] read error: %v", err)
		return 0
	}

	seen := make(map[string]struct{}, len(existing))
	for _, a := range existing {
		seen[a.ID] = struct{}{}
	}

	added := 0
	for _, a := range fresh {
		if _, dup := seen[a.ID]; dup {
			continue
		}
		seen[a.ID] = struct{}{}
		existing = append(existing, a)
		added++
	}

	if added == 0 {
		return 0
	}

	// Trim per-source: keep only the newsPerSourceCap most recent items per
	// Source name. A transient feed outage doesn't shrink retained history
	// because trimming runs only when we've actually added something.
	bySource := map[string][]NewsArticle{}
	for _, a := range existing {
		bySource[a.Source] = append(bySource[a.Source], a)
	}
	trimmed := make([]NewsArticle, 0, len(existing))
	for _, group := range bySource {
		sort.SliceStable(group, func(i, j int) bool {
			return group[i].Published > group[j].Published
		})
		if len(group) > newsPerSourceCap {
			group = group[:newsPerSourceCap]
		}
		trimmed = append(trimmed, group...)
	}

	if err := writeNews(trimmed); err != nil {
		log.Printf("[news-worker] write error (category=%s): %v", category, err)
		return 0
	}
	return added
}

// ───────────────────────── helpers ─────────────────────────

func pickDescription(item *gofeed.Item) string {
	raw := item.Description
	if strings.TrimSpace(raw) == "" {
		raw = item.Content
	}
	raw = htmlTagRegex.ReplaceAllString(raw, " ")
	raw = whitespaceRegex.ReplaceAllString(raw, " ")
	raw = strings.TrimSpace(raw)
	if len(raw) > newsDescriptionLimit {
		raw = raw[:newsDescriptionLimit] + "..."
	}
	return raw
}

func articleID(link string) string {
	sum := sha1.Sum([]byte(strings.TrimSpace(link)))
	return hex.EncodeToString(sum[:8])
}

func hostOf(rawurl string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return rawurl
	}
	return strings.ToLower(u.Host)
}

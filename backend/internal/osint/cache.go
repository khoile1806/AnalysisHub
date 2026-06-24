package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// cacheKeyPrefix namespaces every OSINT cache entry in Redis.
const cacheKeyPrefix = "osint:cache:"

// Cache TTLs per data class. Reputation / registration / geolocation data
// changes slowly, so a few hours of caching is safe and dramatically cuts
// third-party API quota use across repeated investigations and daily watches.
const (
	ttlGeoIP      = 24 * time.Hour
	ttlRDAP       = 24 * time.Hour
	ttlInternetDB = 6 * time.Hour
	ttlVirusTotal = 6 * time.Hour
	ttlShodan     = 6 * time.Hour
	ttlXposed     = 24 * time.Hour
	ttlHashLookup = 7 * 24 * time.Hour // file reputation is effectively static
	ttlTyposquat  = 12 * time.Hour
	ttlNVD        = 24 * time.Hour // CVE lists for a fixed product@version change slowly
	ttlReputation = 6 * time.Hour  // abuse.ch / pulsedive / greynoise / abuseipdb verdicts
	ttlCrtSh      = 6 * time.Hour   // CT-log subdomain set grows slowly
	ttlWayback    = 24 * time.Hour  // archived-URL history is effectively append-only
)

// osintCache is a thin TTL cache over Redis for idempotent third-party lookups
// (GeoIP, RDAP, Shodan InternetDB, VirusTotal). Every method is nil-safe and
// degrades to a plain cache miss when Redis is unavailable, so a Redis outage
// only removes the speed-up - it never breaks a scan. Only deterministic,
// target-keyed lookups are cached; anything that depends on live state or a
// per-request token is left uncached.
type osintCache struct {
	rdb *redis.Client
}

// newOsintCache wraps a redis client, or returns nil (caching disabled) when no
// client is configured.
func newOsintCache(rdb *redis.Client) *osintCache {
	if rdb == nil {
		return nil
	}
	return &osintCache{rdb: rdb}
}

// cacheEnvelope is the stored representation: the original HTTP status plus the
// raw JSON body (kept only for cacheable success responses).
type cacheEnvelope struct {
	Status int    `json:"s"`
	Body   []byte `json:"b,omitempty"`
}

// get returns the cached (status, body) for key, or ok=false on miss/error.
// Safe to call on a nil receiver.
func (c *osintCache) get(ctx context.Context, key string) (status int, body []byte, ok bool) {
	if c == nil || c.rdb == nil || key == "" {
		return 0, nil, false
	}
	raw, err := c.rdb.Get(ctx, cacheKeyPrefix+key).Bytes()
	if err != nil {
		return 0, nil, false
	}
	var env cacheEnvelope
	if json.Unmarshal(raw, &env) != nil {
		return 0, nil, false
	}
	return env.Status, env.Body, true
}

// set stores (status, body) under key with ttl. Best-effort; errors are ignored.
// Safe to call on a nil receiver.
func (c *osintCache) set(ctx context.Context, key string, status int, body []byte, ttl time.Duration) {
	if c == nil || c.rdb == nil || key == "" {
		return
	}
	raw, err := json.Marshal(cacheEnvelope{Status: status, Body: body})
	if err != nil {
		return
	}
	_ = c.rdb.Set(ctx, cacheKeyPrefix+key, raw, ttl).Err()
}

// cacheableStatus reports whether an HTTP status is safe to cache. We keep
// successful responses and the definitive "absent" (404); transient statuses
// (rate-limit, auth failure, 5xx) are always re-fetched.
func cacheableStatus(s int) bool {
	return s == 200 || s == 404
}

// cachedGetJSON is httpGetJSON with a Redis read-through cache keyed by `key`.
// On a hit it decodes the cached body into out and returns the cached status.
// On a miss it fetches (honouring the rate limiter), decodes, and stores the
// result for cacheable statuses. A nil cache or empty key transparently
// disables caching, so callers behave identically with or without Redis.
func cachedGetJSON(ctx context.Context, c *osintCache, key string, rl *rateLimiter,
	url string, headers map[string]string, out interface{}, ttl time.Duration) (int, error) {

	if status, body, hit := c.get(ctx, key); hit {
		if status == 200 && out != nil && len(body) > 0 {
			// A corrupt cache entry is treated as an empty success, not an error,
			// so a bad write can never wedge a collector.
			_ = json.Unmarshal(body, out)
		}
		return status, nil
	}

	body, status, err := httpGetBody(ctx, rl, url, headers)
	if err != nil {
		return status, err
	}
	if status >= 200 && status < 300 && out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return status, fmt.Errorf("decode response: %w", err)
		}
	}
	if cacheableStatus(status) {
		stored := body
		if status != 200 {
			stored = nil // no need to retain a not-found body
		}
		c.set(ctx, key, status, stored, ttl)
	}
	return status, nil
}

// cachedGetBody is httpGetBody with a Redis read-through cache keyed by `key`,
// for collectors that parse the raw body themselves (e.g. crt.sh, Wayback). A
// nil cache or empty key transparently disables caching.
func cachedGetBody(ctx context.Context, c *osintCache, key string, rl *rateLimiter,
	url string, headers map[string]string, ttl time.Duration) ([]byte, int, error) {

	if status, body, hit := c.get(ctx, key); hit {
		return body, status, nil
	}
	body, status, err := httpGetBody(ctx, rl, url, headers)
	if err != nil {
		return body, status, err
	}
	if cacheableStatus(status) {
		stored := body
		if status != 200 {
			stored = nil
		}
		c.set(ctx, key, status, stored, ttl)
	}
	return body, status, nil
}

// cachedPostJSON is httpPostBody with a Redis read-through cache keyed by `key`.
// Used for the abuse.ch feeds, whose APIs are POST-only; the key must capture the
// query (endpoint + indicator) so distinct lookups don't collide. A "no result"
// 200 is cached too, so a negative lookup isn't repeated within the TTL.
func cachedPostJSON(ctx context.Context, c *osintCache, key string, rl *rateLimiter,
	url, contentType string, reqBody []byte, headers map[string]string, out interface{}, ttl time.Duration) (int, error) {

	if status, body, hit := c.get(ctx, key); hit {
		if status == 200 && out != nil && len(body) > 0 {
			_ = json.Unmarshal(body, out)
		}
		return status, nil
	}
	body, status, err := httpPostBody(ctx, rl, url, contentType, reqBody, headers)
	if err != nil {
		return status, err
	}
	if status >= 200 && status < 300 && out != nil && len(body) > 0 {
		// Best-effort decode: the abuse.ch feeds return a non-array "data"/"urls"
		// field on a no-result query, which is a JSON type mismatch but NOT a real
		// error. encoding/json still populates the fields that do match (notably
		// query_status), so let the caller decide from query_status instead of
		// failing the whole collector on the expected no-result shape.
		_ = json.Unmarshal(body, out)
	}
	if cacheableStatus(status) {
		stored := body
		if status != 200 {
			stored = nil
		}
		c.set(ctx, key, status, stored, ttl)
	}
	return status, nil
}

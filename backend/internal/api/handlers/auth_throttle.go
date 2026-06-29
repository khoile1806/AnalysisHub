package handlers

import (
	"context"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Brute-force protection for the login endpoint. State lives in Redis so the
// counters survive across backend restarts and are shared by every instance.
// Two independent layers run on each attempt:
//
//   - Per-account lockout (keyed by email) — the primary defense. After
//     bfAccountMaxFails failures inside bfAccountWindow the account is locked
//     for a duration that grows exponentially with each repeated lockout
//     (capped at bfAccountLockMax). This cannot be bypassed by rotating the
//     source IP.
//   - Per-IP throttle (keyed by client IP) — secondary. Slows a single host
//     spraying many accounts. Note c.ClientIP() honours X-Forwarded-For, so
//     set gin trusted proxies in production or this layer is spoofable; the
//     account lockout remains effective regardless.
//
// When Redis is unavailable the limiter fails open (login still works) — an
// outage must not lock every operator out of the platform.
const (
	bfAccountMaxFails = 5
	bfAccountWindow   = 15 * time.Minute
	bfAccountLockBase = 1 * time.Minute
	bfAccountLockMax  = 30 * time.Minute
	bfGenTTL          = 24 * time.Hour // how long repeated-lockout memory persists

	bfIPMaxFails = 20
	bfIPWindow   = 15 * time.Minute
	bfIPBlock    = 15 * time.Minute
)

func bfAcctFailsKey(email string) string { return "bf:acct:fails:" + email }
func bfAcctLockKey(email string) string  { return "bf:acct:lock:" + email }
func bfAcctGenKey(email string) string   { return "bf:acct:gen:" + email }
func bfIPFailsKey(ip string) string      { return "bf:ip:fails:" + ip }
func bfIPLockKey(ip string) string       { return "bf:ip:lock:" + ip }

// normalizeEmail lower-cases and trims the email so counters can't be evaded by
// case/whitespace variation.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// loginThrottleCheck reports whether the current attempt is currently blocked.
// It returns the remaining lock duration (for a Retry-After header) and a short
// reason ("account" or "ip"). A nil client fails open.
func loginThrottleCheck(ctx context.Context, rdb *redis.Client, email, ip string) (blocked bool, retryAfter time.Duration, reason string) {
	if rdb == nil {
		return false, 0, ""
	}
	email = normalizeEmail(email)

	// IP block first — cheaper to reject an abusive host outright.
	if ttl, err := rdb.TTL(ctx, bfIPLockKey(ip)).Result(); err == nil && ttl > 0 {
		return true, ttl, "ip"
	}
	if ttl, err := rdb.TTL(ctx, bfAcctLockKey(email)).Result(); err == nil && ttl > 0 {
		return true, ttl, "account"
	}
	return false, 0, ""
}

// loginThrottleFail records a failed attempt against both the account and the
// source IP, applying a lock once a threshold is crossed.
func loginThrottleFail(ctx context.Context, rdb *redis.Client, email, ip string) {
	if rdb == nil {
		return
	}
	email = normalizeEmail(email)

	// --- account layer ---
	if n, err := rdb.Incr(ctx, bfAcctFailsKey(email)).Result(); err == nil {
		if n == 1 {
			rdb.Expire(ctx, bfAcctFailsKey(email), bfAccountWindow)
		}
		if n >= bfAccountMaxFails {
			// gen tracks how many times this account has been locked, driving
			// exponential backoff. It outlives a single window so a persistent
			// attacker faces ever-longer locks.
			gen, gerr := rdb.Incr(ctx, bfAcctGenKey(email)).Result()
			if gerr == nil && gen == 1 {
				rdb.Expire(ctx, bfAcctGenKey(email), bfGenTTL)
			}
			lock := bfAccountLockBase << uint(maxInt(gen-1, 0))
			if lock > bfAccountLockMax || lock <= 0 {
				lock = bfAccountLockMax
			}
			rdb.Set(ctx, bfAcctLockKey(email), "1", lock)
			// Reset the window counter so a fresh batch is needed after unlock.
			rdb.Del(ctx, bfAcctFailsKey(email))
		}
	}

	// --- IP layer ---
	if m, err := rdb.Incr(ctx, bfIPFailsKey(ip)).Result(); err == nil {
		if m == 1 {
			rdb.Expire(ctx, bfIPFailsKey(ip), bfIPWindow)
		}
		if m >= bfIPMaxFails {
			rdb.Set(ctx, bfIPLockKey(ip), "1", bfIPBlock)
			rdb.Del(ctx, bfIPFailsKey(ip))
		}
	}
}

// loginThrottleReset clears the per-account counters after a successful login.
// The per-IP counter is intentionally left to decay on its own so a shared
// gateway IP can't be fully reset by one valid login among many bad ones.
func loginThrottleReset(ctx context.Context, rdb *redis.Client, email string) {
	if rdb == nil {
		return
	}
	email = normalizeEmail(email)
	rdb.Del(ctx, bfAcctFailsKey(email), bfAcctLockKey(email), bfAcctGenKey(email))
}

func maxInt(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

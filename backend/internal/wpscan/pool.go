// Package wpscan owns the shared state for the WPScan Vulnerability DB
// token pool â€” the ordered token list plus per-token "circuit breaker"
// state that prevents callers from re-hitting a token whose daily quota
// has been exhausted.
//
// Two subsystems consume the pool:
//
//   - The CVE Intel search handler (internal/api/handlers/cve.go) issues
//     direct REST calls to the WPScan HTTPS API.
//   - The recon engine's WordPress step (internal/recon/engine.go) shells
//     out to the `wpscan` CLI which accepts a single --api-token flag.
//
// Both need to (a) pick a token that isn't currently locked and (b) mark
// a token locked when they observe a 429 / quota-exhausted response so
// the other subsystem stops sending traffic to it. Keeping this in a
// dedicated package avoids a cyclic dependency between handlers and
// recon, and lets both share one source of truth.
package wpscan

import (
	"log"
	"sync"
	"time"
)

// Pool is the shared WPScan token registry. Safe for concurrent use.
type Pool struct {
	tokens []string

	mu    sync.RWMutex
	locks map[string]int64 // token â†’ unix timestamp until which the token is locked
}

// NewPool returns a pool seeded with the given tokens in priority order.
// Callers should pass the tokens loaded from config (WPSCAN_API_TOKEN +
// WPSCAN_API_TOKEN_2â€¦). Duplicates and empty entries are filtered.
func NewPool(tokens []string) *Pool {
	seen := make(map[string]bool, len(tokens))
	cleaned := make([]string, 0, len(tokens))
	for _, t := range tokens {
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		cleaned = append(cleaned, t)
	}
	return &Pool{
		tokens: cleaned,
		locks:  make(map[string]int64),
	}
}

// Tokens returns the configured token list (read-only).
func (p *Pool) Tokens() []string {
	return p.tokens
}

// Configured reports whether the pool has at least one token.
func (p *Pool) Configured() bool {
	return len(p.tokens) > 0
}

// IsLocked returns true while the given token is in the circuit breaker.
// Lazily clears expired entries so callers always see fresh state without
// a separate sweeper goroutine.
func (p *Pool) IsLocked(token string) bool {
	p.mu.RLock()
	until, ok := p.locks[token]
	p.mu.RUnlock()
	if !ok || until == 0 {
		return false
	}
	if time.Now().Unix() < until {
		return true
	}
	p.mu.Lock()
	if p.locks[token] == until {
		delete(p.locks, token)
	}
	p.mu.Unlock()
	return false
}

// Lock engages the breaker for one token until the next 00:00 UTC â€” the
// time WPScan's free tier daily quota resets. Idempotent: concurrent
// callers that observe 429 in parallel just write the same value.
func (p *Pool) Lock(token string) {
	next := time.Now().UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
	p.mu.Lock()
	p.locks[token] = next.Unix()
	p.mu.Unlock()
	suffix := token
	if len(suffix) > 6 {
		suffix = "â€¦" + suffix[len(suffix)-6:]
	}
	log.Printf("[wpscan-pool] token %s quota exhausted â€” locked until %s UTC", suffix, next.Format(time.RFC3339))
}

// NextUnlocked returns the first token in priority order that isn't
// currently locked. Returns "" when every configured token is locked or
// none are configured â€” callers should treat this as "WPScan unavailable
// right now" and degrade gracefully.
//
// Used by the recon engine, which can only pass one --api-token to the
// wpscan CLI per invocation. The CVE Intel handler iterates the full
// list (with IsLocked + Lock) instead so it can retry within a single
// request when the first choice 429s.
func (p *Pool) NextUnlocked() string {
	for _, t := range p.tokens {
		if !p.IsLocked(t) {
			return t
		}
	}
	return ""
}

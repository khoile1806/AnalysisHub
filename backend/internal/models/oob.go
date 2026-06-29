package models

import (
	"time"

	"github.com/google/uuid"
)

// OobClient is a registered out-of-band ("Catch" / Interactsh-style) interaction
// session. Each client owns a unique CorrelationID — the leading label of every
// payload hostname it hands out — so any DNS / HTTP / SMTP callback that arrives
// at the interaction server can be attributed back to the test that generated
// the payload.
//
// Use case: during an authorised pentest, blind vulnerabilities (SSRF, blind
// XXE/RCE, blind SQLi, email-header injection) are confirmed by making the
// target reach out to a payload domain. This server is the controlled endpoint
// that records that out-of-band reach-out.
type OobClient struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`

	// CorrelationID is the unguessable prefix shared by all of this client's
	// payload hostnames (e.g. the first 20 chars of "<corr><unique>.<domain>").
	CorrelationID string `gorm:"uniqueIndex;not null" json:"correlation_id"`

	// Secret is a random token the poller must present to read this client's
	// interactions, so captured callbacks are only visible to their creator.
	Secret string `gorm:"not null" json:"secret,omitempty"`

	// Name / Note are the operator's label and free-text context.
	Name string `gorm:"not null;default:''" json:"name"`
	Note string `gorm:"type:text"          json:"note,omitempty"`

	// CaseID optionally ties captured interactions to an investigation Case.
	CaseID *uuid.UUID `gorm:"type:uuid;index" json:"case_id,omitempty"`

	// InteractionCount / LastSeenAt are denormalised so the list view avoids a
	// COUNT per row and can show recency at a glance.
	InteractionCount int        `gorm:"not null;default:0" json:"interaction_count"`
	LastSeenAt       *time.Time `                          json:"last_seen_at,omitempty"`

	// ── Webhook mode response config ──────────────────────────────────────
	// The HTTP response the instant webhook endpoint (/oob/r/<token>) returns to
	// the caller — webhook.site-style, so an operator can shape what the target
	// sees (e.g. a 302 redirect, a JSON body, a deliberate delay). Defaults to a
	// plain 200. GORM omits zero-value fields carrying a default, so a freshly
	// created client falls back to these DB defaults.
	RespStatus      int    `gorm:"not null;default:200"          json:"resp_status"`
	RespContentType string `gorm:"not null;default:'text/plain'" json:"resp_content_type"`
	RespBody        string `gorm:"type:text"                     json:"resp_body"`
	RespDelayMs     int    `gorm:"not null;default:0"            json:"resp_delay_ms"`
	// RespHeaders is a JSON object of extra response headers to send back
	// (e.g. {"Location":"https://...","X-Foo":"bar"}). Empty = none.
	RespHeaders string `gorm:"type:text" json:"resp_headers"`

	// NotifyURL is an optional outbound webhook called asynchronously on every
	// new interaction. Supports Slack / Discord incoming webhooks or any HTTP
	// endpoint that accepts a POST with a JSON body. Empty = disabled.
	NotifyURL string `gorm:"type:text" json:"notify_url"`

	CreatedBy uuid.UUID `gorm:"type:uuid" json:"created_by"`
	CreatedAt time.Time `                 json:"created_at"`
	UpdatedAt time.Time `                 json:"updated_at"`
}

// OobResponseRule is a conditional HTTP response for the webhook receiver. A
// session can have several; on each request the rules are evaluated by ascending
// Priority and the FIRST match wins, shaping what the target sees (Burp-style
// "match → response"). When no rule matches, the session-level default response
// (OobClient.Resp*) is used.
type OobResponseRule struct {
	ID       uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	ClientID uuid.UUID `gorm:"type:uuid;not null;index"                       json:"client_id"`

	Priority int    `gorm:"not null;default:0" json:"priority"`
	Name     string `gorm:"default:''"         json:"name"`

	// Match conditions (all set conditions must hold; empty = ignore that one).
	MatchMethod     string `json:"match_method,omitempty"`      // exact HTTP method
	MatchPathPrefix string `json:"match_path_prefix,omitempty"` // path starts-with
	MatchPathSub    string `json:"match_path_sub,omitempty"`    // path contains

	// Response when matched.
	Status      int    `gorm:"not null;default:200"          json:"status"`
	ContentType string `gorm:"not null;default:'text/plain'" json:"content_type"`
	Body        string `gorm:"type:text"                     json:"body"`
	Headers     string `gorm:"type:text"                     json:"headers"` // JSON map
	DelayMs     int    `gorm:"not null;default:0"            json:"delay_ms"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// OobInteraction is a single captured out-of-band callback — one DNS query, one
// HTTP(S) request, or one SMTP delivery — recorded by the interaction server.
type OobInteraction struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	ClientID      uuid.UUID `gorm:"type:uuid;not null;index"                       json:"client_id"`
	CorrelationID string    `gorm:"index;not null"                                 json:"correlation_id"`

	// Protocol is the channel the callback arrived on: dns | http | https | smtp.
	Protocol string `gorm:"index;not null" json:"protocol"`

	// FullHost is the full hostname queried / Host header / RCPT domain.
	FullHost string `json:"full_host"`
	// UniqueID is the per-payload random portion that follows the CorrelationID
	// in the leading label — lets the operator tie a callback to a specific
	// generated payload, not just to the client.
	UniqueID string `json:"unique_id,omitempty"`

	// Source network identity of the caller.
	RemoteAddr string `              json:"remote_addr,omitempty"` // ip:port as seen on the wire
	RemoteIP   string `gorm:"index" json:"remote_ip,omitempty"`

	// --- DNS ---
	QueryType string `json:"query_type,omitempty"` // A | AAAA | TXT | CNAME | NS | ...

	// --- HTTP(S) ---
	Method    string `                 json:"method,omitempty"`
	Path      string `gorm:"type:text" json:"path,omitempty"`
	UserAgent string `gorm:"type:text" json:"user_agent,omitempty"`

	// --- SMTP ---
	SMTPFrom string `json:"smtp_from,omitempty"`
	SMTPTo   string `json:"smtp_to,omitempty"`

	// RawRequest is a human-readable dump of the request (DNS question, raw HTTP
	// head+body, or the SMTP transcript) so the operator sees exactly what hit.
	RawRequest string `gorm:"type:text" json:"raw_request,omitempty"`

	// ── Triage state (operator-set) ───────────────────────────────────────
	Seen    bool   `gorm:"not null;default:false;index" json:"seen"`
	Starred bool   `gorm:"not null;default:false;index" json:"starred"`
	Note    string `gorm:"type:text"                    json:"note,omitempty"`
	Tags    string `                                    json:"tags,omitempty"` // comma-separated

	// ── Source-IP enrichment (async, best-effort via ip-api.com) ──────────
	GeoCountry string `json:"geo_country,omitempty"`
	GeoCity    string `json:"geo_city,omitempty"`
	ASN        string `json:"asn,omitempty"`
	ISP        string `json:"isp,omitempty"`
	RDNS       string `json:"rdns,omitempty"` // reverse DNS / PTR
	// Network-type flags from ip-api — surface proxy/VPN/hosting for triage.
	IsProxy   bool `json:"is_proxy,omitempty"`
	IsHosting bool `json:"is_hosting,omitempty"`

	CreatedAt time.Time `gorm:"index" json:"created_at"`
}

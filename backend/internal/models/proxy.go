package models

import "time"

// ProxyProfile is one saved egress proxy in the proxy pool. Multiple profiles may
// exist; exactly one is marked IsActive and drives the project-wide egress layer
// (internal/egress). Switching the active profile re-points every outbound client
// at runtime with no restart. URL may embed credentials (socks5://user:pass@host)
// so it is never sent raw to the client — MaskedURL carries the safe form.
type ProxyProfile struct {
	ID   uint   `json:"id" gorm:"primaryKey"`
	Name string `json:"name" gorm:"not null"`
	// URL is the raw proxy URL (http/https/socks5). Never serialized directly.
	URL            string `json:"-"`
	MaskedURL      string `json:"url" gorm:"-"` // scheme://host, credentials stripped — for display
	NoProxy        string `json:"no_proxy"`
	FallbackDirect bool   `json:"fallback_direct" gorm:"default:false"`
	IsActive       bool   `json:"is_active" gorm:"index;default:false"`

	// Lane binds a profile to an egress lane so different traffic classes can use
	// different exits: "default" (project-wide egress), "osint", or "vulnscan".
	// Exactly one profile per lane may be active. Empty is treated as "default".
	Lane string `json:"lane" gorm:"index;default:'default'"`

	// QuotaBytes caps total bytes (in+out) attributed to this profile's label over
	// the retained flow window; 0 = unlimited. Metered residential proxies bill by
	// GB, so this surfaces a soft budget with a UI warning.
	QuotaBytes int64 `json:"quota_bytes" gorm:"default:0"`
	// QuotaHardStop upgrades the quota from advisory to enforced: when usage
	// reaches QuotaBytes the profile is auto-deactivated (its lane drops to direct)
	// so it can't keep spending. Off by default.
	QuotaHardStop bool `json:"quota_hard_stop" gorm:"default:false"`

	// Last health-probe result for this profile (updated by an explicit check or
	// when the profile is active and the background probe runs).
	Healthy   bool       `json:"healthy" gorm:"default:false"`
	LatencyMs int64      `json:"latency_ms" gorm:"default:0"`
	LastError string     `json:"last_error"`
	LastCheck *time.Time `json:"last_check"`

	// Exit identity — the public face traffic presents when routed through this
	// proxy (discovered by an explicit identity probe).
	ExitIP        string     `json:"exit_ip"`
	ExitCountry   string     `json:"exit_country"`
	ExitOrg       string     `json:"exit_org"`
	IsTor         bool       `json:"is_tor" gorm:"default:false"`
	ExitCheckedAt *time.Time `json:"exit_checked_at"`

	// Exit-identity drift: the previously-seen exit IP and a flag raised when a
	// later auto-refresh finds a different IP — an unexpected change can mean the
	// proxy died and traffic fell back, or the exit rotated under you.
	ExitIPPrev    string `json:"exit_ip_prev,omitempty"`
	IdentityDrift bool   `json:"identity_drift" gorm:"default:false"`

	// QuotaUsedBytes / OverQuota are computed (not stored) for the list response.
	QuotaUsedBytes int64 `json:"quota_used_bytes" gorm:"-"`
	OverQuota      bool  `json:"over_quota" gorm:"-"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ProxyHealthSample is one timestamped health-probe result for a profile, kept as
// a rolling window so the UI can draw an uptime/latency sparkline per proxy.
type ProxyHealthSample struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	ProfileID uint      `json:"profile_id" gorm:"index"`
	Healthy   bool      `json:"healthy"`
	LatencyMs int64     `json:"latency_ms"`
	CreatedAt time.Time `json:"created_at" gorm:"index"`
}

// ProxyFlow is one recorded outbound request/response through the egress layer —
// the "flow" the Proxy Manager displays. Persisted (rolling window) so history
// survives a restart; a bounded in-memory ring buffer serves the live view.
type ProxyFlow struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time `json:"created_at" gorm:"index"`

	ProxyLabel string `json:"proxy_label"` // active profile name, or "direct"
	ViaProxy   bool   `json:"via_proxy"`
	Leaked     bool   `json:"leaked" gorm:"index"` // went direct while a proxy was active
	Source     string `json:"source"`              // originating module (osint, app, …)

	Method      string `json:"method"`
	Scheme      string `json:"scheme"`
	Host        string `json:"host" gorm:"index"`
	URL         string `json:"url"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	TLSVersion  string `json:"tls_version"`
	BytesOut    int64  `json:"bytes_out"`
	BytesIn     int64  `json:"bytes_in"`
	DurationMs  int64  `json:"duration_ms"`
	DNSMs       int64  `json:"dns_ms"`
	ConnectMs   int64  `json:"connect_ms"`
	TLSMs       int64  `json:"tls_ms"`
	TTFBMs      int64  `json:"ttfb_ms"`
	Error       string `json:"error"`
}

// ProxyPoolSetting is a singleton row (id = 1) holding pool-automation config:
//   - manual:   the operator switches proxies by hand (default).
//   - failover: if the active proxy's health probe fails, auto-switch to the next
//     healthy profile.
//   - rotate:   round-robin the active proxy across healthy profiles every
//     IntervalSec seconds (rotating exit identity).
type ProxyPoolSetting struct {
	ID          uint   `json:"id" gorm:"primaryKey"`
	Mode        string `json:"mode" gorm:"default:manual"`
	IntervalSec int    `json:"interval_sec" gorm:"default:300"`
	// KillSwitch, when on, HARD-BLOCKS all project-wide egress whenever no healthy
	// proxy is available (none configured, or the active one is confirmed down and
	// fall-back-to-direct is off) — fail-closed so recon can never leak the real
	// IP the moment anonymity drops.
	KillSwitch bool      `json:"kill_switch" gorm:"default:false"`
	UpdatedAt  time.Time `json:"updated_at"`
}

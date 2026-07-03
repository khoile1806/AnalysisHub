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

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
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
	ID          uint      `json:"id" gorm:"primaryKey"`
	Mode        string    `json:"mode" gorm:"default:manual"`
	IntervalSec int       `json:"interval_sec" gorm:"default:300"`
	UpdatedAt   time.Time `json:"updated_at"`
}

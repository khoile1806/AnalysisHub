package models

import (
	"time"

	"github.com/google/uuid"
)

// CanaryToken is an administrator-created tracking link ("canary" / honeytoken).
// When the public slug is visited the server records the visitor's real IP,
// User-Agent and other request metadata, then redirects (HTTP 302) to a benign
// TargetURL chosen by the administrator.
//
// Defensive use cases: detecting when a planted bait document / link is opened,
// deanonymising who is probing leaked credentials, and phishing-back
// investigations on authorised engagements.
//
// Ethics / authorisation: this records PII (IP address, User-Agent). It must
// only be operated inside an authorised investigation, and the redirect target
// must be a harmless page. The UI surfaces this warning to the operator.
type CanaryToken struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`

	// Slug is the short, unguessable path component of the public link
	// (/c/<slug>). Unique across all tokens.
	Slug string `gorm:"uniqueIndex;not null" json:"slug"`

	// Name is the operator's label for the token (e.g. "leaked-creds-bait").
	Name string `gorm:"not null" json:"name"`

	// TargetURL is the harmless page the visitor is redirected to after the
	// hit is recorded. Must be an absolute http(s) URL.
	TargetURL string `gorm:"not null" json:"target_url"`

	// BaseURL optionally overrides the public base used to build this token's
	// link (e.g. "https://promo-event.io"). Lets the operator front the link
	// with a disposable domain so the real ForensicHub host is never exposed.
	// When empty, the global CANARY_BASE_URL config (or the request host) is used.
	BaseURL string `json:"base_url,omitempty"`

	Description string `gorm:"type:text" json:"description,omitempty"`

	// CaseID optionally ties this canary to an investigation Case, so captured
	// visits can be pivoted/attributed within that case.
	CaseID *uuid.UUID `gorm:"type:uuid;index" json:"case_id,omitempty"`

	// Active gates the link: when false the public endpoint returns 404 and
	// records nothing.
	Active bool `gorm:"not null;default:true" json:"active"`

	// CollectDetails, when true, serves a brief JS interstitial page that gathers
	// rich client data (screen, timezone, hardware, GPU, battery, network…)
	// before redirecting. When false the link is a fully transparent 302 that
	// only captures HTTP headers + IP GeoIP (the default — stealthier, opt-in
	// collection). No `default` tag: GORM omits zero-value bools that carry a
	// default, which would silently flip false→true; we always write the value.
	CollectDetails bool `gorm:"not null" json:"collect_details"`

	// RequestLocation, when true (requires CollectDetails), additionally asks the
	// browser for precise GPS coordinates via the Geolocation API — the visitor
	// sees a permission prompt and must consent.
	RequestLocation bool `gorm:"not null" json:"request_location"`

	// HitCount / LastHitAt are denormalised counters kept in sync on each hit
	// so the list view avoids a COUNT per row.
	HitCount  int        `gorm:"not null;default:0" json:"hit_count"`
	LastHitAt *time.Time `                          json:"last_hit_at,omitempty"`

	CreatedBy uuid.UUID `gorm:"type:uuid" json:"created_by"`
	CreatedAt time.Time `                 json:"created_at"`
	UpdatedAt time.Time `                 json:"updated_at"`
}

// CanaryHit is a single recorded visit to a CanaryToken's link.
type CanaryHit struct {
	ID      uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	TokenID uuid.UUID `gorm:"type:uuid;not null;index"                       json:"token_id"`

	// Network identity of the visitor.
	IP           string `gorm:"index" json:"ip"`                       // best-effort real client IP
	ForwardedFor string `              json:"forwarded_for,omitempty"` // raw X-Forwarded-For chain
	RemoteAddr   string `              json:"remote_addr,omitempty"`   // direct TCP peer (proxy/CDN edge)

	// Client software, parsed best-effort from the User-Agent.
	UserAgent      string `gorm:"type:text" json:"user_agent,omitempty"`
	Browser        string `                 json:"browser,omitempty"`
	OS             string `                 json:"os,omitempty"`
	DeviceType     string `                 json:"device_type,omitempty"` // desktop | mobile | tablet | bot
	Referer        string `gorm:"type:text" json:"referer,omitempty"`
	AcceptLanguage string `                 json:"accept_language,omitempty"`

	// IsBot flags automated visits — link-preview unfurlers (Slack/Telegram/
	// Facebook/Discord/Twitter…) and security scanners (Safe Links, Proofpoint…)
	// that fetch the URL without a human clicking. Lets the UI separate real
	// human clicks from noise so the hit count stays meaningful.
	IsBot bool `gorm:"index" json:"is_bot"`

	// GeoIP enrichment (APPROXIMATE — IP-based, city level), filled asynchronously
	// after the hit via ip-api.com. Skipped for private / loopback addresses.
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	City        string  `json:"city,omitempty"`
	ISP         string  `json:"isp,omitempty"`
	ASN         string  `json:"asn,omitempty"`
	Lat         float64 `json:"lat,omitempty"`
	Lon         float64 `json:"lon,omitempty"`

	// Network-type flags from ip-api — surface VPN/proxy, datacenter/hosting and
	// mobile-carrier connections so an analyst can judge how trustworthy the IP is.
	Mobile  bool `json:"mobile,omitempty"`
	Proxy   bool `json:"proxy,omitempty"`
	Hosting bool `json:"hosting,omitempty"`

	// ---- Rich client-side data (interstitial JS; only when CollectDetails) ----

	// Precise GPS location from the browser Geolocation API (visitor-consented).
	// Pointers so "not collected" is distinct from a real 0 value.
	GeoLat      *float64 `json:"geo_lat,omitempty"`
	GeoLon      *float64 `json:"geo_lon,omitempty"`
	GeoAccuracy *float64 `json:"geo_accuracy,omitempty"` // radius in metres
	GeoError    string   `json:"geo_error,omitempty"`    // e.g. "User denied Geolocation"

	// Device / browser fingerprint.
	Timezone     string   `json:"timezone,omitempty"`      // IANA tz (Intl)
	Languages    string   `json:"languages,omitempty"`     // navigator.languages, comma-joined
	ScreenW      int      `json:"screen_w,omitempty"`
	ScreenH      int      `json:"screen_h,omitempty"`
	ViewportW    int      `json:"viewport_w,omitempty"`
	ViewportH    int      `json:"viewport_h,omitempty"`
	PixelRatio   float64  `json:"pixel_ratio,omitempty"`
	Platform     string   `json:"platform,omitempty"`
	CPUCores     int      `json:"cpu_cores,omitempty"`     // navigator.hardwareConcurrency
	DeviceMemory float64  `json:"device_memory,omitempty"` // navigator.deviceMemory (GB)
	GPUVendor    string   `json:"gpu_vendor,omitempty"`    // WebGL UNMASKED_VENDOR
	GPURenderer  string   `json:"gpu_renderer,omitempty"`  // WebGL UNMASKED_RENDERER
	ConnType     string   `json:"conn_type,omitempty"`     // NetworkInformation effectiveType
	BatteryLevel *float64 `json:"battery_level,omitempty"` // 0..1

	// ClientData is the full raw JSON payload the interstitial reported, so any
	// field not promoted to a column above is still preserved for the UI.
	ClientData string `gorm:"type:text" json:"client_data,omitempty"`

	CreatedAt time.Time `gorm:"index" json:"created_at"`
}

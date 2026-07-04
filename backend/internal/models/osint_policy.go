package models

import "time"

// OsintScopeRule is one admin-defined rule of the OSINT scope policy. Rules are
// evaluated in ascending Priority order for each scan launch; the FIRST enabled
// rule whose conditions all match decides what the scan is allowed to do. This
// lets an administrator say, per situation, whether OSINT may run its active
// (target-touching) collectors or must stay passive.
//
// Conditions ("" or "any" means "don't care"):
//   - MatchTargetType: domain | ip | email | username | phone | hash | wallet | name | social_profile
//   - MatchScope:      internal | external  (internal = private-IP target or a
//     host under an admin-listed internal domain suffix)
//   - MatchEgress:     anonymized | direct  (whether OSINT egress currently goes
//     through a proxy)
//
// Action decides the collector set:
//   - all:          run every collector for the target type
//   - passive_only: drop active/target-touching collectors (favicon, webtech,
//     port scan, subdomain brute) — only third-party lookups run
//   - block:        run nothing (OSINT is refused for this case)
//
// RequireProxy, when set, downgrades an "all" action to "passive_only" whenever
// egress is direct — i.e. active collectors are only allowed once traffic is
// anonymized, so the operator's real IP is never exposed to the target.
type OsintScopeRule struct {
	ID       uint   `json:"id" gorm:"primaryKey"`
	Priority int    `json:"priority" gorm:"index;default:100"` // lower = evaluated first
	Name     string `json:"name" gorm:"not null"`
	Enabled  bool   `json:"enabled" gorm:"default:true"`

	MatchTargetType string `json:"match_target_type" gorm:"default:'any'"`
	MatchScope      string `json:"match_scope" gorm:"default:'any'"`
	MatchEgress     string `json:"match_egress" gorm:"default:'any'"`

	Action       string `json:"action" gorm:"default:'all'"`
	RequireProxy bool   `json:"require_proxy" gorm:"default:false"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// OsintScopeSetting is the singleton (id = 1) master configuration for the OSINT
// scope policy.
//
//   - Enforce:         master switch. When false the policy is bypassed entirely
//     (every collector runs) — useful to disable the feature without deleting
//     the rules.
//   - AllowOverride:   whether the operator may override the policy decision at
//     scan launch. Overrides may only make a scan MORE restrictive, never expand
//     it beyond what the policy allows.
//   - InternalDomains: newline/comma separated domain suffixes considered
//     "internal" (e.g. corp, local, mycompany.com). A target matching one is
//     classified as internal scope WITHOUT any DNS lookup (a lookup would itself
//     leak the recon).
type OsintScopeSetting struct {
	ID              uint      `json:"id" gorm:"primaryKey"`
	Enforce         bool      `json:"enforce" gorm:"default:true"`
	AllowOverride   bool      `json:"allow_override" gorm:"default:true"`
	InternalDomains string    `json:"internal_domains"`
	UpdatedAt       time.Time `json:"updated_at"`
}

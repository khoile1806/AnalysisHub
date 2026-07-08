package osint

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/models"
)

// policy.go — the OSINT scope policy. It lets an administrator decide, per
// situation (target type, internal/external scope, and whether egress is
// anonymized), whether an OSINT scan may run its ACTIVE collectors — the ones
// that touch the target's own infrastructure and would otherwise expose the
// operator's real IP — or must stay passive, or is refused entirely.

// CollectorClass categorises a collector by how it reaches the target.
type CollectorClass string

const (
	// ClassPassive queries only third-party sources (crt.sh, Shodan, WHOIS, breach
	// feeds…). The target's own infrastructure never sees the request, so it
	// leaves no trace on the target and cannot leak the operator's IP to it.
	ClassPassive CollectorClass = "passive"
	// ClassActive contacts the target's own infrastructure directly (fetching its
	// web root or favicon, brute-forcing its subdomains, scanning its ports).
	// Without a proxy these expose the operator's real IP to the target.
	ClassActive CollectorClass = "active"
)

// activeCollectors lists the collectors that touch the target's own
// infrastructure. Everything not listed is passive (third-party lookups only).
// Keyed by the stable collector name used in buildCollectors / OsintCollector.
var activeCollectors = map[string]bool{
	"favicon":  true, // GETs http(s)://<target>/favicon.ico
	"webtech":  true, // GETs the target web root to fingerprint the stack
	"portscan": true, // raw-TCP port sweep of the target (also intrusive)
	"subbrute": true, // resolves guessed subdomains against the target's DNS zone
}

// intrusiveCollectors are active collectors whose traffic is unmistakably a scan
// rather than a normal request. Not used to gate on its own yet, but recorded so
// the UI can flag the loudest collector.
var intrusiveCollectors = map[string]bool{
	"portscan": true,
}

// ClassOf returns the class of a collector by name.
func ClassOf(name string) CollectorClass {
	if activeCollectors[name] {
		return ClassActive
	}
	return ClassPassive
}

// IsIntrusiveCollector reports whether a collector performs an unmistakable scan.
func IsIntrusiveCollector(name string) bool { return intrusiveCollectors[name] }

// ScopeMode is the collector set a scope decision permits.
type ScopeMode string

const (
	ModeAll         ScopeMode = "all"          // run every collector
	ModePassiveOnly ScopeMode = "passive_only" // drop active/target-touching collectors
	ModeBlock       ScopeMode = "block"        // run nothing
)

// scopeModeRank orders modes from most permissive (0) to most restrictive, so an
// operator override can only ever tighten a policy decision, never loosen it.
func scopeModeRank(m ScopeMode) int {
	switch m {
	case ModeBlock:
		return 2
	case ModePassiveOnly:
		return 1
	default:
		return 0
	}
}

// ScopeDecision is the outcome of evaluating the scope policy for one target. It
// is returned to the launch UI (to show what will run) and enforced when the
// scan is created.
type ScopeDecision struct {
	Mode         ScopeMode `json:"mode"`
	Allowed      []string  `json:"allowed_collectors"`
	Blocked      []string  `json:"blocked_collectors"`
	RequireProxy bool      `json:"require_proxy"`
	Anonymized   bool      `json:"anonymized"` // current OSINT egress state
	Scope        string    `json:"scope"`      // internal | external
	Enforced     bool      `json:"enforced"`   // false when the master switch is off
	MatchedRule  string    `json:"matched_rule"`
	Reason       string    `json:"reason"`
}

// EgressAnonymized reports whether OSINT egress currently rides a proxy
// (OSINT_PROXY / OUTBOUND_PROXY / an active Proxy Manager profile). Exported so
// the API layer can evaluate the scope policy without reaching into the
// unexported egress helpers.
func EgressAnonymized() bool { return osintAnonymized() }

// isInternalIP reports whether ip is in a non-public range (loopback / private /
// link-local / unspecified) — i.e. an internal target.
func isInternalIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// normalizeSuffixes splits the admin's internal-domains blob (newline/comma
// separated) into lowercased, dot-trimmed suffixes.
func normalizeSuffixes(blob string) []string {
	fields := strings.FieldsFunc(blob, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t' || r == ';'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		s := strings.Trim(strings.ToLower(strings.TrimSpace(f)), ".")
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// TargetScope classifies a target as "internal" or "external" using NO network
// I/O (a DNS lookup would itself leak the recon). IP targets are judged by their
// range; domain / email / social targets are matched against the admin-supplied
// internal domain suffixes. Anything unmatched is external.
func TargetScope(target, ttype string, internalSuffixes []string) string {
	t := strings.ToLower(strings.TrimSpace(target))
	switch ttype {
	case TargetIP:
		if ip := net.ParseIP(t); ip != nil && isInternalIP(ip) {
			return "internal"
		}
	case TargetDomain, TargetEmail, TargetSocial:
		host := t
		if at := strings.LastIndex(host, "@"); at >= 0 { // email → domain part
			host = host[at+1:]
		}
		for _, s := range internalSuffixes {
			if host == s || strings.HasSuffix(host, "."+s) {
				return "internal"
			}
		}
	}
	return "external"
}

// EvaluateScopePolicy applies the rule set to one target and returns the
// decision. rules are evaluated in ascending priority order; the first enabled
// rule whose conditions all match wins. When enforce is false, or no rule
// matches, every collector is allowed.
func EvaluateScopePolicy(rules []models.OsintScopeRule, internalSuffixes []string, target, ttype string, anonymized, enforce bool) ScopeDecision {
	names := CollectorNamesFor(ttype)
	scope := TargetScope(target, ttype, internalSuffixes)
	egress := "direct"
	if anonymized {
		egress = "anonymized"
	}

	if !enforce {
		return finalizeDecision(names, ModeAll, false, anonymized, scope, false,
			"policy disabled — all collectors run", "")
	}

	sorted := append([]models.OsintScopeRule(nil), rules...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority < sorted[j].Priority
		}
		return sorted[i].ID < sorted[j].ID
	})

	for _, r := range sorted {
		if !r.Enabled {
			continue
		}
		if !matchCond(r.MatchTargetType, ttype) {
			continue
		}
		if !matchCond(r.MatchScope, scope) {
			continue
		}
		if !matchCond(r.MatchEgress, egress) {
			continue
		}
		mode := ScopeMode(strings.TrimSpace(r.Action))
		if mode != ModeAll && mode != ModePassiveOnly && mode != ModeBlock {
			mode = ModeAll
		}
		return finalizeDecision(names, mode, r.RequireProxy, anonymized, scope, true,
			"", r.Name)
	}

	return finalizeDecision(names, ModeAll, false, anonymized, scope, true,
		"no rule matched — default allow", "")
}

// matchCond reports whether a rule condition (""/"any" = wildcard) matches value.
func matchCond(cond, value string) bool {
	cond = strings.TrimSpace(cond)
	return cond == "" || cond == "any" || cond == value
}

// finalizeDecision resolves the effective mode (applying RequireProxy), splits
// the collector list, and composes a human reason.
func finalizeDecision(names []string, mode ScopeMode, requireProxy, anonymized bool, scope string, enforced bool, reason, ruleName string) ScopeDecision {
	effective := mode
	forcedByProxy := false
	if requireProxy && !anonymized && effective == ModeAll {
		effective = ModePassiveOnly
		forcedByProxy = true
	}

	var allowed, blocked []string
	for _, n := range names {
		if allowCollector(effective, n) {
			allowed = append(allowed, n)
		} else {
			blocked = append(blocked, n)
		}
	}

	if reason == "" {
		reason = describeReason(effective, scope, anonymized, forcedByProxy, len(blocked))
	}

	return ScopeDecision{
		Mode:         effective,
		Allowed:      allowed,
		Blocked:      blocked,
		RequireProxy: requireProxy,
		Anonymized:   anonymized,
		Scope:        scope,
		Enforced:     enforced,
		MatchedRule:  ruleName,
		Reason:       reason,
	}
}

// allowCollector reports whether a collector runs under mode.
func allowCollector(mode ScopeMode, name string) bool {
	switch mode {
	case ModeBlock:
		return false
	case ModePassiveOnly:
		return ClassOf(name) == ClassPassive
	default:
		return true
	}
}

func describeReason(mode ScopeMode, scope string, anonymized, forcedByProxy bool, blocked int) string {
	egress := "direct egress"
	if anonymized {
		egress = "anonymized egress"
	}
	switch mode {
	case ModeBlock:
		return fmt.Sprintf("OSINT refused for this %s target (%s)", scope, egress)
	case ModePassiveOnly:
		if forcedByProxy {
			return fmt.Sprintf("active collectors require a proxy but egress is direct — %d active collector(s) skipped to avoid exposing the real IP", blocked)
		}
		return fmt.Sprintf("passive-only for this %s target (%s) — %d active collector(s) skipped", scope, egress, blocked)
	default:
		return fmt.Sprintf("all collectors allowed (%s target, %s)", scope, egress)
	}
}

// LiftPassiveToActive upgrades a passive-only decision to full active scanning when
// an operator explicitly authorises touching the target directly — accepting the
// IP-exposure risk that forced passive-only on direct egress. It never lifts a
// Block decision (the hard boundary) and is a no-op for any non-passive mode.
func LiftPassiveToActive(d ScopeDecision, names []string) ScopeDecision {
	if d.Mode != ModePassiveOnly {
		return d
	}
	var allowed []string
	for _, n := range names {
		if allowCollector(ModeAll, n) {
			allowed = append(allowed, n)
		}
	}
	d.Mode = ModeAll
	d.Allowed = allowed
	d.Blocked = nil
	d.Reason = "operator-authorised active scan on direct egress — " + d.Reason
	return d
}

// ApplyOverride tightens a decision with an operator-supplied mode. The override
// may only make the scan MORE restrictive; a looser or unknown override is
// ignored. Returns the (possibly) adjusted decision.
func ApplyOverride(d ScopeDecision, override string, names []string) ScopeDecision {
	m := ScopeMode(strings.TrimSpace(override))
	if m != ModeAll && m != ModePassiveOnly && m != ModeBlock {
		return d
	}
	if scopeModeRank(m) <= scopeModeRank(d.Mode) {
		return d // not stricter — ignore
	}
	var allowed, blocked []string
	for _, n := range names {
		if allowCollector(m, n) {
			allowed = append(allowed, n)
		} else {
			blocked = append(blocked, n)
		}
	}
	d.Mode = m
	d.Allowed = allowed
	d.Blocked = blocked
	d.Reason = fmt.Sprintf("operator override → %s (%d collector(s) skipped)", m, len(blocked))
	return d
}

// LoadScopePolicy reads the rule set and settings from the database, seeding the
// singleton settings row on first use. Rules are returned unsorted (the
// evaluator sorts by priority).
func LoadScopePolicy(db *gorm.DB) (rules []models.OsintScopeRule, settings models.OsintScopeSetting) {
	if db == nil {
		return nil, models.OsintScopeSetting{Enforce: true, AllowOverride: true}
	}
	if err := db.First(&settings, 1).Error; err != nil {
		settings = models.OsintScopeSetting{ID: 1, Enforce: true, AllowOverride: true}
		db.Create(&settings)
	}
	db.Order("priority asc, id asc").Find(&rules)
	return rules, settings
}

// DecideScope loads the policy and evaluates it for one target — the convenience
// entry point used by the API handler and the auto-pivot engine so both enforce
// the same decision.
func DecideScope(db *gorm.DB, target, ttype string) ScopeDecision {
	rules, settings := LoadScopePolicy(db)
	return EvaluateScopePolicy(rules, normalizeSuffixes(settings.InternalDomains),
		target, ttype, EgressAnonymized(), settings.Enforce)
}

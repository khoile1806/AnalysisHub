package sigma

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Alert represents a triggered Sigma rule against an event.
type Alert struct {
	RuleID          string                 `json:"rule_id,omitempty"`
	RuleTitle       string                 `json:"rule_title"`
	RuleLevel       string                 `json:"rule_level"`
	RuleDescription string                 `json:"rule_description"`
	Tags            []string               `json:"tags,omitempty"`
	Techniques      []string               `json:"mitre_techniques,omitempty"`
	Tactics         []string               `json:"mitre_tactics,omitempty"`
	Event           map[string]interface{} `json:"event"`
	// EventCount is how many events matched this rule in the scan. Alerts are
	// rolled up per rule so one noisy rule over a 10k-event pull no longer
	// produces 10k indistinguishable rows.
	EventCount int `json:"event_count,omitempty"`
	// Condition and Matches explain WHY the rule fired: the rule's boolean
	// condition, and the field comparisons that satisfied it on this event.
	Condition string       `json:"condition,omitempty"`
	Matches   []FieldMatch `json:"matches,omitempty"`
}

// LoadStats records what happened during the last rule load. Parse failures used
// to be discarded silently, so a ruleset that half-loaded looked healthy.
type LoadStats struct {
	Files       int `json:"files"`
	Loaded      int `json:"loaded"`
	Unsupported int `json:"unsupported"`
	Errors      int `json:"errors"`
}

// Engine loads and evaluates Sigma rules.
type Engine struct {
	rules []*Rule
	stats LoadStats

	// byEventID / unbound narrow the rules a single event has to be evaluated
	// against. The split mirrors the EventID gate in logsourceMatches exactly:
	// a rule only lands in an ID bucket when logsourceMatches would reject every
	// other ID anyway, so this is a pure speedup and never changes a verdict.
	// It matters once a full SigmaHQ sync is loaded — matching every event
	// against every one of ~3k rules is tens of millions of comparisons.
	byEventID map[string][]*Rule
	unbound   []*Rule

	mu sync.RWMutex
}

var (
	DefaultEngine *Engine
	once          sync.Once
)

// maxAlertsPerRule bounds how many sample events a single rule contributes.
const maxAlertsPerRule = 25

// Init loads rules from the specified directory.
func Init(rulesDir string) {
	once.Do(func() {
		DefaultEngine = &Engine{}
		DefaultEngine.LoadDirectory(rulesDir)
	})
}

// LoadDirectory loads all .yml and .yaml files in a directory recursively.
func (e *Engine) LoadDirectory(dir string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.rules = make([]*Rule, 0)
	e.stats = LoadStats{}

	if _, statErr := os.Stat(dir); statErr != nil {
		// Worth shouting about: a missing directory used to be reported as
		// "loaded 0 rules", which reads like an empty ruleset rather than a
		// deployment that never shipped one.
		log.Printf("Sigma engine: rules directory %s is not readable (%v) - no rules loaded", dir, statErr)
		return
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		e.stats.Files++
		rules, loadErr := LoadRules(path)
		if loadErr != nil {
			e.stats.Errors++
			return nil
		}
		for _, rule := range rules {
			if rule == nil {
				continue
			}
			if rule.Unsupported != "" {
				e.stats.Unsupported++
				continue
			}
			e.rules = append(e.rules, rule)
			e.stats.Loaded++
		}
		return nil
	})

	if err != nil {
		log.Printf("Sigma engine failed to walk directory %s: %v", dir, err)
		return
	}
	e.buildIndex()
	log.Printf("Sigma engine loaded %d rules from %s (%d files, %d unsupported, %d unreadable)",
		e.stats.Loaded, dir, e.stats.Files, e.stats.Unsupported, e.stats.Errors)
}

// buildIndex buckets the loaded rules by the event IDs their logsource category
// pins them to. Callers must hold the write lock.
func (e *Engine) buildIndex() {
	e.byEventID = make(map[string][]*Rule)
	e.unbound = nil
	for _, rule := range e.rules {
		ids := gateEventIDs(rule)
		if len(ids) == 0 {
			e.unbound = append(e.unbound, rule)
			continue
		}
		for _, id := range ids {
			e.byEventID[id] = append(e.byEventID[id], rule)
		}
	}
}

// gateEventIDs returns the event IDs logsourceMatches would restrict a rule to,
// or nil when it applies no ID gate. Keep this in step with logsourceMatches —
// they must agree, or the index would hide rules that could legitimately match.
func gateEventIDs(rule *Rule) []string {
	if len(rule.Logsource) == 0 {
		return nil
	}
	category := strings.ToLower(rule.Logsource["category"])
	if product := strings.ToLower(rule.Logsource["product"]); product != "" && product != "windows" {
		// Non-Windows events are keyed by category name, not by a Windows event
		// number. Bucketing these under categoryEventIDs would file a linux rule
		// under 4688 and it would never be considered for a linux event.
		if category != "" {
			return []string{category}
		}
		return nil
	}
	if ids, ok := categoryEventIDs[category]; ok {
		return ids
	}
	return nil
}

// Scan takes an array of JSON objects (events) and evaluates them against all rules.
func (e *Engine) Scan(jsonData string) ([]Alert, error) {
	return e.ScanContext(context.Background(), jsonData)
}

// ScanContext is Scan with cancellation: a large event set against a large rule
// set is bounded by ctx so a slow/abusive scan can be aborted (it is checked
// once per event, between rule batches).
func (e *Engine) ScanContext(ctx context.Context, jsonData string) ([]Alert, error) {
	var events []map[string]interface{}
	if err := json.Unmarshal([]byte(jsonData), &events); err != nil {
		// Try parsing as single object
		var singleEvent map[string]interface{}
		if err2 := json.Unmarshal([]byte(jsonData), &singleEvent); err2 != nil {
			return nil, fmt.Errorf("invalid json event data")
		}
		events = append(events, singleEvent)
	}

	return e.ScanEvents(ctx, events)
}

// ScanEvents evaluates already-decoded events. Callers that hold the events in
// memory should use this directly: routing them through ScanContext would
// marshal and immediately unmarshal the whole batch again.
func (e *Engine) ScanEvents(ctx context.Context, events []map[string]interface{}) ([]Alert, error) {
	// Snapshot under the read lock and release it before matching. Holding it
	// for the whole scan blocked every Reload/sync for the duration, and a large
	// batch against a synced ruleset can run for a long time.
	e.mu.RLock()
	all := e.rules
	byEventID := e.byEventID
	unbound := e.unbound
	e.mu.RUnlock()

	var alerts []Alert
	// index maps a rule key to the position of its first alert so repeated
	// matches roll up into EventCount instead of appending a new row each time.
	index := make(map[string]int)
	samples := make(map[string]int)

	consider := func(rule *Rule, event map[string]interface{}) {
		if !logsourceMatches(rule, event) || !MatchEvent(rule, event) {
			return
		}
		key := rule.ID
		if key == "" {
			key = rule.Title + "\x00" + rule.filepath
		}
		if pos, seen := index[key]; seen {
			alerts[pos].EventCount++
			if samples[key] < maxAlertsPerRule {
				samples[key]++
				alerts = append(alerts, newAlert(rule, event, 0))
			}
			return
		}
		index[key] = len(alerts)
		samples[key] = 1
		alerts = append(alerts, newAlert(rule, event, 1))
	}

	for _, event := range events {
		if err := ctx.Err(); err != nil {
			return alerts, err
		}
		for _, rule := range candidateRules(all, byEventID, unbound, event) {
			consider(rule, event)
		}
	}

	return alerts, nil
}

// candidateRules narrows the ruleset for one event using the EventID index.
// An event we cannot classify falls back to the full set, which is what
// logsourceMatches does too — gating is only ever applied on a positive match.
func candidateRules(all []*Rule, byEventID map[string][]*Rule, unbound []*Rule, event map[string]interface{}) []*Rule {
	// An Engine assembled without LoadDirectory has no index. Falling through to
	// the buckets would evaluate nothing at all and report a clean scan, so treat
	// a missing index as "no narrowing available".
	if byEventID == nil && unbound == nil {
		return all
	}
	got, found := lookupDirect(event, "EventID")
	if !found {
		return all
	}
	id := strings.TrimSpace(fmt.Sprintf("%v", got))
	if id == "" {
		return all
	}
	bucket := byEventID[id]
	if len(bucket) == 0 {
		return unbound
	}
	out := make([]*Rule, 0, len(bucket)+len(unbound))
	out = append(out, bucket...)
	return append(out, unbound...)
}

func newAlert(rule *Rule, event map[string]interface{}, count int) Alert {
	return Alert{
		Condition:       rule.Condition,
		Matches:         ExplainMatch(rule, event),
		RuleID:          rule.ID,
		RuleTitle:       rule.Title,
		RuleLevel:       rule.Level,
		RuleDescription: rule.Description,
		Tags:            rule.Tags,
		Techniques:      rule.Techniques,
		Tactics:         rule.Tactics,
		Event:           event,
		EventCount:      count,
	}
}

// RuleCount returns the number of currently loaded rules.
func (e *Engine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// Stats returns the outcome of the last rule load.
func (e *Engine) Stats() LoadStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.stats
}

// Reload re-reads all rules from a directory (used after a SigmaHQ sync).
func (e *Engine) Reload(dir string) int {
	e.LoadDirectory(dir)
	return e.RuleCount()
}

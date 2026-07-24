package sigma

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Source is one EVTX query needed to give the loaded ruleset something to match
// against: a channel plus the event IDs the rules actually reference.
type Source struct {
	LogName  string `json:"log_name"`
	EventIDs []int  `json:"event_ids"`
	Rules    int    `json:"rules"` // how many loaded rules target this source
}

// channelIDs pairs a channel with the event IDs that carry a category on it.
type channelIDs struct {
	Channel string
	IDs     []int
}

// categorySources maps a Sigma logsource category to the channels that can carry
// it AND the event IDs it lives under on each one. Keeping the two together
// matters: process_creation is 4688 on Security but 1 on Sysmon, so a sweep that
// derived the channel and the ID separately would filter the wrong log.
//
// Most rules never state an EventID — they rely on the category — so without
// this table those channels would have to be pulled unfiltered, and a capped
// pull of an unfiltered Security log is mostly logon noise with the process
// events the rules actually need pushed off the end.
var categorySources = map[string][]channelIDs{
	"process_creation":     {{"Security", []int{4688}}, {sysmonChannel, []int{1}}},
	"process_termination":  {{"Security", []int{4689}}, {sysmonChannel, []int{5}}},
	"network_connection":   {{sysmonChannel, []int{3}}, {"Security", []int{5156}}},
	"file_event":           {{sysmonChannel, []int{11}}},
	"file_delete":          {{sysmonChannel, []int{23, 26}}},
	"file_change":          {{sysmonChannel, []int{2}}},
	"image_load":           {{sysmonChannel, []int{7}}},
	"driver_load":          {{sysmonChannel, []int{6}}},
	"create_remote_thread": {{sysmonChannel, []int{8}}},
	"raw_access_thread":    {{sysmonChannel, []int{9}}},
	"process_access":       {{sysmonChannel, []int{10}}},
	"registry_event":       {{sysmonChannel, []int{12, 13, 14}}},
	"registry_add":         {{sysmonChannel, []int{12}}},
	"registry_set":         {{sysmonChannel, []int{13}}},
	"registry_delete":      {{sysmonChannel, []int{12, 14}}},
	"registry_rename":      {{sysmonChannel, []int{14}}},
	"pipe_created":         {{sysmonChannel, []int{17, 18}}},
	"wmi_event":            {{sysmonChannel, []int{19, 20, 21}}},
	"dns_query":            {{sysmonChannel, []int{22}}},
	"clipboard_capture":    {{sysmonChannel, []int{24}}},
	"process_tampering":    {{sysmonChannel, []int{25}}},
	"ps_script":            {{psChannel, []int{4104}}},
	"ps_module":            {{psChannel, []int{4103}}},
	"ps_classic_start":     {{"Windows PowerShell", []int{400, 403, 600}}},
}

// serviceChannels maps a logsource service to its channel.
var serviceChannels = map[string]string{
	"security":                             "Security",
	"system":                               "System",
	"application":                          "Application",
	"sysmon":                               sysmonChannel,
	"powershell":                           psChannel,
	"powershell-classic":                   "Windows PowerShell",
	"taskscheduler":                        "Microsoft-Windows-TaskScheduler/Operational",
	"wmi":                                  "Microsoft-Windows-WMI-Activity/Operational",
	"terminalservices-localsessionmanager": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
	"bits-client":                          "Microsoft-Windows-Bits-Client/Operational",
	"windefend":                            "Microsoft-Windows-Windows Defender/Operational",
	"applocker":                            "Microsoft-Windows-AppLocker/EXE and DLL",
	"codeintegrity-operational":            "Microsoft-Windows-CodeIntegrity/Operational",
	"ntlm":                                 "Microsoft-Windows-NTLM/Operational",
	"printservice-operational":             "Microsoft-Windows-PrintService/Operational",
	"smbclient-security":                   "Microsoft-Windows-SmbClient/Security",
}

const (
	sysmonChannel = "Microsoft-Windows-Sysmon/Operational"
	psChannel     = "Microsoft-Windows-PowerShell/Operational"
)

// maxIDsPerSource caps how many event IDs one query may carry. Past this the
// filter stops being selective and it is cheaper to pull the channel unfiltered.
const maxIDsPerSource = 40

// RequiredSources derives the EVTX queries needed to exercise the whole loaded
// ruleset. It is driven by the rules themselves — their logsource plus the
// EventID values they reference — rather than a fixed list, so syncing more
// rules automatically widens the sweep.
//
// A channel where at least one rule matches on something other than EventID is
// returned with an empty ID list, meaning "pull this channel unfiltered".
func (e *Engine) RequiredSources() []Source {
	e.mu.RLock()
	defer e.mu.RUnlock()

	ids := map[string]map[int]bool{}
	unfiltered := map[string]bool{}
	counts := map[string]int{}

	for _, rule := range e.rules {
		// An EventID written into the detection is authoritative and applies to
		// every channel the rule targets; otherwise fall back to the IDs the
		// category occupies on each specific channel.
		explicit := ruleEventIDs(rule)
		for _, target := range ruleTargets(rule) {
			ch := target.Channel
			counts[ch]++
			if ids[ch] == nil {
				ids[ch] = map[int]bool{}
			}
			effective := explicit
			if len(effective) == 0 {
				effective = target.IDs
			}
			if len(effective) == 0 {
				unfiltered[ch] = true
				continue
			}
			for _, id := range effective {
				ids[ch][id] = true
			}
		}
	}

	out := make([]Source, 0, len(counts))
	for ch, n := range counts {
		s := Source{LogName: ch, Rules: n}
		if !unfiltered[ch] {
			for id := range ids[ch] {
				s.EventIDs = append(s.EventIDs, id)
			}
			sort.Ints(s.EventIDs)
			if len(s.EventIDs) > maxIDsPerSource {
				s.EventIDs = nil
			}
		}
		out = append(out, s)
	}
	// Deterministic order, busiest channel first so the most productive query
	// runs before any time budget runs out.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Rules != out[j].Rules {
			return out[i].Rules > out[j].Rules
		}
		return out[i].LogName < out[j].LogName
	})
	return out
}

// TechniqueCoverage describes how much of the loaded ruleset maps to one ATT&CK
// technique, and which log channels those rules depend on.
type TechniqueCoverage struct {
	Technique string   `json:"technique"`
	Tactics   []string `json:"tactics,omitempty"`
	Rules     int      `json:"rules"`
	Channels  []string `json:"channels"`
}

// TechniqueCoverage reports the ATT&CK techniques the loaded ruleset claims to
// cover. Pairing each technique with the channels its rules need is what makes
// the answer honest: "12 rules cover T1003" means nothing if all twelve need a
// Sysmon channel that no host actually has.
func (e *Engine) TechniqueCoverage() []TechniqueCoverage {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	type acc struct {
		tactics  map[string]bool
		channels map[string]bool
		rules    int
	}
	byTechnique := map[string]*acc{}

	for _, rule := range rules {
		if len(rule.Techniques) == 0 {
			continue
		}
		var channels []string
		for _, t := range ruleTargets(rule) {
			channels = append(channels, t.Channel)
		}
		for _, tech := range rule.Techniques {
			a := byTechnique[tech]
			if a == nil {
				a = &acc{tactics: map[string]bool{}, channels: map[string]bool{}}
				byTechnique[tech] = a
			}
			a.rules++
			for _, tac := range rule.Tactics {
				a.tactics[tac] = true
			}
			for _, ch := range channels {
				a.channels[ch] = true
			}
		}
	}

	out := make([]TechniqueCoverage, 0, len(byTechnique))
	for tech, a := range byTechnique {
		tc := TechniqueCoverage{Technique: tech, Rules: a.rules}
		for t := range a.tactics {
			tc.Tactics = append(tc.Tactics, t)
		}
		for c := range a.channels {
			tc.Channels = append(tc.Channels, c)
		}
		sort.Strings(tc.Tactics)
		sort.Strings(tc.Channels)
		out = append(out, tc)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Rules != out[j].Rules {
			return out[i].Rules > out[j].Rules
		}
		return out[i].Technique < out[j].Technique
	})
	return out
}

// ruleTargets resolves the channels a rule could match on, each with the event
// IDs its category occupies there.
func ruleTargets(r *Rule) []channelIDs {
	if len(r.Logsource) == 0 {
		return []channelIDs{{Channel: "Security"}}
	}
	if product := strings.ToLower(r.Logsource["product"]); product != "" && product != "windows" {
		return nil
	}
	var out []channelIDs
	out = append(out, categorySources[strings.ToLower(r.Logsource["category"])]...)
	if ch, ok := serviceChannels[strings.ToLower(r.Logsource["service"])]; ok {
		if !hasChannel(out, ch) {
			out = append(out, channelIDs{Channel: ch})
		}
	}
	if len(out) == 0 {
		// A windows rule with no usable category/service still has to be given
		// something; Security is where most ID-only rules live.
		out = []channelIDs{{Channel: "Security"}}
	}
	return out
}

func hasChannel(list []channelIDs, ch string) bool {
	for _, c := range list {
		if c.Channel == ch {
			return true
		}
	}
	return false
}

// ruleEventIDs collects every EventID literal referenced anywhere in a rule's
// detection block, so a sweep can filter the channel down to what the rule
// actually needs.
func ruleEventIDs(r *Rule) []int {
	seen := map[int]bool{}
	var walk func(v interface{})
	walk = func(v interface{}) {
		switch t := v.(type) {
		case map[string]interface{}:
			for k, val := range t {
				field := strings.ToLower(strings.SplitN(k, "|", 2)[0])
				if field == "eventid" {
					collectInts(val, seen)
					continue
				}
				walk(val)
			}
		case []interface{}:
			for _, item := range t {
				walk(item)
			}
		}
	}
	for key, val := range r.Detection {
		if key == "condition" || key == "timeframe" {
			continue
		}
		walk(val)
	}
	out := make([]int, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Ints(out)
	return out
}

func collectInts(v interface{}, into map[int]bool) {
	switch t := v.(type) {
	case []interface{}:
		for _, item := range t {
			collectInts(item, into)
		}
	case int:
		into[t] = true
	default:
		if n, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", v))); err == nil {
			into[n] = true
		}
	}
}

package sigma

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rule represents a parsed Sigma rule.
type Rule struct {
	ID          string
	Title       string
	Description string
	Level       string
	Status      string
	Tags        []string
	Techniques  []string // MITRE ATT&CK technique IDs derived from tags (e.g. T1059.001)
	Tactics     []string // MITRE ATT&CK tactic names derived from tags (e.g. Execution)
	Logsource   map[string]string
	Detection   map[string]interface{}
	Condition   string

	// Unsupported is set when the rule parsed but cannot be evaluated faithfully
	// (aggregation/correlation conditions, unknown selection references, …).
	// Such rules are kept for reporting but never matched, because evaluating
	// them partially produces false positives rather than detections.
	Unsupported string

	filepath string
}

// LoadRules parses a Sigma YAML file, which may hold several documents. Upstream
// "rule collections" put shared keys in a document marked `action: global` and
// the per-rule deltas in the ones that follow; decoding only the first document
// silently dropped every rule in such a file.
func LoadRules(path string) ([]*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var docs []map[string]interface{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var raw map[string]interface{}
		if err := dec.Decode(&raw); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if len(raw) > 0 {
			docs = append(docs, raw)
		}
	}
	if len(docs) == 0 {
		return nil, nil
	}

	var global map[string]interface{}
	var out []*Rule
	for _, raw := range docs {
		if action, _ := raw["action"].(string); strings.EqualFold(action, "global") {
			global = raw
			continue
		}
		merged := raw
		if global != nil {
			merged = mergeRuleDocs(global, raw)
		}
		if r := ruleFromMap(merged, path); r != nil {
			out = append(out, r)
		}
	}
	// A collection whose only document was the global block still yields nothing
	// useful; a plain single-document rule falls through here unchanged.
	return out, nil
}

// mergeRuleDocs overlays a rule document on top of the collection's global
// document. Top-level keys win from the child; logsource/detection are merged
// one level deep, which is what the Sigma spec prescribes.
func mergeRuleDocs(global, child map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(global)+len(child))
	for k, v := range global {
		if k == "action" {
			continue
		}
		out[k] = v
	}
	for k, v := range child {
		gm, gok := out[k].(map[string]interface{})
		cm, cok := v.(map[string]interface{})
		if gok && cok {
			nested := make(map[string]interface{}, len(gm)+len(cm))
			for gk, gv := range gm {
				nested[gk] = gv
			}
			for ck, cv := range cm {
				nested[ck] = cv
			}
			out[k] = nested
			continue
		}
		out[k] = v
	}
	return out
}

func ruleFromMap(raw map[string]interface{}, path string) *Rule {
	r := &Rule{filepath: path}

	if id, ok := raw["id"].(string); ok {
		r.ID = id
	}
	if t, ok := raw["title"].(string); ok {
		r.Title = t
	}
	if d, ok := raw["description"].(string); ok {
		r.Description = d
	}
	if l, ok := raw["level"].(string); ok {
		r.Level = l
	}
	if s, ok := raw["status"].(string); ok {
		r.Status = strings.ToLower(s)
	}

	// Tags carry the MITRE ATT&CK mapping (attack.t1059.001, attack.execution, …).
	if tags, ok := raw["tags"].([]interface{}); ok {
		for _, t := range tags {
			if s, ok := t.(string); ok {
				r.Tags = append(r.Tags, s)
			}
		}
		r.Techniques, r.Tactics = mitreFromTags(r.Tags)
	}

	if ls, ok := raw["logsource"].(map[string]interface{}); ok {
		r.Logsource = make(map[string]string)
		for k, v := range ls {
			r.Logsource[k] = fmt.Sprintf("%v", v)
		}
	}

	det, ok := raw["detection"].(map[string]interface{})
	if !ok {
		return nil
	}
	r.Detection = det
	r.Condition = conditionString(det["condition"])

	r.Unsupported = validateRule(r)
	return r
}

// conditionString normalises the `condition` key, which the spec allows to be a
// single string or a list of alternatives (an implicit OR). The list form used
// to type-assert to "" and left the rule permanently inert.
func conditionString(v interface{}) string {
	switch c := v.(type) {
	case string:
		return c
	case []interface{}:
		parts := make([]string, 0, len(c))
		for _, item := range c {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				parts = append(parts, "( "+s+" )")
			}
		}
		return strings.Join(parts, " or ")
	}
	return ""
}

// validateRule returns the reason a rule cannot be evaluated, or "" when it can.
func validateRule(r *Rule) string {
	if r.Status == "deprecated" || r.Status == "unsupported" {
		return "rule status: " + r.Status
	}
	if strings.TrimSpace(r.Condition) == "" {
		return "missing or unreadable condition"
	}
	node := parseCondition(r.Condition)
	if node == nil {
		// Aggregations (`| count() by X > N`) and near-correlations land here.
		return "unsupported condition syntax: " + strings.TrimSpace(r.Condition)
	}
	var names []string
	node.idents(&names)
	for _, n := range names {
		if _, ok := r.Detection[n]; !ok {
			// A dangling name silently evaluates to false — and to *true* under
			// `not`, turning a suppression clause into a pass-through.
			return "condition references unknown selection: " + n
		}
	}
	return ""
}

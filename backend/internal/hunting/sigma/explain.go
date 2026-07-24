package sigma

import (
	"fmt"
	"strings"
)

// FieldMatch is one field comparison that contributed to a rule firing: which
// selection it belongs to, what the rule asked for, and what the event actually
// contained. Without this an analyst sees "rule X fired" and has to re-read the
// YAML and eyeball the raw event to work out why.
type FieldMatch struct {
	Selection string `json:"selection"`
	Field     string `json:"field"`
	Modifier  string `json:"modifier,omitempty"`
	Expected  string `json:"expected"`
	Actual    string `json:"actual"`
}

// maxExplainValue bounds a reported value. Command lines and script blocks run
// to tens of kilobytes and would dwarf the alert itself.
const maxExplainValue = 500

// maxExplainFields bounds how many comparisons one alert reports.
const maxExplainFields = 40

// ExplainMatch reports the field comparisons that made a rule match an event.
//
// It re-runs the comparison instead of instrumenting matchSelection, because an
// explanation is only ever needed for the handful of events that become alerts —
// paying for it inside the matching loop would slow down every event that does
// not match, which is nearly all of them.
func ExplainMatch(rule *Rule, event map[string]interface{}) []FieldMatch {
	if rule == nil || rule.Detection == nil {
		return nil
	}
	var out []FieldMatch
	for key, val := range rule.Detection {
		if key == "condition" || key == "timeframe" {
			continue
		}
		switch v := val.(type) {
		case map[string]interface{}:
			if matchSelection(v, event) {
				out = append(out, explainSelection(key, v, event)...)
			}
		case []interface{}:
			// A list of selection blocks is an OR; report the first branch that
			// matched rather than every branch that exists.
			for i, item := range v {
				m, ok := item.(map[string]interface{})
				if !ok || !matchSelection(m, event) {
					continue
				}
				name := fmt.Sprintf("%s[%d]", key, i)
				out = append(out, explainSelection(name, m, event)...)
				break
			}
		}
		if len(out) >= maxExplainFields {
			return out[:maxExplainFields]
		}
	}
	return out
}

// explainSelection records, for a selection already known to match, which
// expected value satisfied each field.
func explainSelection(name string, selection map[string]interface{}, event map[string]interface{}) []FieldMatch {
	out := make([]FieldMatch, 0, len(selection))
	for fieldKey, expected := range selection {
		parts := strings.Split(fieldKey, "|")
		fieldName := parts[0]
		mods := parseModifiers(parts[1:])

		actualVal, found := lookupField(event, fieldName)
		actual := ""
		if found {
			actual = fmt.Sprintf("%v", actualVal)
		}

		fm := FieldMatch{
			Selection: name,
			Field:     fieldName,
			Modifier:  strings.Join(parts[1:], "|"),
			Actual:    truncExplain(actual),
		}

		switch {
		case expected == nil:
			fm.Expected = "(absent or empty)"
		case mods.op == "exists":
			fm.Expected = fmt.Sprintf("exists=%v", expected)
		default:
			fm.Expected = truncExplain(matchedExpected(expected, actual, mods))
		}
		out = append(out, fm)
	}
	return out
}

// matchedExpected picks the specific value that matched out of a list, so the
// explanation names the one entry that fired rather than the whole alternation.
func matchedExpected(expected interface{}, actual string, mods modifiers) string {
	list, ok := expected.([]interface{})
	if !ok {
		return fmt.Sprintf("%v", expected)
	}
	if mods.all {
		// Every member had to match, so the whole list is the reason.
		return joinValues(list)
	}
	for _, item := range list {
		s := fmt.Sprintf("%v", item)
		if matchOne(s, actual, mods) {
			return s
		}
	}
	return joinValues(list)
}

func joinValues(list []interface{}) string {
	parts := make([]string, 0, len(list))
	for _, item := range list {
		parts = append(parts, fmt.Sprintf("%v", item))
	}
	return strings.Join(parts, ", ")
}

func truncExplain(s string) string {
	if len(s) <= maxExplainValue {
		return s
	}
	return s[:maxExplainValue] + "…"
}

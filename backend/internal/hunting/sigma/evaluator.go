package sigma

import (
	"fmt"
	"regexp"
	"strings"
)

// MatchEvent evaluates a single event against a Sigma Rule.
func MatchEvent(rule *Rule, event map[string]interface{}) bool {
	if rule.Detection == nil || rule.Condition == "" {
		return false
	}

	// 1. Evaluate all named selections
	results := make(map[string]bool)
	for key, val := range rule.Detection {
		if key == "condition" || key == "timeframe" {
			continue
		}
		
		// val is either a map (field: value) or a list of maps
		matched := false
		switch v := val.(type) {
		case map[string]interface{}:
			matched = matchSelection(v, event)
		case []interface{}:
			// If it's a list, usually it implies OR between elements
			for _, item := range v {
				if m, ok := item.(map[string]interface{}); ok {
					if matchSelection(m, event) {
						matched = true
						break
					}
				}
			}
		}
		results[key] = matched
	}

	// 2. Evaluate condition
	return evaluateCondition(rule.Condition, results)
}

func matchSelection(selection map[string]interface{}, event map[string]interface{}) bool {
	// A selection block implies AND between all its fields
	for fieldKey, expected := range selection {
		fieldParts := strings.Split(fieldKey, "|")
		fieldName := fieldParts[0]
		modifier := ""
		if len(fieldParts) > 1 {
			modifier = fieldParts[1]
		}

		// Find value in event (case-insensitive key match)
		var actualVal interface{}
		found := false
		for k, v := range event {
			if strings.EqualFold(k, fieldName) {
				actualVal = v
				found = true
				break
			}
		}

		if !found {
			// If field is missing, the AND condition fails
			return false
		}

		// Match expected vs actual
		if !matchValue(expected, actualVal, modifier) {
			return false
		}
	}
	return true
}

func matchValue(expected, actual interface{}, modifier string) bool {
	actualStr := fmt.Sprintf("%v", actual)
	
	switch e := expected.(type) {
	case string:
		return matchString(e, actualStr, modifier)
	case []interface{}:
		// List of values implies OR
		for _, item := range e {
			if matchString(fmt.Sprintf("%v", item), actualStr, modifier) {
				return true
			}
		}
		return false
	default:
		// int, bool, etc.
		return matchString(fmt.Sprintf("%v", e), actualStr, modifier)
	}
}

func matchString(expected, actual, modifier string) bool {
	// Default is case-insensitive exact match in Sigma for strings, unless regex
	expectedStr := strings.ToLower(expected)
	actualStr := strings.ToLower(actual)

	switch modifier {
	case "contains":
		return strings.Contains(actualStr, expectedStr)
	case "startswith":
		return strings.HasPrefix(actualStr, expectedStr)
	case "endswith":
		return strings.HasSuffix(actualStr, expectedStr)
	case "re":
		// Regex match
		re, err := regexp.Compile("(?i)" + expected)
		if err != nil {
			return false
		}
		return re.MatchString(actual)
	default:
		return expectedStr == actualStr
	}
}

func evaluateCondition(condition string, results map[string]bool) bool {
	// A very basic condition evaluator for standard patterns.
	// In a full implementation, this would be a boolean parser.
	cond := strings.TrimSpace(condition)
	
	if cond == "1 of them" || cond == "any of them" {
		for _, v := range results {
			if v { return true }
		}
		return false
	}
	
	if cond == "all of them" {
		for _, v := range results {
			if !v { return false }
		}
		return true
	}

	// Basic "selection" or named identifier
	if val, exists := results[cond]; exists {
		return val
	}

	// "selection and not filter"
	if strings.Contains(cond, " and not ") {
		parts := strings.SplitN(cond, " and not ", 2)
		left := strings.TrimSpace(parts[0])
		right := strings.TrimSpace(parts[1])
		return results[left] && !results[right]
	}

	// "selection1 or selection2"
	if strings.Contains(cond, " or ") {
		parts := strings.Split(cond, " or ")
		for _, p := range parts {
			if results[strings.TrimSpace(p)] {
				return true
			}
		}
		return false
	}

	// "selection1 and selection2"
	if strings.Contains(cond, " and ") {
		parts := strings.Split(cond, " and ")
		for _, p := range parts {
			if !results[strings.TrimSpace(p)] {
				return false
			}
		}
		return true
	}

	return false
}

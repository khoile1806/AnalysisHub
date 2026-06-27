package sigma

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// MatchEvent evaluates a single event against a Sigma Rule.
func MatchEvent(rule *Rule, event map[string]interface{}) bool {
	if rule.Detection == nil || rule.Condition == "" {
		return false
	}

	// 1. Evaluate all named selections.
	results := make(map[string]bool)
	for key, val := range rule.Detection {
		if key == "condition" || key == "timeframe" {
			continue
		}

		// val is either a map (field: value) or a list of maps.
		matched := false
		switch v := val.(type) {
		case map[string]interface{}:
			matched = matchSelection(v, event)
		case []interface{}:
			// A list of selection blocks implies OR between elements.
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

	// 2. Evaluate the (possibly complex boolean) condition.
	return evaluateCondition(rule.Condition, results)
}

func matchSelection(selection map[string]interface{}, event map[string]interface{}) bool {
	// A selection block implies AND between all of its fields.
	for fieldKey, expected := range selection {
		fieldParts := strings.Split(fieldKey, "|")
		fieldName := fieldParts[0]

		// Sigma allows chained modifiers, e.g. "CommandLine|contains|all".
		op := ""
		all := false
		for _, m := range fieldParts[1:] {
			switch strings.ToLower(m) {
			case "all":
				all = true
			case "contains", "startswith", "endswith", "re":
				op = strings.ToLower(m)
				// Unknown/unsupported modifiers (base64, cidr, ...) degrade to a
				// default string compare rather than silently dropping the field.
			}
		}

		actualVal, found := lookupField(event, fieldName)
		if !found {
			// A missing field fails the AND-joined selection.
			return false
		}

		if !matchFieldValue(expected, actualVal, op, all) {
			return false
		}
	}
	return true
}

// lookupField finds a value in the event by case-insensitive key match.
func lookupField(event map[string]interface{}, fieldName string) (interface{}, bool) {
	for k, v := range event {
		if strings.EqualFold(k, fieldName) {
			return v, true
		}
	}
	return nil, false
}

// matchValue keeps the original OR-list semantics (kept for callers/tests).
func matchValue(expected, actual interface{}, modifier string) bool {
	return matchFieldValue(expected, actual, modifier, false)
}

// matchFieldValue compares an expected spec against an actual value.
// When all is true and expected is a list, every member must match (the |all
// modifier); otherwise a list matches if any member matches.
func matchFieldValue(expected, actual interface{}, op string, all bool) bool {
	actualStr := fmt.Sprintf("%v", actual)

	switch e := expected.(type) {
	case string:
		return matchString(e, actualStr, op)
	case []interface{}:
		if all {
			if len(e) == 0 {
				return false
			}
			for _, item := range e {
				if !matchString(fmt.Sprintf("%v", item), actualStr, op) {
					return false
				}
			}
			return true
		}
		for _, item := range e {
			if matchString(fmt.Sprintf("%v", item), actualStr, op) {
				return true
			}
		}
		return false
	default:
		// int, bool, etc.
		return matchString(fmt.Sprintf("%v", e), actualStr, op)
	}
}

func matchString(expected, actual, modifier string) bool {
	// Default is case-insensitive exact match in Sigma for strings, unless regex.
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
		// Go's regexp is RE2 (linear time) so it is immune to catastrophic
		// backtracking; compileRe additionally caches the compiled program so a
		// rule's pattern is built once, not once per scanned event.
		re := compileRe(expected)
		if re == nil {
			return false
		}
		return re.MatchString(actual)
	default:
		return expectedStr == actualStr
	}
}

// regexCache memoises compiled rule patterns. A nil entry records a pattern
// that failed to compile so we never retry (and never match it).
var regexCache sync.Map // pattern(string) -> *regexp.Regexp | nil

// maxRegexLen bounds the size of a rule-supplied pattern as defence in depth.
const maxRegexLen = 4096

func compileRe(pattern string) *regexp.Regexp {
	if len(pattern) > maxRegexLen {
		return nil
	}
	if v, ok := regexCache.Load(pattern); ok {
		re, _ := v.(*regexp.Regexp)
		return re
	}
	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		regexCache.Store(pattern, (*regexp.Regexp)(nil))
		return nil
	}
	regexCache.Store(pattern, re)
	return re
}

// evaluateCondition parses and evaluates a Sigma condition string against the
// per-selection match results. It supports the full boolean grammar:
//
//	and, or, not, parentheses,
//	"<N|all|any|1> of them",
//	"<N|all|any|1> of <pattern*>"  (pattern matched against selection names)
//
// Unparseable conditions evaluate to false (fail-safe).
func evaluateCondition(condition string, results map[string]bool) bool {
	cond := strings.TrimSpace(condition)
	if cond == "" {
		return false
	}
	toks := tokenizeCondition(cond)
	if len(toks) == 0 {
		return false
	}
	p := &condParser{toks: toks}
	node := p.parseExpr()
	if node == nil || p.pos < len(p.toks) {
		// Trailing garbage / parse failure → fail-safe.
		if node == nil {
			return false
		}
	}
	return node.eval(results)
}

// --- condition parser (recursive descent) ---

type condNode interface {
	eval(results map[string]bool) bool
}

type identNode struct{ name string }

func (n identNode) eval(r map[string]bool) bool { return r[n.name] }

type notNode struct{ child condNode }

func (n notNode) eval(r map[string]bool) bool { return !n.child.eval(r) }

type andNode struct{ left, right condNode }

func (n andNode) eval(r map[string]bool) bool { return n.left.eval(r) && n.right.eval(r) }

type orNode struct{ left, right condNode }

func (n orNode) eval(r map[string]bool) bool { return n.left.eval(r) || n.right.eval(r) }

// ofNode implements "<quant> of <pattern>". quant<=0 means "all".
type ofNode struct {
	quant   int // minimum count required; 0 == all
	pattern string
}

func (n ofNode) eval(r map[string]bool) bool {
	matched, total := 0, 0
	for name, v := range r {
		if n.pattern == "them" || wildcardMatch(n.pattern, name) {
			total++
			if v {
				matched++
			}
		}
	}
	if total == 0 {
		return false
	}
	if n.quant <= 0 { // all
		return matched == total
	}
	return matched >= n.quant
}

type condParser struct {
	toks []string
	pos  int
}

func (p *condParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *condParser) peekAt(off int) string {
	if p.pos+off < len(p.toks) {
		return p.toks[p.pos+off]
	}
	return ""
}

func (p *condParser) advance() string { t := p.peek(); p.pos++; return t }

func (p *condParser) parseExpr() condNode { return p.parseOr() }

func (p *condParser) parseOr() condNode {
	left := p.parseAnd()
	for strings.EqualFold(p.peek(), "or") {
		p.advance()
		right := p.parseAnd()
		if left == nil || right == nil {
			return nil
		}
		left = orNode{left, right}
	}
	return left
}

func (p *condParser) parseAnd() condNode {
	left := p.parseNot()
	for strings.EqualFold(p.peek(), "and") {
		p.advance()
		right := p.parseNot()
		if left == nil || right == nil {
			return nil
		}
		left = andNode{left, right}
	}
	return left
}

func (p *condParser) parseNot() condNode {
	if strings.EqualFold(p.peek(), "not") {
		p.advance()
		child := p.parseNot()
		if child == nil {
			return nil
		}
		return notNode{child}
	}
	return p.parsePrimary()
}

func (p *condParser) parsePrimary() condNode {
	t := p.peek()
	if t == "" {
		return nil
	}
	if t == "(" {
		p.advance()
		inner := p.parseExpr()
		if p.peek() == ")" {
			p.advance()
		}
		return inner
	}
	// Quantifier aggregate: "<N|all|any|1> of <them|pattern>".
	if q, ok := quantValue(t); ok && strings.EqualFold(p.peekAt(1), "of") {
		p.advance() // quantifier
		p.advance() // "of"
		pattern := p.advance()
		if pattern == "" {
			return nil
		}
		return ofNode{quant: q, pattern: pattern}
	}
	// Bare selection identifier.
	p.advance()
	return identNode{t}
}

// quantValue interprets a quantifier token. ok is false if it is not numeric /
// "all" / "any" / "1". "all" → 0 (meaning every selection in scope).
func quantValue(t string) (int, bool) {
	switch strings.ToLower(t) {
	case "all":
		return 0, true
	case "any":
		return 1, true
	}
	n := 0
	if t == "" {
		return 0, false
	}
	for _, r := range t {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}

// tokenizeCondition splits a condition into tokens, isolating parentheses.
func tokenizeCondition(s string) []string {
	s = strings.ReplaceAll(s, "(", " ( ")
	s = strings.ReplaceAll(s, ")", " ) ")
	return strings.Fields(s)
}

// wildcardMatch reports whether name matches a glob pattern containing '*'.
func wildcardMatch(pattern, name string) bool {
	pattern = strings.ToLower(pattern)
	name = strings.ToLower(name)
	if !strings.Contains(pattern, "*") {
		return pattern == name
	}
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(name[pos:], part)
		if idx < 0 {
			return false
		}
		if i == 0 && idx != 0 {
			return false // first segment must anchor at the start
		}
		pos += idx + len(part)
	}
	// A trailing non-empty segment must reach the end of the name.
	if last := parts[len(parts)-1]; last != "" {
		return strings.HasSuffix(name, last)
	}
	return true
}

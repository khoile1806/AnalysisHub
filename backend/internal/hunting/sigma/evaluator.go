package sigma

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode/utf16"
)

// MatchEvent evaluates a single event against a Sigma Rule.
func MatchEvent(rule *Rule, event map[string]interface{}) bool {
	if rule.Detection == nil || rule.Condition == "" || rule.Unsupported != "" {
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
		mods := parseModifiers(fieldParts[1:])

		actualVal, found := lookupField(event, fieldName)

		// Sigma's `Field: null` means "absent or empty", a common idiom for
		// orphaned processes (ParentImage: null). Treating a missing field as a
		// plain mismatch would make those rules impossible to fire.
		if expected == nil {
			if !found || fmt.Sprintf("%v", actualVal) == "" {
				continue
			}
			return false
		}

		if mods.op == "exists" {
			if found != truthy(expected) {
				return false
			}
			continue
		}

		if !found {
			// A missing field fails the AND-joined selection.
			return false
		}

		if !matchFieldValue(expected, actualVal, mods) {
			return false
		}
	}
	return true
}

// modifiers holds the parsed `Field|mod1|mod2` chain of a selection key.
type modifiers struct {
	op      string // contains | startswith | endswith | re | cidr | exists | gt | gte | lt | lte
	all     bool   // every list member must match instead of any
	cased   bool   // case-sensitive comparison
	base64  bool   // compare against the base64 encoding of the expected value
	b64offs bool   // base64offset: the three byte alignments of an embedded value
	wide    bool   // encode the expected value as UTF-16LE before base64
	windash bool   // treat -flag / /flag and the unicode dashes as equivalent
}

func parseModifiers(parts []string) modifiers {
	var m modifiers
	for _, p := range parts {
		switch strings.ToLower(p) {
		case "all":
			m.all = true
		case "cased":
			m.cased = true
		case "base64":
			m.base64 = true
		case "base64offset":
			m.b64offs = true
		case "wide", "utf16", "utf16le":
			m.wide = true
		case "windash":
			m.windash = true
		case "contains", "startswith", "endswith", "re", "cidr", "exists", "gt", "gte", "lt", "lte":
			m.op = strings.ToLower(p)
		}
	}
	return m
}

func truthy(v interface{}) bool {
	switch t := v.(type) {
	case bool:
		return t
	default:
		return strings.EqualFold(fmt.Sprintf("%v", v), "true")
	}
}

// lookupField finds a value in the event by case-insensitive key match, then by
// dotted-path leaf (winlog.event_data.CommandLine) and finally through the
// Sysmon/Security alias table.
func lookupField(event map[string]interface{}, fieldName string) (interface{}, bool) {
	if v, ok := lookupDirect(event, fieldName); ok {
		return v, true
	}
	if i := strings.LastIndex(fieldName, "."); i >= 0 && i+1 < len(fieldName) {
		if v, ok := lookupDirect(event, fieldName[i+1:]); ok {
			return v, true
		}
	}
	for _, alt := range fieldAliases[strings.ToLower(fieldName)] {
		if v, ok := lookupDirect(event, alt); ok {
			return v, true
		}
	}
	return nil, false
}

func lookupDirect(event map[string]interface{}, fieldName string) (interface{}, bool) {
	for k, v := range event {
		if strings.EqualFold(k, fieldName) {
			return v, true
		}
	}
	return nil, false
}

// matchValue keeps the original OR-list semantics (kept for callers/tests).
func matchValue(expected, actual interface{}, modifier string) bool {
	return matchFieldValue(expected, actual, modifiers{op: modifier})
}

// matchFieldValue compares an expected spec against an actual value. When
// mods.all is set and expected is a list, every member must match (the |all
// modifier); otherwise a list matches if any member matches.
func matchFieldValue(expected, actual interface{}, mods modifiers) bool {
	actualStr := fmt.Sprintf("%v", actual)

	switch e := expected.(type) {
	case string:
		return matchOne(e, actualStr, mods)
	case []interface{}:
		if mods.all {
			if len(e) == 0 {
				return false
			}
			for _, item := range e {
				if !matchOne(fmt.Sprintf("%v", item), actualStr, mods) {
					return false
				}
			}
			return true
		}
		for _, item := range e {
			if matchOne(fmt.Sprintf("%v", item), actualStr, mods) {
				return true
			}
		}
		return false
	default:
		// int, bool, etc.
		return matchOne(fmt.Sprintf("%v", e), actualStr, mods)
	}
}

func matchString(expected, actual, modifier string) bool {
	return matchOne(expected, actual, modifiers{op: modifier})
}

// matchOne applies a single expected value against the observed one, honouring
// the whole modifier chain.
func matchOne(expected, actual string, mods modifiers) bool {
	switch mods.op {
	case "re":
		// Go's regexp is RE2 (linear time) so it is immune to catastrophic
		// backtracking; compileRe additionally caches the compiled program so a
		// rule's pattern is built once, not once per scanned event.
		re := compileRe(expected, mods.cased)
		if re == nil {
			return false
		}
		return re.MatchString(actual)
	case "cidr":
		return cidrMatch(expected, actual)
	case "gt", "gte", "lt", "lte":
		return numCompare(mods.op, expected, actual)
	}

	// Encoding modifiers rewrite the expected value into the form that actually
	// shows up in the event (e.g. an encoded PowerShell command line).
	if mods.base64 || mods.b64offs {
		raw := []byte(expected)
		if mods.wide {
			raw = toWideBytes(expected)
		}
		var cands []string
		if mods.b64offs {
			cands = base64OffsetVariants(raw)
		} else {
			cands = []string{base64.StdEncoding.EncodeToString(raw)}
		}
		for _, c := range cands {
			if matchPlain(c, actual, mods) {
				return true
			}
		}
		return false
	}

	for _, c := range dashVariants(expected, mods.windash) {
		if matchPlain(c, actual, mods) {
			return true
		}
	}
	return false
}

// matchPlain is the string comparison itself: case folding, Sigma value
// wildcards, then the positional modifier.
func matchPlain(expected, actual string, mods modifiers) bool {
	if !mods.cased {
		expected = strings.ToLower(expected)
		actual = strings.ToLower(actual)
	}
	// '*' and '?' are wildcards in every Sigma string value — comparing them
	// literally is why almost no upstream rule used to match anything.
	if hasSigmaWildcard(expected) {
		re := compileGlob(expected, mods.op)
		return re != nil && re.MatchString(actual)
	}
	switch mods.op {
	case "contains":
		return strings.Contains(actual, expected)
	case "startswith":
		return strings.HasPrefix(actual, expected)
	case "endswith":
		return strings.HasSuffix(actual, expected)
	default:
		return expected == actual
	}
}

// hasSigmaWildcard reports whether the value carries a * or ?.
func hasSigmaWildcard(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && s[i+1] == '\\' {
			i++ // "\\" is a literal backslash, never a wildcard
			continue
		}
		if s[i] == '*' || s[i] == '?' {
			return true
		}
	}
	return false
}

// globToRegex converts a Sigma value glob into an RE2 pattern.
//
// Deliberate deviation from the letter of the spec: upstream reads "\*" as an
// escaped literal asterisk, but in Windows telemetry that backslash is a path
// separator and rules are written as 'C:\Windows\*' meaning "anything below
// this directory". Honouring the escape there turns the rule into a search for
// a literal star and silently kills it, so only "\\" escapes and a wildcard
// after a path separator stays a wildcard.
func globToRegex(pattern string) string {
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if c == '\\' {
			b.WriteString(regexp.QuoteMeta(`\`))
			if i+1 < len(pattern) && pattern[i+1] == '\\' {
				i++
			}
			continue
		}
		switch c {
		case '*':
			b.WriteString(`(?s).*`)
		case '?':
			b.WriteString(`(?s).`)
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String()
}

// compileGlob builds (and caches) the anchored pattern for a wildcard value.
// A bare value is a full-string match; contains/startswith/endswith relax the
// anchors accordingly.
func compileGlob(pattern, op string) *regexp.Regexp {
	key := op + "\x00" + pattern
	if v, ok := globCache.Load(key); ok {
		re, _ := v.(*regexp.Regexp)
		return re
	}
	body := globToRegex(pattern)
	switch op {
	case "contains":
	case "startswith":
		body = "^" + body
	case "endswith":
		body = body + "$"
	default:
		body = "^" + body + "$"
	}
	re, err := regexp.Compile(body)
	if err != nil {
		globCache.Store(key, (*regexp.Regexp)(nil))
		return nil
	}
	globCache.Store(key, re)
	return re
}

var globCache sync.Map // op+pattern(string) -> *regexp.Regexp | nil

// dashVariants expands the |windash modifier: attackers swap the parameter
// prefix freely, so "-encodedcommand" must also match "/encodedcommand".
func dashVariants(s string, windash bool) []string {
	if !windash || !strings.Contains(s, "-") {
		return []string{s}
	}
	alts := []string{"-", "/", "–", "—", "―"}
	out := make([]string, 0, len(alts))
	for _, a := range alts {
		out = append(out, strings.ReplaceAll(s, "-", a))
	}
	return out
}

// toWideBytes encodes a string as UTF-16LE, the in-memory form PowerShell
// encodes before base64 (`-EncodedCommand`).
func toWideBytes(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(u)*2)
	for _, r := range u {
		b = append(b, byte(r), byte(r>>8))
	}
	return b
}

// base64OffsetVariants returns the three encodings of a value embedded at each
// byte alignment inside a larger base64 blob, trimmed of the characters that
// carry bits from the surrounding data (the pySigma base64offset algorithm).
func base64OffsetVariants(v []byte) []string {
	starts := [3]int{0, 2, 3}
	ends := [3]int{0, -3, -2} // 0 means "no trim"
	out := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		buf := append(bytes.Repeat([]byte{' '}, i), v...)
		enc := base64.StdEncoding.EncodeToString(buf)
		s := starts[i]
		e := len(enc)
		if t := ends[(len(v)+i)%3]; t != 0 {
			e += t
		}
		if s < 0 || e > len(enc) || s >= e {
			continue
		}
		out = append(out, enc[s:e])
	}
	return out
}

// cidrMatch implements |cidr: the expected value is a network, the observed one
// an address.
func cidrMatch(cidr, actual string) bool {
	_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(actual))
	if ip == nil {
		return false
	}
	return network.Contains(ip)
}

// numCompare implements |gt |gte |lt |lte, which used to degrade to a string
// equality test and therefore never fired.
func numCompare(op, expected, actual string) bool {
	e, err1 := strconv.ParseFloat(strings.TrimSpace(expected), 64)
	a, err2 := strconv.ParseFloat(strings.TrimSpace(actual), 64)
	if err1 != nil || err2 != nil {
		return false
	}
	switch op {
	case "gt":
		return a > e
	case "gte":
		return a >= e
	case "lt":
		return a < e
	case "lte":
		return a <= e
	}
	return false
}

// regexCache memoises compiled rule patterns. A nil entry records a pattern
// that failed to compile so we never retry (and never match it).
var regexCache sync.Map // flag+pattern(string) -> *regexp.Regexp | nil

// maxRegexLen bounds the size of a rule-supplied pattern as defence in depth.
const maxRegexLen = 4096

func compileRe(pattern string, cased bool) *regexp.Regexp {
	if len(pattern) > maxRegexLen {
		return nil
	}
	prefix := "(?i)"
	if cased {
		prefix = ""
	}
	key := prefix + "\x00" + pattern
	if v, ok := regexCache.Load(key); ok {
		re, _ := v.(*regexp.Regexp)
		return re
	}
	re, err := regexp.Compile(prefix + pattern)
	if err != nil {
		regexCache.Store(key, (*regexp.Regexp)(nil))
		return nil
	}
	regexCache.Store(key, re)
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
	node := parseCondition(condition)
	if node == nil {
		return false
	}
	return node.eval(results)
}

// parseCondition returns the parsed condition tree, or nil when the condition
// cannot be represented. Anything left over after the expression (aggregations
// such as "| count() by User > 5", "| near", …) makes the whole rule
// unrepresentable: evaluating only the part we understood would fire on every
// event the aggregate was meant to threshold, which is the single largest
// false-positive source in a synced ruleset. Fail closed instead.
func parseCondition(condition string) condNode {
	cond := strings.TrimSpace(condition)
	if cond == "" {
		return nil
	}
	toks := tokenizeCondition(cond)
	if len(toks) == 0 {
		return nil
	}
	p := &condParser{toks: toks}
	node := p.parseExpr()
	if node == nil || p.pos < len(p.toks) {
		return nil
	}
	return node
}

// --- condition parser (recursive descent) ---

type condNode interface {
	eval(results map[string]bool) bool
	// idents appends every selection name the node references.
	idents(out *[]string)
}

type identNode struct{ name string }

func (n identNode) eval(r map[string]bool) bool { return r[n.name] }
func (n identNode) idents(out *[]string)        { *out = append(*out, n.name) }

type notNode struct{ child condNode }

func (n notNode) eval(r map[string]bool) bool { return !n.child.eval(r) }
func (n notNode) idents(out *[]string)        { n.child.idents(out) }

type andNode struct{ left, right condNode }

func (n andNode) eval(r map[string]bool) bool { return n.left.eval(r) && n.right.eval(r) }
func (n andNode) idents(out *[]string)        { n.left.idents(out); n.right.idents(out) }

type orNode struct{ left, right condNode }

func (n orNode) eval(r map[string]bool) bool { return n.left.eval(r) || n.right.eval(r) }
func (n orNode) idents(out *[]string)        { n.left.idents(out); n.right.idents(out) }

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

// idents is a no-op: the pattern is resolved against whatever selections exist,
// so there is no fixed name to validate.
func (n ofNode) idents(out *[]string) {}

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
		if p.peek() != ")" {
			return nil // unbalanced — do not silently accept a partial parse
		}
		p.advance()
		return inner
	}
	// Quantifier aggregate: "<N|all|any|1> of <them|pattern>".
	if q, ok := quantValue(t); ok && strings.EqualFold(p.peekAt(1), "of") {
		p.advance() // quantifier
		p.advance() // "of"
		if p.peek() == "(" {
			// "1 of (sel_a or sel_b)": the group already expresses the quantity.
			// Treating "(" as a selection-name pattern matched nothing and made
			// these rules permanently false.
			return p.parsePrimary()
		}
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

// Package forge is a CyberChef-style transform engine: it runs an ordered
// "recipe" of operations over an input, each operation's output feeding the
// next. It is aimed at the decode/encode/crypto tasks that come up constantly in
// DFIR — peeling obfuscated payloads, decoding attacker artefacts, hashing,
// classic ciphers — rather than being a general programming environment.
package forge

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// ArgType tells the UI how to render an operation's argument.
type ArgType string

const (
	ArgString ArgType = "string"
	ArgInt    ArgType = "int"
	ArgBool   ArgType = "bool"
	ArgSelect ArgType = "select" // one of Options
)

// ArgSpec declares one argument an operation accepts.
type ArgSpec struct {
	Key     string   `json:"key"`
	Label   string   `json:"label"`
	Type    ArgType  `json:"type"`
	Default string   `json:"default,omitempty"`
	Options []string `json:"options,omitempty"`
	Help    string   `json:"help,omitempty"`
}

// Operation is one transform. Run receives the previous stage's bytes and the
// user-supplied args, and returns the transformed bytes. Operations must be pure
// (no I/O, no globals) so a recipe is deterministic and safe to run on request.
type Operation struct {
	Name        string    `json:"name"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
	Args        []ArgSpec `json:"args,omitempty"`
	run         func(in []byte, args Args) ([]byte, error)
}

// Args is the argument bag passed to an operation, keyed by ArgSpec.Key.
type Args map[string]string

func (a Args) str(key, def string) string {
	if v, ok := a[key]; ok && v != "" {
		return v
	}
	return def
}

func (a Args) boolv(key string) bool {
	switch strings.ToLower(a[key]) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// registry holds every available operation, keyed by name.
var registry = map[string]*Operation{}

// register adds an operation to the global registry. Called from init() in the
// per-category files.
func register(op *Operation) {
	if _, exists := registry[op.Name]; exists {
		panic("forge: duplicate operation " + op.Name)
	}
	registry[op.Name] = op
}

// Operations returns every registered operation, sorted by category then name,
// so the UI can present a stable, grouped palette.
func Operations() []*Operation {
	out := make([]*Operation, 0, len(registry))
	for _, op := range registry {
		out = append(out, op)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// RecipeStep is one operation invocation in a recipe.
type RecipeStep struct {
	Op   string `json:"op"`
	Args Args   `json:"args,omitempty"`
}

// StepResult reports what one step produced, so the UI can show the chain and
// point at exactly which step failed.
type StepResult struct {
	Op     string `json:"op"`
	Output string `json:"output"`
	Binary bool   `json:"binary"` // output isn't valid/printable UTF-8 → shown as hex
	Bytes  int    `json:"bytes"`
	Error  string `json:"error,omitempty"`
}

// Result is the outcome of running a recipe.
type Result struct {
	Steps  []StepResult `json:"steps"`
	Output string       `json:"output"`
	Binary bool         `json:"binary"`
	Bytes  int          `json:"bytes"`
}

// maxInput bounds a single run so one request can't pin CPU/memory. 1 MB is far
// above any realistic paste of an encoded blob.
const maxInput = 1 << 20

// maxStages bounds recipe length.
const maxStages = 40

// Run executes the recipe over input and returns the per-step trace plus the
// final output. A failing step stops the chain and is reported; earlier steps
// are still returned so the analyst sees how far the peel got.
func Run(input string, recipe []RecipeStep) (Result, error) {
	if len(input) > maxInput {
		return Result{}, fmt.Errorf("input too large (%d bytes, max %d)", len(input), maxInput)
	}
	if len(recipe) > maxStages {
		return Result{}, fmt.Errorf("recipe too long (%d steps, max %d)", len(recipe), maxStages)
	}

	cur := []byte(input)
	res := Result{Steps: make([]StepResult, 0, len(recipe))}

	for _, step := range recipe {
		op, ok := registry[step.Op]
		if !ok {
			res.Steps = append(res.Steps, StepResult{Op: step.Op, Error: "unknown operation"})
			return res, fmt.Errorf("unknown operation %q", step.Op)
		}
		out, err := runGuarded(op, cur, step.Args)
		sr := StepResult{Op: step.Op}
		if err != nil {
			sr.Error = err.Error()
			res.Steps = append(res.Steps, sr)
			return res, fmt.Errorf("step %q: %w", step.Op, err)
		}
		if len(out) > maxInput {
			out = out[:maxInput]
		}
		cur = out
		sr.Bytes = len(out)
		sr.Binary = !isPrintableUTF8(out)
		sr.Output = display(out, sr.Binary)
		res.Steps = append(res.Steps, sr)
	}

	res.Bytes = len(cur)
	res.Binary = !isPrintableUTF8(cur)
	res.Output = display(cur, res.Binary)
	return res, nil
}

// runGuarded recovers a panicking operation into an error so a single malformed
// input (e.g. a bad regex, an out-of-range slice) never takes down the request.
func runGuarded(op *Operation, in []byte, args Args) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("operation crashed: %v", r)
		}
	}()
	return op.run(in, args)
}

// isPrintableUTF8 reports whether b is valid UTF-8 made of printable/whitespace
// runes — the test for showing output as text vs. a hex dump.
func isPrintableUTF8(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	if !utf8.Valid(b) {
		return false
	}
	nonPrint := 0
	for _, r := range string(b) {
		if r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			nonPrint++
		}
	}
	// Allow a few stray control bytes but treat a mostly-binary blob as binary.
	return nonPrint*20 <= len(b)
}

// display renders output for transport: text as-is, binary as a hex dump so the
// JSON stays valid and the analyst can still read the bytes.
func display(b []byte, binary bool) string {
	if !binary {
		return string(b)
	}
	return hexDump(b)
}

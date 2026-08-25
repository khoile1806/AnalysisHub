package ai

import (
	"context"
	"runtime"
	"strings"
	"time"
)

// meter.go — token accounting for every AI call the platform makes.
//
// Usage was already returned by StreamChat; almost nobody stored it. Exactly one
// of the twenty-one call sites wrote a token count (the AI Analysis session), so
// the System Health "Token Usage" panel reported a fraction of real consumption
// and every feature added since was invisible by default.
//
// Patching call sites was the wrong fix: it is twenty-one edits that silently
// regress the moment someone adds the twenty-second. Instead the client itself is
// wrapped once, at the single place clients are constructed, so accounting is a
// property of "making an AI call" rather than something each caller remembers.

// UsageSink persists one completion's token consumption. It is an interface so
// this package stays free of a database dependency — the implementation lives
// next to the models.
type UsageSink interface {
	RecordUsage(providerID, feature string, u Usage, ok bool, elapsed time.Duration)
}

type featureKeyType struct{}

var featureKey featureKeyType

// WithFeature labels the work a completion belongs to, so consumption can be
// attributed to "malware synthesis" rather than to one anonymous total.
func WithFeature(ctx context.Context, name string) context.Context {
	if name == "" {
		return ctx
	}
	return context.WithValue(ctx, featureKey, name)
}

// FeatureFrom returns the label set by WithFeature, or "".
func FeatureFrom(ctx context.Context) string {
	if v, ok := ctx.Value(featureKey).(string); ok {
		return v
	}
	return ""
}

// CallerFeature derives a label from the call stack: "package.Function" of the
// first frame outside this package and the analysis helper.
//
// It must be called on the CALLER'S goroutine. analysis.Chat hands StreamChat off
// to a fresh goroutine, whose stack no longer contains the original caller, so a
// label derived inside StreamChat would read "analysis.Chat" for almost every
// feature in the product. Chat therefore stamps the label before it spawns.
func CallerFeature(skip int) string {
	pcs := make([]uintptr, 12)
	n := runtime.Callers(skip+2, pcs)
	if n == 0 {
		return ""
	}
	frames := runtime.CallersFrames(pcs[:n])
	for {
		fr, more := frames.Next()
		if name := shortFuncName(fr.Function); name != "" {
			return name
		}
		if !more {
			break
		}
	}
	return ""
}

// shortFuncName reduces a fully-qualified symbol to "package.Function", skipping
// the plumbing packages that would otherwise absorb every attribution.
func shortFuncName(full string) string {
	if full == "" {
		return ""
	}
	// ".../internal/ai.Chat" → drop the path, keep "ai.Chat".
	if i := strings.LastIndex(full, "/"); i >= 0 {
		full = full[i+1:]
	}
	// Strip the closure/method suffixes Go appends ("Foo.func1", "(*T).Foo").
	full = strings.ReplaceAll(full, "(*", "")
	full = strings.ReplaceAll(full, ")", "")
	if i := strings.Index(full, ".func"); i >= 0 {
		full = full[:i]
	}

	// Skip the plumbing the call passes through, by exact function rather than by
	// package: excluding all of `analysis` would also discard a genuine caller that
	// happens to live there, which is how the attribution walked past the real
	// frame and landed on testing.tRunner.
	pkg := full
	if i := strings.Index(pkg, "."); i >= 0 {
		pkg = pkg[:i]
	}
	if pkg == "ai" || pkg == "runtime" || pkg == "testing" {
		return ""
	}
	if full == "analysis.Chat" {
		return ""
	}
	if len(full) > 80 {
		full = full[:80]
	}
	return full
}

// meteredClient records every completion, then behaves exactly like the client
// it wraps.
type meteredClient struct {
	inner      Client
	providerID string
	sink       UsageSink
}

// Meter wraps a client so its token consumption is recorded. A nil sink or a nil
// client returns the input unchanged, so metering can never be the reason an
// analysis fails.
func Meter(c Client, providerID string, sink UsageSink) Client {
	if c == nil || sink == nil {
		return c
	}
	return &meteredClient{inner: c, providerID: providerID, sink: sink}
}

func (m *meteredClient) StreamChat(ctx context.Context, msgs []Message, opts Options, out chan<- string) (Usage, error) {
	feature := FeatureFrom(ctx)
	if feature == "" {
		// A direct StreamChat caller is still on its own goroutine here, so the
		// stack walk works for them.
		feature = CallerFeature(1)
	}
	if feature == "" {
		feature = "unattributed"
	}

	started := time.Now()
	u, err := m.inner.StreamChat(ctx, msgs, opts, out)
	// Recorded even on error: a failed call that streamed 40k input tokens still
	// cost 40k input tokens, and a run of failures is exactly what a health panel
	// needs to surface rather than hide.
	m.sink.RecordUsage(m.providerID, feature, u, err == nil, time.Since(started))
	return u, err
}

func (m *meteredClient) TestConnection(ctx context.Context) error {
	return m.inner.TestConnection(ctx)
}

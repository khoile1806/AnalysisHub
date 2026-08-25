package ai

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClient returns a fixed usage/error without touching a provider.
type fakeClient struct {
	usage Usage
	err   error
}

func (f *fakeClient) StreamChat(ctx context.Context, msgs []Message, opts Options, out chan<- string) (Usage, error) {
	out <- "hello"
	return f.usage, f.err
}
func (f *fakeClient) TestConnection(ctx context.Context) error { return nil }

type recorded struct {
	providerID string
	feature    string
	usage      Usage
	ok         bool
	elapsed    time.Duration
}

type fakeSink struct {
	mu   sync.Mutex
	rows []recorded
}

func (s *fakeSink) RecordUsage(providerID, feature string, u Usage, ok bool, elapsed time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = append(s.rows, recorded{providerID, feature, u, ok, elapsed})
}

func drain(out chan string) {
	for range out {
	}
}

// The whole point of metering at the client: a caller that never asks to be
// measured is measured anyway. Twenty of the platform's twenty-one AI call sites
// discarded usage, which is why the health panel under-reported consumption.
func TestMeter_RecordsWithoutCallerCooperation(t *testing.T) {
	sink := &fakeSink{}
	c := Meter(&fakeClient{usage: Usage{InputTokens: 120, OutputTokens: 30}}, "prov-1", sink)

	out := make(chan string, 4)
	go func() { drain(out) }()
	u, err := c.StreamChat(context.Background(), nil, Options{}, out)
	close(out)
	if err != nil {
		t.Fatalf("StreamChat: %v", err)
	}
	if u.Total() != 150 {
		t.Errorf("usage passed through wrong: %d", u.Total())
	}
	if len(sink.rows) != 1 {
		t.Fatalf("recorded %d rows, want 1", len(sink.rows))
	}
	r := sink.rows[0]
	if r.providerID != "prov-1" {
		t.Errorf("providerID = %q", r.providerID)
	}
	if r.usage.Total() != 150 || !r.ok {
		t.Errorf("recorded %+v, want 150 tokens and ok", r.usage)
	}
	// Every row carries SOME label; a call with no attributable frame must still be
	// recorded rather than dropped. This test calls from inside package ai, which
	// is plumbing by definition, so "unattributed" is the correct answer here —
	// real attribution is covered by analysis.TestChat_AttributesTheRealCaller,
	// where a genuine caller frame exists.
	if r.feature == "" {
		t.Error("feature label must never be empty")
	}
}

// A failed completion still consumed its input tokens, and a run of failures is
// exactly what a health panel should surface rather than hide.
func TestMeter_RecordsFailedCalls(t *testing.T) {
	sink := &fakeSink{}
	c := Meter(&fakeClient{usage: Usage{InputTokens: 900}, err: errors.New("provider 500")}, "p", sink)

	out := make(chan string, 4)
	go func() { drain(out) }()
	_, err := c.StreamChat(context.Background(), nil, Options{}, out)
	close(out)
	if err == nil {
		t.Fatal("the error must still reach the caller")
	}
	if len(sink.rows) != 1 {
		t.Fatalf("a failed call must still be recorded, got %d rows", len(sink.rows))
	}
	if sink.rows[0].ok {
		t.Error("the row must be marked failed")
	}
	if sink.rows[0].usage.InputTokens != 900 {
		t.Error("input tokens spent before the failure must be recorded")
	}
}

// An explicit label wins over the derived one, so a caller that knows better can
// say so.
func TestMeter_ContextFeatureWins(t *testing.T) {
	sink := &fakeSink{}
	c := Meter(&fakeClient{}, "p", sink)
	ctx := WithFeature(context.Background(), "malware.Synthesize")

	out := make(chan string, 4)
	go func() { drain(out) }()
	_, _ = c.StreamChat(ctx, nil, Options{}, out)
	close(out)

	if sink.rows[0].feature != "malware.Synthesize" {
		t.Errorf("feature = %q, want the explicit label", sink.rows[0].feature)
	}
}

// Metering must never be the reason an analysis fails: with no sink the client is
// handed back untouched.
func TestMeter_NilSinkIsPassthrough(t *testing.T) {
	inner := &fakeClient{}
	if got := Meter(inner, "p", nil); got != Client(inner) {
		t.Error("a nil sink must return the original client, not a wrapper")
	}
	if Meter(nil, "p", &fakeSink{}) != nil {
		t.Error("a nil client must stay nil")
	}
}

// The label must name the feature that asked, not the plumbing it went through.
func TestShortFuncName_SkipsPlumbing(t *testing.T) {
	for _, in := range []string{
		"github.com/analysishub/backend/internal/analysis.Chat",
		"github.com/analysishub/backend/internal/ai.Meter",
		"runtime.goexit",
		"testing.tRunner",
	} {
		if got := shortFuncName(in); got != "" {
			t.Errorf("shortFuncName(%q) = %q, want empty so the walk continues", in, got)
		}
	}
	for in, want := range map[string]string{
		"github.com/analysishub/backend/internal/malware.Synthesize":           "malware.Synthesize",
		"github.com/analysishub/backend/internal/api/handlers.TriageOsintScan": "handlers.TriageOsintScan",
		"github.com/analysishub/backend/internal/malware.(*Engine).Detonate":   "malware.Engine.Detonate",
		"github.com/analysishub/backend/internal/netscan.summarise.func1":      "netscan.summarise",
	} {
		if got := shortFuncName(in); got != want {
			t.Errorf("shortFuncName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := shortFuncName(strings.Repeat("x", 200) + ".F"); len(got) > 80 {
		t.Errorf("label not bounded: %d chars", len(got))
	}
}

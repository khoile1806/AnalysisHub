package analysis

import (
	"context"
	"testing"
	"time"

	ai "github.com/analysishub/backend/internal/ai"
)

type stubClient struct{ usage ai.Usage }

func (s *stubClient) StreamChat(ctx context.Context, msgs []ai.Message, opts ai.Options, out chan<- string) (ai.Usage, error) {
	out <- "ok"
	return s.usage, nil
}
func (s *stubClient) TestConnection(ctx context.Context) error { return nil }

type capturingSink struct {
	feature string
	total   int
}

func (c *capturingSink) RecordUsage(providerID, feature string, u ai.Usage, ok bool, d time.Duration) {
	c.feature = feature
	c.total = u.Total()
}

// Chat hands the completion to a fresh goroutine, whose stack no longer contains
// the caller. Deriving the label down there would attribute nearly every AI
// feature in the product to "analysis.Chat" and make the per-feature breakdown
// useless — so Chat stamps the label before spawning, and this is the test that
// keeps that true.
func TestChat_AttributesTheRealCaller(t *testing.T) {
	sink := &capturingSink{}
	client := ai.Meter(&stubClient{usage: ai.Usage{InputTokens: 10, OutputTokens: 5}}, "prov", sink)

	if _, _, err := Chat(context.Background(), client, "hi", ai.Options{}); err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if sink.total != 15 {
		t.Errorf("recorded %d tokens, want 15", sink.total)
	}
	if sink.feature == "analysis.Chat" || sink.feature == "" || sink.feature == "unattributed" {
		t.Fatalf("feature = %q — the caller was lost to the goroutine boundary", sink.feature)
	}
	if sink.feature != "analysis.TestChat_AttributesTheRealCaller" {
		t.Errorf("feature = %q, want this test function attributed", sink.feature)
	}
}

// An explicit label set by a caller must survive Chat untouched.
func TestChat_KeepsExplicitFeature(t *testing.T) {
	sink := &capturingSink{}
	client := ai.Meter(&stubClient{}, "prov", sink)
	ctx := ai.WithFeature(context.Background(), "malware.SynthesizeCampaign")

	if _, _, err := Chat(ctx, client, "hi", ai.Options{}); err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if sink.feature != "malware.SynthesizeCampaign" {
		t.Errorf("feature = %q, want the explicit label preserved", sink.feature)
	}
}

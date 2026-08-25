package analysis

import (
	"context"
	"strings"

	ai "github.com/analysishub/backend/internal/ai"
)

// Chat runs a single non-streamed completion and returns the full text plus
// token usage. It is the shared inference helper for the action-style AI
// features (timeline extraction, compliance assessment) that want one answer
// rather than a live token stream — replacing the goroutine + channel boiler-
// plate each handler used to duplicate. The streaming AI Analysis flow keeps
// its own loop because it emits per-token SSE + chain-step progress.
func Chat(ctx context.Context, client ai.Client, prompt string, opts ai.Options) (string, ai.Usage, error) {
	// Attribute the token spend to whoever asked, while their frame is still on
	// the stack. The completion runs on a fresh goroutine below, whose stack no
	// longer contains the caller — a label derived down there would read
	// "analysis.Chat" for nearly every feature in the product.
	if ai.FeatureFrom(ctx) == "" {
		ctx = ai.WithFeature(ctx, ai.CallerFeature(1))
	}

	tokenCh := make(chan string, 256)
	usageCh := make(chan ai.Usage, 1)
	errCh := make(chan error, 1)
	go func() {
		u, err := client.StreamChat(ctx, []ai.Message{{Role: "user", Content: prompt}}, opts, tokenCh)
		close(tokenCh)
		usageCh <- u
		errCh <- err
	}()
	var sb strings.Builder
	for tok := range tokenCh {
		sb.WriteString(tok)
	}
	usage := <-usageCh
	return sb.String(), usage, <-errCh
}

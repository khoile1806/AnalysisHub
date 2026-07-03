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

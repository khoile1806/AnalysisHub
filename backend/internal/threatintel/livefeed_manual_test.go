package threatintel

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"
)

// TestLiveFeedsParse hits the real feeds. Skipped unless TI_LIVE=1, so an
// ordinary test run stays offline and deterministic; the point of it is to catch
// an upstream format change, which no fixture can.
func TestLiveFeedsParse(t *testing.T) {
	if os.Getenv("TI_LIVE") != "1" {
		t.Skip("set TI_LIVE=1 to check the live feed formats")
	}
	hc := &http.Client{Timeout: 90 * time.Second}
	for _, f := range DefaultFeeds() {
		f := f
		t.Run(f.ID, func(t *testing.T) {
			items, err := FetchFeed(context.Background(), hc, f, os.Getenv("ABUSE_CH_API_KEY"))
			if err != nil {
				t.Fatalf("%s: %v", f.Name, err)
			}
			t.Logf("%s: %d indicators; first=%q type=%s expires=%s",
				f.ID, len(items), items[0].Value, items[0].Type,
				items[0].Expires.Format(time.RFC3339))
			seen := map[string]int{}
			for _, it := range items {
				seen[it.Type]++
				if it.Value == "" || it.Type == "" {
					t.Fatalf("%s produced an empty indicator", f.ID)
				}
			}
			t.Logf("%s types: %v", f.ID, seen)
		})
	}
}

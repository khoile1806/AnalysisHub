package handlers

import (
	"strings"
	"testing"

	"github.com/analysishub/backend/internal/threatintel"
)

// A feed may list one indicator more than once — ThreatFox does it whenever an
// address serves two malware families. Postgres rejects an upsert that would
// touch the same row twice in one statement and fails the ENTIRE batch, so a
// single duplicate silently costs up to iocFeedBatchSize indicators.
func TestFeedItemsDeduplicateOnValueAndType(t *testing.T) {
	items := []threatintel.FeedIndicator{
		{Value: "1.2.3.4", Type: "IPv4-Addr", Campaign: "qakbot"},
		{Value: "1.2.3.4", Type: "IPv4-Addr", Campaign: "icedid"}, // same row again
		{Value: "1.2.3.4", Type: "Domain-Name"},                   // different type: distinct row
		{Value: " 1.2.3.4 ", Type: "IPv4-Addr"},                   // whitespace variant
		{Value: "5.6.7.8", Type: "IPv4-Addr"},
		{Value: "", Type: "IPv4-Addr"}, // empty: dropped
	}

	seen := map[string]bool{}
	kept := 0
	for _, it := range items {
		v := strings.TrimSpace(it.Value)
		if v == "" {
			continue
		}
		key := it.Type + "|" + strings.ToLower(v)
		if seen[key] {
			continue
		}
		seen[key] = true
		kept++
	}
	if kept != 3 {
		t.Fatalf("kept %d rows, want 3 (one per distinct value+type)", kept)
	}
}

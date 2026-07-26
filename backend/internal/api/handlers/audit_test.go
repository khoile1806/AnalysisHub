package handlers

import "testing"

func TestParseAuditTime(t *testing.T) {
	cases := []struct {
		in   string
		zero bool
	}{
		{"", true},
		{"   ", true},
		{"garbage", true},
		{"2026-07-24", false},
		{"2026-07-24T09:30", false},
		{"2026-07-24T09:30:00Z", false},
		{"2026-07-24T09:30:00+07:00", false},
	}
	for _, c := range cases {
		got := parseAuditTime(c.in)
		if got.IsZero() != c.zero {
			t.Errorf("parseAuditTime(%q): zero=%v, want zero=%v", c.in, got.IsZero(), c.zero)
		}
	}
}

// A date-only bound must parse to midnight of that day so a "from 2026-07-24"
// filter includes the whole day rather than silently excluding it.
func TestParseAuditTime_DateIsMidnight(t *testing.T) {
	got := parseAuditTime("2026-07-24")
	if got.Hour() != 0 || got.Minute() != 0 || got.Second() != 0 {
		t.Errorf("date-only should parse to midnight, got %v", got)
	}
	if got.Year() != 2026 || got.Month() != 7 || got.Day() != 24 {
		t.Errorf("wrong date parsed: %v", got)
	}
}

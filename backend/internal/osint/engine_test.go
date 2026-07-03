package osint

import (
	"testing"

	"github.com/analysishub/backend/internal/config"
)

func TestMaxConcurrentScans(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.Config
		want int
	}{
		{"nil config defaults", nil, 6},
		{"unset (zero) defaults", &config.Config{}, 6},
		{"explicit value honoured", &config.Config{OsintMaxConcurrentScans: 3}, 3},
		{"negative falls back", &config.Config{OsintMaxConcurrentScans: -1}, 6},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := maxConcurrentScans(tc.cfg); got != tc.want {
				t.Errorf("maxConcurrentScans(%+v) = %d, want %d", tc.cfg, got, tc.want)
			}
		})
	}
}

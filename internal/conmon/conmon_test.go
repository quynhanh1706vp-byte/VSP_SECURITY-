package conmon

import (
	"testing"
	"time"
)

func TestNextRun(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		cadence string
		days    int
	}{
		{"daily", 1},
		{"weekly", 7},
		{"30d", 30},
		{"60d", 60},
		{"90d", 90},
		{"unknown", 30}, // fallback to 30d
	}

	for _, c := range cases {
		got := nextRun(base, c.cadence)
		want := base.AddDate(0, 0, c.days)
		if !got.Equal(want) {
			t.Errorf("nextRun(%q): got %v, want %v", c.cadence, got, want)
		}
	}
}

func TestNextRun_Hourly(t *testing.T) {
	// daily cadence is +24h, not "next midnight" — verify
	base := time.Date(2026, 1, 1, 14, 30, 0, 0, time.UTC)
	got := nextRun(base, "daily")
	want := base.Add(24 * time.Hour)
	if !got.Equal(want) {
		t.Errorf("daily: got %v, want %v", got, want)
	}
}

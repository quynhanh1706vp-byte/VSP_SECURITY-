package virustotal

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestNewClient_NoEnv(t *testing.T) {
	_ = os.Unsetenv("VSP_VT_API_KEY")
	c := NewClient()
	if c.Configured() {
		t.Error("expected not configured when VSP_VT_API_KEY unset")
	}
	_, err := c.GetFileReport(context.Background(), "0000000000000000000000000000000000000000000000000000000000000000")
	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("expected ErrNotConfigured, got %v", err)
	}
}

func TestNewClient_WithEnv(t *testing.T) {
	t.Setenv("VSP_VT_API_KEY", "test-key-fake")
	c := NewClient()
	if !c.Configured() {
		t.Error("expected configured with env set")
	}
}

func TestGetFileReport_InvalidHash(t *testing.T) {
	t.Setenv("VSP_VT_API_KEY", "test-key-fake")
	c := NewClient()
	_, err := c.GetFileReport(context.Background(), "tooshort")
	if err == nil {
		t.Error("expected error for invalid hash")
	}
}

func TestComputeVerdict(t *testing.T) {
	cases := []struct {
		mal, susp int
		want      string
	}{
		{0, 0, "clean"},
		{0, 2, "clean"},
		{0, 3, "suspicious"},
		{1, 0, "suspicious"},
		{4, 0, "suspicious"},
		{5, 0, "malicious"},
		{10, 5, "malicious"},
	}
	for _, c := range cases {
		got := computeVerdict(c.mal, c.susp)
		if got != c.want {
			t.Errorf("computeVerdict(mal=%d, susp=%d) = %q, want %q",
				c.mal, c.susp, got, c.want)
		}
	}
}

func TestStats(t *testing.T) {
	t.Setenv("VSP_VT_API_KEY", "abc")
	c := NewClient()
	s := c.Stats()
	if !s.Configured {
		t.Error("Stats: configured should be true")
	}
	if s.APIKeyLen != 3 {
		t.Errorf("Stats: APIKeyLen = %d, want 3", s.APIKeyLen)
	}
}

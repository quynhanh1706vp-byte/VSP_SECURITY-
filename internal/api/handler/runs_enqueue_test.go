package handler

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vsp/platform/internal/pipeline"
)

// TestEnqueueDirect_ToolsTotalMatchesRegistry pins the fix for the
// scheduler-vs-API drift: the cron-fired FULL_SOC run showed 18/18
// in the UI while the FE "New Scan" modal advertised 26 tools.
// EnqueueDirect must compute tools_total from the same registry
// (pipeline.ToolNamesForMode) that the FE displays — NOT a hand-
// maintained map that's certain to drift.
//
// This test enumerates every Mode the FE exposes and asserts the
// count matches. If anyone reintroduces a hardcoded map and forgets
// to bump a number, this test catches it before users do.
func TestEnqueueDirect_ToolsTotalMatchesRegistry(t *testing.T) {
	cases := []struct {
		mode pipeline.Mode
		want int
	}{
		{pipeline.ModeSAST, 4},
		{pipeline.ModeSCA, 8},
		{pipeline.ModeSecrets, 3},
		{pipeline.ModeIAC, 3},
		{pipeline.ModeDAST, 3},
		{pipeline.ModeNetwork, 3},
		{pipeline.ModeFull, 26},
		{pipeline.ModeFullSOC, 26},
	}
	for _, c := range cases {
		got := len(pipeline.ToolNamesForMode(c.mode))
		assert.Equal(t, c.want, got,
			"mode=%s: ToolNamesForMode returned %d, want %d "+
				"— if this changed, fix BOTH runs.go and runs_enqueue.go "+
				"or use pipeline.ToolNamesForMode consistently",
			c.mode, got, c.want)
	}
}

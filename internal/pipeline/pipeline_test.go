package pipeline

import (
	"testing"
)

func TestModeConstants(t *testing.T) {
	modes := []Mode{ModeSAST, ModeDAST, ModeSCA, ModeSecrets, ModeIAC, ModeFull}
	for _, m := range modes {
		if string(m) == "" {
			t.Errorf("mode constant is empty")
		}
	}
}

func TestProfileConstants(t *testing.T) {
	profiles := []Profile{ProfileFast, ProfileExt, ProfileAggr, ProfilePremium, ProfileFull, ProfileFullSOC}
	for _, p := range profiles {
		if string(p) == "" {
			t.Errorf("profile constant is empty")
		}
	}
}

func TestStatusConstants(t *testing.T) {
	statuses := []Status{StatusQueued, StatusRunning, StatusDone, StatusFailed, StatusCancelled}
	for _, s := range statuses {
		if string(s) == "" {
			t.Errorf("status constant is empty")
		}
	}
}

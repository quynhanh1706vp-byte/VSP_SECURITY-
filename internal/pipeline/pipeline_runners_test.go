package pipeline

import (
	"testing"
)

func TestRunnersFor_SAST(t *testing.T) {
	runners := RunnersFor(ModeSAST)
	if len(runners) == 0 {
		t.Error("expected runners for SAST mode")
	}
}

func TestRunnersFor_Secrets(t *testing.T) {
	runners := RunnersFor(ModeSecrets)
	if len(runners) == 0 {
		t.Error("expected runners for SECRETS mode")
	}
}

func TestRunnersFor_Full(t *testing.T) {
	runners := RunnersFor(ModeFull)
	if len(runners) == 0 {
		t.Error("expected runners for FULL mode")
	}
	// FULL should have more runners than SAST
	sastRunners := RunnersFor(ModeSAST)
	if len(runners) < len(sastRunners) {
		t.Errorf("FULL should have >= runners than SAST: full=%d sast=%d", len(runners), len(sastRunners))
	}
}

func TestRunnersFor_SCA(t *testing.T) {
	runners := RunnersFor(ModeSCA)
	if len(runners) == 0 {
		t.Error("expected runners for SCA mode")
	}
}

func TestRunnersFor_AllModes(t *testing.T) {
	modes := []Mode{ModeSAST, ModeDAST, ModeSCA, ModeSecrets, ModeIAC, ModeFull}
	for _, mode := range modes {
		runners := RunnersFor(mode)
		t.Logf("Mode %s: %d runners", mode, len(runners))
	}
}

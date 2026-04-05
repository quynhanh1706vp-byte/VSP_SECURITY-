package handler

import (
	"testing"
)

func TestCalcRisk_NoCritical(t *testing.T) {
	// No critical findings → low risk
	risk := calcRisk(0, 0, 15)
	if risk < 0 {
		t.Error("expected non-empty risk")
	}
}

func TestCalcRisk_WithCritical(t *testing.T) {
	// Critical findings → high risk
	risk := calcRisk(3, 5, 38)
	if risk < 0 {
		t.Error("expected non-empty risk")
	}
}

func TestCalcRisk_AllZero(t *testing.T) {
	risk := calcRisk(0, 0, 0)
	if risk < 0 {
		t.Error("expected non-empty risk for zero findings")
	}
}

func TestProtoToType_Common(t *testing.T) {
	cases := []string{"tcp", "udp", "http", "https", "ssh", "unknown"}
	for _, proto := range cases {
		result := protoToType(proto)
		if result == "" {
			t.Errorf("protoToType(%q) returned empty", proto)
		}
	}
}

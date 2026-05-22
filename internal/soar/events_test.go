package soar

import (
	"strings"
	"testing"
)

func TestEvent_RoundTrip(t *testing.T) {
	e := Event{Type: EvtStepDone, RunID: "r1", NodeID: "n0", Status: "done"}
	bytes := EncodeEvent(e)
	if !strings.Contains(string(bytes), `"_event":"soar:step:done"`) {
		t.Errorf("missing _event")
	}
	got, err := DecodeEvent(bytes)
	if err != nil || got.Type != EvtStepDone || got.NodeID != "n0" {
		t.Fatalf("decode mismatch: %+v err=%v", got, err)
	}
}

func TestEvent_OmitsEmpty(t *testing.T) {
	bytes := EncodeEvent(Event{Type: EvtRunStart, RunID: "r1"})
	if strings.Contains(string(bytes), `"node_id"`) {
		t.Error("empty field leaked")
	}
}

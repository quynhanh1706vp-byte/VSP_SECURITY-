package handler

import (
	"encoding/json"

	"github.com/vsp/platform/internal/store"
)

// fakeRun creates a store.Run with a given JSON summary for testing.
func fakeRun(summaryJSON []byte) *store.Run {
	return &store.Run{
		ID:      "run-1",
		RID:     "RID_TEST",
		Summary: json.RawMessage(summaryJSON),
	}
}


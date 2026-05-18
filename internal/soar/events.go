package soar

import (
	"encoding/json"
	"time"
)

// EventType — typed SSE event names. Frontend matches by these strings.
type EventType string

const (
	EvtRunStart        EventType = "soar:run:start"
	EvtRunEnd          EventType = "soar:run:end"
	EvtRunCancelled    EventType = "soar:run:cancelled"
	EvtRunWaitApproval EventType = "soar:run:waiting_approval"
	EvtStepStart       EventType = "soar:step:start"
	EvtStepDone        EventType = "soar:step:done"
	EvtStepFailed      EventType = "soar:step:failed"
	EvtStepRetry       EventType = "soar:step:retry"
	EvtApprovalCreated EventType = "soar:approval:created"
	EvtApprovalDecided EventType = "soar:approval:decided"
)

// Event — schema sent over WSHub.Broadcast.
//
// Frontend receives `{"_event":"soar:step:done","run_id":"...","node_id":"...",...}`.
// Use `EncodeEvent` to construct, `DecodeEvent` if engine receives back.
type Event struct {
	Type       EventType `json:"_event"`
	Timestamp  time.Time `json:"_ts"`
	RunID      string    `json:"run_id,omitempty"`
	PlaybookID string    `json:"playbook_id,omitempty"`
	TenantID   string    `json:"tenant_id,omitempty"`

	// Step-specific (omitempty so run-level events skip these)
	NodeID     string   `json:"node_id,omitempty"`
	StepType   StepType `json:"step_type,omitempty"`
	StepName   string   `json:"step_name,omitempty"`
	Status     string   `json:"status,omitempty"`
	DurationMS int      `json:"duration_ms,omitempty"`
	Attempt    int      `json:"attempt,omitempty"`
	Error      string   `json:"error,omitempty"`

	// Run-specific
	Trigger     string `json:"trigger,omitempty"`
	TriggeredBy string `json:"triggered_by,omitempty"`
	IsTest      bool   `json:"is_test,omitempty"`
	StepsTotal  int    `json:"steps_total,omitempty"`
	CurrentNode string `json:"current_node,omitempty"`

	// Approval-specific
	ApprovalID string   `json:"approval_id,omitempty"`
	Approvers  []string `json:"approvers,omitempty"`
	Decision   string   `json:"decision,omitempty"`
	DecidedBy  string   `json:"decided_by,omitempty"`

	// Free-form payload for extensions
	Payload json.RawMessage `json:"payload,omitempty"`
}

// EncodeEvent marshals to JSON ready for Broadcast.
func EncodeEvent(e Event) []byte {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	b, _ := json.Marshal(e)
	return b
}

// DecodeEvent — for testing or replay.
func DecodeEvent(b []byte) (Event, error) {
	var e Event
	err := json.Unmarshal(b, &e)
	return e, err
}

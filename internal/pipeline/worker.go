package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"
	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/gate"
	"github.com/vsp/platform/internal/scanner"
"github.com/vsp/platform/internal/store"
)

const TaskTypeScan = "scan:run"

// NewScanTask creates an asynq task for a scan job.
func NewScanTask(payload JobPayload) (*asynq.Task, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(TaskTypeScan, b,
		asynq.MaxRetry(2),
		asynq.Timeout(20*time.Minute),
	), nil
}

// ScanHandler is the asynq task handler that runs the actual scan.
type ScanHandler struct {
	DB       *store.DB
	Exec     *Executor
}

func NewScanHandler(db *store.DB) *ScanHandler {
	return &ScanHandler{
		DB: db,
		Exec: &Executor{
			OnProgress: func(tool string, done, total, findings int) {
				log.Info().
					Str("tool", tool).
					Int("done", done).Int("total", total).
					Int("findings", findings).
					Msg("tool done")
			},
		},
	}
}

func (h *ScanHandler) ProcessTask(ctx context.Context, t *asynq.Task) error {
	var payload JobPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	log.Info().Str("rid", payload.RID).Str("mode", string(payload.Mode)).Msg("scan started")

	// Mark RUNNING
	h.DB.UpdateRunStatus(ctx, payload.TenantID, payload.RID, "RUNNING", 0)

	// Execute
	result, err := h.Exec.Execute(ctx, payload)
	if err != nil {
		h.DB.UpdateRunStatus(ctx, payload.TenantID, payload.RID, "FAILED", 0)
		return err
	}

	// Persist findings
	dbFindings := make([]store.Finding, 0, len(result.Findings))
	for _, f := range result.Findings {
		raw, _ := json.Marshal(f.Raw)
		dbFindings = append(dbFindings, store.Finding{
			TenantID:  payload.TenantID,
			Tool:      f.Tool,
			Severity:  string(f.Severity),
			RuleID:    f.RuleID,
			Message:   f.Message,
			Path:      f.Path,
			LineNum:   f.Line,
			CWE:       f.CWE,
			FixSignal: f.FixSignal,
			Raw:       raw,
		})
	}

	// Get run ID for findings FK
	run, _ := h.DB.GetRunByRID(ctx, payload.TenantID, payload.RID)
	if run != nil {
		for i := range dbFindings {
			dbFindings[i].RunID = run.ID
		}
	}
	h.DB.InsertFindings(ctx, dbFindings)

	// Compute gate + posture
	s := result.Summary
	policyRule := gate.DefaultRule()
	rules, _ := h.DB.ListPolicyRules(ctx, payload.TenantID)
	if len(rules) > 0 {
		r0 := rules[0]
		policyRule = gate.PolicyRule{
			FailOn: r0.FailOn, MinScore: r0.MinScore, MaxHigh: r0.MaxHigh,
			BlockSecrets: r0.BlockSecrets, BlockCritical: r0.BlockCritical,
		}
	}
	eval := gate.Evaluate(policyRule, s)

	summaryJSON, _ := json.Marshal(map[string]int{
		"CRITICAL": s.Critical, "HIGH": s.High,
		"MEDIUM": s.Medium, "LOW": s.Low, "INFO": s.Info,
	})

	h.DB.UpdateRunResult(ctx, payload.TenantID, payload.RID,
		string(eval.Decision), eval.Posture,
		len(result.Findings), summaryJSON)

	// Write tool errors as audit
	for tool, terr := range result.ToolErrors {
		log.Warn().Str("rid", payload.RID).Str("tool", tool).Err(terr).Msg("tool error")
	}

	log.Info().
		Str("rid", payload.RID).
		Str("gate", string(eval.Decision)).
		Str("posture", eval.Posture).
		Int("findings", len(result.Findings)).
		Dur("duration", result.Duration).
		Msg("scan complete")

	return nil
}

// EnqueueScan enqueues a scan task. Called by the gateway trigger handler.
func EnqueueScan(client *asynq.Client, payload JobPayload) error {
	task, err := NewScanTask(payload)
	if err != nil {
		return err
	}
	_, err = client.Enqueue(task, asynq.Queue("default"))
	return err
}

// ScannerSummaryFromStore converts store.FindingSummary to scanner.Summary.
func ScannerSummaryFromStore(s *store.FindingSummary) scanner.Summary {
	if s == nil { return scanner.Summary{} }
	return scanner.Summary{
		Critical: s.Critical, High: s.High,
		Medium: s.Medium, Low: s.Low, Info: s.Info,
	}
}

// broadcastSSE sends event to all SSE clients if Hub is wired.
// Uses a package-level func to avoid import cycle with handler.
var broadcastSSE func([]byte) = func([]byte) {} // no-op default

// SetBroadcast wires the SSE hub broadcast function.
func SetBroadcast(fn func([]byte)) { broadcastSSE = fn }

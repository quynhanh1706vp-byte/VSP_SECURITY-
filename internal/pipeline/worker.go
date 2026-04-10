package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"
	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/audit"
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
	DB   *store.DB
	Exec *Executor
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

	// Execute — apply profile filtering + timeout per profile
	profileRunners := RunnersForProfile(payload.Mode, payload.Profile)
	payload.TimeoutSec = TimeoutForProfile(payload.Profile)
	result, err := h.Exec.ExecuteWith(ctx, payload, profileRunners)
	if err != nil {
		h.DB.UpdateRunStatus(ctx, payload.TenantID, payload.RID, "FAILED", 0)
		return err
	}

	// Use background context for DB ops — task ctx may be cancelled after Execute
	dbCtx := context.Background()

	// Persist findings
	dbFindings := make([]store.Finding, 0, len(result.Findings))
	for _, f := range result.Findings {
		raw, _ := json.Marshal(f.Raw)
		// Enrich CWE + CVSS for tools that don't emit them natively
		enrichedCWE := f.CWE
		enrichedCVSS := f.CVSS
		if enrichedCWE == "" || enrichedCVSS == 0 {
			cwe, cvss := scanner.EnrichFinding(f.Tool, f.RuleID, string(f.Severity), f.Message)
			if enrichedCWE == "" {
				enrichedCWE = cwe
			}
			if enrichedCVSS == 0 {
				enrichedCVSS = cvss
			}
		}
		dbFindings = append(dbFindings, store.Finding{
			TenantID:  payload.TenantID,
			Tool:      f.Tool,
			Severity:  string(f.Severity),
			RuleID:    f.RuleID,
			Message:   f.Message,
			Path:      f.Path,
			LineNum:   f.Line,
			CWE:       enrichedCWE,
			CVSS:      enrichedCVSS,
			FixSignal: f.FixSignal,
			Raw:       raw,
		})
	}

	// Get run ID for findings FK
	run, _ := h.DB.GetRunByRID(dbCtx, payload.TenantID, payload.RID)
	if run != nil {
		for i := range dbFindings {
			dbFindings[i].RunID = run.ID
		}
	}
	if err := h.DB.InsertFindingsBatch(dbCtx, dbFindings); err != nil {
		log.Error().Err(err).Str("run_id", payload.RID).Msg("insert findings batch failed")
	}

	// Auto-create remediation records trong 1 batch transaction
	saved, _, _ := h.DB.ListFindings(dbCtx, payload.TenantID, store.FindingFilter{
		RunID: run.ID, Limit: len(dbFindings) + 100,
	})
	remItems := make([]store.Remediation, 0, len(saved))
	for _, f := range saved {
		remItems = append(remItems, store.Remediation{
			FindingID: f.ID,
			TenantID:  payload.TenantID,
			Status:    store.RemOpen,
			Priority:  severityToPriority(f.Severity),
		})
	}
	if err := h.DB.BulkUpsertRemediations(dbCtx, remItems); err != nil {
		log.Error().Err(err).Str("run_id", payload.RID).Msg("bulk upsert remediations failed")
	}

	// Compute gate + posture
	s := result.Summary
	policyRule := gate.DefaultRule()
	rules, _ := h.DB.ListPolicyRules(dbCtx, payload.TenantID)
	if len(rules) > 0 {
		r0 := rules[0]
		policyRule = gate.PolicyRule{
			FailOn: r0.FailOn, MinScore: r0.MinScore, MaxHigh: r0.MaxHigh,
			BlockSecrets: r0.BlockSecrets, BlockCritical: r0.BlockCritical,
		}
	}
	eval := gate.Evaluate(policyRule, s)

	summaryJSON, _ := json.Marshal(map[string]any{
		"CRITICAL":    s.Critical,
		"HIGH":        s.High,
		"MEDIUM":      s.Medium,
		"LOW":         s.Low,
		"INFO":        s.Info,
		"HAS_SECRETS": s.HasSecrets,
		"SCORE":       eval.Score,
	})

	h.DB.UpdateRunResult(dbCtx, payload.TenantID, payload.RID,
		string(eval.Decision), eval.Posture,
		len(result.Findings), summaryJSON)
	// Store gate reason for audit trail
	h.DB.UpdateRunGateReason(dbCtx, payload.TenantID, payload.RID, eval.Reason)
	// Audit: log scan completion (synchronous - context.Background avoids cancellation)
	{
		auditCtx := context.Background()
		action := fmt.Sprintf("SCAN_%s", string(eval.Decision))
		resource := fmt.Sprintf("%s · %s · %d findings", payload.RID, string(payload.Mode), len(result.Findings))
		prevHash, _ := h.DB.GetLastAuditHash(auditCtx, payload.TenantID)
		e := audit.Entry{
			TenantID: payload.TenantID,
			Action:   action,
			Resource: resource,
			PrevHash: prevHash,
		}
		e.StoredHash = audit.Hash(e)
		h.DB.InsertAudit(auditCtx, store.AuditWriteParams{TenantID: payload.TenantID, Action: action, Resource: resource, IP: "pipeline", PrevHash: prevHash})
	}

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

	// Broadcast scan_complete to SSE clients
	if msg, err := json.Marshal(map[string]any{
		"type":           "scan_complete",
		"rid":            payload.RID,
		"gate":           string(eval.Decision),
		"posture":        eval.Posture,
		"score":          eval.Score,
		"total_findings": len(result.Findings),
		"critical":       s.Critical,
		"high":           s.High,
	}); err == nil {
		broadcastSSE(msg)
	}

	// Auto-trigger SOAR on gate FAIL
	if string(eval.Decision) == "FAIL" {
		go func() {
			sev := "HIGH"
			if s.Critical > 0 {
				sev = "CRITICAL"
			}
			pbs, err := h.DB.FindEnabledPlaybooks(context.Background(), payload.TenantID, "gate_fail", sev) //#nosec G118 -- async goroutine, request ctx already done
			if err != nil {
				return
			}
			for _, pb := range pbs {
				ctxJSON, _ := json.Marshal(map[string]any{
					"trigger": "gate_fail", "gate": string(eval.Decision),
					"severity": sev, "run_id": payload.RID, "findings": len(result.Findings),
				})
				runID, err := h.DB.CreatePlaybookRun(context.Background(), pb.ID, payload.TenantID, "gate_fail", ctxJSON)
				if err != nil {
					continue
				}
				log.Info().Str("playbook", pb.Name).Str("run_id", runID).Msg("soar: auto-triggered")
			}
		}()
	}

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
	if s == nil {
		return scanner.Summary{}
	}
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

func severityToPriority(sev string) string {
	switch sev {
	case "CRITICAL":
		return "P1"
	case "HIGH":
		return "P2"
	case "MEDIUM":
		return "P3"
	default:
		return "P4"
	}
}

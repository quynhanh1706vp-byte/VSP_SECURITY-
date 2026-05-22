package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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

	// Pre-flight: validate src path exists and is non-empty.
	// Prevents scheduler-triggered scans against missing/empty dirs from
	// reporting "DONE 17/17 tools, 0 findings, gate=PASS" — which polluted
	// 286/488 historical runs (~58%) with false-positive clean status.
	// SAST/IAC/SCA/SECRETS/FULL all require a source dir; DAST/NETWORK use URL.
	requiresSrc := payload.Mode != "DAST" && payload.Mode != "NETWORK"
	if requiresSrc && payload.Src != "" {
		info, statErr := os.Stat(payload.Src)
		if statErr != nil || !info.IsDir() {
			h.DB.UpdateRunStatus(ctx, payload.TenantID, payload.RID, "FAILED", 0)
			h.DB.UpdateRunGateReason(ctx, payload.TenantID, payload.RID,
				fmt.Sprintf("pre-flight: src not found or not a directory: %s", payload.Src))
			log.Warn().
				Str("rid", payload.RID).Str("src", payload.Src).Str("mode", string(payload.Mode)).
				Msg("scan aborted: src missing")
			return nil //nolint:nilerr
		}
		entries, _ := os.ReadDir(payload.Src)
		if len(entries) == 0 {
			h.DB.UpdateRunStatus(ctx, payload.TenantID, payload.RID, "FAILED", 0)
			h.DB.UpdateRunGateReason(ctx, payload.TenantID, payload.RID,
				fmt.Sprintf("pre-flight: src directory is empty: %s", payload.Src))
			log.Warn().
				Str("rid", payload.RID).Str("src", payload.Src).Str("mode", string(payload.Mode)).
				Msg("scan aborted: src empty")
			return nil
		}
	}

	// Execute — apply profile filtering + timeout per profile
	profileRunners := RunnersForProfile(payload.Mode, payload.Profile)
	payload.TimeoutSec = TimeoutForProfile(payload.Profile)

	// Phase B Step 2 — apply per-tenant tool config (disable opt-out).
	// Tools the tenant explicitly disabled in Settings are filtered out here.
	// Best-effort: if DB query fails, fall back to all tools (don't block scan).
	if h.DB != nil && payload.TenantID != "" {
		disabled, dbErr := h.DB.GetDisabledTools(ctx, payload.TenantID)
		if dbErr != nil {
			log.Warn().Err(dbErr).Str("rid", payload.RID).Msg("tool config: read disabled list failed (continuing with all tools)")
		} else if len(disabled) > 0 {
			disabledSet := make(map[string]bool, len(disabled))
			for _, name := range disabled {
				disabledSet[name] = true
			}
			filtered := make([]scanner.Runner, 0, len(profileRunners))
			skipped := make([]string, 0, len(disabled))
			for _, r := range profileRunners {
				if disabledSet[r.Name()] {
					skipped = append(skipped, r.Name())
					continue
				}
				filtered = append(filtered, r)
			}
			if len(skipped) > 0 {
				log.Info().
					Str("rid", payload.RID).
					Int("skipped_count", len(skipped)).
					Strs("skipped_tools", skipped).
					Int("remaining", len(filtered)).
					Msg("tool config: filtered out tenant-disabled tools")
			}
			profileRunners = filtered
		}
	}
	if len(profileRunners) == 0 {
		log.Warn().Str("rid", payload.RID).Msg("tool config: ALL tools disabled by tenant — scan will produce no findings")
	}

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

	// L6-A 7.3.1 fix (2026-05-09): use the POST-dedup count
	// (`len(saved)`) instead of the pre-storage scanner-emit count
	// (`len(result.Findings)`). The findings table dedups on
	// fingerprint UNIQUE (tool|rule|path|line) so the stored row count
	// is always ≤ the emit count. The L6-A db-integrity watchdog
	// caught the drift at every dashboard refresh: total_findings
	// reported by the scoreboard differed from what /findings returned.
	// toolsDone = number of tool runners the worker dispatched in
	// this run. Every runner contributes either a finding set or an
	// entry in ToolErrors, so len(profileRunners) is the canonical
	// "completed" count regardless of per-tool success/fail.
	h.DB.UpdateRunResult(dbCtx, payload.TenantID, payload.RID,
		string(eval.Decision), eval.Posture,
		len(saved), len(profileRunners), summaryJSON)
	// Store gate reason for audit trail
	h.DB.UpdateRunGateReason(dbCtx, payload.TenantID, payload.RID, eval.Reason)

	// Post-scan: fill conmon_schedules.last_verdict for any ConMon
	// schedule that fired this run. Pre-2026-05-12 conmon_schedules
	// stored last_run_id BIGINT (always 0 — runs use UUIDs), so this
	// hook had nothing to match against; migration 021 added
	// last_run_rid TEXT and the conmon scheduler now writes the RID
	// when firing. Match here and set the verdict from the gate
	// decision — that's the user-visible "LAST VERDICT" column.
	// Best-effort: a missing column on older deploys silently no-ops.
	go func(tenantID, rid, verdict string) {
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = h.DB.Pool().Exec(bgCtx, `
			UPDATE conmon_schedules
			   SET last_verdict = $1, updated_at = now()
			 WHERE tenant_id    = $2
			   AND last_run_rid = $3
		`, verdict, tenantID, rid)
	}(payload.TenantID, payload.RID, string(eval.Decision))

	// Post-scan hook: auto-resolve orphan remediations whose finding fingerprint
	// is no longer present in this newer same-mode run. Non-fatal — log and continue.
	// Only triggers on PASS/WARN paths (FAILED runs return early above).
	if len(result.Findings) > 0 {
		go func(tenantID, runID string) {
			bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			res, err := h.DB.AutoResolveOrphans(bgCtx, tenantID)
			if err != nil {
				log.Warn().Err(err).
					Str("tenant", tenantID).Str("run_id", runID).
					Msg("post-scan auto-resolve failed (non-fatal)")
				return
			}
			log.Info().
				Int("resolved", res.Resolved).
				Int("checked", res.Checked).
				Int("skipped", res.Skipped).
				Str("tenant", tenantID).Str("run_id", runID).
				Msg("post-scan auto-resolve completed")
		}(payload.TenantID, payload.RID)
	}
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

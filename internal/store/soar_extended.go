package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ════════════════════════════════════════════════════════════════════
// Phase 2.1.B.4 — SOAR engine store extensions
//
// Adds 18 methods for engine-driven playbook execution. Existing methods
// in siem.go are preserved for legacy compat.
// ════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────
// Extended types (separate from existing Playbook/PlaybookRun)
// ─────────────────────────────────────────────────────────────────

// PlaybookFull contains all columns including new ones (graph, version, ...).
type PlaybookFull struct {
	ID             string          `json:"id"`
	TenantID       string          `json:"tenant_id"`
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	TriggerEvent   string          `json:"trigger_event"`
	SevFilter      string          `json:"sev_filter"`
	TriggerFilter  json.RawMessage `json:"trigger_filter"`
	Steps          json.RawMessage `json:"steps,omitempty"` // legacy
	Graph          json.RawMessage `json:"graph"`
	Status         string          `json:"status"`
	Version        int             `json:"version"`
	Enabled        bool            `json:"enabled"`
	SecretRefs     []string        `json:"secret_refs"`
	Tags           []string        `json:"tags"`
	TimeoutSeconds int             `json:"timeout_seconds"`
	MaxRetries     int             `json:"max_retries"`
	RunCount       int             `json:"run_count"`
	SuccessCount   int             `json:"success_count"`
	CreatedBy      string          `json:"created_by"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

// RunFull contains all columns of playbook_runs.
type RunFull struct {
	ID              string          `json:"id"`
	PlaybookID      string          `json:"playbook_id"`
	TenantID        string          `json:"tenant_id"`
	Status          string          `json:"status"`
	TriggerEvent    string          `json:"trigger_event"`
	TriggeredBy     string          `json:"triggered_by"`
	IsTest          bool            `json:"is_test"`
	Context         json.RawMessage `json:"context"`
	StepResults     json.RawMessage `json:"step_results"`
	CurrentNode     string          `json:"current_node"`
	Error           string          `json:"error,omitempty"`
	PlaybookVersion int             `json:"playbook_version"`
	StartedAt       time.Time       `json:"started_at"`
	FinishedAt      *time.Time      `json:"finished_at,omitempty"`
	DurationMS      int             `json:"duration_ms"`
}

// PlaybookVersion — entry in version history table.
type PlaybookVersion struct {
	ID         int64           `json:"id"`
	PlaybookID string          `json:"playbook_id"`
	Version    int             `json:"version"`
	Graph      json.RawMessage `json:"graph"`
	SavedBy    string          `json:"saved_by"`
	SavedAt    time.Time       `json:"saved_at"`
	Note       string          `json:"note"`
}

// SOARSecretMetadata — public-safe secret info (no value).
type SOARSecretMetadata struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	LastUsedBy  string     `json:"last_used_by,omitempty"`
	UseCount    int64      `json:"use_count"`
}

// ApprovalRequestParams — what soar engine submits when an approval step fires.
type ApprovalRequestParams struct {
	NodeID         string
	Approvers      []string
	Quorum         string
	QuorumN        int
	TimeoutMinutes int
	Message        string
}

// ApprovalSummary — list view of pending approvals.
type ApprovalSummary struct {
	ID        string    `json:"id"`
	RunID     string    `json:"run_id"`
	NodeID    string    `json:"node_id"`
	Approvers []string  `json:"approvers"`
	Quorum    string    `json:"quorum"`
	QuorumN   int       `json:"quorum_n"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateRunParams — args for CreatePlaybookRunExtended.
type CreateRunParams struct {
	PlaybookID      string
	PlaybookVersion int
	TenantID        string
	TriggerEvent    string
	TriggeredBy     string
	IsTest          bool
	Context         json.RawMessage
}

// ─────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────

// ErrPlaybookNotFound returned when no row matches.
var ErrPlaybookNotFound = errors.New("store: playbook not found")

// ErrRunNotFound returned when run lookup fails.
var ErrRunNotFound = errors.New("store: run not found")

// ErrSecretNotFound returned when secret lookup fails.
var ErrStoreSecretNotFound = errors.New("store: secret not found")

// ErrApprovalNotFound returned when approval lookup fails.
var ErrApprovalNotFound = errors.New("store: approval not found")

// ─────────────────────────────────────────────────────────────────
// Playbook CRUD
// ─────────────────────────────────────────────────────────────────

// GetPlaybookByID fetches one playbook with all extended columns.
func (db *DB) GetPlaybookByID(ctx context.Context, tenantID, id string) (*PlaybookFull, error) {
	var pb PlaybookFull
	pb.ID = id
	pb.TenantID = tenantID

	row := db.pool.QueryRow(ctx, `
		SELECT name, description, trigger_event, sev_filter,
		       COALESCE(trigger_filter, '{}'::jsonb), steps, COALESCE(graph, '{}'::jsonb),
		       status, version, enabled,
		       COALESCE(secret_refs, '{}'), COALESCE(tags, '{}'),
		       COALESCE(timeout_seconds, 300), COALESCE(max_retries, 0),
		       run_count, success_count,
		       COALESCE(created_by, ''), created_at, updated_at
		FROM playbooks
		WHERE id = $1 AND tenant_id = $2
	`, id, tenantID)

	err := row.Scan(
		&pb.Name, &pb.Description, &pb.TriggerEvent, &pb.SevFilter,
		&pb.TriggerFilter, &pb.Steps, &pb.Graph,
		&pb.Status, &pb.Version, &pb.Enabled,
		&pb.SecretRefs, &pb.Tags,
		&pb.TimeoutSeconds, &pb.MaxRetries,
		&pb.RunCount, &pb.SuccessCount,
		&pb.CreatedBy, &pb.CreatedAt, &pb.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPlaybookNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan playbook: %w", err)
	}
	return &pb, nil
}

// UpdatePlaybookGraph updates the graph and bumps version. Stores prev version
// in playbook_versions for rollback. Returns new version number.
func (db *DB) UpdatePlaybookGraph(ctx context.Context, tenantID, id string, graph json.RawMessage, savedBy string) (int, error) {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Fetch current version
	var curVersion int
	var curGraph json.RawMessage
	err = tx.QueryRow(ctx, `
		SELECT version, COALESCE(graph, '{}'::jsonb)
		FROM playbooks WHERE id = $1 AND tenant_id = $2
	`, id, tenantID).Scan(&curVersion, &curGraph)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrPlaybookNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("get version: %w", err)
	}

	newVersion := curVersion + 1

	// Snapshot current to versions table
	_, err = tx.Exec(ctx, `
		INSERT INTO playbook_versions(playbook_id, version, graph, saved_by, saved_at, note)
		VALUES ($1, $2, $3, $4, NOW(), 'auto-snapshot before update')
		ON CONFLICT (playbook_id, version) DO NOTHING
	`, id, curVersion, curGraph, savedBy)
	if err != nil {
		return 0, fmt.Errorf("snapshot prev version: %w", err)
	}

	// Apply new graph
	_, err = tx.Exec(ctx, `
		UPDATE playbooks
		SET graph = $1, version = $2, updated_at = NOW()
		WHERE id = $3 AND tenant_id = $4
	`, graph, newVersion, id, tenantID)
	if err != nil {
		return 0, fmt.Errorf("update graph: %w", err)
	}

	// Insert new version row
	_, err = tx.Exec(ctx, `
		INSERT INTO playbook_versions(playbook_id, version, graph, saved_by, saved_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT DO NOTHING
	`, id, newVersion, graph, savedBy)
	if err != nil {
		return 0, fmt.Errorf("insert version: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return newVersion, nil
}

// ListPlaybookVersions — newest first.
func (db *DB) ListPlaybookVersions(ctx context.Context, playbookID string, limit int) ([]PlaybookVersion, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := db.pool.Query(ctx, `
		SELECT id, playbook_id, version, graph, saved_by, saved_at, note
		FROM playbook_versions
		WHERE playbook_id = $1
		ORDER BY version DESC
		LIMIT $2
	`, playbookID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []PlaybookVersion{}
	for rows.Next() {
		var v PlaybookVersion
		if err := rows.Scan(&v.ID, &v.PlaybookID, &v.Version, &v.Graph, &v.SavedBy, &v.SavedAt, &v.Note); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// RollbackPlaybookVersion sets playbook.graph to a prior version's graph.
// Bumps version (so rollback itself is a new version, preserving history).
func (db *DB) RollbackPlaybookVersion(ctx context.Context, playbookID string, toVersion int, by string) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var graph json.RawMessage
	err = tx.QueryRow(ctx, `
		SELECT graph FROM playbook_versions
		WHERE playbook_id = $1 AND version = $2
	`, playbookID, toVersion).Scan(&graph)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("version %d not found", toVersion)
	}
	if err != nil {
		return err
	}

	// Get current version to bump
	var curVer int
	if err := tx.QueryRow(ctx, `SELECT version FROM playbooks WHERE id=$1`, playbookID).Scan(&curVer); err != nil {
		return err
	}
	newVer := curVer + 1

	// Apply
	_, err = tx.Exec(ctx, `
		UPDATE playbooks SET graph=$1, version=$2, updated_at=NOW() WHERE id=$3
	`, graph, newVer, playbookID)
	if err != nil {
		return err
	}

	// Record rollback as new version row
	_, err = tx.Exec(ctx, `
		INSERT INTO playbook_versions(playbook_id, version, graph, saved_by, saved_at, note)
		VALUES ($1, $2, $3, $4, NOW(), $5)
	`, playbookID, newVer, graph, by, fmt.Sprintf("rollback to v%d", toVersion))
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// SetPlaybookStatus changes status (draft/enabled/disabled/archived). Also
// flips legacy `enabled` boolean for compat.
func (db *DB) SetPlaybookStatus(ctx context.Context, tenantID, id, status string) error {
	enabled := status == "enabled"
	tag, err := db.pool.Exec(ctx, `
		UPDATE playbooks SET status=$1, enabled=$2, updated_at=NOW()
		WHERE id=$3 AND tenant_id=$4
	`, status, enabled, id, tenantID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrPlaybookNotFound
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────
// Run lifecycle
// ─────────────────────────────────────────────────────────────────

// CreatePlaybookRunExtended — creates run with full extended fields.
// Returns the run with ID populated.
func (db *DB) CreatePlaybookRunExtended(ctx context.Context, p CreateRunParams) (*RunFull, error) {
	if p.Context == nil {
		p.Context = json.RawMessage(`{}`)
	}
	r := &RunFull{
		PlaybookID:      p.PlaybookID,
		PlaybookVersion: p.PlaybookVersion,
		TenantID:        p.TenantID,
		TriggerEvent:    p.TriggerEvent,
		TriggeredBy:     p.TriggeredBy,
		IsTest:          p.IsTest,
		Context:         p.Context,
		Status:          "running",
		StepResults:     json.RawMessage(`[]`),
	}

	row := db.pool.QueryRow(ctx, `
		INSERT INTO playbook_runs(
			playbook_id, tenant_id, status, trigger_event,
			triggered_by, is_test, context, step_results,
			playbook_version, started_at
		)
		VALUES ($1, $2, 'running', $3, $4, $5, $6, '[]'::jsonb, $7, NOW())
		RETURNING id, started_at
	`, p.PlaybookID, p.TenantID, p.TriggerEvent, p.TriggeredBy,
		p.IsTest, p.Context, p.PlaybookVersion)

	if err := row.Scan(&r.ID, &r.StartedAt); err != nil {
		return nil, fmt.Errorf("create run: %w", err)
	}
	return r, nil
}

// UpdateRunStatus changes status mid-execution (e.g. → waiting_approval).
func (db *DB) UpdatePlaybookRunStatus(ctx context.Context, runID, status, currentNode string) error {
	tag, err := db.pool.Exec(ctx, `
		UPDATE playbook_runs
		SET status = $1, current_node = $2
		WHERE id = $3
	`, status, currentNode, runID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrRunNotFound
	}
	return nil
}

// UpdateRunResults persists step results + error message (if any).
// Called after each step completes for live progress visibility.
func (db *DB) UpdateRunResults(ctx context.Context, runID string, stepResults json.RawMessage, errMsg string) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE playbook_runs SET step_results = $1, error = $2 WHERE id = $3
	`, stepResults, errMsg, runID)
	return err
}

// FinishRun sets terminal status + duration.
func (db *DB) FinishRun(ctx context.Context, runID, status string, durationMS int) error {
	tag, err := db.pool.Exec(ctx, `
		UPDATE playbook_runs
		SET status = $1, finished_at = NOW(), duration_ms = $2,
		    duration_s = $2 / 1000
		WHERE id = $3
	`, status, durationMS, runID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrRunNotFound
	}

	// Bump playbook stats
	if status == "success" {
		_, _ = db.pool.Exec(ctx, `
			UPDATE playbooks
			SET success_count = success_count + 1, run_count = run_count + 1
			WHERE id = (SELECT playbook_id FROM playbook_runs WHERE id = $1)
		`, runID)
	} else {
		_, _ = db.pool.Exec(ctx, `
			UPDATE playbooks
			SET run_count = run_count + 1
			WHERE id = (SELECT playbook_id FROM playbook_runs WHERE id = $1)
		`, runID)
	}
	return nil
}

// GetRunByID fetches a run with all extended fields.
func (db *DB) GetPlaybookRunByID(ctx context.Context, tenantID, runID string) (*RunFull, error) {
	var r RunFull
	r.ID = runID
	r.TenantID = tenantID

	row := db.pool.QueryRow(ctx, `
		SELECT playbook_id, status, trigger_event, COALESCE(triggered_by, ''),
		       is_test, context, step_results, COALESCE(current_node, ''),
		       error, COALESCE(playbook_version, 1),
		       started_at, finished_at, COALESCE(duration_ms, 0)
		FROM playbook_runs
		WHERE id = $1 AND tenant_id = $2
	`, runID, tenantID)

	err := row.Scan(
		&r.PlaybookID, &r.Status, &r.TriggerEvent, &r.TriggeredBy,
		&r.IsTest, &r.Context, &r.StepResults, &r.CurrentNode,
		&r.Error, &r.PlaybookVersion,
		&r.StartedAt, &r.FinishedAt, &r.DurationMS,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRunNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan run: %w", err)
	}
	return &r, nil
}

// ─────────────────────────────────────────────────────────────────
// Secrets vault — implements soar.SecretsStore interface
// ─────────────────────────────────────────────────────────────────

// GetSecret returns encrypted value + nonce. Caller decrypts via crypto.AESGCM.
func (db *DB) GetSecret(ctx context.Context, tenantID, name string) ([]byte, []byte, error) {
	var enc, nonce []byte
	err := db.pool.QueryRow(ctx, `
		SELECT value_encrypted, nonce
		FROM playbook_secrets
		WHERE tenant_id = $1 AND name = $2
	`, tenantID, name).Scan(&enc, &nonce)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrStoreSecretNotFound
	}
	return enc, nonce, err
}

// UpsertSecret creates or updates a secret.
func (db *DB) UpsertSecret(ctx context.Context, tenantID, name, description string, encValue, nonce []byte, createdBy string) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO playbook_secrets(tenant_id, name, description, value_encrypted, nonce, created_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		ON CONFLICT (tenant_id, name) DO UPDATE SET
			value_encrypted = EXCLUDED.value_encrypted,
			nonce = EXCLUDED.nonce,
			description = EXCLUDED.description,
			created_by = EXCLUDED.created_by,
			created_at = NOW()
	`, tenantID, name, description, encValue, nonce, createdBy)
	return err
}

// DeleteSecret removes a secret.
func (db *DB) DeleteSecret(ctx context.Context, tenantID, name string) error {
	tag, err := db.pool.Exec(ctx, `
		DELETE FROM playbook_secrets WHERE tenant_id=$1 AND name=$2
	`, tenantID, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrStoreSecretNotFound
	}
	return nil
}

// ListSecrets returns metadata only (no values) sorted by name.
// NOTE: returns SOARSecretMetadata, which engine maps to soar.SecretMetadata.
func (db *DB) ListSecrets(ctx context.Context, tenantID string) ([]SOARSecretMetadata, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT name, description, COALESCE(created_by, ''), created_at,
		       last_used_at, COALESCE(last_used_by, ''), use_count
		FROM playbook_secrets
		WHERE tenant_id = $1
		ORDER BY name
		LIMIT 1000
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []SOARSecretMetadata{}
	for rows.Next() {
		var s SOARSecretMetadata
		if err := rows.Scan(&s.Name, &s.Description, &s.CreatedBy, &s.CreatedAt,
			&s.LastUsedAt, &s.LastUsedBy, &s.UseCount); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// TouchSecret bumps usage stats. Called async after Resolve().
func (db *DB) TouchSecret(ctx context.Context, tenantID, name, usedBy string) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE playbook_secrets
		SET last_used_at = NOW(), last_used_by = $1, use_count = use_count + 1
		WHERE tenant_id = $2 AND name = $3
	`, usedBy, tenantID, name)
	return err
}

// WriteSecretAudit records a secret access/create/delete event.
func (db *DB) WriteSecretAudit(ctx context.Context, tenantID, name, runID, action, actor string) error {
	var runIDArg interface{}
	if runID != "" {
		runIDArg = runID
	}
	_, err := db.pool.Exec(ctx, `
		INSERT INTO playbook_secret_audit(tenant_id, secret_name, run_id, action, actor, accessed_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
	`, tenantID, name, runIDArg, action, actor)
	return err
}

// ─────────────────────────────────────────────────────────────────
// Approvals — implements soar.ApprovalDecisionResolver
// ─────────────────────────────────────────────────────────────────

// CreateApproval persists a pending approval. Returns approval ID.
func (db *DB) CreateApproval(ctx context.Context, runID string, req ApprovalRequestParams) (string, error) {
	if req.Quorum == "" {
		req.Quorum = "any"
	}
	if req.QuorumN == 0 {
		req.QuorumN = 1
	}
	if req.TimeoutMinutes <= 0 {
		req.TimeoutMinutes = 60
	}
	expiresAt := time.Now().Add(time.Duration(req.TimeoutMinutes) * time.Minute)

	var id string
	err := db.pool.QueryRow(ctx, `
		INSERT INTO playbook_approvals(run_id, node_id, approvers, quorum, quorum_n, status, note, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7, NOW())
		RETURNING id
	`, runID, req.NodeID, req.Approvers, req.Quorum, req.QuorumN, req.Message, expiresAt).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create approval: %w", err)
	}
	return id, nil
}

// PollApprovalDecision returns (decision, decided). decided=false → still pending.
// Auto-marks as 'timeout' if expired and status still 'pending'.
func (db *DB) PollApprovalDecision(ctx context.Context, approvalID string) (string, bool, error) {
	var status string
	var expired bool
	err := db.pool.QueryRow(ctx, `
		SELECT status, (expires_at < NOW()) AS expired
		FROM playbook_approvals
		WHERE id = $1
	`, approvalID).Scan(&status, &expired)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, ErrApprovalNotFound
	}
	if err != nil {
		return "", false, err
	}

	if status == "pending" && expired {
		// Auto-transition to timeout
		_, _ = db.pool.Exec(ctx, `
			UPDATE playbook_approvals
			SET status = 'timeout', decided_at = NOW()
			WHERE id = $1 AND status = 'pending'
		`, approvalID)
		return "timeout", true, nil
	}

	if status == "pending" {
		return "", false, nil
	}
	return status, true, nil
}

// RecordApprovalDecision applies a single approver's decision. Updates aggregate
// status to approved/rejected if quorum reached.
func (db *DB) RecordApprovalDecision(ctx context.Context, approvalID, by, decision, note string) error {
	if decision != "approved" && decision != "rejected" {
		return fmt.Errorf("invalid decision: %s", decision)
	}

	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Fetch current state
	var status, quorum string
	var quorumN int
	var approvers []string
	var decisions json.RawMessage
	err = tx.QueryRow(ctx, `
		SELECT status, quorum, quorum_n, approvers, decisions
		FROM playbook_approvals WHERE id = $1 FOR UPDATE
	`, approvalID).Scan(&status, &quorum, &quorumN, &approvers, &decisions)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrApprovalNotFound
	}
	if err != nil {
		return err
	}
	if status != "pending" {
		return fmt.Errorf("approval already %s", status)
	}

	// Verify approver is allowed
	allowed := false
	for _, a := range approvers {
		if a == by {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("user %q not in approver list", by)
	}

	// Append decision
	var decList []map[string]interface{}
	_ = json.Unmarshal(decisions, &decList)
	decList = append(decList, map[string]interface{}{
		"by": by, "decision": decision, "note": note,
		"at": time.Now().UTC().Format(time.RFC3339),
	})
	newDecJSON, _ := json.Marshal(decList)

	// Determine if quorum reached
	approvedCount := 0
	rejectedCount := 0
	for _, d := range decList {
		switch d["decision"] {
		case "approved":
			approvedCount++
		case "rejected":
			rejectedCount++
		}
	}

	newStatus := "pending"
	switch quorum {
	case "any":
		if approvedCount > 0 {
			newStatus = "approved"
		}
		if rejectedCount > 0 {
			newStatus = "rejected"
		}
	case "all":
		if approvedCount == len(approvers) {
			newStatus = "approved"
		}
		if rejectedCount > 0 {
			newStatus = "rejected"
		}
	case "m_of_n":
		if approvedCount >= quorumN {
			newStatus = "approved"
		}
		if rejectedCount > len(approvers)-quorumN {
			newStatus = "rejected"
		}
	}

	var decidedAt interface{}
	if newStatus != "pending" {
		decidedAt = time.Now()
	}
	_, err = tx.Exec(ctx, `
		UPDATE playbook_approvals
		SET decisions = $1, status = $2, decided_at = $3
		WHERE id = $4
	`, newDecJSON, newStatus, decidedAt, approvalID)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// ListPendingApprovals — for tenant dashboard.
func (db *DB) ListPendingApprovals(ctx context.Context, tenantID string) ([]ApprovalSummary, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT a.id, a.run_id, a.node_id, a.approvers, a.quorum, a.quorum_n,
		       a.status, a.note, a.expires_at, a.created_at
		FROM playbook_approvals a
		JOIN playbook_runs r ON r.id = a.run_id
		WHERE r.tenant_id = $1 AND a.status = 'pending'
		ORDER BY a.created_at DESC LIMIT 100
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []ApprovalSummary{}
	for rows.Next() {
		var s ApprovalSummary
		if err := rows.Scan(&s.ID, &s.RunID, &s.NodeID, &s.Approvers, &s.Quorum,
			&s.QuorumN, &s.Status, &s.Message, &s.ExpiresAt, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ─────────────────────────────────────────────────────────────────
// Trigger dedup
// ─────────────────────────────────────────────────────────────────

// CheckAndRecordTrigger atomically checks if a trigger fingerprint was
// recorded within `window`. Returns true if duplicate (caller should skip).
// On false (new), records it.
func (db *DB) CheckAndRecordTrigger(ctx context.Context, fingerprint, playbookID, tenantID string, window time.Duration) (bool, error) {
	if window <= 0 {
		window = 60 * time.Second
	}
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var exists bool
	err = tx.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM playbook_trigger_dedup
			WHERE fingerprint = $1
			  AND fired_at > NOW() - $2::interval
		)
	`, fingerprint, fmt.Sprintf("%d seconds", int(window.Seconds()))).Scan(&exists)
	if err != nil {
		return false, err
	}
	if exists {
		return true, nil
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO playbook_trigger_dedup(fingerprint, playbook_id, tenant_id, fired_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (fingerprint) DO UPDATE SET fired_at = NOW()
	`, fingerprint, playbookID, tenantID)
	if err != nil {
		return false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return false, nil
}

// ════════════════════════════════════════════════════════════════════
// Bridge methods for soar.DBLike interface (primitive args only)
// ════════════════════════════════════════════════════════════════════

// GetPlaybookJSON returns the playbook row as JSON for adapter consumption.
func (db *DB) GetPlaybookJSON(ctx context.Context, tenantID, id string) (json.RawMessage, error) {
	pb, err := db.GetPlaybookByID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	return json.Marshal(pb)
}

// CreateRunRow is the primitive-args version of CreatePlaybookRunExtended.
func (db *DB) CreateRunRow(ctx context.Context,
	playbookID string, playbookVersion int, tenantID, triggerEvent, triggeredBy string,
	isTest bool, contextJSON json.RawMessage,
) (string, time.Time, error) {
	r, err := db.CreatePlaybookRunExtended(ctx, CreateRunParams{
		PlaybookID:      playbookID,
		PlaybookVersion: playbookVersion,
		TenantID:        tenantID,
		TriggerEvent:    triggerEvent,
		TriggeredBy:     triggeredBy,
		IsTest:          isTest,
		Context:         contextJSON,
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return r.ID, r.StartedAt, nil
}

// CreateApprovalRow is the primitive-args version of CreateApproval.
func (db *DB) CreateApprovalRow(ctx context.Context,
	runID, nodeID string, approvers []string, quorum string, quorumN, timeoutMin int, message string,
) (string, error) {
	return db.CreateApproval(ctx, runID, ApprovalRequestParams{
		NodeID:         nodeID,
		Approvers:      approvers,
		Quorum:         quorum,
		QuorumN:        quorumN,
		TimeoutMinutes: timeoutMin,
		Message:        message,
	})
}

// MarkZombieRunsFailed marks runs that have been in 'running' status for too
// long as 'failed'. Returns count.
func (db *DB) MarkZombieRunsFailed(ctx context.Context, olderThan time.Duration) (int, error) {
	tag, err := db.pool.Exec(ctx, `
		UPDATE playbook_runs
		SET status = 'failed',
		    error = 'zombie run — engine restarted, run abandoned',
		    finished_at = NOW(),
		    duration_ms = EXTRACT(EPOCH FROM (NOW() - started_at))::int * 1000
		WHERE status IN ('running')
		  AND started_at < NOW() - $1::interval
	`, fmt.Sprintf("%d seconds", int(olderThan.Seconds())))
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// ListSecretsJSON returns ListSecrets results marshaled as JSON.
// Used by soar.SecretsStoreAdapter to bridge across packages.
func (db *DB) ListSecretsJSON(ctx context.Context, tenantID string) ([]byte, error) {
	rows, err := db.ListSecrets(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return json.Marshal(rows)
}

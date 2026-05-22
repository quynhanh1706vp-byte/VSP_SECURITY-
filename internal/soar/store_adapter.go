package soar

import (
	"context"
	"encoding/json"
	"time"
)

// StoreAdapter bridges *store.DB to the EngineStore interface.
//
// Design: DBLike interface uses primitive args ONLY (no struct types
// declared in soar package), so *store.DB satisfies it via duck typing.
// Adapter handles json.RawMessage / time.Time / []string passing.
type StoreAdapter struct {
	DB DBLike
}

// DBLike — the subset of *store.DB methods engine needs, expressed
// with primitive args so *store.DB matches by structural typing.
//
// Note: GetPlaybookByID returns an opaque PlaybookRowReader so we can
// extract fields without importing store package. Real *store.DB returns
// *store.PlaybookFull which has all required getter methods (provided
// by adapter wrappers below if needed). For our purposes, we use a
// 'json.RawMessage' returning method that gives us the full row as JSON.
type DBLike interface {
	// Returns playbook row marshaled as JSON. Engine unmarshals into Playbook.
	GetPlaybookJSON(ctx context.Context, tenantID, id string) (json.RawMessage, error)

	// CreateRun primitives
	CreateRunRow(ctx context.Context,
		playbookID string, playbookVersion int, tenantID, triggerEvent, triggeredBy string,
		isTest bool, contextJSON json.RawMessage,
	) (runID string, startedAt time.Time, err error)

	UpdatePlaybookRunStatus(ctx context.Context, runID, status, currentNode string) error
	UpdateRunResults(ctx context.Context, runID string, stepResults json.RawMessage, errMsg string) error
	FinishRun(ctx context.Context, runID, status string, durationMS int) error

	// Approval primitives
	CreateApprovalRow(ctx context.Context,
		runID, nodeID string, approvers []string, quorum string, quorumN, timeoutMin int, message string,
	) (approvalID string, err error)
	PollApprovalDecision(ctx context.Context, approvalID string) (decision string, decided bool, err error)
}

// ─── EngineStore impl ───

func (a *StoreAdapter) GetPlaybook(ctx context.Context, tenantID, id string) (*Playbook, error) {
	raw, err := a.DB.GetPlaybookJSON(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}

	// store side returns shape: {id, name, graph (as JSONB → bytes), trigger_event, ...}
	// Unmarshal into a flexible intermediate, then map to soar.Playbook.
	var row struct {
		ID             string          `json:"id"`
		TenantID       string          `json:"tenant_id"`
		Name           string          `json:"name"`
		Description    string          `json:"description"`
		TriggerEvent   string          `json:"trigger_event"`
		TriggerFilter  json.RawMessage `json:"trigger_filter"`
		Graph          json.RawMessage `json:"graph"`
		Status         string          `json:"status"`
		Version        int             `json:"version"`
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
	if err := json.Unmarshal(raw, &row); err != nil {
		return nil, err
	}

	pb := &Playbook{
		ID:             row.ID,
		TenantID:       row.TenantID,
		Name:           row.Name,
		Description:    row.Description,
		TriggerEvent:   row.TriggerEvent,
		TriggerFilter:  row.TriggerFilter,
		Status:         row.Status,
		Version:        row.Version,
		SecretRefs:     row.SecretRefs,
		Tags:           row.Tags,
		TimeoutSeconds: row.TimeoutSeconds,
		MaxRetries:     row.MaxRetries,
		RunCount:       row.RunCount,
		SuccessCount:   row.SuccessCount,
		CreatedBy:      row.CreatedBy,
		CreatedAt:      row.CreatedAt,
		UpdatedAt:      row.UpdatedAt,
	}
	if len(row.Graph) > 0 && string(row.Graph) != "{}" && string(row.Graph) != "null" {
		_ = json.Unmarshal(row.Graph, &pb.Graph)
	}
	return pb, nil
}

func (a *StoreAdapter) CreateRun(ctx context.Context, p CreateRunArgs) (string, time.Time, error) {
	return a.DB.CreateRunRow(ctx,
		p.PlaybookID, p.PlaybookVersion, p.TenantID,
		p.TriggerEvent, p.TriggeredBy, p.IsTest, p.Context,
	)
}

func (a *StoreAdapter) UpdateRunStatus(ctx context.Context, runID, status, currentNode string) error {
	return a.DB.UpdatePlaybookRunStatus(ctx, runID, status, currentNode)
}

func (a *StoreAdapter) UpdateRunResults(ctx context.Context, runID string, stepResults json.RawMessage, errMsg string) error {
	return a.DB.UpdateRunResults(ctx, runID, stepResults, errMsg)
}

func (a *StoreAdapter) FinishRun(ctx context.Context, runID, status string, durationMS int) error {
	return a.DB.FinishRun(ctx, runID, status, durationMS)
}

func (a *StoreAdapter) CreateApproval(ctx context.Context, runID string, req *ApprovalRequest) (string, error) {
	return a.DB.CreateApprovalRow(ctx, runID, req.NodeID,
		req.Approvers, req.Quorum, req.QuorumN, req.TimeoutMinutes, req.Message)
}

func (a *StoreAdapter) PollDecision(ctx context.Context, approvalID string) (string, bool, error) {
	return a.DB.PollApprovalDecision(ctx, approvalID)
}

// ════════════════════════════════════════════════════════════════════
// SecretsStoreAdapter — bridges *store.DB to soar.SecretsStore interface.
//
// store.DB has all 6 methods needed but ListSecrets returns
// []store.SOARSecretMetadata while soar.SecretsStore expects
// []soar.SecretMetadata. The two structs have identical shape — adapter
// just converts the slice.
//
// All other methods (GetSecret, UpsertSecret, DeleteSecret, TouchSecret,
// WriteSecretAudit) are pass-through — same signatures, same primitive
// types only.
// ════════════════════════════════════════════════════════════════════

// SecretsDBLike is the duck-typed subset of *store.DB methods that
// SecretsStoreAdapter wraps.
type SecretsDBLike interface {
	GetSecret(ctx context.Context, tenantID, name string) ([]byte, []byte, error)
	UpsertSecret(ctx context.Context, tenantID, name, description string, encValue, nonce []byte, createdBy string) error
	DeleteSecret(ctx context.Context, tenantID, name string) error
	TouchSecret(ctx context.Context, tenantID, name, usedBy string) error
	WriteSecretAudit(ctx context.Context, tenantID, name, runID, action, actor string) error
	// Note: ListSecretsRaw returns shape-compatible row data via JSON to avoid
	// importing store package types here.
	ListSecretsJSON(ctx context.Context, tenantID string) ([]byte, error)
}

// SecretsStoreAdapter implements soar.SecretsStore by wrapping a SecretsDBLike.
type SecretsStoreAdapter struct {
	DB SecretsDBLike
}

// GetSecret pass-through.
func (a *SecretsStoreAdapter) GetSecret(ctx context.Context, tenantID, name string) ([]byte, []byte, error) {
	return a.DB.GetSecret(ctx, tenantID, name)
}

// UpsertSecret pass-through.
func (a *SecretsStoreAdapter) UpsertSecret(ctx context.Context, tenantID, name, description string, encValue, nonce []byte, createdBy string) error {
	return a.DB.UpsertSecret(ctx, tenantID, name, description, encValue, nonce, createdBy)
}

// DeleteSecret pass-through.
func (a *SecretsStoreAdapter) DeleteSecret(ctx context.Context, tenantID, name string) error {
	return a.DB.DeleteSecret(ctx, tenantID, name)
}

// TouchSecret pass-through.
func (a *SecretsStoreAdapter) TouchSecret(ctx context.Context, tenantID, name, usedBy string) error {
	return a.DB.TouchSecret(ctx, tenantID, name, usedBy)
}

// WriteSecretAudit pass-through.
func (a *SecretsStoreAdapter) WriteSecretAudit(ctx context.Context, tenantID, name, runID, action, actor string) error {
	return a.DB.WriteSecretAudit(ctx, tenantID, name, runID, action, actor)
}

// ListSecrets converts JSON rows to soar.SecretMetadata.
func (a *SecretsStoreAdapter) ListSecrets(ctx context.Context, tenantID string) ([]SecretMetadata, error) {
	raw, err := a.DB.ListSecretsJSON(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var out []SecretMetadata
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

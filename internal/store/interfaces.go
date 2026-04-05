package store

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"time"
)

type AuditStore interface {
	InsertAudit(ctx context.Context, p AuditWriteParams) (seq int64, hash string, err error)
	GetLastAuditHash(ctx context.Context, tenantID string) (string, error)
	ListAuditByTenant(ctx context.Context, tenantID string) ([]AuditEntry, error)
	ListAuditPaged(ctx context.Context, tenantID, actionFilter string, limit, offset int) ([]AuditEntry, int64, error)
}

type AuditWriteParams struct {
	TenantID string
	UserID   *string
	Action   string
	Resource string
	IP       string
	Payload  json.RawMessage
	PrevHash string
}

type WebhookStore interface {
	ListSIEMWebhooks(ctx context.Context, tenantID string) ([]SIEMWebhook, error)
	CreateSIEMWebhook(ctx context.Context, h SIEMWebhook) (SIEMWebhook, error)
	DeleteSIEMWebhook(ctx context.Context, tenantID, id string) error
	TouchSIEMWebhook(ctx context.Context, id string) error
}

type CorrelatorStore interface {
	ListCorrelationRules(ctx context.Context, tenantID string) ([]CorrelationRule, error)
	CreateIncident(ctx context.Context, inc Incident) (string, error)
	GetIncident(ctx context.Context, tenantID, id string) (*Incident, error)
	UpdateIncidentStatus(ctx context.Context, tenantID, id, status string) error
	ListIncidents(ctx context.Context, tenantID, status, sev string, limit int) ([]Incident, error)
	UpdateCorrelationRuleHits(ctx context.Context, id string) error
	CountRecentIncidents(ctx context.Context, ruleID string, windowMin int) (int, error)
	CountEventsInWindow(ctx context.Context, tenantID string, since time.Time, extraWhere string, args []any) (int, []string, error)
	FindEnabledPlaybooks(ctx context.Context, tenantID, trigger, sev string) ([]Playbook, error)
	CreatePlaybookRun(ctx context.Context, playbookID, tenantID, trigger string, ctx2 json.RawMessage) (string, error)
	QueryEventCount(ctx context.Context, q string, args []any) (int, []string, error)
	ListAllEnabledRules(ctx context.Context) (pgx.Rows, error)
}

type PlaybookStore interface {
	FindEnabledPlaybooks(ctx context.Context, tenantID, trigger, sev string) ([]Playbook, error)
	CreatePlaybookRun(ctx context.Context, playbookID, tenantID, trigger string, ctx2 json.RawMessage) (string, error)
	CompletePlaybookRun(ctx context.Context, runID string, success bool)
	ListPlaybookRuns(ctx context.Context, tenantID string, limit int) ([]PlaybookRun, error)
	ListPlaybooks(ctx context.Context, tenantID string) ([]Playbook, error)
	CreatePlaybook(ctx context.Context, p Playbook) (string, error)
	TogglePlaybook(ctx context.Context, tenantID, id string) (bool, error)
}

type FindingStore interface {
	InsertFindingsBatch(ctx context.Context, findings []Finding) error
	ListFindings(ctx context.Context, tenantID string, f FindingFilter) ([]Finding, int64, error)
	FindingsSummary(ctx context.Context, tenantID, runID string) (*FindingSummary, error)
}

type PolicyStore interface {
	ListPolicyRules(ctx context.Context, tenantID string) ([]PolicyRule, error)
	CreatePolicyRule(ctx context.Context, r PolicyRule) (*PolicyRule, error)
	DeletePolicyRule(ctx context.Context, tenantID, id string) error
}

type RemediationStore interface {
	GetRemediation(ctx context.Context, tenantID, findingID string) (*Remediation, error)
	UpsertRemediation(ctx context.Context, r Remediation) (*Remediation, error)
	ListRemediations(ctx context.Context, tenantID, status string) ([]Remediation, error)
	RemediationStats(ctx context.Context, tenantID string) (map[string]int, error)
	AddComment(ctx context.Context, remID, author, body string) (*RemediationComment, error)
	ListComments(ctx context.Context, remID string) ([]RemediationComment, error)
	BulkUpsertRemediations(ctx context.Context, items []Remediation) error
}

type UserStore interface {
	GetUserByEmail(ctx context.Context, tenantID, email string) (*User, error)
	GetUserByID(ctx context.Context, tenantID, id string) (*User, error)
	CreateUser(ctx context.Context, tenantID, email, pwHash, role string) (*User, error)
	ListUsers(ctx context.Context, tenantID string, limit, offset int) ([]User, int64, error)
	DeleteUser(ctx context.Context, tenantID, id string) error
	UpdateLastLogin(ctx context.Context, id string) error
	SetMFASecret(ctx context.Context, userID, secret string) error
	VerifyMFASetup(ctx context.Context, userID string) error
	DisableMFA(ctx context.Context, tenantID, userID string) error
	RecordFailedLogin(ctx context.Context, userID string) (int, error)
	ResetFailedLogins(ctx context.Context, userID string) error
	UpdatePassword(ctx context.Context, userID, newHash string) error
	IsPasswordReused(ctx context.Context, userID, newPassword string) (bool, error)
}

type APIKeyStore interface {
	CreateAPIKey(ctx context.Context, tenantID, label, prefix, hash, role string, expiresAt *time.Time) (*APIKey, error)
	GetAPIKeyByPrefix(ctx context.Context, tenantID, prefix string) (*APIKey, error)
	ListAPIKeys(ctx context.Context, tenantID string) ([]APIKey, error)
	DeleteAPIKey(ctx context.Context, tenantID, id string) error
	TouchAPIKey(ctx context.Context, id string) error
}

type RefreshTokenStore interface {
	CreateRefreshToken(ctx context.Context, userID, tenantID, hash string, expiresAt time.Time) error
	RevokeRefreshFamily(ctx context.Context, family string) error
	RevokeAllRefreshTokens(ctx context.Context, userID string) error
}

type RunStore interface {
	CreateRun(ctx context.Context, rid, tenantID, mode, profile, src, targetURL string, toolsTotal int) (*Run, error)
	GetRunByRID(ctx context.Context, tenantID, rid string) (*Run, error)
	GetLatestRun(ctx context.Context, tenantID string) (*Run, error)
	ListRuns(ctx context.Context, tenantID string, limit, offset int) ([]Run, error)
	UpdateRunStatus(ctx context.Context, tenantID, rid, status string, toolsDone int) error
	UpdateRunResult(ctx context.Context, tenantID, rid, gate, posture string, total int, summary json.RawMessage) error
}

type Store interface {
	AuditStore
	WebhookStore
	CorrelatorStore
	PlaybookStore
	FindingStore
	PolicyStore
	RemediationStore
	UserStore
	APIKeyStore
	RefreshTokenStore
	RunStore
}

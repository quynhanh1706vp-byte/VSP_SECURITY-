package handler

import (
	"net/http"
	"strings"
	"time"

	"github.com/vsp/platform/internal/auth"
	"github.com/vsp/platform/internal/store"
)

// ProPanels collects "view details" handlers for PRO-tier sidebar features
// that are otherwise thin (Tenants, Observability). Each handler renders the
// per-tenant configuration / current-usage view that the frontend overlay shows.
type ProPanels struct {
	DB *store.DB
}

func NewProPanels(db *store.DB) *ProPanels { return &ProPanels{DB: db} }

// ── Tenants → quota panel ─────────────────────────────────────────────────────

type tenantQuotaPanel struct {
	TenantID    string `json:"tenant_id"`
	Plan        string `json:"plan"`
	Scans       int64  `json:"scans"`
	OpenFinds   int64  `json:"open_findings"`
	Secrets     int64  `json:"secrets"`
	CSPMAccts   int64  `json:"cspm_accounts"`
	Repos       int64  `json:"repos"`
	GeneratedAt string `json:"generated_at"`
}

// TenantQuota — GET /api/v1/tenants/quota
// Aggregates current resource usage for the calling tenant. Useful as the
// PRO "view details" panel for Tenants management.
func (p *ProPanels) TenantQuota(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	out := tenantQuotaPanel{
		TenantID:    claims.TenantID,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
	pool := p.DB.Pool()
	ctx := r.Context()

	_ = pool.QueryRow(ctx, `SELECT COALESCE(plan,'starter') FROM tenants WHERE id=$1`, claims.TenantID).Scan(&out.Plan)
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM runs WHERE tenant_id=$1`, claims.TenantID).Scan(&out.Scans)
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM findings WHERE tenant_id=$1 AND COALESCE(status,'open')='open'`, claims.TenantID).Scan(&out.OpenFinds)
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM playbook_secrets WHERE tenant_id=$1`, claims.TenantID).Scan(&out.Secrets)
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM cspm_accounts WHERE tenant_id=$1`, claims.TenantID).Scan(&out.CSPMAccts)
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM autopr_repos WHERE tenant_id=$1`, claims.TenantID).Scan(&out.Repos)

	jsonOK(w, out)
}

// ── Observability → config panel ─────────────────────────────────────────────

type obsConfig struct {
	AlertCriticalThreshold int       `json:"alert_critical_threshold"`
	AlertHighThreshold     int       `json:"alert_high_threshold"`
	BurnRateAlertEnabled   bool      `json:"burn_rate_alert_enabled"`
	MetricsRetentionDays   int       `json:"metrics_retention_days"`
	UpdatedAt              time.Time `json:"updated_at"`
}

// ObservabilityConfigGet — GET /api/v1/observability/config
func (p *ProPanels) ObservabilityConfigGet(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var cfg obsConfig
	err := p.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO observability_config(tenant_id) VALUES($1)
		 ON CONFLICT(tenant_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id
		 RETURNING alert_critical_threshold, alert_high_threshold,
		           burn_rate_alert_enabled, metrics_retention_days, updated_at`,
		claims.TenantID,
	).Scan(&cfg.AlertCriticalThreshold, &cfg.AlertHighThreshold,
		&cfg.BurnRateAlertEnabled, &cfg.MetricsRetentionDays, &cfg.UpdatedAt)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, cfg)
}

// ObservabilityConfigPut — PUT /api/v1/observability/config
func (p *ProPanels) ObservabilityConfigPut(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		AlertCriticalThreshold int  `json:"alert_critical_threshold"`
		AlertHighThreshold     int  `json:"alert_high_threshold"`
		BurnRateAlertEnabled   bool `json:"burn_rate_alert_enabled"`
		MetricsRetentionDays   int  `json:"metrics_retention_days"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.AlertCriticalThreshold < 0 || req.AlertCriticalThreshold > 10000 {
		jsonError(w, "alert_critical_threshold must be 0..10000", http.StatusBadRequest)
		return
	}
	if req.AlertHighThreshold < 0 || req.AlertHighThreshold > 10000 {
		jsonError(w, "alert_high_threshold must be 0..10000", http.StatusBadRequest)
		return
	}
	if req.MetricsRetentionDays < 1 || req.MetricsRetentionDays > 365 {
		jsonError(w, "metrics_retention_days must be 1..365", http.StatusBadRequest)
		return
	}

	_, err := p.DB.Pool().Exec(r.Context(),
		`INSERT INTO observability_config(tenant_id, alert_critical_threshold,
		                                   alert_high_threshold, burn_rate_alert_enabled,
		                                   metrics_retention_days, updated_at)
		 VALUES($1,$2,$3,$4,$5,NOW())
		 ON CONFLICT(tenant_id) DO UPDATE SET
		   alert_critical_threshold = EXCLUDED.alert_critical_threshold,
		   alert_high_threshold     = EXCLUDED.alert_high_threshold,
		   burn_rate_alert_enabled  = EXCLUDED.burn_rate_alert_enabled,
		   metrics_retention_days   = EXCLUDED.metrics_retention_days,
		   updated_at               = NOW()`,
		claims.TenantID, req.AlertCriticalThreshold, req.AlertHighThreshold,
		req.BurnRateAlertEnabled, req.MetricsRetentionDays)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"ok": true})
}

// ── Notifications ────────────────────────────────────────────────────────────

type notificationCfg struct {
	SlackWebhook           string    `json:"slack_webhook"`
	TeamsWebhook           string    `json:"teams_webhook"`
	GenericWebhook         string    `json:"generic_webhook"`
	EmailRecipients        []string  `json:"email_recipients"`
	PagerdutyKey           string    `json:"pagerduty_key"`
	AlertOnCriticalFinding bool      `json:"alert_on_critical_finding"`
	AlertOnSecretRotated   bool      `json:"alert_on_secret_rotated"`
	AlertOnPRBlocked       bool      `json:"alert_on_pr_blocked"`
	AlertOnImageAdmission  bool      `json:"alert_on_image_admission"`
	AlertOnSupplyChainFail bool      `json:"alert_on_supply_chain_fail"`
	AlertOnSSOLoginFailure bool      `json:"alert_on_sso_login_failure"`
	RateLimitPerHour       int       `json:"rate_limit_per_hour"`
	UpdatedAt              time.Time `json:"updated_at"`
}

func (p *ProPanels) NotificationConfigGet(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var c notificationCfg
	var emailCSV string
	err := p.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO notification_config(tenant_id) VALUES($1)
		 ON CONFLICT(tenant_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id
		 RETURNING slack_webhook, teams_webhook, generic_webhook, email_recipients,
		           pagerduty_key, alert_on_critical_finding, alert_on_secret_rotated,
		           alert_on_pr_blocked, alert_on_image_admission, alert_on_supply_chain_fail,
		           alert_on_sso_login_failure, rate_limit_per_hour, updated_at`,
		claims.TenantID,
	).Scan(&c.SlackWebhook, &c.TeamsWebhook, &c.GenericWebhook, &emailCSV,
		&c.PagerdutyKey, &c.AlertOnCriticalFinding, &c.AlertOnSecretRotated,
		&c.AlertOnPRBlocked, &c.AlertOnImageAdmission, &c.AlertOnSupplyChainFail,
		&c.AlertOnSSOLoginFailure, &c.RateLimitPerHour, &c.UpdatedAt)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	c.EmailRecipients = splitCSV(emailCSV)
	jsonOK(w, c)
}

func (p *ProPanels) NotificationConfigPut(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		SlackWebhook           string   `json:"slack_webhook"`
		TeamsWebhook           string   `json:"teams_webhook"`
		GenericWebhook         string   `json:"generic_webhook"`
		EmailRecipients        []string `json:"email_recipients"`
		PagerdutyKey           string   `json:"pagerduty_key"`
		AlertOnCriticalFinding bool     `json:"alert_on_critical_finding"`
		AlertOnSecretRotated   bool     `json:"alert_on_secret_rotated"`
		AlertOnPRBlocked       bool     `json:"alert_on_pr_blocked"`
		AlertOnImageAdmission  bool     `json:"alert_on_image_admission"`
		AlertOnSupplyChainFail bool     `json:"alert_on_supply_chain_fail"`
		AlertOnSSOLoginFailure bool     `json:"alert_on_sso_login_failure"`
		RateLimitPerHour       int      `json:"rate_limit_per_hour"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	// URL sanity (very loose — full HTTPS check would block local-dev webhooks)
	for _, u := range []string{req.SlackWebhook, req.TeamsWebhook, req.GenericWebhook} {
		u = strings.TrimSpace(u)
		if u != "" && !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
			jsonError(w, "webhook URL must start with http(s)://", http.StatusBadRequest)
			return
		}
		if len(u) > 2000 {
			jsonError(w, "webhook URL too long", http.StatusBadRequest)
			return
		}
	}
	if req.RateLimitPerHour < 1 || req.RateLimitPerHour > 10000 {
		jsonError(w, "rate_limit_per_hour must be 1..10000", http.StatusBadRequest)
		return
	}
	emailCSV := strings.ToLower(strings.Join(req.EmailRecipients, ","))
	if len(emailCSV) > 4000 {
		jsonError(w, "email_recipients too long", http.StatusBadRequest)
		return
	}
	_, err := p.DB.Pool().Exec(r.Context(),
		`INSERT INTO notification_config(tenant_id, slack_webhook, teams_webhook,
		   generic_webhook, email_recipients, pagerduty_key,
		   alert_on_critical_finding, alert_on_secret_rotated, alert_on_pr_blocked,
		   alert_on_image_admission, alert_on_supply_chain_fail, alert_on_sso_login_failure,
		   rate_limit_per_hour, updated_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW())
		 ON CONFLICT(tenant_id) DO UPDATE SET
		   slack_webhook              = EXCLUDED.slack_webhook,
		   teams_webhook              = EXCLUDED.teams_webhook,
		   generic_webhook            = EXCLUDED.generic_webhook,
		   email_recipients           = EXCLUDED.email_recipients,
		   pagerduty_key              = EXCLUDED.pagerduty_key,
		   alert_on_critical_finding  = EXCLUDED.alert_on_critical_finding,
		   alert_on_secret_rotated    = EXCLUDED.alert_on_secret_rotated,
		   alert_on_pr_blocked        = EXCLUDED.alert_on_pr_blocked,
		   alert_on_image_admission   = EXCLUDED.alert_on_image_admission,
		   alert_on_supply_chain_fail = EXCLUDED.alert_on_supply_chain_fail,
		   alert_on_sso_login_failure = EXCLUDED.alert_on_sso_login_failure,
		   rate_limit_per_hour        = EXCLUDED.rate_limit_per_hour,
		   updated_at                 = NOW()`,
		claims.TenantID, req.SlackWebhook, req.TeamsWebhook, req.GenericWebhook,
		emailCSV, req.PagerdutyKey,
		req.AlertOnCriticalFinding, req.AlertOnSecretRotated, req.AlertOnPRBlocked,
		req.AlertOnImageAdmission, req.AlertOnSupplyChainFail, req.AlertOnSSOLoginFailure,
		req.RateLimitPerHour)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	logAudit(r, p.DB, "NOTIFICATION_CONFIG_UPDATE", "notification_config")
	jsonOK(w, map[string]any{"ok": true})
}

// NotificationTest — POST /api/v1/notifications/test
// Body: {"channel":"slack|teams|generic|email|pagerduty"}
// Sends a synthetic event to the specified channel and logs the result.
// We don't actually open outbound HTTP here (the gateway has no allowlist
// for arbitrary URLs); instead we record the test attempt with a 202 status
// so the frontend gets a real audit row to show.
func (p *ProPanels) NotificationTest(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Channel string `json:"channel"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	ch := strings.ToLower(strings.TrimSpace(req.Channel))
	switch ch {
	case "slack", "teams", "generic", "email", "pagerduty":
	default:
		jsonError(w, "channel must be one of slack/teams/generic/email/pagerduty", http.StatusBadRequest)
		return
	}
	_, err := p.DB.Pool().Exec(r.Context(),
		`INSERT INTO notification_log(tenant_id, channel, event_type, payload, status_code)
		 VALUES($1, $2, 'test', $3, 202)`,
		claims.TenantID, ch,
		`{"text":"VSP test alert from `+ch+`","tenant":"`+claims.TenantID+`"}`)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{
		"ok":      true,
		"channel": ch,
		"note":    "Test event recorded in notification_log. Real outbound delivery requires a worker to drain the log.",
	})
}

// NotificationLog — GET /api/v1/notifications/log?limit=N
func (p *ProPanels) NotificationLog(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	limit := queryInt(r, "limit", 100)
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	rows, err := p.DB.Pool().Query(r.Context(),
		`SELECT id, channel, event_type, status_code, error, sent_at
		   FROM notification_log
		  WHERE tenant_id=$1
		  ORDER BY sent_at DESC
		  LIMIT $2`,
		claims.TenantID, limit)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type entry struct {
		ID         int64     `json:"id"`
		Channel    string    `json:"channel"`
		EventType  string    `json:"event_type"`
		StatusCode int       `json:"status_code"`
		Error      string    `json:"error,omitempty"`
		SentAt     time.Time `json:"sent_at"`
	}
	var out []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.ID, &e.Channel, &e.EventType, &e.StatusCode, &e.Error, &e.SentAt); err != nil {
			continue
		}
		out = append(out, e)
	}
	if out == nil {
		out = []entry{}
	}
	jsonOK(w, map[string]any{"entries": out, "total": len(out)}) // page-size-not-total: TODO 2026-05-12 audit — wire CountX helper
}

// NotificationDLQ — GET /api/v1/notifications/dlq
//
// Lists notifications that exhausted retry attempts (status_code = -1) so ops
// can review what failed and why before manually retrying.
func (p *ProPanels) NotificationDLQ(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), p.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	rows, err := p.DB.Pool().Query(r.Context(),
		`SELECT id, channel, event_type, payload, attempts, max_attempts, error, sent_at, last_attempt_at
		   FROM notification_log
		  WHERE tenant_id=$1 AND status_code = -1
		  ORDER BY last_attempt_at DESC NULLS LAST, sent_at DESC
		  LIMIT 500`,
		tenantID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type dlqEntry struct {
		ID            int64      `json:"id"`
		Channel       string     `json:"channel"`
		EventType     string     `json:"event_type"`
		Payload       string     `json:"payload"`
		Attempts      int        `json:"attempts"`
		MaxAttempts   int        `json:"max_attempts"`
		Error         string     `json:"error"`
		SentAt        time.Time  `json:"sent_at"`
		LastAttemptAt *time.Time `json:"last_attempt_at,omitempty"`
	}
	var out []dlqEntry
	for rows.Next() {
		var e dlqEntry
		if err := rows.Scan(&e.ID, &e.Channel, &e.EventType, &e.Payload,
			&e.Attempts, &e.MaxAttempts, &e.Error, &e.SentAt, &e.LastAttemptAt); err != nil {
			continue
		}
		out = append(out, e)
	}
	if out == nil {
		out = []dlqEntry{}
	}
	jsonOK(w, map[string]any{"entries": out, "total": len(out)}) // page-size-not-total: TODO 2026-05-12 audit — wire CountX helper
}

// NotificationDLQRetry — POST /api/v1/notifications/dlq/retry
//
// Body: {"ids": [1, 2, 3]}  (optional — if omitted, retries ALL DLQ entries)
//
// Resets status_code, error, attempts, next_retry_at on the matching DLQ rows
// so the fanout worker picks them up again on next tick. Audit-logged.
func (p *ProPanels) NotificationDLQRetry(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tenantID := resolveTenantUUID(r.Context(), p.DB, claims.TenantID)
	if tenantID == "" {
		jsonError(w, "tenant not found", http.StatusForbidden)
		return
	}
	var req struct {
		IDs []int64 `json:"ids"`
	}
	_ = decodeJSON(w, r, &req)

	var (
		affected int64
		err      error
	)
	if len(req.IDs) == 0 {
		tag, e := p.DB.Pool().Exec(r.Context(),
			`UPDATE notification_log
			    SET status_code = 0, error = '', attempts = 0, next_retry_at = NULL
			  WHERE tenant_id = $1 AND status_code = -1`,
			tenantID)
		err = e
		if err == nil {
			affected = tag.RowsAffected()
		}
	} else {
		tag, e := p.DB.Pool().Exec(r.Context(),
			`UPDATE notification_log
			    SET status_code = 0, error = '', attempts = 0, next_retry_at = NULL
			  WHERE tenant_id = $1 AND status_code = -1 AND id = ANY($2::bigint[])`,
			tenantID, req.IDs)
		err = e
		if err == nil {
			affected = tag.RowsAffected()
		}
	}
	if err != nil {
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	logAudit(r, p.DB, "NOTIFICATION_DLQ_RETRY",
		"notifications:dlq:requeued="+itoa(int(affected)))
	jsonOK(w, map[string]any{"requeued": affected})
}

// (splitCSV is shared via cspm.go in this same package.)

// ── CWPP / Container security panel config ───────────────────────────────────

type cwppCfg struct {
	AlertCriticalThreshold int       `json:"alert_critical_threshold"`
	BlockAdmissionOnCrit   bool      `json:"block_admission_on_crit"`
	MaxScanAgeHours        int       `json:"max_scan_age_hours"`
	ScanOnPush             bool      `json:"scan_on_push"`
	RegistryAllowlist      string    `json:"registry_allowlist"`
	UpdatedAt              time.Time `json:"updated_at"`
}

// CWPPConfigGet — GET /api/v1/cwpp/config
func (p *ProPanels) CWPPConfigGet(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var c cwppCfg
	err := p.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO cwpp_config(tenant_id) VALUES($1)
		 ON CONFLICT(tenant_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id
		 RETURNING alert_critical_threshold, block_admission_on_crit,
		           max_scan_age_hours, scan_on_push, registry_allowlist, updated_at`,
		claims.TenantID).Scan(&c.AlertCriticalThreshold, &c.BlockAdmissionOnCrit,
		&c.MaxScanAgeHours, &c.ScanOnPush, &c.RegistryAllowlist, &c.UpdatedAt)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, c)
}

// CWPPConfigPut — PUT /api/v1/cwpp/config
func (p *ProPanels) CWPPConfigPut(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		AlertCriticalThreshold int    `json:"alert_critical_threshold"`
		BlockAdmissionOnCrit   bool   `json:"block_admission_on_crit"`
		MaxScanAgeHours        int    `json:"max_scan_age_hours"`
		ScanOnPush             bool   `json:"scan_on_push"`
		RegistryAllowlist      string `json:"registry_allowlist"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.AlertCriticalThreshold < 0 || req.AlertCriticalThreshold > 1000 {
		jsonError(w, "alert_critical_threshold must be 0..1000", http.StatusBadRequest)
		return
	}
	if req.MaxScanAgeHours < 1 || req.MaxScanAgeHours > 720 {
		jsonError(w, "max_scan_age_hours must be 1..720", http.StatusBadRequest)
		return
	}
	allow := strings.TrimSpace(req.RegistryAllowlist)
	if len(allow) > 4000 {
		jsonError(w, "registry_allowlist too long (max 4000 chars)", http.StatusBadRequest)
		return
	}
	_, err := p.DB.Pool().Exec(r.Context(),
		`INSERT INTO cwpp_config(tenant_id, alert_critical_threshold,
		                          block_admission_on_crit, max_scan_age_hours,
		                          scan_on_push, registry_allowlist, updated_at)
		 VALUES($1,$2,$3,$4,$5,$6,NOW())
		 ON CONFLICT(tenant_id) DO UPDATE SET
		   alert_critical_threshold = EXCLUDED.alert_critical_threshold,
		   block_admission_on_crit  = EXCLUDED.block_admission_on_crit,
		   max_scan_age_hours       = EXCLUDED.max_scan_age_hours,
		   scan_on_push             = EXCLUDED.scan_on_push,
		   registry_allowlist       = EXCLUDED.registry_allowlist,
		   updated_at               = NOW()`,
		claims.TenantID, req.AlertCriticalThreshold, req.BlockAdmissionOnCrit,
		req.MaxScanAgeHours, req.ScanOnPush, allow)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"ok": true})
}

// ── Autofix / PR-bot panel config ────────────────────────────────────────────

type autofixCfg struct {
	AutoPREnabled bool      `json:"auto_pr_enabled"`
	SLAHours      int       `json:"sla_hours"`
	DraftPROnly   bool      `json:"draft_pr_only"`
	RequireReview bool      `json:"require_review"`
	MaxOpenPRs    int       `json:"max_open_prs"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// AutofixConfigGet — GET /api/v1/autofix/config
func (p *ProPanels) AutofixConfigGet(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var c autofixCfg
	err := p.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO autofix_config(tenant_id) VALUES($1)
		 ON CONFLICT(tenant_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id
		 RETURNING auto_pr_enabled, sla_hours, draft_pr_only, require_review,
		           max_open_prs, updated_at`,
		claims.TenantID).Scan(&c.AutoPREnabled, &c.SLAHours, &c.DraftPROnly,
		&c.RequireReview, &c.MaxOpenPRs, &c.UpdatedAt)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, c)
}

// AutofixConfigPut — PUT /api/v1/autofix/config
func (p *ProPanels) AutofixConfigPut(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		AutoPREnabled bool `json:"auto_pr_enabled"`
		SLAHours      int  `json:"sla_hours"`
		DraftPROnly   bool `json:"draft_pr_only"`
		RequireReview bool `json:"require_review"`
		MaxOpenPRs    int  `json:"max_open_prs"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.SLAHours < 1 || req.SLAHours > 720 {
		jsonError(w, "sla_hours must be 1..720", http.StatusBadRequest)
		return
	}
	if req.MaxOpenPRs < 1 || req.MaxOpenPRs > 500 {
		jsonError(w, "max_open_prs must be 1..500", http.StatusBadRequest)
		return
	}
	_, err := p.DB.Pool().Exec(r.Context(),
		`INSERT INTO autofix_config(tenant_id, auto_pr_enabled, sla_hours,
		                             draft_pr_only, require_review, max_open_prs, updated_at)
		 VALUES($1,$2,$3,$4,$5,$6,NOW())
		 ON CONFLICT(tenant_id) DO UPDATE SET
		   auto_pr_enabled = EXCLUDED.auto_pr_enabled,
		   sla_hours       = EXCLUDED.sla_hours,
		   draft_pr_only   = EXCLUDED.draft_pr_only,
		   require_review  = EXCLUDED.require_review,
		   max_open_prs    = EXCLUDED.max_open_prs,
		   updated_at      = NOW()`,
		claims.TenantID, req.AutoPREnabled, req.SLAHours, req.DraftPROnly,
		req.RequireReview, req.MaxOpenPRs)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"ok": true})
}

// ── Supply chain panel config ────────────────────────────────────────────────

type supplyChainCfg struct {
	VerifyRequired         bool      `json:"verify_required"`
	SLSAMinLevel           int       `json:"slsa_min_level"`
	AllowUnsigned          bool      `json:"allow_unsigned"`
	BlockAdmissionBelowMin bool      `json:"block_admission_below_min"`
	SigstoreRoot           string    `json:"sigstore_root"`
	UpdatedAt              time.Time `json:"updated_at"`
}

// SupplyChainConfigGet — GET /api/v1/supply-chain/config
func (p *ProPanels) SupplyChainConfigGet(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var c supplyChainCfg
	err := p.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO supply_chain_config(tenant_id) VALUES($1)
		 ON CONFLICT(tenant_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id
		 RETURNING verify_required, slsa_min_level, allow_unsigned,
		           block_admission_below_min, sigstore_root, updated_at`,
		claims.TenantID).Scan(&c.VerifyRequired, &c.SLSAMinLevel, &c.AllowUnsigned,
		&c.BlockAdmissionBelowMin, &c.SigstoreRoot, &c.UpdatedAt)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, c)
}

// SupplyChainConfigPut — PUT /api/v1/supply-chain/config
func (p *ProPanels) SupplyChainConfigPut(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		VerifyRequired         bool   `json:"verify_required"`
		SLSAMinLevel           int    `json:"slsa_min_level"`
		AllowUnsigned          bool   `json:"allow_unsigned"`
		BlockAdmissionBelowMin bool   `json:"block_admission_below_min"`
		SigstoreRoot           string `json:"sigstore_root"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.SLSAMinLevel < 1 || req.SLSAMinLevel > 4 {
		jsonError(w, "slsa_min_level must be 1..4", http.StatusBadRequest)
		return
	}
	root := strings.TrimSpace(req.SigstoreRoot)
	if root == "" {
		root = "public-good"
	}
	if len(root) > 200 {
		jsonError(w, "sigstore_root too long", http.StatusBadRequest)
		return
	}
	_, err := p.DB.Pool().Exec(r.Context(),
		`INSERT INTO supply_chain_config(tenant_id, verify_required, slsa_min_level,
		                                  allow_unsigned, block_admission_below_min,
		                                  sigstore_root, updated_at)
		 VALUES($1,$2,$3,$4,$5,$6,NOW())
		 ON CONFLICT(tenant_id) DO UPDATE SET
		   verify_required           = EXCLUDED.verify_required,
		   slsa_min_level            = EXCLUDED.slsa_min_level,
		   allow_unsigned            = EXCLUDED.allow_unsigned,
		   block_admission_below_min = EXCLUDED.block_admission_below_min,
		   sigstore_root             = EXCLUDED.sigstore_root,
		   updated_at                = NOW()`,
		claims.TenantID, req.VerifyRequired, req.SLSAMinLevel,
		req.AllowUnsigned, req.BlockAdmissionBelowMin, root)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"ok": true})
}

// ── SBOM diff panel config ───────────────────────────────────────────────────

type sbomCfg struct {
	DiffAlertSeverity  string    `json:"diff_alert_severity"`
	AlertOnNewCritical bool      `json:"alert_on_new_critical"`
	SBOMFormat         string    `json:"sbom_format"`
	AutoGenerate       bool      `json:"auto_generate"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// SBOMConfigGet — GET /api/v1/sbom/config
func (p *ProPanels) SBOMConfigGet(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var c sbomCfg
	err := p.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO sbom_config(tenant_id) VALUES($1)
		 ON CONFLICT(tenant_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id
		 RETURNING diff_alert_severity, alert_on_new_critical, sbom_format,
		           auto_generate, updated_at`,
		claims.TenantID).Scan(&c.DiffAlertSeverity, &c.AlertOnNewCritical,
		&c.SBOMFormat, &c.AutoGenerate, &c.UpdatedAt)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, c)
}

// SBOMConfigPut — PUT /api/v1/sbom/config
func (p *ProPanels) SBOMConfigPut(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		DiffAlertSeverity  string `json:"diff_alert_severity"`
		AlertOnNewCritical bool   `json:"alert_on_new_critical"`
		SBOMFormat         string `json:"sbom_format"`
		AutoGenerate       bool   `json:"auto_generate"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	sev := strings.ToLower(strings.TrimSpace(req.DiffAlertSeverity))
	switch sev {
	case "critical", "high", "medium", "low":
	default:
		jsonError(w, "diff_alert_severity must be critical|high|medium|low", http.StatusBadRequest)
		return
	}
	fmtV := strings.ToLower(strings.TrimSpace(req.SBOMFormat))
	switch fmtV {
	case "cyclonedx", "spdx", "syft":
	default:
		jsonError(w, "sbom_format must be cyclonedx|spdx|syft", http.StatusBadRequest)
		return
	}
	_, err := p.DB.Pool().Exec(r.Context(),
		`INSERT INTO sbom_config(tenant_id, diff_alert_severity, alert_on_new_critical,
		                          sbom_format, auto_generate, updated_at)
		 VALUES($1,$2,$3,$4,$5,NOW())
		 ON CONFLICT(tenant_id) DO UPDATE SET
		   diff_alert_severity   = EXCLUDED.diff_alert_severity,
		   alert_on_new_critical = EXCLUDED.alert_on_new_critical,
		   sbom_format           = EXCLUDED.sbom_format,
		   auto_generate         = EXCLUDED.auto_generate,
		   updated_at            = NOW()`,
		claims.TenantID, sev, req.AlertOnNewCritical, fmtV, req.AutoGenerate)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"ok": true})
}

// ── SSO panel config ─────────────────────────────────────────────────────────

type ssoCfg struct {
	DefaultRole     string    `json:"default_role"`
	SCIMEnabled     bool      `json:"scim_enabled"`
	JITProvisioning bool      `json:"jit_provisioning"`
	RequireMFA      bool      `json:"require_mfa"`
	SessionMaxHours int       `json:"session_max_hours"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// SSOConfigGet — GET /api/v1/sso/config
func (p *ProPanels) SSOConfigGet(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var c ssoCfg
	err := p.DB.Pool().QueryRow(r.Context(),
		`INSERT INTO sso_config(tenant_id) VALUES($1)
		 ON CONFLICT(tenant_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id
		 RETURNING default_role, scim_enabled, jit_provisioning, require_mfa,
		           session_max_hours, updated_at`,
		claims.TenantID).Scan(&c.DefaultRole, &c.SCIMEnabled, &c.JITProvisioning,
		&c.RequireMFA, &c.SessionMaxHours, &c.UpdatedAt)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, c)
}

// SSOConfigPut — PUT /api/v1/sso/config
func (p *ProPanels) SSOConfigPut(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.FromContext(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		DefaultRole     string `json:"default_role"`
		SCIMEnabled     bool   `json:"scim_enabled"`
		JITProvisioning bool   `json:"jit_provisioning"`
		RequireMFA      bool   `json:"require_mfa"`
		SessionMaxHours int    `json:"session_max_hours"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	role := strings.ToLower(strings.TrimSpace(req.DefaultRole))
	switch role {
	case "admin", "analyst", "dev", "auditor":
	default:
		jsonError(w, "default_role must be admin|analyst|dev|auditor", http.StatusBadRequest)
		return
	}
	if req.SessionMaxHours < 1 || req.SessionMaxHours > 168 {
		jsonError(w, "session_max_hours must be 1..168", http.StatusBadRequest)
		return
	}
	_, err := p.DB.Pool().Exec(r.Context(),
		`INSERT INTO sso_config(tenant_id, default_role, scim_enabled,
		                         jit_provisioning, require_mfa, session_max_hours, updated_at)
		 VALUES($1,$2,$3,$4,$5,$6,NOW())
		 ON CONFLICT(tenant_id) DO UPDATE SET
		   default_role      = EXCLUDED.default_role,
		   scim_enabled      = EXCLUDED.scim_enabled,
		   jit_provisioning  = EXCLUDED.jit_provisioning,
		   require_mfa       = EXCLUDED.require_mfa,
		   session_max_hours = EXCLUDED.session_max_hours,
		   updated_at        = NOW()`,
		claims.TenantID, role, req.SCIMEnabled, req.JITProvisioning,
		req.RequireMFA, req.SessionMaxHours)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"ok": true})
}

package store

import (
	"context"
	"encoding/json"
	"strconv"
	"time"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
)

// ── Types ─────────────────────────────────────────────────────

type CorrelationRule struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Name      string    `json:"name"`
	Sources   []string  `json:"sources"`
	WindowMin int       `json:"window_min"`
	Severity  string    `json:"severity"`
	Condition string    `json:"cond"`
	Enabled   bool      `json:"enabled"`
	Hits      int       `json:"hits"`
	CreatedAt time.Time `json:"created_at"`
}

type Incident struct {
	ID         string          `json:"id"`
	TenantID   string          `json:"tenant_id"`
	RuleID     *string         `json:"rule_id,omitempty"`
	RuleName   string          `json:"rule_name,omitempty"`
	Title      string          `json:"title"`
	Severity   string          `json:"severity"`
	Status     string          `json:"status"`
	SourceRefs json.RawMessage `json:"source_refs"`
	CreatedAt  time.Time       `json:"created_at"`
}

type Playbook struct {
	ID           string          `json:"id"`
	TenantID     string          `json:"tenant_id"`
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Trigger      string          `json:"trigger"`
	SevFilter    string          `json:"sev"`
	Steps        json.RawMessage `json:"steps"`
	Enabled      bool            `json:"enabled"`
	RunCount     int             `json:"runs"`
	SuccessCount int             `json:"success"`
	CreatedAt    time.Time       `json:"created_at"`
}

type PlaybookRun struct {
	ID          string     `json:"id"`
	PlaybookID  string     `json:"playbook_id"`
	PlaybookName string    `json:"pb"`
	TenantID    string     `json:"tenant_id"`
	Status      string     `json:"status"`
	Trigger     string     `json:"trigger"`
	StartedAt   time.Time  `json:"ts"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
}

type LogSource struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"tenant_id"`
	Name      string     `json:"name"`
	Host      string     `json:"host"`
	Protocol  string     `json:"proto"`
	Port      int        `json:"port"`
	Format    string     `json:"format"`
	Tags      []string   `json:"tags"`
	Enabled   bool       `json:"enabled"`
	EPS       int        `json:"eps"`
	ParseRate float64    `json:"parse_rate"`
	Status    string     `json:"status"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

type IOC struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Value       string    `json:"val"`
	Severity    string    `json:"sev"`
	Feed        string    `json:"feed"`
	Description string    `json:"desc"`
	Matched     bool      `json:"matched"`
	CreatedAt   time.Time `json:"created_at"`
}

// ── Correlation rules ─────────────────────────────────────────

func (db *DB) ListCorrelationRules(ctx context.Context, tenantID string) ([]CorrelationRule, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT id, name, sources, window_min, severity,
		       condition_expr, enabled, hits, created_at
		FROM   correlation_rules
		WHERE  tenant_id = $1
		ORDER  BY created_at DESC LIMIT 500`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CorrelationRule
	for rows.Next() {
		var r CorrelationRule
		r.TenantID = tenantID
		if err := rows.Scan(&r.ID, &r.Name, &r.Sources, &r.WindowMin,
			&r.Severity, &r.Condition, &r.Enabled, &r.Hits, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan correlation rule: %w", err)
		}
		out = append(out, r)
	}
	return out, nil
}

func (db *DB) CreateCorrelationRule(ctx context.Context, r CorrelationRule) (string, error) {
	var id string
	err := db.pool.QueryRow(ctx, `
		INSERT INTO correlation_rules
			(tenant_id, name, sources, window_min, severity, condition_expr, enabled)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		r.TenantID, r.Name, r.Sources, r.WindowMin,
		r.Severity, r.Condition, r.Enabled,
	).Scan(&id)
	return id, err
}

func (db *DB) ToggleCorrelationRule(ctx context.Context, tenantID, id string) (bool, error) {
	var enabled bool
	err := db.pool.QueryRow(ctx, `
		UPDATE correlation_rules SET enabled = NOT enabled
		WHERE id=$1 AND tenant_id=$2 RETURNING enabled`, id, tenantID).Scan(&enabled)
	return enabled, err
}

func (db *DB) DeleteCorrelationRule(ctx context.Context, tenantID, id string) error {
	_, err := db.pool.Exec(ctx,
		`DELETE FROM correlation_rules WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
}

// ── Incidents ─────────────────────────────────────────────────

func (db *DB) ListIncidents(ctx context.Context, tenantID, status, sev string, limit int) ([]Incident, error) {
	q := `SELECT i.id, i.title, i.severity, i.status,
	             COALESCE(i.source_refs,'{}'), i.created_at,
	             COALESCE(r.name,'') as rule_name
	      FROM   incidents i
	      LEFT   JOIN correlation_rules r ON r.id = i.rule_id
	      WHERE  i.tenant_id = $1`
	args := []any{tenantID}
	if status != "" { args = append(args, status); q += " AND i.status=$" + itoa(len(args)) }
	if sev != ""    { args = append(args, sev);    q += " AND i.severity=$" + itoa(len(args)) }
	args = append(args, limit)
	q += " ORDER BY i.created_at DESC LIMIT $" + itoa(len(args))

	rows, err := db.pool.Query(ctx, q, args...)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []Incident
	for rows.Next() {
		var inc Incident
		inc.TenantID = tenantID
		if err := rows.Scan(&inc.ID, &inc.Title, &inc.Severity, &inc.Status,
			&inc.SourceRefs, &inc.CreatedAt, &inc.RuleName); err != nil {
			return nil, fmt.Errorf("scan incident: %w", err)
		}
		out = append(out, inc)
	}
	return out, nil
}

func (db *DB) CreateIncident(ctx context.Context, inc Incident) (string, error) {
	var id string
	err := db.pool.QueryRow(ctx, `
		INSERT INTO incidents (tenant_id, title, severity, status, rule_id, source_refs)
		VALUES ($1,$2,$3,'open',$4,$5) RETURNING id`,
		inc.TenantID, inc.Title, inc.Severity, nullStr(inc.RuleID), inc.SourceRefs,
	).Scan(&id)
	return id, err
}


func (db *DB) UpdateIncidentStatus(ctx context.Context, tenantID, id, status string) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE incidents SET status=$1, updated_at=NOW() WHERE id=$2 AND tenant_id=$3`,
		status, id, tenantID)
	return err
}

func (db *DB) GetIncident(ctx context.Context, tenantID, id string) (*Incident, error) {
	var inc Incident
	inc.TenantID = tenantID
	err := db.pool.QueryRow(ctx, `
		SELECT i.id, i.title, i.severity, i.status,
		       COALESCE(i.source_refs,'{}'), i.created_at,
		       COALESCE(r.name,'') as rule_name
		FROM   incidents i
		LEFT   JOIN correlation_rules r ON r.id = i.rule_id
		WHERE  i.id=$1 AND i.tenant_id=$2`, id, tenantID,
	).Scan(&inc.ID, &inc.Title, &inc.Severity, &inc.Status,
		&inc.SourceRefs, &inc.CreatedAt, &inc.RuleName)
	if err != nil { return nil, err }
	return &inc, nil
}

// ── Playbooks ─────────────────────────────────────────────────

func (db *DB) ListPlaybooks(ctx context.Context, tenantID string) ([]Playbook, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT id, name, description, trigger_event, sev_filter,
		       steps, enabled, run_count, success_count, created_at
		FROM   playbooks WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 200`, tenantID)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []Playbook
	for rows.Next() {
		var p Playbook
		p.TenantID = tenantID
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Trigger,
			&p.SevFilter, &p.Steps, &p.Enabled, &p.RunCount,
			&p.SuccessCount, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan playbook: %w", err)
		}
		out = append(out, p)
	}
	return out, nil
}

func (db *DB) CreatePlaybook(ctx context.Context, p Playbook) (string, error) {
	var id string
	err := db.pool.QueryRow(ctx, `
		INSERT INTO playbooks
			(tenant_id, name, description, trigger_event, sev_filter, steps, enabled)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		p.TenantID, p.Name, p.Description, p.Trigger,
		p.SevFilter, p.Steps, p.Enabled,
	).Scan(&id)
	return id, err
}

func (db *DB) TogglePlaybook(ctx context.Context, tenantID, id string) (bool, error) {
	var enabled bool
	err := db.pool.QueryRow(ctx, `
		UPDATE playbooks SET enabled = NOT enabled
		WHERE id=$1 AND tenant_id=$2 RETURNING enabled`, id, tenantID).Scan(&enabled)
	return enabled, err
}

func (db *DB) CreatePlaybookRun(ctx context.Context, playbookID, tenantID, trigger string, ctx2 json.RawMessage) (string, error) {
	var id string
	err := db.pool.QueryRow(ctx, `
		INSERT INTO playbook_runs (playbook_id, tenant_id, status, trigger_event, context)
		VALUES ($1,$2,'running',$3,$4) RETURNING id`,
		playbookID, tenantID, trigger, ctx2,
	).Scan(&id)
	if err == nil {
		db.pool.Exec(ctx, //nolint:errcheck
			`UPDATE playbooks SET run_count=run_count+1 WHERE id=$1`, playbookID)
	}
	return id, err
}

func (db *DB) CompletePlaybookRun(ctx context.Context, runID string, success bool) {
	status := "success"
	if !success { status = "failed" }
	db.pool.Exec(ctx, //nolint:errcheck
		`UPDATE playbook_runs SET status=$1, finished_at=NOW(),
		        duration_s=EXTRACT(EPOCH FROM NOW()-started_at)::int
		 WHERE id=$2`, status, runID)
	if success {
		db.pool.Exec(ctx, //nolint:errcheck
			`UPDATE playbooks SET success_count=success_count+1
			 WHERE id=(SELECT playbook_id FROM playbook_runs WHERE id=$1)`, runID)
	}
}

func (db *DB) ListPlaybookRuns(ctx context.Context, tenantID string, limit int) ([]PlaybookRun, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT r.id, r.playbook_id, p.name, r.status, r.trigger_event,
		       r.started_at, r.finished_at
		FROM   playbook_runs r JOIN playbooks p ON p.id=r.playbook_id
		WHERE  r.tenant_id=$1 ORDER BY r.started_at DESC LIMIT $2`,
		tenantID, limit)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []PlaybookRun
	for rows.Next() {
		var ru PlaybookRun
		ru.TenantID = tenantID
		if err := rows.Scan(&ru.ID, &ru.PlaybookID, &ru.PlaybookName,
			&ru.Status, &ru.Trigger, &ru.StartedAt, &ru.FinishedAt); err != nil {
			return nil, fmt.Errorf("scan playbook run: %w", err)
		}
		out = append(out, ru)
	}
	return out, nil
}

func (db *DB) FindEnabledPlaybooks(ctx context.Context, tenantID, trigger, sev string) ([]Playbook, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT id, name FROM playbooks
		WHERE  tenant_id=$1 AND enabled=true AND trigger_event=$2
	  AND  (sev_filter='any' OR sev_filter=$3) LIMIT 20`,
		tenantID, trigger, sev)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []Playbook
	for rows.Next() {
		var p Playbook
		if err := rows.Scan(&p.ID, &p.Name); err != nil { log.Warn().Err(err).Caller().Msg("ignored error") }
		out = append(out, p)
	}
	return out, nil
}

// ── Log sources ───────────────────────────────────────────────

func (db *DB) ListLogSources(ctx context.Context, tenantID string) ([]LogSource, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT id, name, host, protocol, port, format,
		       tags, enabled, eps, parse_rate, status, last_seen, created_at
		FROM   log_sources WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 200`, tenantID)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []LogSource
	for rows.Next() {
		var s LogSource
		s.TenantID = tenantID
		if err := rows.Scan(&s.ID, &s.Name, &s.Host, &s.Protocol, &s.Port,
			&s.Format, &s.Tags, &s.Enabled, &s.EPS, &s.ParseRate,
			&s.Status, &s.LastSeen, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan log source: %w", err)
		}
		out = append(out, s)
	}
	return out, nil
}

func (db *DB) CreateLogSource(ctx context.Context, s LogSource) (string, error) {
	if s.Tags == nil { s.Tags = []string{} }
	var id string
	err := db.pool.QueryRow(ctx, `
		INSERT INTO log_sources (tenant_id, name, host, protocol, port, format, tags)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		s.TenantID, s.Name, s.Host, s.Protocol, s.Port, s.Format, s.Tags,
	).Scan(&id)
	return id, err
}

func (db *DB) DeleteLogSource(ctx context.Context, tenantID, id string) error {
	_, err := db.pool.Exec(ctx,
		`DELETE FROM log_sources WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
}

func (db *DB) TestLogSource(ctx context.Context, tenantID, id string) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE log_sources SET status='ok', last_seen=NOW()
		WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
}

func (db *DB) LogSourceStats(ctx context.Context, tenantID string) (total, online, errCount, totalEPS int) {
	db.pool.QueryRow(ctx, `
		SELECT COUNT(*),
		       SUM(CASE WHEN status='ok'  THEN 1 ELSE 0 END),
		       SUM(CASE WHEN status='err' THEN 1 ELSE 0 END),
		       COALESCE(SUM(eps),0)
		FROM   log_sources WHERE tenant_id=$1`, tenantID,
	).Scan(&total, &online, &errCount, &totalEPS) //nolint:errcheck
	return
}

// ── IOCs ──────────────────────────────────────────────────────

func (db *DB) ListIOCs(ctx context.Context, iocType string, limit int) ([]IOC, error) {
	q := `SELECT id, type, value, severity, feed, description, matched, created_at
	      FROM iocs WHERE (expires_at > NOW() OR expires_at IS NULL)`
	args := []any{}
	if iocType != "" { args = append(args, iocType); q += " AND type=$1" }
	args = append(args, limit)
	q += " ORDER BY matched DESC, severity DESC LIMIT $" + itoa(len(args))
	rows, err := db.pool.Query(ctx, q, args...)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []IOC
	for rows.Next() {
		var ioc IOC
		if err := rows.Scan(&ioc.ID, &ioc.Type, &ioc.Value, &ioc.Severity,
			&ioc.Feed, &ioc.Description, &ioc.Matched, &ioc.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan ioc: %w", err)
		}
		out = append(out, ioc)
	}
	return out, nil
}

func (db *DB) IOCFeedCounts(ctx context.Context, feed string) int {
	var cnt int
	db.pool.QueryRow(ctx, `SELECT COUNT(*) FROM iocs WHERE feed=$1`, feed).Scan(&cnt) //nolint:errcheck
	return cnt
}

func (db *DB) SeedIOCsFromFindings(ctx context.Context) {
	db.pool.Exec(ctx, `
		INSERT INTO iocs (type, value, severity, feed, description, matched)
		SELECT 'cve', rule_id, severity, 'NVD', message, true
		FROM   findings
		WHERE  rule_id ILIKE 'CVE-%'
		  AND  rule_id NOT IN (SELECT value FROM iocs WHERE type='cve')
		LIMIT  500
		ON CONFLICT (value) DO NOTHING`)
}

func (db *DB) FindingCWECount(ctx context.Context, cwe string) int {
	var cnt int
	if err := db.pool.QueryRow(ctx, `SELECT COUNT(*) FROM findings WHERE cwe=$1`, cwe).Scan(&cnt); err != nil {
		log.Warn().Err(err).Str("cwe", cwe).Msg("FindingCWECount scan failed")
	}
	return cnt
}


func (db *DB) UpdateCorrelationRule(ctx context.Context, tenantID, id string, sources []string, windowMin int, severity, condExpr string) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE correlation_rules
		SET sources=$1, window_min=$2, severity=$3, condition_expr=$4, updated_at=NOW()
		WHERE id=$5 AND tenant_id=$6`,
		sources, windowMin, severity, condExpr, id, tenantID)
	return err
}

func (db *DB) SeedDefaultCorrelationRules(ctx context.Context, tenantID string) error {
	type rule struct {
		name, severity, condExpr string
		sources []string
		windowMin int
	}
	rules := []rule{
		{"SSH brute force", "HIGH", "count>=5 AND message~Failed password AND process=sshd", []string{"sshd","auth"}, 5},
		{"Critical severity spike", "CRITICAL", "count>=10 AND severity=CRITICAL", []string{"*"}, 10},
		{"Auth failure flood", "HIGH", "count>=20 AND message~authentication failure", []string{"auth","authpriv"}, 15},
		{"Kernel errors", "MEDIUM", "count>=5 AND facility=kern AND severity>=HIGH", []string{"kern"}, 10},
		{"Port scan detection", "HIGH", "count>=50 AND message~Connection refused", []string{"*"}, 5},
		{"Sudo abuse", "HIGH", "count>=3 AND message~sudo AND message~COMMAND", []string{"auth","authpriv"}, 30},
		{"Service crash loop", "HIGH", "count>=5 AND message~segfault", []string{"kern","daemon"}, 15},
	}
	for _, r := range rules {
		_, err := db.pool.Exec(ctx, `
			INSERT INTO correlation_rules
				(tenant_id, name, sources, window_min, severity, condition_expr, enabled)
			VALUES ($1,$2,$3,$4,$5,$6,true)
			ON CONFLICT DO NOTHING`,
			tenantID, r.name, r.sources, r.windowMin, r.severity, r.condExpr)
		if err != nil { return err }
	}
	return nil
}

// ── helpers ───────────────────────────────────────────────────

func itoa(n int) string {
	return strconv.Itoa(n)
}

func nullStr(s *string) any {
	if s == nil || *s == "" { return nil }
	return *s
}

// ── SIEM Webhooks (dùng bởi internal/siem/webhook.go) ────────

type SIEMWebhook struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	Label      string     `json:"label"`
	Type       string     `json:"type"`
	URL        string     `json:"url"`
	SecretHash string     `json:"secret_hash,omitempty"`
	MinSev     string     `json:"min_sev"`
	Active     bool       `json:"active"`
	LastFired  *time.Time `json:"last_fired,omitempty"`
	FireCount  int        `json:"fire_count"`
	CreatedAt  time.Time  `json:"created_at"`
}

func (db *DB) ListSIEMWebhooks(ctx context.Context, tenantID string) ([]SIEMWebhook, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT id, tenant_id, label, type, url,
		       COALESCE(secret_hash,''), min_sev, active,
		       last_fired, fire_count, created_at
		FROM   siem_webhooks WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 100`, tenantID)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []SIEMWebhook
	for rows.Next() {
		var h SIEMWebhook
		if err := rows.Scan(&h.ID, &h.TenantID, &h.Label, &h.Type, &h.URL,
			&h.SecretHash, &h.MinSev, &h.Active,
			&h.LastFired, &h.FireCount, &h.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan webhook: %w", err)
		}
		out = append(out, h)
	}
	return out, nil
}

func (db *DB) CreateSIEMWebhook(ctx context.Context, h SIEMWebhook) (SIEMWebhook, error) {
	var out SIEMWebhook
	err := db.pool.QueryRow(ctx, `
		INSERT INTO siem_webhooks (tenant_id, label, type, url, secret_hash, min_sev)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id, tenant_id, label, type, url,
		          COALESCE(secret_hash,''), min_sev, active,
		          last_fired, fire_count, created_at`,
		h.TenantID, h.Label, h.Type, h.URL, h.SecretHash, h.MinSev,
	).Scan(&out.ID, &out.TenantID, &out.Label, &out.Type, &out.URL,
		&out.SecretHash, &out.MinSev, &out.Active,
		&out.LastFired, &out.FireCount, &out.CreatedAt)
	return out, err
}

func (db *DB) DeleteSIEMWebhook(ctx context.Context, tenantID, id string) error {
	_, err := db.pool.Exec(ctx,
		`DELETE FROM siem_webhooks WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
}

func (db *DB) TouchSIEMWebhook(ctx context.Context, id string) error {
	_, err := db.pool.Exec(ctx, `
		UPDATE siem_webhooks
		SET last_fired=NOW(), fire_count=fire_count+1
		WHERE id=$1`, id)
	return err
}

// ── CorrelatorStore helpers ───────────────────────────────────────────────────

func (db *DB) UpdateCorrelationRuleHits(ctx context.Context, id string) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE correlation_rules SET hits = hits + 1, updated_at = NOW() WHERE id = $1`, id)
	return err
}

func (db *DB) CountRecentIncidents(ctx context.Context, ruleID string, windowMin int) (int, error) {
	var count int
	err := db.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM incidents
		WHERE rule_id=$1 AND status='open'
		  AND created_at > NOW() - make_interval(mins => $2)`,
		ruleID, windowMin).Scan(&count)
	return count, err
}

func (db *DB) QueryEventCount(ctx context.Context, q string, args []any) (int, []string, error) {
	var count int
	var hosts []string
	err := db.pool.QueryRow(ctx, q, args...).Scan(&count, &hosts)
	return count, hosts, err
}

func (db *DB) ListAllEnabledRules(ctx context.Context) (pgx.Rows, error) {
	return db.pool.Query(ctx, `
		SELECT id, tenant_id, name, sources, window_min, severity, condition_expr
		FROM   correlation_rules
		WHERE  enabled = true
		ORDER  BY tenant_id, created_at LIMIT 500`)
}

func (db *DB) CountEventsInWindow(ctx context.Context, tenantID string, since time.Time, extraWhere string, args []any) (int, []string, error) {
	q := fmt.Sprintf(`
		SELECT COUNT(*), COALESCE(array_agg(DISTINCT host) FILTER (WHERE host IS NOT NULL), '{}')
		FROM   log_events
		WHERE  tenant_id = $1
		  AND  ts >= $2
		%s`, extraWhere)
	var count int
	var hosts []string
	err := db.pool.QueryRow(ctx, q, args...).Scan(&count, &hosts)
	return count, hosts, err
}

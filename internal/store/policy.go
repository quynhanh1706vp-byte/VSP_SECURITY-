package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type PolicyRule struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	Name          string    `json:"name"`
	RepoPattern   string    `json:"repo_pattern"`
	FailOn        string    `json:"fail_on"`
	MinScore      int       `json:"min_score"`
	MaxHigh       int       `json:"max_high"`
	BlockSecrets  bool      `json:"block_secrets"`
	BlockCritical bool      `json:"block_critical"`
	Active        bool      `json:"active"`
	CreatedAt     time.Time `json:"created_at"`
}

func (db *DB) ListPolicyRules(ctx context.Context, tenantID string) ([]PolicyRule, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT id, tenant_id, name, repo_pattern, fail_on, min_score,
		        max_high, block_secrets, block_critical, active, created_at
		 FROM policy_rules WHERE tenant_id=$1 AND active=true
		 ORDER BY created_at DESC`,
		tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []PolicyRule
	for rows.Next() {
		var r PolicyRule
		rows.Scan(&r.ID, &r.TenantID, &r.Name, &r.RepoPattern, &r.FailOn,
			&r.MinScore, &r.MaxHigh, &r.BlockSecrets, &r.BlockCritical,
			&r.Active, &r.CreatedAt)
		rules = append(rules, r)
	}
	return rules, nil
}

func (db *DB) CreatePolicyRule(ctx context.Context, r PolicyRule) (*PolicyRule, error) {
	row := db.pool.QueryRow(ctx,
		`INSERT INTO policy_rules
		 (tenant_id, name, repo_pattern, fail_on, min_score, max_high, block_secrets, block_critical)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		 RETURNING id, tenant_id, name, repo_pattern, fail_on, min_score,
		           max_high, block_secrets, block_critical, active, created_at`,
		r.TenantID, r.Name, r.RepoPattern, r.FailOn, r.MinScore,
		r.MaxHigh, r.BlockSecrets, r.BlockCritical)
	var out PolicyRule
	err := row.Scan(&out.ID, &out.TenantID, &out.Name, &out.RepoPattern,
		&out.FailOn, &out.MinScore, &out.MaxHigh, &out.BlockSecrets,
		&out.BlockCritical, &out.Active, &out.CreatedAt)
	if err == pgx.ErrNoRows { return nil, nil }
	if err != nil { return nil, fmt.Errorf("create policy: %w", err) }
	return &out, nil
}

func (db *DB) DeletePolicyRule(ctx context.Context, tenantID, id string) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE policy_rules SET active=false WHERE id=$1 AND tenant_id=$2`,
		id, tenantID)
	return err
}

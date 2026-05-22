package sso

import (
	"context"
	"database/sql"
	"fmt"

	"strings"
	"github.com/lib/pq"
)

// CreateProvider inserts a new SSO provider configuration.
func CreateProvider(ctx context.Context, db *sql.DB, p Provider) (int64, error) {
	if p.Type != "oidc" && p.Type != "saml" {
		return 0, fmt.Errorf("type must be oidc or saml")
	}
	if p.IssuerURL == "" || p.ClientID == "" {
		return 0, fmt.Errorf("issuer_url and client_id required")
	}
	if p.Scopes == "" {
		p.Scopes = "openid email profile"
	}
	if p.DefaultRole == "" {
		p.DefaultRole = "analyst"
	}

	var id int64
	err := db.QueryRowContext(ctx, `
		INSERT INTO sso_providers
		  (tenant_id, name, type, issuer_url, client_id, client_secret,
		   redirect_uri, scopes, enabled, allowed_domains, default_role)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING id
	`, p.TenantID, p.Name, p.Type, p.IssuerURL, p.ClientID, p.ClientSecret,
		p.RedirectURI, p.Scopes, p.Enabled, pq.Array(p.AllowedDomains), p.DefaultRole).Scan(&id)
	if err != nil {
		// lib/pq wraps the error — check both direct cast and error string
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return 0, fmt.Errorf("a provider named %q already exists for this tenant", p.Name)
		}
		if strings.Contains(err.Error(), "23505") || strings.Contains(err.Error(), "idx_sso_providers_tenant_name") {
			return 0, fmt.Errorf("a provider named %q already exists for this tenant", p.Name)
		}
		return 0, err
	}
	return id, nil
}

// ListProviders returns all SSO providers for a tenant.
func ListProviders(ctx context.Context, db *sql.DB, tenantID string) ([]Provider, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, tenant_id, name, type, issuer_url, client_id, '' AS client_secret,
		       redirect_uri, scopes, enabled, COALESCE(allowed_domains, '{}'),
		       default_role
		FROM sso_providers
		WHERE tenant_id = $1
		ORDER BY name
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Provider
	for rows.Next() {
		var p Provider
		if err := rows.Scan(&p.ID, &p.TenantID, &p.Name, &p.Type, &p.IssuerURL,
			&p.ClientID, &p.ClientSecret, &p.RedirectURI, &p.Scopes, &p.Enabled,
			pq.Array(&p.AllowedDomains), &p.DefaultRole); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetProvider fetches a single provider including its secret.
func GetProvider(ctx context.Context, db *sql.DB, id int64) (*Provider, error) {
	var p Provider
	err := db.QueryRowContext(ctx, `
		SELECT id, tenant_id, name, type, issuer_url, client_id, client_secret,
		       redirect_uri, scopes, enabled, COALESCE(allowed_domains, '{}'),
		       default_role
		FROM sso_providers
		WHERE id = $1
	`, id).Scan(&p.ID, &p.TenantID, &p.Name, &p.Type, &p.IssuerURL,
		&p.ClientID, &p.ClientSecret, &p.RedirectURI, &p.Scopes, &p.Enabled,
		pq.Array(&p.AllowedDomains), &p.DefaultRole)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// GetProviderByName looks up a provider by tenant + name (used at login).
func GetProviderByName(ctx context.Context, db *sql.DB, tenantID, name string) (*Provider, error) {
	var p Provider
	err := db.QueryRowContext(ctx, `
		SELECT id, tenant_id, name, type, issuer_url, client_id, client_secret,
		       redirect_uri, scopes, enabled, COALESCE(allowed_domains, '{}'),
		       default_role
		FROM sso_providers
		WHERE tenant_id = $1 AND name = $2 AND enabled = true
	`, tenantID, name).Scan(&p.ID, &p.TenantID, &p.Name, &p.Type, &p.IssuerURL,
		&p.ClientID, &p.ClientSecret, &p.RedirectURI, &p.Scopes, &p.Enabled,
		pq.Array(&p.AllowedDomains), &p.DefaultRole)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// UpdateProvider modifies an existing provider (partial update via NULL omit).
func UpdateProvider(ctx context.Context, db *sql.DB, p Provider) error {
	res, err := db.ExecContext(ctx, `
		UPDATE sso_providers
		SET name = $1, issuer_url = $2, client_id = $3,
		    client_secret = CASE WHEN $4 = '' THEN client_secret ELSE $4 END,
		    redirect_uri = $5, scopes = $6, enabled = $7,
		    allowed_domains = $8, default_role = $9, updated_at = now(),
		    discovery_json = NULL, discovery_at = NULL
		WHERE id = $10 AND tenant_id = $11
	`, p.Name, p.IssuerURL, p.ClientID, p.ClientSecret, p.RedirectURI,
		p.Scopes, p.Enabled, pq.Array(p.AllowedDomains), p.DefaultRole, p.ID, p.TenantID)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return fmt.Errorf("a provider named %q already exists for this tenant", p.Name)
		}
		if strings.Contains(err.Error(), "23505") || strings.Contains(err.Error(), "idx_sso_providers_tenant_name") {
			return fmt.Errorf("a provider named %q already exists for this tenant", p.Name)
		}
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteProvider removes a provider.
func DeleteProvider(ctx context.Context, db *sql.DB, id int64, tenantID string) error {
	res, err := db.ExecContext(ctx, `
		DELETE FROM sso_providers WHERE id = $1 AND tenant_id = $2
	`, id, tenantID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// RotateSecret rotates the client_secret with a grace period:
// the old secret is kept in client_secret_prev so in-flight token
// exchanges using the old secret still succeed for ~5 minutes.
// After the grace period, UpdateProvider with empty client_secret_prev
// to fully commit the rotation.
func RotateSecret(ctx context.Context, db *sql.DB, id int64, tenantID, newSecret string) error {
	res, err := db.ExecContext(ctx, `
		UPDATE sso_providers
		SET client_secret_prev = client_secret,
		    client_secret = $1,
		    updated_at = now(),
		    discovery_json = NULL, discovery_at = NULL
		WHERE id = $2 AND tenant_id = $3
	`, newSecret, id, tenantID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// CommitRotation clears client_secret_prev after the grace period.
// Call this ~5 minutes after RotateSecret to invalidate the old secret.
func CommitRotation(ctx context.Context, db *sql.DB, id int64, tenantID string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE sso_providers
		SET client_secret_prev = '', updated_at = now()
		WHERE id = $1 AND tenant_id = $2
	`, id, tenantID)
	return err
}

// ListEnabledProviders returns all enabled providers across all tenants.
// Used for JWKS warm-up on gateway start.
func ListEnabledProviders(ctx context.Context, db *sql.DB) ([]Provider, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, tenant_id, name, type, issuer_url, client_id, client_secret,
		       redirect_uri, scopes, enabled, COALESCE(allowed_domains, '{}'),
		       default_role
		FROM sso_providers
		WHERE enabled = true
		ORDER BY tenant_id, name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Provider
	for rows.Next() {
		var p Provider
		if err := rows.Scan(&p.ID, &p.TenantID, &p.Name, &p.Type, &p.IssuerURL,
			&p.ClientID, &p.ClientSecret, &p.RedirectURI, &p.Scopes, &p.Enabled,
			pq.Array(&p.AllowedDomains), &p.DefaultRole); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

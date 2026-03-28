package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ── User model ───────────────────────────────────────────────────────────────

type User struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	Email      string     `json:"email"`
	PwHash     string     `json:"-"`
	Role       string     `json:"role"`
	MFAEnabled bool       `json:"mfa_enabled"`
	CreatedAt  time.Time  `json:"created_at"`
	LastLogin  *time.Time `json:"last_login"`
}

func (db *DB) GetUserByEmail(ctx context.Context, tenantID, email string) (*User, error) {
	row := db.pool.QueryRow(ctx,
		`SELECT id, tenant_id, email, pw_hash, role, mfa_enabled, created_at, last_login
		 FROM users WHERE tenant_id = $1 AND email = $2 LIMIT 1`,
		tenantID, email)
	return scanUser(row)
}

func (db *DB) GetUserByID(ctx context.Context, tenantID, id string) (*User, error) {
	row := db.pool.QueryRow(ctx,
		`SELECT id, tenant_id, email, pw_hash, role, mfa_enabled, created_at, last_login
		 FROM users WHERE id = $1 AND tenant_id = $2 LIMIT 1`,
		id, tenantID)
	return scanUser(row)
}

func (db *DB) CreateUser(ctx context.Context, tenantID, email, pwHash, role string) (*User, error) {
	row := db.pool.QueryRow(ctx,
		`INSERT INTO users (tenant_id, email, pw_hash, role)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, tenant_id, email, pw_hash, role, mfa_enabled, created_at, last_login`,
		tenantID, email, pwHash, role)
	return scanUser(row)
}

func (db *DB) ListUsers(ctx context.Context, tenantID string, limit, offset int) ([]User, int64, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT id, tenant_id, email, pw_hash, role, mfa_enabled, created_at, last_login
		 FROM users WHERE tenant_id = $1
		 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		tenantID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, err
		}
		users = append(users, *u)
	}

	var count int64
	db.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE tenant_id = $1`, tenantID).Scan(&count)
	return users, count, nil
}

func (db *DB) DeleteUser(ctx context.Context, tenantID, id string) error {
	_, err := db.pool.Exec(ctx,
		`DELETE FROM users WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return err
}

func (db *DB) UpdateLastLogin(ctx context.Context, id string) error {
	_, err := db.pool.Exec(ctx, `UPDATE users SET last_login = NOW() WHERE id = $1`, id)
	return err
}

// scanUser works for both pgx.Row and pgx.Rows
type scanner interface {
	Scan(dest ...any) error
}

func scanUser(row scanner) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.TenantID, &u.Email, &u.PwHash,
		&u.Role, &u.MFAEnabled, &u.CreatedAt, &u.LastLogin)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}
	return &u, nil
}

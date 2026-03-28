// Package store provides PostgreSQL access using pgx/v5.
// Queries in this file are hand-written; run `sqlc generate` to regenerate
// type-safe wrappers once sqlc is installed.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB wraps a pgxpool and provides all query methods needed by the gateway.
type DB struct {
	pool *pgxpool.Pool
}

// New creates a new DB from the given DSN and verifies connectivity.
func New(ctx context.Context, dsn string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parse config: %w", err)
	}
	cfg.MaxConns = 20
	cfg.MinConns = 2
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &DB{pool: pool}, nil
}

func (db *DB) Close() { db.pool.Close() }

// Pool exposes the raw pool for advanced use (transactions, etc).
func (db *DB) Pool() *pgxpool.Pool { return db.pool }

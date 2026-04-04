package migrate

import (
	"context"
	"database/sql"
	"embed"
	"fmt"

	"github.com/pressly/goose/v3"
	"github.com/rs/zerolog/log"
)

//go:embed sql/*.sql
var migrationFS embed.FS

func Run(ctx context.Context, db *sql.DB) error {
	goose.SetBaseFS(migrationFS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("migrate: set dialect: %w", err)
	}
	if err := goose.UpContext(ctx, db, "sql"); err != nil {
		return fmt.Errorf("migrate: up: %w", err)
	}
	log.Info().Msg("migrations: all up to date ✓")
	return nil
}

func Status(ctx context.Context, db *sql.DB) error {
	goose.SetBaseFS(migrationFS)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.StatusContext(ctx, db, "sql")
}

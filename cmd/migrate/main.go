package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/vsp/platform/internal/migrate"
)

func main() {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "TEST_DATABASE_URL not set")
		os.Exit(1)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	if err := migrate.Run(context.Background(), db); err != nil {
		fmt.Fprintf(os.Stderr, "migrate failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ migrations OK")
}

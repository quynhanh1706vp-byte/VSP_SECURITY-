// cmd/seed creates a default admin user for development.
// Usage: go run ./cmd/seed/
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/viper"
	"github.com/vsp/platform/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	viper.SetDefault("database.url", "postgres://vsp:vsp@localhost:5432/vsp_go")
	viper.AutomaticEnv()

	dsn := viper.GetString("database.url")
	ctx := context.Background()

	db, err := store.New(ctx, dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Get default tenant
	var tenantID string
	db.Pool().QueryRow(ctx, `SELECT id FROM tenants WHERE slug='default' LIMIT 1`).Scan(&tenantID)
	if tenantID == "" {
		fmt.Fprintln(os.Stderr, "default tenant not found — run: make migrate-up")
		os.Exit(1)
	}

	// Users to seed
	seeds := []struct{ email, password, role string }{
		{"admin@vsp.local",   "admin123",   "admin"},
		{"analyst@vsp.local", "analyst123", "analyst"},
		{"dev@vsp.local",     "dev123",     "dev"},
		{"auditor@vsp.local", "auditor123", "auditor"},
	}

	for _, s := range seeds {
		hash, _ := bcrypt.GenerateFromPassword([]byte(s.password), bcrypt.DefaultCost)
		_, err := db.Pool().Exec(ctx,
			`INSERT INTO users (tenant_id, email, pw_hash, role)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (tenant_id, email) DO UPDATE SET pw_hash = $3, role = $4`,
			tenantID, s.email, string(hash), s.role)
		if err != nil {
			fmt.Fprintf(os.Stderr, "seed %s: %v\n", s.email, err)
		} else {
			fmt.Printf("✓ %s  [%s]  pass: %s\n", s.email, s.role, s.password)
		}
	}
	fmt.Println("\nDone. Login: POST /api/v1/auth/login")
}

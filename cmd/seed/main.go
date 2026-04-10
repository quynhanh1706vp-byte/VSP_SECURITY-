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

func getEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

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

	// Safety guard — refuse to run in production
	if env := os.Getenv("VSP_ENV"); env == "production" || env == "prod" {
		fmt.Fprintln(os.Stderr, "ERROR: seed refused in production environment (VSP_ENV=production)")
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "WARNING: seeding development users with weak passwords — never run in production!")

	// Users to seed — passwords from env or defaults (dev only)
	adminPass := getEnvOrDefault("SEED_ADMIN_PASS", "admin123")
	analystPass := getEnvOrDefault("SEED_ANALYST_PASS", "analyst123")
	devPass := getEnvOrDefault("SEED_DEV_PASS", "dev123")
	auditorPass := getEnvOrDefault("SEED_AUDITOR_PASS", "auditor123")
	seeds := []struct{ email, password, role string }{
		{"admin@vsp.local", adminPass, "admin"},
		{"analyst@vsp.local", analystPass, "analyst"},
		{"dev@vsp.local", devPass, "dev"},
		{"auditor@vsp.local", auditorPass, "auditor"},
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

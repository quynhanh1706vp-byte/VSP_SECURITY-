package secrets

import (
	"os"
	"strings"
)

// EnvProvider reads secrets from environment variables. Logical names are
// mapped to env vars via a small alias table; unknown names fall back to
// upper-cased name. We keep aliases explicit so the deployment surface is
// auditable from one place.
type EnvProvider struct{}

// envAliases maps logical secret names to their env-var keys. Keep this
// in lock-step with internal/secrets/vault.go's vaultKeyMap.
var envAliases = map[string]string{
	"jwt":                "JWT_SECRET",
	"jwt_old":            "JWT_SECRET_OLD",
	"db_password":        "POSTGRES_PASSWORD",
	"db_url":             "DATABASE_URL",
	"webhook_signing":    "WEBHOOK_SIGNING_KEY",
	"redis_password":     "REDIS_PASSWORD",
	"oidc_client_secret": "OIDC_CLIENT_SECRET",
	"smtp_password":      "SMTP_PASSWORD",
	"cosign_password":    "COSIGN_PASSWORD",
}

func (e *EnvProvider) Get(name string) (string, error) {
	key, ok := envAliases[name]
	if !ok {
		key = strings.ToUpper(name)
	}
	v := os.Getenv(key)
	if v == "" {
		return "", ErrNotFound
	}
	return v, nil
}

func (e *EnvProvider) Source() string { return "env" }

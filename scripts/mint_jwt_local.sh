#!/usr/bin/env bash
# Mint a HS256 JWT locally without contacting dev-stub.
# Usage: ./scripts/mint_jwt_local.sh role [secret]
set -euo pipefail
ROLE=${1:-admin}
SECRET=${2:-dev-secret-please-change}
NOW=$(date +%s)
EXP=$((NOW + 86400))
HEADER=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | openssl base64 -e | tr -d '\n=' | tr '/+' '_-' )
# L25 2026-05-09: include `jti` so logout/blacklist flow exercises the
# real revocation path. Pre-fix every dev token had jti="" → revocation
# was a no-op → revoked-token reuse tests false-passed.
JTI=$(openssl rand -hex 16)
PAYLOAD=$(printf '{"sub":"dev@vsp.local","email":"dev@vsp.local","role":"%s","tenant_id":"default","jti":"%s","iat":%d,"exp":%d}' "$ROLE" "$JTI" "$NOW" "$EXP" | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
SIG=$(printf '%s' "$HEADER.$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" -binary | openssl base64 -e | tr -d '\n=' | tr '/+' '_-')
printf '%s.%s.%s\n' "$HEADER" "$PAYLOAD" "$SIG"

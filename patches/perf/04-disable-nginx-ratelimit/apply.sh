#!/usr/bin/env bash
set -euo pipefail
NGINX_CONF="/etc/nginx/sites-available/vsp"
BACKUP="${NGINX_CONF}.bak.perf04"
MARKER="# PERF-04 PATCH APPLIED — nginx rate limiting disabled"

if [[ ! -f "$NGINX_CONF" ]]; then
  echo "nginx conf not found"; exit 1
fi

if sudo grep -q "PERF-04 PATCH APPLIED" "$NGINX_CONF"; then
  echo "PERF-04 already applied. Rollback first if needed."
  exit 0
fi

sudo cp "$NGINX_CONF" "$BACKUP"
echo "Backup: $BACKUP"

sudo sed -i -E '
  /^\s*#/ b
  s/^(\s*)(limit_req_zone\s)/\1# [PERF-04] \2/
  s/^(\s*)(limit_conn_zone\s)/\1# [PERF-04] \2/
  s/^(\s*)(limit_req\s)/\1# [PERF-04] \2/
  s/^(\s*)(limit_conn\s)/\1# [PERF-04] \2/
  s/^(\s*)(limit_req_status\s)/\1# [PERF-04] \2/
' "$NGINX_CONF"

sudo sed -i "1i ${MARKER}" "$NGINX_CONF"

ACTIVE=$(sudo grep -cE '^\s*limit_(req|conn)(\s|_zone\s|_status\s)' "$NGINX_CONF" || true)
echo "Active limit_* directives remaining: $ACTIVE (expect 0)"

if [[ "$ACTIVE" != "0" ]]; then
  echo "Some directives still active, rolling back."
  sudo cp "$BACKUP" "$NGINX_CONF"
  exit 1
fi

if ! sudo nginx -t; then
  echo "nginx -t failed, rolling back."
  sudo cp "$BACKUP" "$NGINX_CONF"
  exit 1
fi

echo "PERF-04 applied. Run: sudo systemctl reload nginx"

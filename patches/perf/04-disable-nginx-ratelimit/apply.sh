#!/usr/bin/env bash
# PERF-04: Disable nginx rate limit at edge.
# Patches BOTH sites-available AND sites-enabled because on this host
# they are independent files (not symlinked).
# Backups go to /etc/nginx/ (NOT inside sites-enabled/) to avoid nginx
# loading them as duplicate configs (would cause "duplicate upstream" emerg).
set -euo pipefail

CONFS=(
  "/etc/nginx/sites-available/vsp"
  "/etc/nginx/sites-enabled/vsp"
)
MARKER="# PERF-04 PATCH APPLIED — nginx rate limiting disabled"

for NGINX_CONF in "${CONFS[@]}"; do
  if [[ ! -f "$NGINX_CONF" ]]; then
    echo "skip: $NGINX_CONF not found"
    continue
  fi
  if sudo grep -q "PERF-04 PATCH APPLIED" "$NGINX_CONF"; then
    echo "skip: $NGINX_CONF already patched"
    continue
  fi

  BACKUP_NAME="$(basename "$NGINX_CONF").bak.perf04"
  BACKUP="/etc/nginx/${BACKUP_NAME}"
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
  echo "Patched: $NGINX_CONF"
done

ACTIVE=$(sudo nginx -T 2>/dev/null | grep -cE "^\s*limit_(req|conn)(\s|_zone\s|_status\s)" || true)
echo "Active limit_* directives (resolved nginx -T): $ACTIVE (expect 0)"

if [[ "$ACTIVE" != "0" ]]; then
  echo "Some directives still active. Inspect: sudo nginx -T | grep limit_"
  exit 1
fi

if ! sudo nginx -t; then
  echo "nginx -t failed."
  exit 1
fi

echo "PERF-04 applied to sites-available + sites-enabled."
echo "Run: sudo systemctl reload nginx"

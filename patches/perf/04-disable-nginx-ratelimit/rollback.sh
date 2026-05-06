#!/usr/bin/env bash
set -euo pipefail
NGINX_CONF="/etc/nginx/sites-available/vsp"
BACKUP="${NGINX_CONF}.bak.perf04"
[[ -f "$BACKUP" ]] || { echo "Backup not found: $BACKUP"; exit 1; }
sudo cp "$BACKUP" "$NGINX_CONF"
sudo nginx -t || exit 1
echo "Rolled back. Run: sudo systemctl reload nginx"

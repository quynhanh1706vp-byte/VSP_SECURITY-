#!/usr/bin/env bash
set -euo pipefail
for NGINX_CONF in /etc/nginx/sites-available/vsp /etc/nginx/sites-enabled/vsp; do
  BACKUP="${NGINX_CONF}.bak.perf04"
  if [[ -f "$BACKUP" ]]; then
    sudo cp "$BACKUP" "$NGINX_CONF"
    echo "Restored $NGINX_CONF"
  fi
done
sudo nginx -t || exit 1
echo "Rolled back. Run: sudo systemctl reload nginx"

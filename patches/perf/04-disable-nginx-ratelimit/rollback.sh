#!/usr/bin/env bash
set -euo pipefail
for NAME in vsp; do
  for DIR in sites-available sites-enabled; do
    TARGET="/etc/nginx/${DIR}/${NAME}"
    BACKUP="/etc/nginx/${NAME}.bak.perf04"
    # Also accept old-style backup location for compatibility
    [[ -f "$BACKUP" ]] || BACKUP="${TARGET}.bak.perf04"
    if [[ -f "$BACKUP" ]]; then
      sudo cp "$BACKUP" "$TARGET"
      echo "Restored $TARGET"
    fi
  done
done
sudo nginx -t || exit 1
echo "Rolled back. Run: sudo systemctl reload nginx"

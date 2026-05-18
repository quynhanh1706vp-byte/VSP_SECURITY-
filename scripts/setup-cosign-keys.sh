#!/usr/bin/env bash
# scripts/setup-cosign-keys.sh — v3
# ─────────────────────────────────────────────────────────────────────────
# Installs Cosign keypair into /etc/vsp + creates 'vsp' group with proper
# perms on ALL runtime dirs (key dir 750, runtime dirs 770 group-writable).
#
# Usage:
#   sudo ./scripts/setup-cosign-keys.sh
#   COSIGN_PASSWORD='hunter2' sudo -E ./scripts/setup-cosign-keys.sh
#   COSIGN_PASSWORD='hunter2' VSP_USER=test sudo -E ./scripts/setup-cosign-keys.sh
# ─────────────────────────────────────────────────────────────────────────
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "✗ this script must be run as root (sudo)"
  exit 1
fi

KEYDIR=/etc/vsp
SRCKEY="${SRCKEY:-./cosign.key}"
SRCPUB="${SRCPUB:-./cosign.pub}"
VSP_USER="${VSP_USER:-${SUDO_USER:-}}"

[[ -f "$SRCKEY" ]] || { echo "✗ $SRCKEY not found in $PWD"; exit 2; }
[[ -f "$SRCPUB" ]] || { echo "✗ $SRCPUB not found in $PWD"; exit 2; }

# ── 1. Group ──────────────────────────────────────────────────────────────
if ! getent group vsp >/dev/null; then
  echo "→ creating group 'vsp'"
  groupadd vsp
else
  echo "· group 'vsp' already exists"
fi

GROUP_ADDED=0
if [[ -n "$VSP_USER" ]] && id -u "$VSP_USER" >/dev/null 2>&1; then
  if id -nG "$VSP_USER" | tr ' ' '\n' | grep -qx vsp; then
    echo "· user '$VSP_USER' already in group 'vsp'"
  else
    echo "→ adding user '$VSP_USER' to group 'vsp'"
    usermod -aG vsp "$VSP_USER"
    GROUP_ADDED=1
  fi
else
  echo "⚠ no VSP_USER specified — only root will access /etc/vsp"
fi

# ── 2. Directories ───────────────────────────────────────────────────────
# /etc/vsp:    750 — read-only secrets (group can list, only root can write)
# /var/lib/vsp, /var/log/vsp, /var/run/vsp:
#              770 — runtime dirs (group MUST be able to write logs/pid/data)
echo "→ setting up directories"
mkdir -p "$KEYDIR"
chown root:vsp "$KEYDIR"
chmod 750 "$KEYDIR"

for d in /var/lib/vsp /var/log/vsp /var/run/vsp; do
  mkdir -p "$d"
  chown root:vsp "$d"
  chmod 770 "$d"   # group-writable — CRITICAL for non-root service user
done

# ── 3. Keypair ───────────────────────────────────────────────────────────
install -o root -g vsp -m 600 "$SRCKEY" "$KEYDIR/cosign.key"
install -o root -g vsp -m 644 "$SRCPUB" "$KEYDIR/cosign.pub"

# ── 4. Password ──────────────────────────────────────────────────────────
if [[ -n "${COSIGN_PASSWORD:-}" ]]; then
  printf '%s' "$COSIGN_PASSWORD" > "$KEYDIR/cosign.pass"
  echo "→ wrote password from \$COSIGN_PASSWORD ($(printf '%s' "$COSIGN_PASSWORD" | wc -c) chars)"
else
  echo
  echo "Enter the password you set when running 'cosign generate-key-pair':"
  read -rs pw
  echo
  if [[ -z "$pw" ]]; then
    echo "✗ Password rỗng — abort (file pass cũ giữ nguyên)"
    exit 1
  fi
  printf '%s' "$pw" > "$KEYDIR/cosign.pass"
  echo "→ wrote password ($(printf '%s' "$pw" | wc -c) chars)"
  unset pw
fi
chown root:vsp "$KEYDIR/cosign.pass"
chmod 600 "$KEYDIR/cosign.pass"

# ── 5. Sanity check ──────────────────────────────────────────────────────
if command -v cosign >/dev/null; then
  if COSIGN_PASSWORD="$(<"$KEYDIR/cosign.pass")" \
     cosign public-key --key "$KEYDIR/cosign.key" >/dev/null 2>&1; then
    echo "✓ keypair verified — cosign accepts the password"
  else
    echo "✗ cosign rejected the password — re-run with correct password:"
    echo "  COSIGN_PASSWORD='<correct-password>' sudo -E $0"
    exit 3
  fi
else
  echo "⚠ cosign CLI not on PATH — skipping password verification"
  echo "  install with: go install github.com/sigstore/cosign/v2/cmd/cosign@latest"
fi

# ── 6. Final state ───────────────────────────────────────────────────────
echo
echo "✓ Installation complete. Permissions:"
stat -c '  %A  %U:%G  %n' "$KEYDIR" /var/lib/vsp /var/log/vsp /var/run/vsp \
                          "$KEYDIR/cosign.key" "$KEYDIR/cosign.pub" "$KEYDIR/cosign.pass"

echo
if [[ "$GROUP_ADDED" == "1" ]]; then
  cat <<MSG
⚠ User '$VSP_USER' was just added to group 'vsp'.
  Refresh your shell BEFORE running start-cosign-api.sh:

    exec sg vsp -c bash       # this terminal
                              # (or logout + login)

  Verify:
    id | tr ',' '\n' | grep vsp     # should print 'vsp'
MSG
else
  echo "Next: ./scripts/start-cosign-api.sh"
fi

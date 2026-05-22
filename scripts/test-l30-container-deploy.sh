#!/usr/bin/env bash
# scripts/test-l30-container-deploy.sh — container / deploy security audit.
#
# Static checks against Dockerfile + Helm chart + systemd unit:
#
#   31.1 Dockerfile USER directive — final stage runs as non-root.
#   31.2 Dockerfile HEALTHCHECK present.
#   31.3 No ADD url:// (use COPY for local + curl/wget where needed).
#   31.4 No `apt-get install ... && rm -rf /var/lib/apt/lists/*` skipped
#        — image size + cache hygiene.
#   31.5 Helm values has resource limits + readiness/liveness probes.
#   31.6 systemd unit has hardening (NoNewPrivileges, ProtectSystem,
#        PrivateTmp).
#   31.7 .env.example tracked but real .env files NOT (prevents secret
#        leak via repo).
#
# Pre-flight: jq.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

require_command grep awk

# ── 31.1 Dockerfile non-root USER ─────────────────────────────────────────

phase_open "31.1 Dockerfile — final stage runs as non-root"

DF="$ROOT/Dockerfile"
if [[ ! -f "$DF" ]]; then
  _skip "31.1.1 Dockerfile" "no Dockerfile at repo root"
else
  # Last USER directive in the file. Must NOT be root / 0 / unset.
  LAST_USER=$(grep -E "^USER " "$DF" | tail -1 | awk '{print $2}')
  if [[ -z "$LAST_USER" ]]; then
    _fail "31.1.1 Dockerfile no USER directive" \
      "container will run as root by default"
  elif [[ "$LAST_USER" == "root" || "$LAST_USER" == "0" ]]; then
    _fail "31.1.1 Dockerfile final USER is root" "$LAST_USER"
  else
    _pass "31.1.1 Dockerfile runs as non-root [$LAST_USER]"
  fi
fi

# ── 31.2 Dockerfile HEALTHCHECK ───────────────────────────────────────────

phase_open "31.2 Dockerfile — HEALTHCHECK directive present"

if [[ -f "$DF" ]]; then
  if grep -qE "^HEALTHCHECK " "$DF"; then
    _pass "31.2.1 HEALTHCHECK declared"
  else
    _fail "31.2.1 HEALTHCHECK missing" \
      "orchestrators won't know when the container is ready"
  fi
fi

# ── 31.3 No ADD url:// in Dockerfile ──────────────────────────────────────

phase_open "31.3 Dockerfile — no ADD with remote URL"

if [[ -f "$DF" ]]; then
  REMOTE_ADDS=$(grep -E "^ADD\s+https?://" "$DF" || true)
  if [[ -z "$REMOTE_ADDS" ]]; then
    _pass "31.3.1 no ADD https:// (use COPY + verified curl)"
  else
    _fail "31.3.1 ADD with remote URL" "$REMOTE_ADDS"
  fi
fi

# ── 31.4 apt cache hygiene ───────────────────────────────────────────────

phase_open "31.4 Dockerfile — apt cache cleaned"

if [[ -f "$DF" ]]; then
  HAS_APT=$(grep -cE "apt-get install" "$DF" || true)
  HAS_CLEAN=$(grep -cE "rm -rf /var/lib/apt/lists/\*|apt-get clean" "$DF" || true)
  if (( HAS_APT == 0 )); then
    _pass "31.4.1 no apt-get install — cache hygiene N/A"
  elif (( HAS_CLEAN >= 1 )); then
    _pass "31.4.1 apt cache cleaned after install"
  else
    _fail "31.4.1 apt-get install without cache cleanup" \
      "image bloat — consider rm -rf /var/lib/apt/lists/* in same RUN"
  fi
fi

# ── 31.5 Helm values — resource limits + probes ──────────────────────────

phase_open "31.5 Helm values — resources + probes"

HELM_VALUES=""
for candidate in deploy/helm/values.yaml charts/vsp/values.yaml \
                 helm/vsp/values.yaml deploy/values.yaml; do
  if [[ -f "$ROOT/$candidate" ]]; then
    HELM_VALUES="$ROOT/$candidate"
    break
  fi
done

if [[ -z "$HELM_VALUES" ]]; then
  _skip "31.5.1 Helm values" "no values.yaml found in standard locations"
else
  has_resources=$(grep -c "^resources:\|  resources:" "$HELM_VALUES" || true)
  has_probes=$(grep -cE "(livenessProbe|readinessProbe):" "$HELM_VALUES" || true)
  if (( has_resources >= 1 && has_probes >= 1 )); then
    _pass "31.5.1 helm values declares resources + probes"
  else
    _fail "31.5.1 helm values incomplete" \
      "resources=$has_resources probes=$has_probes"
  fi
fi

# ── 31.6 systemd unit hardening ───────────────────────────────────────────

phase_open "31.6 systemd unit — sandboxing directives"

UNIT=""
for candidate in deploy/systemd/vsp-gateway.service \
                 deployments/systemd/vsp-gateway.service \
                 /etc/systemd/system/vsp-gateway.service; do
  if [[ -r "$candidate" ]]; then
    UNIT="$candidate"
    break
  fi
done

if [[ -z "$UNIT" ]]; then
  _skip "31.6.1 systemd unit" "no unit file accessible"
else
  expected=( "NoNewPrivileges=true" "ProtectSystem=" "PrivateTmp=true" )
  missing=()
  for d in "${expected[@]}"; do
    if ! grep -qE "^${d//=/=}" "$UNIT"; then
      missing+=("${d%=*}")
    fi
  done
  if (( ${#missing[@]} == 0 )); then
    _pass "31.6.1 systemd unit has NoNewPrivileges + ProtectSystem + PrivateTmp"
  else
    _fail "31.6.1 systemd hardening missing" "${missing[*]}"
  fi
fi

# ── 31.7 .env tracked / not tracked ──────────────────────────────────────

phase_open "31.7 .env.example tracked, .env not"

if git -C "$ROOT" ls-files .env.example 2>/dev/null | grep -q .env.example; then
  _pass "31.7.1 .env.example tracked"
else
  _fail "31.7.1 .env.example not tracked" \
    "operators have no template for env config"
fi

if git -C "$ROOT" ls-files 2>/dev/null | grep -qE '(^|/)\.env$'; then
  _fail "31.7.2 real .env tracked" \
    "secrets file in repo — rotate immediately"
else
  _pass "31.7.2 no real .env tracked"
fi

# ── final ──────────────────────────────────────────────────────────────────

final_summary

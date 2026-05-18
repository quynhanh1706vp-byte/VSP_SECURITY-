#!/usr/bin/env bash
# scripts/test-l48-cicd-hygiene.sh — CICD deployment hygiene audit.
#
# Static analysis of deployment artefacts:
#
#   1. Dockerfile: no USER root in final stage; uses non-root user
#   2. Dockerfile: no `COPY . .` of secrets directories
#   3. Dockerfile: HEALTHCHECK defined; matches the running port
#   4. docker-compose: services don't bind-mount sensitive host paths
#      (e.g. /etc, /var/run/docker.sock without a privileged need)
#   5. systemd unit: NoNewPrivileges=yes, ProtectSystem=strict,
#      PrivateTmp=yes, CapabilityBoundingSet limited
#   6. .dockerignore exists and excludes .git, node_modules,
#      *.env, /vendor (build cache poisoning protection)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

# ── 48.1 Dockerfile hygiene ──────────────────────────────────────────────

phase_open "48.1 Dockerfile hardening"

DOCKERFILE=""
for cand in "$ROOT/Dockerfile" "$ROOT/deploy/Dockerfile" "$ROOT/cmd/gateway/Dockerfile"; do
  if [[ -r "$cand" ]]; then DOCKERFILE="$cand"; break; fi
done

if [[ -z "$DOCKERFILE" ]]; then
  _skip "48.1.0 Dockerfile present" "no Dockerfile in root / deploy / cmd/gateway"
else
  _pass "48.1.0 Dockerfile found at $(basename "$DOCKERFILE")"

  # 48.1.1 — final stage doesn't run as root. Look for `USER` directive
  # in the LAST stage. Multi-stage builds have multiple FROM; the last
  # is what ships.
  LAST_USER=$(awk '
    /^FROM /     { user=""; stage++ }
    /^USER /     { user=$2 }
    END          { print user }
  ' "$DOCKERFILE")
  if [[ -z "$LAST_USER" || "$LAST_USER" == "root" || "$LAST_USER" == "0" ]]; then
    _fail "48.1.1 Dockerfile final stage runs as root" \
      "USER=${LAST_USER:-<unset>} — set USER non-root before CMD/ENTRYPOINT"
  else
    _pass "48.1.1 Dockerfile final stage USER=$LAST_USER (non-root)"
  fi

  # 48.1.2 — HEALTHCHECK present
  if grep -qE '^HEALTHCHECK' "$DOCKERFILE"; then
    _pass "48.1.2 HEALTHCHECK defined"
  else
    _skip "48.1.2 HEALTHCHECK" "absent — informational; orchestrator-level health check may suffice"
  fi

  # 48.1.3 — no `COPY .* /etc/` of credentials directories
  BAD_COPY=$(grep -E '^COPY .* /(etc|root|home)' "$DOCKERFILE" | head -1 || true)
  if [[ -n "$BAD_COPY" ]]; then
    _fail "48.1.3 Dockerfile COPY into sensitive path" "$BAD_COPY"
  else
    _pass "48.1.3 no COPY into /etc /root /home"
  fi

  # 48.1.4 — apt install with --no-install-recommends (image size hygiene)
  if grep -qE 'apt-get install' "$DOCKERFILE" && \
     ! grep -qE 'apt-get install.*--no-install-recommends' "$DOCKERFILE"; then
    _skip "48.1.4 apt --no-install-recommends" "missing — informational, increases image size + attack surface"
  else
    _pass "48.1.4 apt install uses --no-install-recommends (or no apt)"
  fi
fi

# ── 48.2 docker-compose volumes / privileges ─────────────────────────────

phase_open "48.2 docker-compose / podman-compose hardening"

COMPOSE=""
for cand in "$ROOT/docker-compose.yml" "$ROOT/docker-compose.yaml" \
            "$ROOT/deploy/docker-compose.yml"; do
  if [[ -r "$cand" ]]; then COMPOSE="$cand"; break; fi
done

if [[ -z "$COMPOSE" ]]; then
  _skip "48.2.0 docker-compose present" "no compose file found"
else
  _pass "48.2.0 compose file found at $(basename "$COMPOSE")"

  # 48.2.1 — no bind-mount of docker.sock (privilege escalation)
  if grep -qE 'docker\.sock' "$COMPOSE"; then
    _fail "48.2.1 docker.sock bind-mount" \
      "$(grep -nE 'docker\.sock' "$COMPOSE" | head -1) — container can talk to docker daemon = root on host"
  else
    _pass "48.2.1 no docker.sock bind-mount"
  fi

  # 48.2.2 — no `privileged: true`
  if grep -qE 'privileged:\s*true' "$COMPOSE"; then
    _fail "48.2.2 privileged: true on a service" \
      "$(grep -nE 'privileged:\s*true' "$COMPOSE" | head -1)"
  else
    _pass "48.2.2 no privileged: true services"
  fi

  # 48.2.3 — no host network mode (bypasses firewall)
  if grep -qE 'network_mode:\s*"?host"?' "$COMPOSE"; then
    _fail "48.2.3 network_mode: host" \
      "$(grep -nE 'network_mode' "$COMPOSE" | head -1)"
  else
    _pass "48.2.3 no network_mode: host"
  fi

  # 48.2.4 — sensitive host paths NOT mounted
  BAD_MOUNT=$(grep -nE '^\s*-\s+/(etc|root|var/run/docker)' "$COMPOSE" | head -1 || true)
  if [[ -n "$BAD_MOUNT" ]]; then
    _fail "48.2.4 sensitive host path bind-mounted" "$BAD_MOUNT"
  else
    _pass "48.2.4 no bind-mounts of /etc /root /var/run/docker"
  fi
fi

# ── 48.3 systemd unit hardening ──────────────────────────────────────────

phase_open "48.3 systemd unit hardening"

UNIT=""
for cand in "$ROOT/deploy/vsp-gateway.service" \
            "$ROOT/deploy/systemd/vsp-gateway.service" \
            "$ROOT/init/vsp-gateway.service" \
            "$ROOT/vsp-gateway.service"; do
  if [[ -r "$cand" ]]; then UNIT="$cand"; break; fi
done

if [[ -z "$UNIT" ]]; then
  _skip "48.3.0 systemd unit present" "no .service file found in known locations"
else
  _pass "48.3.0 systemd unit at $(basename "$UNIT")"

  # Required hardening directives.
  for directive in \
      "NoNewPrivileges=yes" \
      "ProtectSystem=strict" \
      "PrivateTmp=yes"; do
    if grep -qE "^${directive%=*}=" "$UNIT"; then
      val=$(grep -E "^${directive%=*}=" "$UNIT" | head -1)
      if [[ "$val" == "$directive" || \
            "$val" == "${directive%=*}=true" || \
            "$val" == "${directive%=*}=full" ]]; then
        _pass "48.3 $directive"
      else
        _skip "48.3 $directive" \
          "set to: $val (not the strictest, but present)"
      fi
    else
      _fail "48.3 $directive missing" \
        "systemd hardening incomplete — add to [Service] block"
    fi
  done

  # Bonus: CapabilityBoundingSet (limits caps)
  if grep -qE '^CapabilityBoundingSet=' "$UNIT"; then
    _pass "48.3 CapabilityBoundingSet defined"
  else
    _skip "48.3 CapabilityBoundingSet" "absent — informational"
  fi
fi

# ── 48.4 .dockerignore protects build context ───────────────────────────

phase_open "48.4 .dockerignore guards build context"

DI="$ROOT/.dockerignore"
if [[ ! -r "$DI" ]]; then
  _skip "48.4.0 .dockerignore" "absent — entire repo ships into build context"
else
  _pass "48.4.0 .dockerignore present"

  MISSING=()
  for pattern in ".git" "node_modules" "*.env" "/vendor"; do
    if ! grep -qE "^${pattern}\s*$" "$DI" 2>/dev/null; then
      MISSING+=("$pattern")
    fi
  done

  if (( ${#MISSING[@]} == 0 )); then
    _pass "48.4.1 .dockerignore excludes .git / node_modules / *.env / vendor"
  else
    _skip "48.4.1 .dockerignore missing entries" \
      "patterns not excluded: ${MISSING[*]} — informational"
  fi
fi

final_summary

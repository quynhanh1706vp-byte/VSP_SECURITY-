# JWT Secret Rotation Runbook

**Frequency:** Every 90 days (FedRAMP IA-5 / NIST 800-53), or immediately
on suspected compromise.

**Rotation model:** Dual-secret, zero-downtime. Active user sessions are
**preserved** across rotation — no forced logout.

**Implementation:** `internal/auth/rotation.go` (PR #63, Sprint 0).

---

## How It Works

- `JWT_SECRET` — primary secret, used for **issuing** new tokens.
- `JWT_SECRET_OLD` — optional, used **only for validating** existing
  tokens during the transition window.
- Both secrets are accepted for validation; only the primary is used
  for signing.
- After all old-signed tokens expire (≥ `JWT_TTL`, typically 24h),
  `JWT_SECRET_OLD` is unset.

---

## Pre-rotation Checklist

- [ ] Confirm `JWT_TTL` value — rotation window must be ≥ TTL (default 24h).
- [ ] New secret generated (min 32 chars, cryptographically random).
- [ ] Vault / secret store reachable from all gateway instances.
- [ ] Audit log ingestion working (rotation event must be captured).
- [ ] Rollback plan: know the previous `JWT_SECRET` value until window ends.

---

## Generate New Secret

```bash
# 64-char hex (recommended)
openssl rand -hex 32

# Or base64
openssl rand -base64 48 | tr -d '\n'
```

Never reuse an old secret. Never commit secrets to git.

---

## Rotation Steps

### 1. Move current secret to OLD slot

```bash
# Read current value
CURRENT=$(vault kv get -field=jwt_secret secret/vsp/prod)

# Stage it as OLD
vault kv patch secret/vsp/prod jwt_secret_old="$CURRENT"
```

Or, for `.env`-based deployments:

```bash
# Copy current JWT_SECRET value to JWT_SECRET_OLD
# (edit .env on each gateway instance)
JWT_SECRET_OLD=<current-value>
```

### 2. Generate and set new primary secret

```bash
NEW=$(openssl rand -hex 32)
vault kv patch secret/vsp/prod jwt_secret="$NEW"

# Or .env:
JWT_SECRET=<new-value>
```

After step 2, the environment has:
- `JWT_SECRET` = new value (signs new tokens)
- `JWT_SECRET_OLD` = previous value (validates in-flight tokens)

### 3. Rolling restart (zero-downtime)

```bash
# Multi-instance (behind load balancer):
#   drain → restart → verify → repeat
for i in 1 2 3; do
  kubectl rollout restart deployment/vsp-gateway-$i
  kubectl rollout status deployment/vsp-gateway-$i --timeout=90s
  curl -fsS https://vsp-$i.internal/health | jq -e '.status == "ok"'
done

# Single-instance dev:
sudo systemctl restart vsp-gateway
```

### 4. Verify dual-secret active

```bash
# New login issues new-secret-signed tokens
curl -sS -c /tmp/c.txt https://vsp.example.gov/api/v1/auth/login \
  -d '{"username":"test","password":"..."}' | jq .

# Existing (pre-rotation) tokens still validate
curl -sS -b /tmp/pre_rotation_cookie.txt \
  https://vsp.example.gov/api/v1/vsp/runs | jq '. | length'
# Expected: 200 OK with data (NOT 401)
```

If existing tokens return 401, `JWT_SECRET_OLD` is not being read —
check env propagation and restart.

### 5. Wait for transition window to close

Window = `JWT_TTL` + safety margin. Default: **24h + 1h = 25h**.

During this window, **do not** touch `JWT_SECRET_OLD`. All in-flight
tokens must expire naturally.

### 6. Remove OLD secret

```bash
# After 25h:
vault kv patch secret/vsp/prod jwt_secret_old=""
# Or .env: comment out the JWT_SECRET_OLD line

# Rolling restart again
kubectl rollout restart deployment/vsp-gateway
```

### 7. Audit entry

```bash
# Verify rotation event was logged
grep "JWT_SECRET_ROTATED" /var/log/vsp/audit.log | tail -1
```

Update the **Rotation History** table below in the same commit.

---

## Emergency Rotation (Compromise Suspected)

When a secret leak is suspected, the dual-secret window is a liability
(it keeps compromised tokens valid). Use the **break-glass** procedure:

### 1. Skip dual-secret; force all logout

```bash
# Set new JWT_SECRET
vault kv patch secret/vsp/prod jwt_secret="$(openssl rand -hex 32)"

# Explicitly CLEAR the old slot (do not carry over)
vault kv patch secret/vsp/prod jwt_secret_old=""
```

### 2. Restart all instances immediately (not rolling)

```bash
kubectl rollout restart deployment/vsp-gateway --grace-period=0
```

### 3. All users forced to re-login. Expected.

### 4. Investigate

```bash
# Failed logins pattern
grep "LOGIN_FAILED" /var/log/vsp/audit.log | \
  awk -F'|' '{print $1, $4}' | sort | uniq -c | sort -rn | head -20

# Successful logins from unusual IPs
grep "LOGIN_OK" /var/log/vsp/audit.log | \
  awk -F'|' '{print $5}' | sort | uniq -c | sort -rn | head -20
```

### 5. File incident per `docs/security/incident-response.md`

---

## Rotation History

| Date | Rotated By | Reason | Method |
|------|-----------|--------|--------|
| 2026-04-10 | security-team | Initial setup | Single-secret (pre-PR-63) |

---

## Related

- `internal/auth/rotation.go` — dual-secret implementation
- `internal/auth/rotation_test.go` — 10 tests covering rotation paths
- `.env.example` — `JWT_SECRET`, `JWT_SECRET_OLD`, `JWT_TTL`
- `THREAT_MODEL.md` § S — JWT key compromise threat
- `SECURITY.md` — disclosure process

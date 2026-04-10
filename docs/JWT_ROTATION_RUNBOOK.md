# JWT Secret Rotation Runbook

**Frequency:** Every 90 days or immediately after suspected compromise

## Pre-rotation Checklist

- [ ] Schedule maintenance window (15 min)
- [ ] Notify active users (all sessions will be invalidated)
- [ ] Have new secret ready (min 32 chars, cryptographically random)

## Generate New Secret

```bash
# Generate 64-char hex secret
openssl rand -hex 32

# Or base64
openssl rand -base64 48 | tr -d '\n'
```

## Rotation Steps

### 1. Update secret in environment
```bash
# Update .env on each server
JWT_SECRET=<new-secret-here>

# Or in Vault (preferred)
vault kv put secret/vsp/prod jwt_secret=<new-secret>
```

### 2. Rolling restart (zero-downtime)
```bash
# If running multiple instances behind load balancer:
# 1. Update instance 1, restart, verify health
# 2. Update instance 2, restart, verify health

# Single instance:
sudo systemctl restart vsp-gateway
# or
bash ~/Data/GOLANG_VSP/start.sh
```

### 3. Verify
```bash
curl -s http://localhost:8921/health | jq .status
# Expected: "ok"

# Verify old tokens are rejected
curl -H "Authorization: Bearer <old-token>" \
     http://localhost:8921/api/v1/vsp/runs
# Expected: 401 Unauthorized
```

### 4. Post-rotation
- [ ] All users must re-login (sessions invalidated)
- [ ] Update CI/CD secrets: GitHub → Settings → Secrets → JWT_SECRET
- [ ] Update staging environment
- [ ] Log rotation in audit: `JWT_SECRET_ROTATED` event
- [ ] Update this runbook with rotation date

## Emergency Rotation (Compromise Suspected)

If token is suspected compromised:

```bash
# 1. Rotate immediately — no maintenance window needed
# 2. All sessions invalidated instantly
# 3. Check audit logs for suspicious activity
grep "LOGIN_OK\|LOGIN_FAILED" /var/log/vsp/audit.log | \
  awk -F'|' '{print $1, $4}' | sort | uniq -c | sort -rn | head -20
```

## Rotation History

| Date | Rotated By | Reason |
|------|-----------|--------|
| 2026-04-10 | security-team | Initial setup |

## Related

- THREAT_MODEL.md — JWT Spoofing section
- internal/auth/middleware.go — JWT validation
- .env.example — Environment variables reference

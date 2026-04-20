# VSP Operations Runbook

**Audience:** On-call engineer, SRE, infrastructure team.
**Last updated:** 2026-04-20
**Scope:** Production incident response for VSP Security Platform.

This runbook is the authoritative source for what to do when VSP breaks
in production. If you find yourself improvising during an incident,
update this document after the incident so the next person doesn't have to.

---

## Incident severity levels

| Severity | Definition | Response time | Who gets paged |
|----------|------------|---------------|----------------|
| **SEV-1** | Complete outage (gateway down, data loss, security breach) | 5 min | On-call + eng lead + CEO |
| **SEV-2** | Major degradation (>50% error rate, scanner queue stuck, auth down) | 15 min | On-call + eng lead |
| **SEV-3** | Minor degradation (one scanner down, slow responses, non-critical feature broken) | 1 hour | On-call |
| **SEV-4** | Advisory (CVE disclosed, dependency deprecated) | Next business day | Security lead |

For SEV-1 and SEV-2, start an incident channel immediately:
`[TODO: fill in Slack channel naming convention]`.

---

## Quick commands reference

```bash
# Check gateway health
curl -sf http://localhost:8921/health && echo OK

# Container status
docker compose ps

# Live logs (all services)
docker compose logs -f --tail=100

# Live logs (gateway only)
docker compose logs -f --tail=100 gateway

# Restart gateway (graceful, keeps DB/Redis)
docker compose restart gateway

# Full restart (use when DB/Redis also acting up)
docker compose down && docker compose up -d

# Connect to DB
docker compose exec postgres psql -U vsp -d vsp

# Connect to Redis
docker compose exec redis redis-cli

# Check recent audit log entries (who did what)
docker compose exec postgres psql -U vsp -d vsp \
  -c "SELECT ts, user_id, action, resource, result FROM audit_log ORDER BY seq DESC LIMIT 20;"

# Verify audit log hash chain integrity
curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8921/api/p4/audit/verify
```

---

## Scenario 1: Gateway is down

**Symptoms:**
- `/health` returns 5xx or connection refused
- Users cannot login
- No new findings appearing

### Triage (5 minutes)

```bash
# 1. Is the container running?
docker compose ps gateway
# If "Exit 1" or "Restarting" — check logs:
docker compose logs --tail=200 gateway

# 2. Common causes in logs:
grep -E "panic|fatal|failed to listen|connection refused" <(docker compose logs --tail=500 gateway)

# 3. Is PostgreSQL reachable?
docker compose exec gateway wget -qO- postgres:5432 2>&1 | head -5
# "connection refused" = DB issue (see Scenario 2)

# 4. Is Redis reachable?
docker compose exec gateway redis-cli -h redis ping
# Expected: PONG
```

### Common root causes

| Symptom in logs | Root cause | Fix |
|-----------------|------------|-----|
| `listen tcp :8921: bind: address already in use` | Port conflict | `lsof -i :8921`, kill old process, restart |
| `failed to connect to postgres` | DB down or wrong creds | See Scenario 2 |
| `panic: runtime error: invalid memory address` | Code bug | Revert to last known good image, file SEV-1 |
| `OOM killed` | Memory leak or undersized | Scale up container memory; check `docker stats` |
| `too many open files` | FD leak | Restart gateway; check `ulimit -n` (should be ≥ 65536) |

### Escalation

- If restart doesn't resolve: roll back to previous image tag
  ```bash
  docker compose up -d --no-deps gateway=ghcr.io/.../vsp_security-:sha-<previous>
  ```
- If rollback doesn't resolve: SEV-1, wake eng lead

---

## Scenario 2: Database is down or slow

**Symptoms:**
- Gateway logs: `failed to connect to postgres` or `context deadline exceeded`
- Slow page loads (>5s)
- Background scan queue stopped draining

### Triage

```bash
# 1. PostgreSQL container status
docker compose ps postgres

# 2. Can we connect at all?
docker compose exec postgres pg_isready -U vsp

# 3. Active connections
docker compose exec postgres psql -U vsp -d vsp -c "
SELECT state, count(*)
FROM pg_stat_activity
WHERE datname='vsp' GROUP BY state;"

# If count is near max_connections (default 100), we have connection leak.

# 4. Long-running queries
docker compose exec postgres psql -U vsp -d vsp -c "
SELECT pid, now()-query_start AS duration, state, query
FROM pg_stat_activity
WHERE state != 'idle' AND now()-query_start > interval '30 seconds'
ORDER BY duration DESC LIMIT 10;"

# 5. Disk space
docker compose exec postgres df -h /var/lib/postgresql/data
```

### Common root causes

| Symptom | Root cause | Fix |
|---------|------------|-----|
| Disk >90% full | `audit_log` growing, no cleanup | Run archival: `DELETE FROM audit_log WHERE ts < NOW()-INTERVAL '1 year'` (verify hash chain first!) |
| Many idle-in-transaction | Gateway connection leak | Restart gateway, file P1 ticket to audit `defer rows.Close()` usage |
| Long-running queries | Missing index or bad query plan | `EXPLAIN ANALYZE` the query, add index if appropriate |
| Out of memory | Postgres misconfigured | Check `shared_buffers`, `work_mem` in postgresql.conf |

### Safe recovery actions

```bash
# Kill a single runaway query (not all connections)
docker compose exec postgres psql -U vsp -d vsp \
  -c "SELECT pg_cancel_backend(<pid>);"

# If really stuck: terminate (last resort)
docker compose exec postgres psql -U vsp -d vsp \
  -c "SELECT pg_terminate_backend(<pid>);"

# Rebuild stats if plans are bad
docker compose exec postgres psql -U vsp -d vsp -c "ANALYZE;"
```

### What NOT to do

- ❌ Do not `TRUNCATE audit_log` — breaks hash chain, violates SOC 2
- ❌ Do not `DROP` tables — obvious but documented for audit
- ❌ Do not run `VACUUM FULL` without warning users — locks tables

---

## Scenario 3: Scanner queue stuck

**Symptoms:**
- Scans submitted but never start
- Dashboard shows "Running" for >30 min
- Scanner containers show CPU idle

### Triage

```bash
# 1. Check Redis queue depth
docker compose exec redis redis-cli LLEN vsp:scan_queue

# 2. Check scanner containers
docker compose ps scanner
docker compose logs --tail=200 scanner

# 3. Check scheduler in gateway (scheduler is embedded in gateway)
docker compose logs --tail=200 gateway | grep -i scheduler

# 4. Check tool binaries are available in scanner container
docker compose exec scanner which gosec trivy semgrep gitleaks
```

### Common root causes

| Symptom | Root cause | Fix |
|---------|------------|-----|
| Queue LLEN high, scanner idle | Scanner panicked, not consuming | Restart scanner container |
| Queue LLEN 0, scans still stuck | Gateway not enqueueing | Check gateway logs for enqueue errors |
| Scanner logs "exec: not found" | Tool binary missing | Rebuild scanner image, check Dockerfile |
| Scans hang on one specific tool | Tool crashed, holding stdout | Add timeout to tool wrapper; restart scanner |

---

## Scenario 4: Authentication broken

**Symptoms:**
- Users see 401 on login
- Session cookies not being set
- OIDC flow redirects to error page

### Triage

```bash
# 1. Check JWT secret is set
docker compose exec gateway printenv | grep JWT_SECRET
# Expected: JWT_SECRET=<64 hex chars>. If empty → critical misconfig.

# 2. Check login endpoint directly
curl -v -X POST http://localhost:8921/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@vsp.local","password":"..."}'

# 3. Check OIDC config (if using SSO)
curl -sf http://localhost:8921/api/v1/auth/oidc/providers

# 4. Check gateway logs for auth errors
docker compose logs --tail=200 gateway | grep -iE "auth|login|jwt|oidc"
```

### Common root causes

| Symptom | Root cause | Fix |
|---------|------------|-----|
| All logins 401 | JWT_SECRET rotated but gateway not restarted | Restart gateway |
| OIDC "invalid_client" | OIDC provider creds wrong | Check `OIDC_CLIENT_SECRET` env var, confirm with provider |
| Cookie not in browser | `Secure: true` but connection is HTTP | Ensure TLS in front of gateway (nginx/CF) |
| MFA users stuck after code entry | TOTP clock skew | Check server time (`date`, should match NTP) |

### Emergency auth bypass

**Only if SEV-1 and admin lockout.** Document every use as SD-XXXX.

```bash
# Issue emergency admin token (valid 1 hour)
docker compose exec gateway ./vsp-cli admin token \
  --tenant-id default --role admin --ttl 3600
```

Log the action:
```bash
# After using emergency token, log what you did:
cat >> docs/SECURITY_DECISIONS.md << EOF
## SD-XXXX — Emergency admin token issued

**Date:** $(date -Iseconds)
**Who:** $(whoami)
**Reason:** [fill in]
**Token ID:** [from vsp-cli output]
**Actions taken under this token:** [fill in]
EOF
```

---

## Scenario 5: Disk full

**Symptoms:**
- Postgres write errors
- Container restart loops
- `df -h` shows 100%

### Triage

```bash
# 1. Find the biggest consumers
docker system df
du -sh /var/lib/docker/volumes/* | sort -h | tail -10

# 2. Postgres-specific
docker compose exec postgres psql -U vsp -d vsp -c "
SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables WHERE schemaname='public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC LIMIT 10;"

# 3. Docker logs growth (common culprit)
du -sh /var/lib/docker/containers/*/
```

### Safe cleanup

```bash
# Old Docker images
docker image prune -a --filter "until=720h"

# Truncate container logs (does NOT remove data)
truncate -s 0 /var/lib/docker/containers/*/*-json.log

# Archive old audit entries (preserves hash chain)
# [TODO: write archival script — currently a known gap]
```

### Prevention

- Set up log rotation: `logrotate.conf` already in repo, deploy it
- Set Postgres `log_rotation_age = 1d`, `log_rotation_size = 100MB`
- Archive audit log monthly to cold storage (S3 Glacier, etc.)

---

## Scenario 6: Security incident (suspected breach)

**If you see any of these, treat as SEV-1:**
- Unknown user in `users` table
- `API_KEY_LEAK` finding on VSP's own repo
- Audit log has gaps (hash chain fails verify)
- Unusual outbound traffic from gateway
- Gosec finds unreviewed `//#nosec` annotation

### Immediate actions

1. **Do not restart or wipe anything** — preserve evidence
2. Take DB snapshot: `docker compose exec postgres pg_dump -U vsp vsp > /tmp/incident-$(date +%s).sql`
3. Save container logs: `docker compose logs > /tmp/incident-logs-$(date +%s).txt`
4. Capture running processes: `docker compose exec gateway ps auxf > /tmp/incident-ps.txt`
5. Notify security lead **by phone/signal**, not Slack (Slack may be compromised)
6. Rotate ALL credentials (see `docs/JWT_ROTATION_RUNBOOK.md`)

### Longer-term

7. Follow [SECURITY.md](../SECURITY.md) disclosure process
8. Create post-mortem in `docs/incidents/` (keep template there)
9. If customer data involved, follow breach notification (72h per GDPR Art. 33)

---

## Deployment procedures

### Standard deploy (staging)

Automated — see `.github/workflows/ci.yml` `deploy-staging` job.

### Standard deploy (production)

**Manual, requires 2 approvers.**

```bash
# 1. Verify staging is healthy
curl -sf $STAGING_URL/health && echo OK

# 2. Pull the tagged image on prod host
ssh prod-01 "docker pull ghcr.io/quynhanh1706vp-byte/vsp_security-:v<X.Y.Z>"

# 3. Run migrations (idempotent, safe to re-run)
ssh prod-01 "cd /opt/vsp && goose -dir migrations postgres \$DATABASE_URL up"

# 4. Rolling restart
ssh prod-01 "cd /opt/vsp && docker compose up -d --no-deps gateway"

# 5. Smoke test
for i in 1 2 3 4 5; do
  curl -sf https://vsp.agency.gov/health && echo "Health check $i OK"
  sleep 2
done

# 6. Monitor for 15 min
ssh prod-01 "docker compose logs -f --tail=200 gateway" &
# Watch for error spikes; if any, rollback (step 7)

# 7. Rollback (if needed)
ssh prod-01 "docker pull ghcr.io/.../:v<X.Y.Z-1> && docker compose up -d --no-deps gateway"
ssh prod-01 "cd /opt/vsp && goose -dir migrations postgres \$DATABASE_URL down-to <prev_rev>"
```

---

## Contact list

| Role | Contact | When to escalate |
|------|---------|------------------|
| On-call engineer | `[TODO: fill in pager]` | First responder for SEV-2/3 |
| Eng lead | `[TODO: fill in]` | SEV-1, SEV-2 lasting >30 min |
| Security lead | `[TODO: fill in]` | Suspected breach, CVE response |
| DBA | `[TODO: fill in]` | DB recovery, migration issues |
| CEO/Founder | `[TODO: fill in]` | SEV-1 over 1 hour, customer data incident |

---

## Post-incident

After every SEV-1 or SEV-2:

1. Incident channel summary: timeline, impact, root cause
2. Post-mortem doc in `docs/incidents/YYYY-MM-DD-<short-name>.md`
3. Blameless review meeting within 7 days
4. Action items tracked as JIRA tickets or GitHub issues
5. Update this RUNBOOK with new scenarios or fixes learned
6. If action items affect security posture, add SD-XXXX entry

---

## Change log

- **2026-04-20 v1.0** — Initial runbook. Based on `cmd/gateway/main.go:257`
  health check + `docker-compose.yml` topology + audit_log hash chain design.
  `[TODO]` markers are for team-specific info (contacts, pager, Slack channels).

**Review cadence:** After every incident + quarterly (2026-07-20 next).


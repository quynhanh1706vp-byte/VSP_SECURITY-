# VSP Platform — Production Deployment Guide

## Prerequisites

- Docker 24+ và docker-compose v2
- PostgreSQL 16+ hoặc managed service (RDS, Cloud SQL)
- Redis 7+ hoặc managed service (ElastiCache, Memorystore)
- Domain với TLS certificate
- SMTP server cho email alerts (optional)

---

## 1. Environment Setup

```bash
# Clone repo
git clone https://github.com/vsp/platform
cd platform

# Copy và điền env file
cp .env.example .env
```

Điền các giá trị bắt buộc trong `.env`:

```bash
# BẮTBUỘC — Generate random values
JWT_SECRET=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -base64 24)
REDIS_PASSWORD=$(openssl rand -base64 24)

# Server
SERVER_ENV=production
ALLOWED_ORIGINS=https://your-domain.com
```

---

## 2. Database Setup

```bash
# Khởi động PostgreSQL và Redis trước
docker-compose up -d postgres redis

# Đợi healthy
docker-compose ps

# Migrations chạy tự động khi gateway start
# Verify sau khi start:
docker-compose exec postgres psql -U vsp vsp_go -c "SELECT version_id, is_applied FROM goose_db_version ORDER BY id DESC LIMIT 5;"
```

---

## 3. Deploy

```bash
# Build image
docker build -t vsp-platform:$(git rev-parse --short HEAD) .

# Start tất cả services
docker-compose up -d

# Verify
docker-compose ps
docker-compose logs -f gateway | head -20
```

### Health check
```bash
curl -sf https://your-domain.com/health | jq .
# Expected: {"status":"ok","checks":{"database":{"status":"ok"},...}}
```

---

## 4. Post-deploy

### Tạo admin user
```bash
curl -X POST https://your-domain.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@your-org.com","password":"initialpassword"}'

# Sau đó đổi password ngay
curl -X POST https://your-domain.com/api/v1/auth/password/change \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"current_password":"initialpassword","new_password":"StrongNewPassword123!"}'
```

### Bật MFA cho admin
```bash
# Setup MFA
curl -X POST https://your-domain.com/api/v1/auth/mfa/setup \
  -H "Authorization: Bearer $TOKEN"

# Verify với code từ authenticator app
curl -X POST https://your-domain.com/api/v1/auth/mfa/verify \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code":"123456"}'
```

### Setup SIEM webhook (Slack)
```bash
curl -X POST https://your-domain.com/api/v1/siem/webhooks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"label":"Security Alerts","type":"slack","url":"https://hooks.slack.com/services/xxx","min_sev":"CRITICAL"}'
```

---

## 5. Monitoring

### Prometheus
```yaml
# prometheus.yml
scrape_configs:
  - job_name: vsp-gateway
    static_configs:
      - targets: ['your-domain.com:8921']
    metrics_path: /metrics
```

### Alert rules
```bash
# Copy rules vào Prometheus
cp config/prometheus_rules.yml /etc/prometheus/rules/vsp.yml
systemctl reload prometheus
```

### Key metrics to monitor
- `vsp_gate_decisions_total{decision="FAIL"}` — Gate failures
- `vsp_findings_current{severity="CRITICAL"}` — Critical findings count
- `vsp_login_attempts_total{result="failed"}` — Brute force detection
- `vsp_db_pool_connections{state="acquired"}` — DB pool health
- `up{job="vsp-gateway"}` — Server availability

---

## 6. Backup

```bash
# Database backup
docker-compose exec postgres pg_dump -U vsp vsp_go | gzip > backup_$(date +%Y%m%d).sql.gz

# Automated backup (crontab)
0 2 * * * docker-compose exec -T postgres pg_dump -U vsp vsp_go | gzip > /backups/vsp_$(date +\%Y\%m\%d).sql.gz
```

---

## 7. Updates

```bash
# Pull latest
git pull origin main

# Build new image
docker build -t vsp-platform:$(git rev-parse --short HEAD) .

# Rolling update (zero downtime)
docker-compose up -d --no-deps gateway

# Verify migrations ran
curl -sf https://your-domain.com/health | jq .checks
```

---

## 8. Troubleshooting

```bash
# View logs
docker-compose logs -f gateway --tail=100

# Check DB connection
docker-compose exec gateway wget -qO- http://localhost:8921/health

# Force migration re-run
docker-compose exec postgres psql -U vsp vsp_go -c "DELETE FROM goose_db_version WHERE version_id=5;"
docker-compose restart gateway

# Redis connection test
docker-compose exec redis redis-cli -a $REDIS_PASSWORD ping

# Kill hung connections
docker-compose exec postgres psql -U vsp vsp_go -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state='idle' AND query_start < NOW() - INTERVAL '10 minutes';"
```

---

## 9. Security Checklist

- [ ] JWT_SECRET được set (không phải default)
- [ ] POSTGRES_PASSWORD mạnh
- [ ] REDIS_PASSWORD được set
- [ ] MFA bật cho tất cả admin accounts
- [ ] CORS chỉ allow domain production
- [ ] TLS/HTTPS được cấu hình
- [ ] Firewall chỉ expose port 443 (qua reverse proxy)
- [ ] pprof endpoint disabled (`server.env=production`)
- [ ] SMTP configured cho incident alerts
- [ ] Prometheus metrics endpoint secured (chỉ internal network)
- [ ] Backup tự động được setup
- [ ] Log retention configured

---

## 10. Rollback

```bash
# Nếu có vấn đề sau deploy
git log --oneline -5  # Tìm commit trước

# Rollback code
git checkout <previous-commit>
docker build -t vsp-platform:rollback .
docker-compose up -d --no-deps gateway

# Rollback migration (nếu cần)
docker-compose exec gateway /vsp-gateway migrate-down
```

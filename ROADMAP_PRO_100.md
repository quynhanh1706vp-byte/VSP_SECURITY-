# VSP — Roadmap đẩy lên 100% mức pro DevSecOps

**File này tổng hợp toàn bộ những gì cần làm để VSP đạt mức "pro chuyên ngành" ngang Wiz / Snyk / Prisma Cloud / SonarQube combined.**
Build target: 2026-Q3.

---

## 0. Cách dùng `vsp_pro_100.js`

```html
<!-- Thêm dòng này TRƯỚC </body> trong index.html (và các trang khác nếu muốn) -->
<script src="vsp_pro_100.js"></script>
```

Patch tự động:
- Inject thêm 1 nav-section "Cloud-native security PRO" với 9 module mới phía trên section Reports
- Mở mỗi module bằng overlay full-width, không đụng tới `showPanel()` cũ
- Mặc định dùng mock data sạch — khi backend có endpoint thật sẽ tự fetch (hàm `api()` trong file đã handle graceful degrade)
- Không sửa, không xoá, không động tới state hiện tại của app

---

## 1. Bảng đối chiếu 21 nhóm tính năng — trước & sau patch

| # | Hạng mục | Trước | Sau patch v1 | Còn cần backend |
|---|---|---|---|---|
| 1 | SAST/SCA/Secrets | Pro ✓ | Pro ✓ | — |
| 2 | IaC scanning | Pro ✓ | Pro ✓ | — |
| 3 | Compliance/RMF/OSCAL | Pro ✓ (vượt) | Pro ✓ | — |
| 4 | SOAR/playbooks | Pro ✓ | Pro ✓ | — |
| 5 | SIEM ingestion | Pro ✓ | Pro ✓ | — |
| 6 | Threat intel/UEBA | Pro ✓ | Pro ✓ | — |
| 7 | DAST | Polish ⚠ | Polish ⚠ | nuclei/ZAP runner real |
| 8 | SBOM | Polish ⚠ | **Pro ✓** (diff UI thêm) | endpoint `/sbom/diff` đã có |
| 9 | Auto-remediation | Polish ⚠ | Polish ⚠ | status state-machine |
| 10 | RASP | Polish ⚠ | Polish ⚠ | SSE thay vì poll |
| 11 | Scheduler | Polish ⚠ | Polish ⚠ | wire UI ↔ cron backend |
| 12 | RBAC | Polish ⚠ | Polish ⚠ | custom roles |
| 13 | **Container/k8s scan** | Gap ✗ | **Pro ✓** UI | Trivy image runner |
| 14 | **CSPM (cloud posture)** | Gap ✗ | **Pro ✓** UI | Steampipe / Cloud Custodian |
| 15 | **Supply chain SLSA** | Gap ✗ | **Pro ✓** UI | cosign + in-toto runner |
| 16 | **PR/repo bot** | Gap ✗ | **Pro ✓** UI | GitHub App + webhook |
| 17 | **Secret vault** | Gap ✗ | **Pro ✓** UI | Vault/KMS connector |
| 18 | **Multi-tenant** | Gap ✗ | **Pro ✓** UI | DB row-level security |
| 19 | **SSO SAML/OIDC** | Gap ✗ | **Pro ✓** UI | dex/keycloak proxy |
| 20 | **Observability** | Gap ✗ | **Pro ✓** UI | `/metrics` endpoint + OTel SDK |
| 21 | SBOM diff UI | Gap ✗ | **Pro ✓** | — đã xong |

**Score:** 6 pro → 16 pro (76%). Còn 5 cell "polish" cần fix backend ~1-2 sprint nữa là 100%.

---

## 2. Backend cần build — checklist theo độ ưu tiên

### P0 — phải có ngay (tuần 1-2)

#### 2.1 Container image scanning
```bash
# Tạo runner mới
mkdir -p /opt/vsp/runners/container
cat > /opt/vsp/runners/container/scan.sh <<'EOF'
#!/bin/bash
IMAGE=$1
mkdir -p /var/vsp/results/$VSP_RID
trivy image --format cyclonedx --output /var/vsp/results/$VSP_RID/sbom.cdx.json $IMAGE
trivy image --format json      --output /var/vsp/results/$VSP_RID/cves.json     $IMAGE
syft  $IMAGE -o spdx-json    > /var/vsp/results/$VSP_RID/sbom.spdx.json
grype $IMAGE -o json          > /var/vsp/results/$VSP_RID/grype.json
EOF
chmod +x /opt/vsp/runners/container/scan.sh
```

**API endpoint cần thêm trong `openapi.yaml`:**
```yaml
/api/v1/container/scan:
  post:
    summary: Scan container image
    tags: [Container]
    requestBody:
      content:
        application/json:
          schema:
            type: object
            required: [image]
            properties:
              image:    { type: string, example: "vsp/api:v1.4.2" }
              registry: { type: string }
              auth:     { type: object }

/api/v1/container/images:
  get:
    summary: List scanned images with vulnerability summary
    tags: [Container]

/api/v1/container/policy:
  get:
    summary: Get admission control policies (Kyverno / OPA)
  post:
    summary: Create admission policy
```

**Frontend hook:** Module `cwpp` trong `vsp_pro_100.js` đang mock — đổi `render()` để gọi `await api('/api/v1/container/images')`.

---

#### 2.2 SLSA / cosign signing
```bash
# Trong CI/CD pipeline (GitHub Actions example)
- name: Build & sign with cosign
  run: |
    docker build -t $IMG .
    cosign sign --key env://COSIGN_KEY $IMG
    syft $IMG -o cyclonedx-json > sbom.json
    cosign attest --predicate sbom.json --type cyclonedx --key env://COSIGN_KEY $IMG
    # SLSA provenance (slsa-github-generator)
    cosign attest --predicate provenance.json --type slsaprovenance --key env://COSIGN_KEY $IMG
```

**Endpoint mới:**
```yaml
/api/v1/supplychain/builds:
  get: { summary: List recent builds with SLSA level }

/api/v1/supplychain/verify:
  post:
    summary: Verify image signature + attestations
    requestBody:
      content:
        application/json:
          schema:
            type: object
            properties:
              image: { type: string }
              key:   { type: string }

/api/v1/supplychain/policy:
  get:  { summary: Get admission verification policy }
  post: { summary: Update verification policy }
```

---

#### 2.3 PR bot — GitHub App
File `.github/vsp-bot/app.yaml`:
```yaml
name: VSP Security Bot
description: Inline security comments on pull requests
permissions:
  pull_requests: write
  checks:        write
  contents:      read
events:
  - pull_request
  - check_suite
webhook_url: https://vsp.local/api/v1/webhooks/github
```

**Webhook handler cần build:**
```python
# vsp/webhooks/github.py
@app.post("/api/v1/webhooks/github")
def github_webhook(req):
    if req.event == "pull_request":
        run_id = enqueue_scan(req.repo, req.head_sha)
        post_check_status(req.pr_url, "pending", "VSP scanning…")

    if req.event == "scan_complete":
        for finding in get_findings(run_id):
            post_inline_comment(
                pr=req.pr,
                file=finding.path,
                line=finding.line,
                body=f"**{finding.severity}** · {finding.rule}\n{finding.message}"
            )
        gate = compute_gate(run_id)
        post_check_status(req.pr_url, "failure" if gate=="FAIL" else "success", f"Gate: {gate}")
```

---

#### 2.4 SSO — dex auth proxy
```yaml
# docker-compose.yml addition
dex:
  image: ghcr.io/dexidp/dex:v2.39.0
  ports: ["5556:5556"]
  volumes:
    - ./dex.yaml:/etc/dex/cfg/config.yaml
```

`dex.yaml`:
```yaml
issuer: https://vsp.local/dex
storage: { type: postgres, config: { ... } }
connectors:
- type: saml
  id:   okta
  name: Okta
  config:
    ssoURL: https://vsp.okta.com/app/.../sso/saml
    ca:     /etc/dex/okta-ca.pem
    redirectURI: https://vsp.local/api/v1/auth/callback
- type: oidc
  id:   azure
  name: Azure AD
  config:
    issuer:       https://login.microsoftonline.com/{TENANT_ID}/v2.0
    clientID:     ${AZURE_CLIENT_ID}
    clientSecret: ${AZURE_CLIENT_SECRET}
```

**VSP gateway đổi auth middleware:**
```go
// thay JWT-only bằng dual support
func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if claims, ok := verifyDexToken(r); ok {
            r = r.WithContext(context.WithValue(r.Context(), userKey, claims))
        } else if claims, ok := verifyJWT(r); ok {
            r = r.WithContext(context.WithValue(r.Context(), userKey, claims))
        } else {
            http.Error(w, "unauthorized", 401); return
        }
        next.ServeHTTP(w, r)
    })
}
```

---

### P1 — sprint sau (tuần 3-4)

#### 2.5 CSPM scanner — multi-cloud
```python
# Dùng Steampipe SDK
import steampipe

def scan_aws_account(account_id):
    sp = steampipe.connect()
    findings = []
    findings += sp.query("""
        SELECT name, region FROM aws_s3_bucket
        WHERE bucket_policy_is_public = true
    """).map(lambda r: Finding(rule="S3 publicly accessible", resource=r.name, sev="CRITICAL"))
    findings += sp.query("""
        SELECT name FROM aws_iam_user
        WHERE mfa_enabled = false AND attached_policy_arns @> '["arn:aws:iam::aws:policy/AdministratorAccess"]'
    """).map(lambda r: Finding(rule="IAM admin without MFA", resource=r.name, sev="CRITICAL"))
    return findings
```

Cron mỗi 15 phút quét 4 cloud, đẩy findings vào pipeline chính.

---

#### 2.6 Multi-tenant — DB row-level security
```sql
-- Postgres RLS
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
CREATE POLICY findings_tenant_isolation ON findings
  USING (tenant_id = current_setting('vsp.current_tenant')::uuid);

ALTER TABLE runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY runs_tenant_isolation ON runs
  USING (tenant_id = current_setting('vsp.current_tenant')::uuid);

-- Mỗi connection set tenant từ JWT:
SET vsp.current_tenant = '<uuid>';
```

Middleware Go:
```go
func tenantMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        tid := r.Context().Value(userKey).(*Claims).TenantID
        db.Exec("SET vsp.current_tenant = $1", tid)
        next.ServeHTTP(w, r)
    })
}
```

---

#### 2.7 Observability — Prometheus + OTel
```go
// thêm vào main.go
import (
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "go.opentelemetry.io/otel"
    sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func main() {
    // Prometheus
    http.Handle("/metrics", promhttp.Handler())

    // OTel
    exp, _ := otlptracehttp.New(context.Background())
    tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp))
    otel.SetTracerProvider(tp)

    // Wrap handler:
    handler := otelhttp.NewHandler(mux, "vsp-api")
    http.ListenAndServe(":8921", handler)
}
```

Custom metrics cần expose:
- `vsp_scan_duration_seconds{mode,profile}` (histogram)
- `vsp_findings_total{severity,tool}` (counter)
- `vsp_gate_decisions_total{decision}` (counter)
- `vsp_active_runs` (gauge)
- `vsp_remediation_success_total` (counter)
- `vsp_sbom_components_total` (gauge)

---

### P2 — quarterly (tuần 5-8)

#### 2.8 Secret vault — Vault Agent integration
```hcl
# vault-agent.hcl
auto_auth {
  method "approle" {
    config = { role_id_file_path = "/etc/vsp/role-id"; secret_id_file_path = "/etc/vsp/secret-id" }
  }
  sink "file" { config = { path = "/run/vsp/token" } }
}
template {
  source      = "/etc/vsp/templates/db.tmpl"
  destination = "/run/vsp/db.env"
  command     = "systemctl reload vsp"
}
```

Auto-revoke loop:
```python
async def watch_secrets():
    while True:
        for finding in await scanner.find_secrets():
            if finding.confidence > 0.85:
                await vault.revoke(finding.secret_id)
                await notify_owner(finding.repo, finding.owner)
                await create_incident(finding)
        await asyncio.sleep(30)
```

---

#### 2.9 Auto-remediation state-machine
```
new ──assign──▶ assigned ──work──▶ in_progress ──fix──▶ resolved ──verify──▶ closed
                    │                    │                  │
                    └──reject──▶ rejected (with reason) ────┘
                                                    ──reopen──▶ assigned (if regression)
```

DB schema:
```sql
CREATE TABLE remediation_state (
  finding_id UUID PRIMARY KEY,
  state      TEXT NOT NULL CHECK (state IN ('new','assigned','in_progress','resolved','closed','rejected')),
  assignee   TEXT,
  resolved_at TIMESTAMPTZ,
  closed_at   TIMESTAMPTZ,
  state_history JSONB DEFAULT '[]'
);
```

---

#### 2.10 RASP live SSE
```go
func raspStream(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")
    ch := raspBus.Subscribe()
    defer raspBus.Unsubscribe(ch)
    for {
        select {
        case event := <-ch:
            fmt.Fprintf(w, "event: rasp\ndata: %s\n\n", event.JSON())
            w.(http.Flusher).Flush()
        case <-r.Context().Done():
            return
        }
    }
}
```

Frontend:
```js
const sse = new EventSource('/api/v1/rasp/stream');
sse.addEventListener('rasp', (e) => {
    const event = JSON.parse(e.data);
    appendToTable(event);
});
```

---

#### 2.11 Scheduler ↔ backend wiring
Backend đã có endpoint trong `scheduler.html`:
- `PATCH /api/v1/schedules/{id}/toggle`
- `POST /api/v1/schedules/{id}/run`

Nhưng chưa có: `GET /api/v1/schedules`, `POST /api/v1/schedules`, `DELETE /api/v1/schedules/{id}`. Cần build CRUD + cron daemon (apscheduler hoặc gocron).

---

## 3. Acceptance criteria — 100% pro

Định nghĩa "100% pro" của VSP:

- [ ] Tất cả 21 hạng mục trong bảng đạt **Pro ✓**
- [ ] Có demo flow end-to-end: commit code → PR → scan → block CI → ticket → remediation → verify → close
- [ ] Có demo SLSA L3: build artifact → cosign sign → in-toto attest → admission verify → deploy
- [ ] Có ít nhất 2 tenant production chạy song song với data hoàn toàn isolated (verified bằng SQL pen-test)
- [ ] SSO SAML round-trip với Okta, OIDC với Azure AD
- [ ] Prometheus scrape /metrics OK, Grafana dashboard có 5 SLO panels
- [ ] Container image scan trong < 60s cho image < 500MB
- [ ] CSPM quét 1 AWS account < 5 phút, có > 80 rules CIS
- [ ] Pen-test bên ngoài: 0 CRITICAL, < 3 HIGH
- [ ] Documentation đầy đủ trong `docs.html` cho 7 module mới

---

## 4. Effort estimate

| Module | Backend (dev-day) | Test (dev-day) | Tổng |
|---|---|---|---|
| Container scan | 5 | 2 | 7 |
| CSPM | 8 | 3 | 11 |
| SLSA + cosign | 6 | 2 | 8 |
| PR bot (GitHub App) | 7 | 3 | 10 |
| Secret vault | 5 | 2 | 7 |
| Multi-tenant RLS | 8 | 4 | 12 |
| SSO (dex) | 4 | 2 | 6 |
| Observability | 3 | 1 | 4 |
| Auto-remediation FSM | 4 | 2 | 6 |
| RASP SSE | 2 | 1 | 3 |
| Scheduler CRUD | 3 | 1 | 4 |
| Polish 5 cell còn lại | 5 | 2 | 7 |
| **Total** | **60** | **25** | **85 dev-day** |

≈ **17 tuần** với 1 dev full-time, hoặc **8-9 tuần** với 2 dev.

---

## 5. Việc cần làm ngay hôm nay (30 phút)

1. Copy `vsp_pro_100.js` vào root project (cùng cấp với `index.html`)
2. Thêm `<script src="vsp_pro_100.js"></script>` ngay trước `</body>` trong `index.html`
3. Reload trang → kiểm tra sidebar có thêm section "Cloud-native security PRO" với 9 mục mới
4. Click thử từng mục để xem UI
5. Commit với message: `feat(pro): add 9 cloud-native security modules (UI scaffold)`
6. Mở backlog issue cho từng P0 item ở section 2

Sau khi merge `vsp_pro_100.js`, VSP đã chuyển từ **65% pro → 76% pro** chỉ với 1 file frontend. Phần còn lại 24% là backend integration theo roadmap section 2.

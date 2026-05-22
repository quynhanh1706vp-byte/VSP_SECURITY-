PRO Modules Improvements (tóm tắt)
=================================

Mục tiêu: biến các module PRO từ mock → dữ liệu thật, chuẩn hoá UX (overlay giống panel) và ưu tiên các tính năng cần nâng cấp.

1) CWPP — Container & Kubernetes security (Ưu tiên: High)
- Tình trạng hiện tại: UI mock trong `static/js/vsp_pro_100.js`; đã có patch realapi `static/js/vsp_pro_cwpp_realapi.js`.
- Endpoints đề xuất (backend):
  - GET `/api/v1/container/images` → [{id, ref, os, os_version, size_mb, layers, crit, high, med, low, signed, sbom_attested, status, scanned_at, total_cve}]
  - POST `/api/v1/container/scan`  body:{ref} → {id, image, queued}
  - POST `/api/v1/container/seed`  → seeds demo images (dev only)
  - GET `/api/v1/container/scan/{id}` → {image, vulnerabilities:[{cve,severity,package,installed}]}
- Nhiệm vụ kỹ thuật: validate JSON schema, trả 401 khi cần auth, cung cấp CORS same-origin.
- Kiểm thử (local):
  - `curl -X POST -H "Content-Type: application/json" -d '{"ref":"nginx:1.25"}' http://localhost:8921/api/v1/container/scan`
  - `curl http://localhost:8921/api/v1/container/images`

2) CSPM — Cloud Security Posture (Ưu tiên: High)
- Tình trạng: mock accounts + findings in `vsp_pro_100.js`.
- Endpoints đề xuất:
  - GET `/api/v1/cspm/accounts`
  - GET `/api/v1/cspm/findings?account=<id>`
  - POST `/api/v1/cspm/auto_fix` (kickoff remediation run)
- Cải tiến: connectors với AWS/Azure/GCP, lịch sử drift, audit trail cho auto-fix.

3) Software supply chain — SLSA (Ưu tiên: High)
- Tình trạng: SLSA matrix + sample builds present.
- Endpoints đề xuất:
  - GET `/api/v1/builds?limit=N`
  - GET `/api/v1/builds/{id}/provenance` (return provenance JSON)
  - POST `/api/v1/slsa/verify` (verify cosign/provenance)
- Cải tiến: thực thi cosign verification, tie to CI, surface missing SLSA controls.

4) PR / repo bot (Ưu tiên: Medium)
- Tình trạng: mock PRs + inline comments.
- Endpoints đề xuất:
  - GET `/api/v1/prs?state=open`
  - GET `/api/v1/prs/{id}`
  - POST `/api/v1/prs/{id}/comments` (post bot comment)
- Cải tiến: integrate GitHub/GitLab webhooks, actionable auto-fix PRs.

5) Secret vault (Ưu tiên: High)
- Tình trạng: rotation/incident UI mocked.
- Endpoints đề xuất:
  - GET `/api/v1/secrets`
  - POST `/api/v1/secrets/{name}/rotate`
  - POST `/api/v1/secrets/{name}/revoke`
  - Audit log: GET `/api/v1/secrets/logs?name=`
- Cải tiến: no-values-in-UI, RBAC on rotation, provider connectors (Vault/KMS).

6) Observability / Continuous Monitoring (Ưu tiên: Medium)
- Tình trạng: SLOs + sample metrics.
- Endpoints / integrations:
  - Proxy metrics: `/api/v1/metrics` → forward to Prometheus
  - Traces: `/api/v1/traces?service=` (OTel backend)
  - SLO config: GET/POST `/api/v1/slo`
- Cải tiến: live charts, alert config, link to traces, burn-rate alerts.

7) Tenants (Ưu tiên: Medium)
- Tình trạng: tenant directory mock.
- Endpoints:
  - GET `/api/v1/tenants`
  - POST `/api/v1/tenants/{id}/switch` (set session tenant)
  - Tenant quota / ATO endpoints.

8) SSO / Identity (Ưu tiên: Medium)
- Tình trạng: IdP list, attribute mapping UI.
- Endpoints:
  - GET `/api/v1/auth/idps`
  - POST `/api/v1/auth/idp/test` (test login)
  - SCIM: `/api/v1/scim/*` for provisioning
- Cải tiến: SCIM provisioning, downloadable metadata, test/troubleshoot flow.

UX / Quick wins
- Đã làm: chỉnh CSS overlay để `PRO` overlay trông gần giống panel (đã patch `static/js/vsp_pro_100.js`).
- Thêm ngay: nút "Open full page" trên mỗi overlay module để chuyển tới trang panel đầy đủ.
- Kỹ thuật UX: thêm timestamp "last updated", empty-state hành vi, banner lỗi backend (đã dùng trong cwpp patch), and consistent action button styles.

Implementation checklist (minimal PRs)
- PR #1 (small): CSS + add "Open full page" link to overlay header (frontend-only).
- PR #2 (medium): `cwpp` realapi wiring + JSON schema + example backend mocks (tests). (đã bắt đầu: `static/js/vsp_pro_cwpp_realapi.js`)
- PR #3 (medium): CSPM connectors + findings API.
- PR #4 (medium): Supply-chain provenance + cosign verify endpoints.
- PR #5 (small): SSO SCIM and IdP test endpoints.

Next steps tôi có thể làm cho bạn (chọn):
- A: Tự động chuyển `cwpp` overlay → full-page panel (migrate UI + route).
- B: Wire `cspm` → call `/api/v1/cspm/accounts` with live fallback.
- C: Giúp viết mock backend handlers (Go) cho các endpoints trên để dev-stub dùng ngay.

---
Tôi có thể tạo PR / patch cho lựa chọn A/B/C. Bạn muốn tôi làm tiếp phần nào? 

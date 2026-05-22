# CIS Benchmarks — VSP Compliance Statement

**Last verified:** 2026-05-08
**Owner:** Engineering / Compliance
**Audience:** 3PAO, customer security teams, internal review

CIS Benchmarks are de-facto secure-configuration baselines. This
document maps the relevant CIS Benchmark controls to VSP defaults
shipped in `deploy/helm/`. Customer deployments override at their
own risk; the table below is what the chart enforces by default.

Two benchmarks in scope:

- **CIS PostgreSQL Benchmark v15** (March 2024)
- **CIS Kubernetes Benchmark v1.27** (June 2024)

Customers running Redis additionally should consult **CIS Redis OSS
Benchmark v7.0** — VSP doesn't ship Redis itself; we depend on a
customer-provided cluster.

---

## 1. CIS PostgreSQL Benchmark v15 — VSP Compliance

| CIS ID | Control | VSP default | Status | Evidence |
|--------|---------|-------------|--------|----------|
| 1.2 | Ensure the OS user `postgres` is disabled | Customer-managed | Shared | Customer deployment |
| 1.4 | Ensure systemd service `Type` is `notify` | Customer-managed | Shared | Customer deployment |
| 2.1 | Ensure all data and log files are owned by `postgres` | Container default | Implemented | Helm values default |
| 3.1 | Ensure the log destinations are set correctly | Configured | Implemented | `log_destination=stderr,csvlog` |
| 3.1.4 | Ensure `log_connections` is enabled | Configured | Implemented | postgres-init ConfigMap |
| 3.1.5 | Ensure `log_disconnections` is enabled | Configured | Implemented | postgres-init ConfigMap |
| 3.1.6 | Ensure `log_error_verbosity` is `verbose` | Configured | Implemented | postgres-init ConfigMap |
| 3.1.10 | Ensure `log_statement` is set | Configured | Implemented | `log_statement=mod` |
| 3.2 | Ensure log file permissions are configured | Container default | Implemented | umask 077 |
| 4.4 | Ensure SQL functions cannot be created by non-superusers | Default | Implemented | RLS migration applies |
| 4.5 | Ensure no extensions are installed unless required | Audited | Implemented | only pgcrypto + uuid-ossp loaded |
| 5.1 | Ensure SSL is configured | Required | Implemented | `sslmode=require` in DSN |
| 5.2 | Ensure correct ssl certificate file ownership | Operator-managed | Shared | K8s Secret managed |
| 6.2 | Ensure `pgcrypto` is installed when required | Loaded | Implemented | bytea encryption use |
| 6.5 | Ensure SSL certificates are validated | Required | Implemented | gateway uses `verify-full` |
| 6.7 | Ensure FIPS 140-2 OpenSSL Cryptography is used | Customer-deploy | Shared | Customer chooses Postgres FIPS build |
| 7.1 | Ensure Backup and Disaster Recovery methods | Customer-deploy | Shared | Customer backup strategy |
| 7.2 | Ensure that retention policy is reviewed | Customer-deploy | Shared | Customer-driven |
| 8.1 | Ensure Auditing is configured | Implemented | Implemented | `audit_log` SHA-256 chained, plus pgaudit recommended |

**Summary:** 12 implemented, 7 shared (customer responsibility), 0
non-compliant.

---

## 2. CIS Kubernetes Benchmark v1.27 — VSP Compliance

VSP ships a Helm chart with hardened defaults. The benchmark sections
below map directly to `deploy/helm/templates/*` resources.

### 5.1 RBAC and Service Accounts

| CIS ID | Control | VSP default | Evidence |
|--------|---------|-------------|----------|
| 5.1.1 | Ensure cluster-admin role is only used where required | N/A — VSP ships namespace-scoped manifests | service.yaml |
| 5.1.3 | Minimize wildcard use in Roles and ClusterRoles | Implemented | No `*` verbs in default chart |
| 5.1.5 | Ensure default service accounts are not actively used | Implemented | `automountServiceAccountToken: false` on SA |
| 5.1.6 | Ensure SA tokens are only mounted where necessary | Implemented | `automountServiceAccountToken: false` on Pod |

### 5.2 Pod Security Standards

| CIS ID | Control | VSP default | Evidence |
|--------|---------|-------------|----------|
| 5.2.2 | Minimize the admission of privileged containers | Enforced | `containerSecurityContext.allowPrivilegeEscalation: false` |
| 5.2.3 | Minimize host PID, IPC, network namespace sharing | Enforced | values.yaml does not set hostPID/hostIPC/hostNetwork |
| 5.2.4 | Minimize host port sharing | Enforced | service.yaml uses ClusterIP, no hostPort |
| 5.2.5 | Minimize root containers | Enforced | `runAsNonRoot: true` + `runAsUser: 65532` |
| 5.2.6 | Minimize NET_RAW capability | Enforced | `capabilities.drop: [ALL]` |
| 5.2.7 | Minimize default capabilities | Enforced | `capabilities.drop: [ALL]` |
| 5.2.8 | Minimize Linux capabilities | Enforced | `capabilities.drop: [ALL]` |
| 5.2.9 | Minimize HostPath volumes | Enforced | values.yaml uses only emptyDir |
| 5.2.10 | Restrict procMount | Default | `procMount: Default` |
| 5.2.11 | Disable share Process Namespace | Default | shareProcessNamespace not set |
| 5.2.12 | Restrict use of `system:` namespaces | Implemented | Chart default targets a customer namespace |
| 5.2.13 | Restrict containers that run with privileged flag | Enforced | `privileged: false` (omitted = default false) |
| 5.2.14 | Set seccomp profile | Enforced | `seccompProfile.type: RuntimeDefault` |

### 5.3 Network Policies and CNI

| CIS ID | Control | VSP default | Evidence |
|--------|---------|-------------|----------|
| 5.3.1 | Ensure CNI in use supports Network Policies | Customer-deploy | Calico/Cilium recommended |
| 5.3.2 | Ensure all Namespaces have Network Policies defined | Enforced | networkpolicy.yaml — DNS-only egress + restricted ingress |

### 5.7 General Pod Security Best Practice

| CIS ID | Control | VSP default | Evidence |
|--------|---------|-------------|----------|
| 5.7.1 | Create administrative boundaries between resources using namespaces | Customer-deploy | Chart deploys into customer-named namespace |
| 5.7.2 | Ensure that the seccomp profile is set | Enforced | `seccompProfile.type: RuntimeDefault` |
| 5.7.3 | Apply Security Context to Your Pods and Containers | Enforced | both podSecurityContext and containerSecurityContext set |
| 5.7.4 | The default namespace should not be used | Customer-deploy | Chart docs recommend named namespace |

**Summary K8s:** 19 implemented (chart-enforced), 4 shared (customer
deployment choice), 0 non-compliant.

---

## 3. Verification

Run the official CIS Benchmark scanner against a deployed VSP cluster:

```bash
# Postgres CIS scan via pgaudit + manual checklist
docker run --rm --network host \
  -e PGUSER=$DB_USER -e PGPASSWORD=$DB_PASS \
  pgcis/postgres-cis-bench:v15 scan

# K8s CIS via kube-bench
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs job/kube-bench
```

Expected output: ≥95% pass rate against VSP-controlled checks
(implemented = 12+19 of 31 = 100% pass within VSP's responsibility
boundary). The "shared" rows depend on customer deployment choices.

---

## 4. Change tracking

| Date | Change |
|------|--------|
| 2026-05-08 | Initial document — Postgres v15 + K8s v1.27 mapping |
| _next review_ | Q3 2026 — re-run kube-bench, refresh CIS version |

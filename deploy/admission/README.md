# VSP K8s Admission Controller Policies

Two policy engines supported — pick one based on what your cluster
already runs:

- **Kyverno** (`kyverno/`) — declarative YAML policies, no Rego required.
  Easier to read; stronger ecosystem for K8s-native workloads.
- **OPA Gatekeeper** (`opa-gatekeeper/`) — Rego-based; more flexible
  for cross-resource policies; required if your org already uses OPA.

Both express the **same VSP-mandated policies**:

| # | Policy | Why |
|---|--------|-----|
| 1 | `vsp-deny-unsigned-images` | Block deployments referencing images not signed by VSP cosign key — closes supply-chain gap |
| 2 | `vsp-require-non-root` | Refuse pods running as root (uid 0); enforce CIS K8s 5.2.5 |
| 3 | `vsp-require-readonly-rootfs` | Refuse pods without `readOnlyRootFilesystem: true` (CIS 5.2.x) |
| 4 | `vsp-require-resource-limits` | Refuse pods without CPU + memory limits |
| 5 | `vsp-deny-host-namespaces` | Refuse hostNetwork / hostPID / hostIPC (CIS 5.2.3) |
| 6 | `vsp-require-runtime-default-seccomp` | Enforce `seccompProfile.type: RuntimeDefault` (CIS 5.7.2) |
| 7 | `vsp-deny-privileged-containers` | Refuse `securityContext.privileged: true` |
| 8 | `vsp-vault-required-in-prod` | Refuse pods using `VSP_SECRETS_PROVIDER=env` in `prod` namespaces |

## Installation

### Kyverno path (recommended for new clusters)

```bash
# Install Kyverno (one-time)
kubectl create -f https://github.com/kyverno/kyverno/releases/download/v1.11.0/install.yaml

# Apply VSP policies
kubectl apply -f deploy/admission/kyverno/
```

### OPA Gatekeeper path

```bash
# Install Gatekeeper (one-time)
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml

# Install ConstraintTemplates (resource definitions)
kubectl apply -f deploy/admission/opa-gatekeeper/templates/

# Wait for templates to register, then apply Constraints
kubectl apply -f deploy/admission/opa-gatekeeper/constraints/
```

## Verifying policies are active

```bash
# Try to deploy a non-compliant pod — should be REJECTED
kubectl run badpod --image=nginx --restart=Never --dry-run=server
# Expected: error from server: admission webhook ... denied the request

# Verify VSP gateway still deploys (compliant Helm chart)
helm install vsp-test deploy/helm/ --dry-run
# Expected: success — Helm chart values match all policies
```

## Reporting violations

Violations show up in:

- `kubectl get policyreport -A` (Kyverno)
- `kubectl describe constraint -A` (Gatekeeper)
- VSP audit log if the K8s cluster has the audit webhook configured
  to forward to `POST /api/v1/security/disclose`

## Maintenance

These policies are version-pinned to VSP 1.4. When upgrading:

1. Test new VSP Helm chart against old policies in staging
2. Update policies if VSP introduces new SecurityContext requirements
3. Roll out policy update + Helm upgrade together

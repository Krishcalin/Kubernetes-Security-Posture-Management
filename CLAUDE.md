# CLAUDE.md — Kubernetes Security Posture Management (KSPM) Scanner

## Project Identity

- **Repository**: `Kubernetes-Security-Posture-Management`
- **Scanner file**: `kspm_scanner.py`
- **Version**: 2.0.0
- **Language**: Python 3.8+
- **Dependency**: `kubernetes` (Python client for Kubernetes API)
- **Type**: Agentless live-cluster scanner — queries the Kubernetes API via kubeconfig or in-cluster config
- **License**: MIT

## Architecture

### Core Pattern

The scanner follows the same architecture as the broader Security Audit Scanner collection:

```
Finding class  →  KSPMScanner class  →  CLI (argparse)
                    ├── _check_rbac()
                    ├── _check_workloads()      → _check_pod_spec()
                    ├── _check_network_security()
                    ├── _check_namespace_security()
                    ├── _check_secret_management()
                    ├── _check_service_accounts()
                    ├── _check_cluster_config()
                    ├── _check_persistent_volumes()
                    ├── _check_jobs()
                    ├── _check_admission_control()
                    ├── _check_node_security()        [v1.1.0]
                    ├── _check_pod_disruption_budgets() [v1.1.0]
                    ├── _check_hpa_security()          [v1.1.0]
                    ├── _check_service_mesh()          [v1.1.0]
                    ├── _check_deprecated_apis()       [v1.1.0]
                    ├── _check_runtime_security()      [v1.1.0]
                    ├── _check_advanced_rbac()         [v1.3.0]
                    ├── _check_supply_chain()          [v1.4.0]
                    ├── _check_kyverno_policies()      [v2.0.0]
                    ├── _run_custom_policies()          [v2.0.0]
                    ├── _run_rego_policies()            [v2.0.0]
                    ├── _apply_exceptions()             [v2.0.0]
                    └── _apply_profile()                [v2.0.0]
```

### Key Design Decisions

1. **Agentless**: No pods/DaemonSets deployed to the cluster. Uses `kubernetes` Python client library to query the API server.
2. **Workload-centric**: Scans workload controllers (Deployments, StatefulSets, DaemonSets, Jobs, CronJobs) rather than raw Pods, since controllers are the source of truth.
3. **Finding.file_path repurposed**: For this scanner, `file_path` holds the resource path (`namespace/Kind/name`) and `line_content` holds the config detail string.
4. **Compliance Framework Maps**: Six class-level dicts map rule IDs to framework controls: `CIS_MAP` (CIS Benchmark), `NSA_CISA_MAP` (NSA/CISA Hardening Guide v1.2), `MITRE_MAP` (ATT&CK for Containers), `SOC2_MAP` (Trust Service Criteria), `PCIDSS_MAP` (PCI-DSS v4.0), `NIST_800_190_MAP` (NIST SP 800-190). `_compliance_refs()` returns all framework refs for a rule; `compliance_summary()` computes per-framework coverage stats.
5. **Managed cluster awareness**: API server pod inspection is wrapped in try/except — on EKS/GKE/AKS where kube-apiserver isn't a visible pod, the scanner falls back to informational findings.
6. **System namespace filtering**: `SYSTEM_NAMESPACES` set (`kube-system`, `kube-public`, `kube-node-lease`, `default`) is used to skip noisy findings on system components and flag workloads in `default`.

### Rule ID Convention

Format: `K8S-{CATEGORY}-{NNN}`

| Prefix | Category | Count |
|--------|----------|-------|
| K8S-RBAC | RBAC Security | 15 |
| K8S-POD | Workload / Pod Security | 25 |
| K8S-IMG | Image Security | 5 |
| K8S-NET | Network Security | 10 |
| K8S-NS | Namespace Security | 5 |
| K8S-SECRET | Secret Management | 6 |
| K8S-SA | Service Account Security | 4 |
| K8S-CLUSTER | Cluster Configuration | 10 |
| K8S-PV | Storage Security | 4 |
| K8S-JOB | Job Security | 3 |
| K8S-ADM | Admission Control | 5 |
| K8S-NODE | Node Security | 6 |
| K8S-PDB | Pod Disruption Budgets | 3 |
| K8S-HPA | HPA / Availability | 4 |
| K8S-MESH | Service Mesh | 4 |
| K8S-API | Deprecated APIs | 3 |
| K8S-RC | Runtime Classes | 1 |
| K8S-EPH | Ephemeral Containers | 2 |
| K8S-SC | Supply Chain Security | 10 |
| K8S-KYV | Kyverno Policies | 6 |
| K8S-CUSTOM | Custom YAML Policies | dynamic |
| K8S-REGO | OPA/Rego Policies | dynamic |

### Severity Model

- **CRITICAL**: Immediate cluster compromise risk (privileged containers, cluster-admin bindings, anonymous API access)
- **HIGH**: Significant security gap (root containers, secrets exposure, missing network policies, no audit logging)
- **MEDIUM**: Defense-in-depth gaps (missing resource limits, writable root FS, warn-only PSA)
- **LOW**: Best practice deviations (missing probes, unused SAs, no AppArmor)

### Output Formats

- **Console**: ANSI color-coded, sorted by severity → category → rule_id
- **JSON**: `scanner`, `version`, `generated`, `cluster`, `findings_count`, `summary`, `findings[]`
- **HTML**: Dark theme (Catppuccin palette), Kubernetes blue gradient (#326ce5), JS filter/search
- **SARIF**: v2.1.0 format for GitHub Security tab (`--sarif`)
- **PDF**: Professional report with executive summary (`--pdf`); uses reportlab if available, stdlib fallback otherwise

## Development Guidelines

- Keep the scanner as a **single file** (`kspm_scanner.py`) — no multi-module package
- All checks are **read-only** — never create, modify, or delete any Kubernetes resources
- New rules should follow the `K8S-{CATEGORY}-{NNN}` ID format with sequential numbering
- Every finding must have a non-empty `recommendation` field with actionable remediation
- CWE references are encouraged but optional
- Add CIS Benchmark mapping to `CIS_MAP` when applicable
- System namespaces should be handled carefully — skip noisy checks on system components
- Wrap all API calls in try/except `ApiException` to handle RBAC restrictions gracefully
- Test with `--verbose` flag to ensure proper diagnostic output

## Building and Testing

```bash
# Install dependency
pip install kubernetes

# Run against current kubeconfig
python kspm_scanner.py -v

# Run against specific context with reports
python kspm_scanner.py --context minikube --html report.html --json scan.json

# Filter to critical/high only
python kspm_scanner.py --severity HIGH
```

### Testing Without a Cluster

For development without a live cluster, use:
```bash
# Minikube
minikube start
python kspm_scanner.py --context minikube

# Kind
kind create cluster
python kspm_scanner.py --context kind-kind
```

## Roadmap — Future Enhancements

### v1.1.0 — Expanded Checks (COMPLETE)
- [x] **Node security** (K8S-NODE-001 to 006): Kubelet/K8s version, container runtime version, node health/pressure, topology labels, control plane taints, kernel version
- [x] **Pod Disruption Budgets** (K8S-PDB-001 to 003): Deployments/StatefulSets without PDBs, maxUnavailable=0, minAvailable=100%
- [x] **Horizontal Pod Autoscaler** (K8S-HPA-001 to 004): minReplicas=1, min==max, target without resource requests, no scale-down stabilization
- [x] **Service mesh detection** (K8S-MESH-001 to 004): Istio/Linkerd sidecar injection, mTLS mode (PERMISSIVE/DISABLE), missing AuthorizationPolicy, exposed gateways
- [x] **Deprecated API versions** (K8S-API-001 to 003): 12 deprecated API versions tracked, PodSecurityPolicy remnants, severity based on cluster version
- [x] **Runtime classes** (K8S-RC-001): Non-existent RuntimeClass references, sandboxed runtime detection
- [x] **Ephemeral containers** (K8S-EPH-001 to 002): Active debug containers, privileged ephemeral containers

### v1.2.0 — Compliance Frameworks (COMPLETE)
- [x] **NSA/CISA Kubernetes Hardening Guide** mapping (70+ rules → NSA sections 1-5)
- [x] **MITRE ATT&CK for Containers** mapping (45+ rules → T1190, T1609, T1611, T1613, etc.)
- [x] **SOC 2 Trust Service Criteria** mapping (65+ rules → CC6, CC7, CC8, A1)
- [x] **PCI-DSS v4.0** control mapping (45+ rules → Req 1-11)
- [x] **NIST SP 800-190** (Container Security Guide) mapping (45+ rules → Sections 3.1-3.5)
- [x] **Compliance dashboard** in HTML report with per-framework coverage cards and progress bars
- [x] **Per-finding compliance tags** in console, JSON, and HTML output
- [x] **`compliance_summary()`** method and `compliance_summary` in JSON output

### v1.3.0 — Advanced RBAC Analysis (COMPLETE)
- [x] **RBAC graph analysis**: Build SA → RoleBinding → Role → permissions graph, emit findings for dangerous patterns
- [x] **Dormant permission detection** (K8S-RBAC-016): SAs with bindings but no running pod references
- [x] **Cross-namespace escalation** (K8S-RBAC-017): SAs with dangerous cluster-wide permissions via ClusterRoleBindings
- [x] **RBAC modification detection** (K8S-RBAC-018): SAs that can create/modify Roles/Bindings (escalation path)
- [x] **Multi-hop escalation** (K8S-RBAC-019): SAs that can both create pods and access sensitive resources
- [x] **Least-privilege analysis** (K8S-RBAC-020): Overly broad roles (>10 resources or many dangerous verbs)
- [x] **Cross-scope admin detection** (K8S-RBAC-022): Users/Groups with admin roles across 3+ scopes
- [x] **Orphaned bindings** (K8S-RBAC-023): Bindings referencing non-existent Roles/ClusterRoles
- [x] **Aggregate role selector** (K8S-RBAC-024): Aggregate ClusterRoles with empty label selectors (match-all)
- [x] **Permission drift tracking** (K8S-RBAC-025/026/027): `--baseline-save` / `--baseline-compare` CLI for RBAC state diff
- [x] **ClusterRole reuse analysis** (K8S-RBAC-021): ClusterRoles bound in 3+ namespaces via RoleBindings

### v1.4.0 — Supply Chain & Image Security (COMPLETE)
- [x] **Image vulnerability scanning**: Integrate with Trivy/Grype for CVE scanning (K8S-SC-006/007)
- [x] **SBOM generation**: Software Bill of Materials via Trivy/Syft (K8S-SC-003/009)
- [x] **Signature verification**: cosign image signature verification (K8S-SC-008)
- [x] **Registry allow-list enforcement**: Configurable trusted registry list via `--trusted-registries` (K8S-SC-005)
- [x] **Base image analysis**: EOL/insecure base image detection with 34 known entries (K8S-SC-004)
- [x] **Admission policy check**: Verify image verification webhook exists (K8S-SC-010)
- [x] **Tool availability checks**: Detect missing Trivy/Grype/cosign/Syft (K8S-SC-001/002/003)

### v1.5.0 — Multi-Cluster & Reporting (COMPLETE)
- [x] **Multi-cluster scanning**: `--contexts ctx1,ctx2,...` scans multiple clusters, consolidated summary, per-cluster reports
- [x] **Diff/trend reporting**: `--diff PREV.json` compares findings between runs, shows new/resolved/persistent with severity deltas
- [x] **PDF report generation**: `--pdf FILE` with reportlab (professional layout) or stdlib fallback (text-based PDF)
- [x] **Slack/Teams notifications**: `--slack-webhook URL`, `--teams-webhook URL` with severity summary and top findings
- [x] **SARIF output**: `--sarif FILE` in SARIF v2.1.0 format with rule definitions, CWE tags, compliance properties

### v2.0.0 — Policy Engine (COMPLETE)
- [x] **Custom policy DSL**: YAML-based custom check definitions loaded from `--policy-dir`
- [x] **OPA/Rego integration**: Execute `.rego` policies via `opa eval` subprocess (`--rego-dir`)
- [x] **Kyverno policy validation**: K8S-KYV-001 to 006 — verifies Kyverno installation, policy health, failurePolicy, mutating/generate coverage
- [x] **Baseline profiles**: `--profile dev|staging|production` — built-in profiles with min severity, fail-on thresholds, and rule suppressions
- [x] **Exception management**: `--exceptions FILE` — JSON/YAML allow-list with glob matching on rule_id and resource

## Known Limitations

1. **API server pod inspection**: On managed K8s (EKS, GKE, AKS), kube-apiserver runs outside the cluster. Checks K8S-CLUSTER-001 to 007 produce informational findings rather than definitive results.
2. **Kubelet configuration**: Kubelet config is not directly accessible via the Kubernetes API in most deployments. K8S-CLUSTER-006 is limited.
3. **etcd encryption verification**: The scanner can check if `--encryption-provider-config` is set on the API server, but cannot verify the actual EncryptionConfiguration contents.
4. **Network policy effectiveness**: The scanner checks for policy existence but cannot verify that the CNI plugin (Calico, Cilium, etc.) actually enforces them.
5. **Image scanning**: Current version checks tags and registries only — no CVE/vulnerability scanning of image contents.
6. **RBAC effective permissions**: The scanner analyzes individual Roles/ClusterRoles but does not compute the full effective permission set for a given subject across all bindings.

## Related Projects

- **Application-Security-Scanner**: Parent collection of SAST/SSPM scanners
- **CIS Kubernetes Benchmark**: https://www.cisecurity.org/benchmark/kubernetes
- **NSA/CISA K8s Hardening Guide**: https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF
- **MITRE ATT&CK Containers**: https://attack.mitre.org/matrices/enterprise/containers/

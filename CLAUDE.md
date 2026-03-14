# CLAUDE.md — Kubernetes Security Posture Management (KSPM) Scanner

## Project Identity

- **Repository**: `Kubernetes-Security-Posture-Management`
- **Scanner file**: `kspm_scanner.py`
- **Version**: 1.0.0
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
                    └── _check_admission_control()
```

### Key Design Decisions

1. **Agentless**: No pods/DaemonSets deployed to the cluster. Uses `kubernetes` Python client library to query the API server.
2. **Workload-centric**: Scans workload controllers (Deployments, StatefulSets, DaemonSets, Jobs, CronJobs) rather than raw Pods, since controllers are the source of truth.
3. **Finding.file_path repurposed**: For this scanner, `file_path` holds the resource path (`namespace/Kind/name`) and `line_content` holds the config detail string.
4. **CIS_MAP**: A class-level dict maps rule IDs → CIS Kubernetes Benchmark section numbers. Displayed in both console and HTML output.
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

### Severity Model

- **CRITICAL**: Immediate cluster compromise risk (privileged containers, cluster-admin bindings, anonymous API access)
- **HIGH**: Significant security gap (root containers, secrets exposure, missing network policies, no audit logging)
- **MEDIUM**: Defense-in-depth gaps (missing resource limits, writable root FS, warn-only PSA)
- **LOW**: Best practice deviations (missing probes, unused SAs, no AppArmor)

### Output Formats

- **Console**: ANSI color-coded, sorted by severity → category → rule_id
- **JSON**: `scanner`, `version`, `generated`, `cluster`, `findings_count`, `summary`, `findings[]`
- **HTML**: Dark theme (Catppuccin palette), Kubernetes blue gradient (#326ce5), JS filter/search

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

### v1.1.0 — Expanded Checks
- [ ] **Runtime class checks**: Detect workloads using non-default RuntimeClass (gVisor, Kata)
- [ ] **Pod Disruption Budgets**: Flag Deployments without PDBs in production namespaces
- [ ] **Horizontal Pod Autoscaler**: Flag HPA without resource requests
- [ ] **Service mesh detection**: Identify Istio/Linkerd sidecar injection status
- [ ] **Deprecated API versions**: Scan for resources using deprecated apiVersions
- [ ] **Ephemeral containers**: Flag pods with debug/ephemeral containers active
- [ ] **Init container security**: Separate severity for init vs runtime containers
- [ ] **Node security**: Check node labels, taints, and kernel version

### v1.2.0 — Compliance Frameworks
- [ ] **NSA/CISA Kubernetes Hardening Guide** mapping (separate from CIS)
- [ ] **MITRE ATT&CK for Containers** mapping (T1610, T1611, T1613, etc.)
- [ ] **SOC 2 / PCI-DSS** control mapping
- [ ] **NIST 800-190** (Container Security Guide) mapping
- [ ] **Compliance summary section** in HTML report with pass/fail per framework

### v1.3.0 — Advanced RBAC Analysis (KIEM-style)
- [ ] **RBAC graph analysis**: Map SA → RoleBinding → Role → permissions
- [ ] **Dormant permission detection**: SAs with bindings but no pod references
- [ ] **Permission drift tracking**: Compare current RBAC state against a saved baseline
- [ ] **Least-privilege recommendations**: Suggest narrowed roles based on actual API audit logs
- [ ] **Cross-namespace escalation paths**: Detect multi-hop privilege escalation chains

### v1.4.0 — Supply Chain & Image Security
- [ ] **Image vulnerability scanning**: Integrate with Trivy/Grype for CVE scanning
- [ ] **SBOM generation**: Software Bill of Materials for container images
- [ ] **Signature verification**: Check for cosign/notary image signatures
- [ ] **Registry allow-list enforcement**: Configurable trusted registry list
- [ ] **Base image analysis**: Flag images based on known-insecure base images

### v1.5.0 — Multi-Cluster & Reporting
- [ ] **Multi-cluster scanning**: Scan multiple contexts in a single run
- [ ] **Diff/trend reporting**: Compare findings between scan runs (JSON diff)
- [ ] **PDF report generation**: Professional PDF output with executive summary
- [ ] **Slack/Teams notifications**: Webhook integration for CI/CD alerts
- [ ] **SARIF output**: Static Analysis Results Interchange Format for GitHub Security tab

### v2.0.0 — Policy Engine
- [ ] **Custom policy DSL**: YAML-based custom check definitions
- [ ] **OPA/Rego integration**: Execute Rego policies against fetched resources
- [ ] **Kyverno policy validation**: Verify Kyverno policies are correctly configured
- [ ] **Baseline profiles**: Built-in profiles (dev/staging/production) with different thresholds
- [ ] **Exception management**: Allow-list specific findings by resource annotation

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

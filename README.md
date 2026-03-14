<p align="center">
  <img src="banner.svg" alt="KSPM Scanner Banner" width="100%"/>
</p>

# Kubernetes Security Posture Management (KSPM) Scanner

An open-source, agentless Python-based **Kubernetes Security Posture Management (KSPM)** tool that connects to a live Kubernetes cluster via the Kubernetes API and performs comprehensive security posture assessments.

**No agents, sidecars, or DaemonSets required** — the scanner uses your existing kubeconfig or in-cluster service account to query the Kubernetes API directly.

---

## Features

- **~150+ security checks** across 19 check groups
- **Policy Engine (v2.0.0)** — custom YAML policy DSL, OPA/Rego integration, Kyverno policy validation
- **Baseline profiles** — built-in `dev`/`staging`/`production` profiles with different thresholds (`--profile`)
- **Exception management** — allow-list specific findings by rule ID or resource pattern (`--exceptions`)
- **Multi-cluster scanning** — scan multiple contexts in a single run (`--contexts`)
- **Supply chain & image security** — Trivy/Grype CVE scanning, cosign signature verification, SBOM generation, EOL base image detection
- **Advanced RBAC analysis** — graph-based escalation paths, dormant SAs, permission drift tracking
- **RBAC baseline drift** — save & compare RBAC state across scans (`--baseline-save`/`--baseline-compare`)
- **Diff/trend reporting** — compare findings between scan runs (`--diff PREV.json`)
- **6 compliance frameworks** — CIS Benchmark, NSA/CISA, MITRE ATT&CK, SOC 2, PCI-DSS, NIST 800-190
- **Compliance dashboard** — per-framework coverage metrics in HTML report
- **Agentless** — connects via kubeconfig or in-cluster config
- **All workload types** — Deployments, StatefulSets, DaemonSets, Jobs, CronJobs
- **Managed cluster support** — graceful handling for EKS, GKE, AKS where API server pods aren't visible
- **5 output formats** — colored console, JSON, interactive HTML, SARIF (GitHub Security), PDF
- **Webhook notifications** — Slack & Microsoft Teams CI/CD alerts (`--slack-webhook`, `--teams-webhook`)
- **Exit codes** — returns `1` if CRITICAL or HIGH findings, `0` otherwise (CI/CD friendly)

---

## Check Groups (~150+ Rules)

| # | Category | Rule IDs | Key Checks |
|---|----------|----------|------------|
| 1 | **RBAC Security** | K8S-RBAC-001 to 015 | Cluster-admin bindings, wildcard permissions, secrets access, pod exec/attach, escalate/bind/impersonate verbs, anonymous/unauthenticated bindings, CSR approval, SA token creation |
| 2 | **Workload Security** | K8S-POD-001 to 025 | Privileged containers, root user, hostNetwork/PID/IPC, privilege escalation, capabilities (SYS_ADMIN/ALL/NET_RAW), readOnlyRootFilesystem, resource limits/requests, liveness/readiness probes, seccomp, AppArmor/SELinux, process namespace sharing, unsafe sysctls |
| 3 | **Image Security** | K8S-IMG-001 to 005 | `latest` tag, missing tag, pull policy not Always, untrusted registry, missing digest |
| 4 | **Network Security** | K8S-NET-001 to 010 | Missing network policies, allow-all ingress/egress, LoadBalancer/NodePort exposure, ExternalIPs, Ingress without TLS, wildcard hosts, ExternalName services |
| 5 | **Namespace Security** | K8S-NS-002 to 006 | Pod Security Admission labels (enforce/warn/audit), PSA level not restricted, missing ResourceQuota, missing LimitRange |
| 6 | **Secret Management** | K8S-SECRET-001 to 006 | Secrets in env vars, sensitive ConfigMap keys (password/token/api_key patterns), incomplete TLS secrets |
| 7 | **Service Accounts** | K8S-SA-001 to 004 | Default SA with ClusterRoleBindings, auto-mount tokens, SA bound to cluster-admin, unused service accounts |
| 8 | **Cluster Configuration** | K8S-CLUSTER-001 to 010 | API server (anonymous auth, insecure port, audit logging, admission controllers, encryption at rest, profiling), Kubernetes Dashboard exposure, Tiller (Helm v2) detection, non-system hostNetwork pods |
| 9 | **Storage Security** | K8S-PV-001 to 004 | hostPath PersistentVolumes, deprecated Recycle policy, ReadWriteMany PVCs, emptyDir without sizeLimit |
| 10 | **Admission Control** | K8S-ADM-001 to 005 | Webhook failurePolicy Ignore, missing namespace selector, overly broad scope, high timeout, no validating webhooks |
| 11 | **Node Security** | K8S-NODE-001 to 006 | Outdated kubelet/K8s version, outdated container runtime, node health (NotReady, pressure), missing topology labels, control plane without NoSchedule taint, old kernel version |
| 12 | **Availability (PDB)** | K8S-PDB-001 to 003 | Deployments/StatefulSets without PDB, PDB maxUnavailable=0, PDB minAvailable=100% |
| 13 | **Availability (HPA)** | K8S-HPA-001 to 004 | minReplicas=1, min equals max, target without resource requests, no scale-down stabilization |
| 14 | **Service Mesh** | K8S-MESH-001 to 004 | Missing sidecar injection (Istio/Linkerd), permissive/disabled mTLS, missing AuthorizationPolicy, exposed mesh gateways |
| 15 | **Deprecated APIs** | K8S-API-001 to 003 | Deprecated API versions in use, removed APIs still present, PodSecurityPolicy remnants |
| 16 | **Runtime Security** | K8S-RC-001, K8S-EPH-001/002 | Non-existent RuntimeClass references, active ephemeral debug containers, privileged ephemeral containers |
| 17 | **Advanced RBAC** | K8S-RBAC-016 to 027 | RBAC graph analysis, dormant SA detection, cross-namespace escalation paths, multi-hop privilege escalation, overly broad roles, orphaned bindings, aggregate role selectors, RBAC baseline drift tracking |
| 18 | **Supply Chain Security** | K8S-SC-001 to 010 | Image CVE scanning (Trivy/Grype), cosign signature verification, SBOM generation, EOL/insecure base image detection, registry allow-list enforcement, admission policy for image verification |
| 19 | **Kyverno Policy Validation** | K8S-KYV-001 to 006 | Kyverno not installed, failed/error policies, audit-mode policies in production, Ignore failurePolicy, missing mutating/generate policies |

---

## Policy Engine (v2.0.0)

### Custom YAML Policy DSL
Define custom security checks in YAML and place them in a policy directory:

```yaml
rule_id: K8S-CUSTOM-001
name: "Require non-root containers"
category: "Custom Policies"
severity: HIGH
description: "All containers must run as non-root"
recommendation: "Set runAsNonRoot: true in securityContext"
cwe: CWE-250
target:
  api_group: apps/v1
  resource: deployments
  namespaced: true
match:
  field: spec.template.spec.containers[*].securityContext.runAsNonRoot
  operator: equals    # equals|not_equals|exists|not_exists|contains|regex|gt|lt
  value: true
```

### OPA/Rego Integration
Write Rego policies using the `kspm` package and place `.rego` files in a directory:

```rego
package kspm

deny[result] {
  input.deployments[_].spec.replicas < 2
  result := {
    "rule_id": "K8S-REGO-001",
    "name": "Single replica deployment",
    "severity": "MEDIUM",
    "description": "Deployment has less than 2 replicas",
    "recommendation": "Increase replicas for availability",
    "resource": input.deployments[_].metadata.name,
    "detail": sprintf("replicas: %d", [input.deployments[_].spec.replicas]),
  }
}
```

Requires the `opa` binary on PATH. The scanner collects namespaces, deployments, and cluster roles as input.

### Kyverno Policy Validation
When Kyverno is installed on the cluster, the scanner automatically validates:
- K8S-KYV-001: Kyverno installation detected
- K8S-KYV-002: Policies in failed/error state
- K8S-KYV-003: Policies in audit mode (should be enforce in production)
- K8S-KYV-004: Policies with `Ignore` failurePolicy
- K8S-KYV-005: No mutating policies defined
- K8S-KYV-006: No generate policies defined

### Baseline Profiles
Three built-in profiles control rule severity thresholds and suppressions:

| Profile | Min Severity | Fail On | Suppressed Rules |
|---------|-------------|---------|-----------------|
| `production` | LOW | CRITICAL, HIGH | None — all rules enforced |
| `staging` | MEDIUM | CRITICAL | PDB-001, HPA-004, POD-024 |
| `dev` | HIGH | CRITICAL | 14 best-practice rules relaxed |

### Exception Management
Create a YAML/JSON file to suppress known-accepted findings:

```yaml
exceptions:
  - rule_id: K8S-POD-001
    resource: "default/Deployment/test-app"
    reason: "Accepted risk for dev workload"
  - rule_id: K8S-IMG-001
    reason: "Latest tag allowed for internal images"
  - resource: "kube-system/*"
    reason: "System namespace excluded"
```

Supports glob patterns for `rule_id` and `resource` matching.

---

## CIS Kubernetes Benchmark Mapping

Rules are mapped to CIS Kubernetes Benchmark sections where applicable:

| Scanner Rule | CIS Reference | Description |
|-------------|---------------|-------------|
| K8S-RBAC-001 | CIS 5.1.1 | Cluster-admin role usage |
| K8S-POD-001 | CIS 5.2.1 | Privileged containers |
| K8S-POD-002 | CIS 5.2.6 | Root containers |
| K8S-POD-003 | CIS 5.2.4 | Host network access |
| K8S-NET-001 | CIS 5.3.2 | Network policy enforcement |
| K8S-CLUSTER-001 | CIS 1.2.1 | API server anonymous auth |
| K8S-CLUSTER-003 | CIS 1.2.22 | Audit logging |
| K8S-CLUSTER-005 | CIS 1.2.29 | Encryption at rest |
| K8S-NODE-001 | CIS 4.1.1 | Kubelet version |
| K8S-NODE-002 | CIS 4.2.6 | Container runtime version |
| K8S-NODE-005 | CIS 4.2.12 | Control plane taints |
| ... | ... | 25+ mappings total |

---

## Compliance Frameworks (v1.2.0)

Every finding is mapped to applicable controls across **6 industry compliance frameworks**. The HTML report includes a compliance dashboard with per-framework coverage metrics.

| Framework | Reference Format | Mapped Rules | Scope |
|-----------|-----------------|--------------|-------|
| **CIS Kubernetes Benchmark** | CIS x.x.x | 25+ | Kubernetes hardening best practices |
| **NSA/CISA Hardening Guide** (v1.2) | NSA x.x | 70+ | US government container hardening |
| **MITRE ATT&CK for Containers** | Txxxx | 45+ | Adversary tactics/techniques |
| **SOC 2 Trust Services** | CCx.x / A1.x | 65+ | Service organization controls |
| **PCI-DSS v4.0** | PCI x.x.x | 45+ | Payment card industry requirements |
| **NIST SP 800-190** | NIST 3.x.x | 45+ | Application container security guide |

### Console Output
Framework references are shown inline per finding:
```
[CRITICAL]  K8S-POD-001  Privileged container
  Resource  : production/Deployment/api-server/main
  Detail    : privileged: true
  Compliance: CIS: CIS 5.2.1, NSA/CISA: NSA 1.1, MITRE: T1611, SOC 2: CC6.8, PCI-DSS: PCI 2.2.1, NIST 800-190: NIST 3.4.1
```

### JSON Output
Each finding includes a `compliance` object and the report includes a `compliance_summary` section.

### HTML Report
Interactive compliance dashboard with coverage cards per framework, progress bars, and per-finding compliance tags.

---

## Installation

```bash
# Install the Kubernetes Python client (required)
pip install kubernetes

# Optional: enhanced PDF reports
pip install reportlab

# Optional: YAML policy files and exceptions (PyYAML)
pip install pyyaml

# Optional: OPA/Rego policies — install the opa binary
# https://www.openpolicyagent.org/docs/latest/#1-download-opa
```

The scanner requires only the `kubernetes` library. All other dependencies are optional and gracefully degrade when absent.

---

## Usage

```bash
# Scan using default kubeconfig (~/.kube/config)
python kspm_scanner.py

# Scan with HTML and JSON reports
python kspm_scanner.py --html report.html --json scan.json

# Scan a specific context
python kspm_scanner.py --context production-cluster

# Scan specific namespace(s)
python kspm_scanner.py --namespace app-ns,staging-ns

# Show only HIGH and CRITICAL findings
python kspm_scanner.py --severity HIGH

# Scan with explicit kubeconfig file
python kspm_scanner.py --kubeconfig /path/to/kubeconfig --html report.html

# Verbose output for debugging
python kspm_scanner.py -v --severity MEDIUM --html report.html

# Save RBAC baseline for drift tracking
python kspm_scanner.py --baseline-save rbac-baseline.json

# Compare against a saved baseline (detects permission drift)
python kspm_scanner.py --baseline-compare rbac-baseline.json --html report.html

# Supply chain scan with Trivy CVE scanning and trusted registries
python kspm_scanner.py --trusted-registries "harbor.corp.io,ecr.us-east-1.amazonaws.com" --html report.html

# Specify custom Trivy path
python kspm_scanner.py --trivy-path /usr/local/bin/trivy --html report.html

# Multi-cluster scanning (v1.5.0)
python kspm_scanner.py --contexts dev-cluster,staging-cluster,prod-cluster --json reports/ --html reports/

# SARIF output for GitHub Security tab
python kspm_scanner.py --sarif results.sarif

# PDF report with executive summary
python kspm_scanner.py --pdf report.pdf

# Diff/trend reporting (compare against previous scan)
python kspm_scanner.py --json current.json --diff previous.json --diff-output diff.json

# Slack/Teams CI/CD notifications
python kspm_scanner.py --slack-webhook https://hooks.slack.com/services/T.../B.../xxx
python kspm_scanner.py --teams-webhook https://outlook.office.com/webhook/...

# Custom YAML policies (v2.0.0)
python kspm_scanner.py --policy-dir ./policies/ --html report.html

# OPA/Rego policies (v2.0.0)
python kspm_scanner.py --rego-dir ./rego-policies/ --html report.html

# Baseline profile — production (strict, all rules, fail on HIGH+)
python kspm_scanner.py --profile production --html report.html

# Baseline profile — dev (relaxed, CRITICAL/HIGH only)
python kspm_scanner.py --profile dev --html report.html

# Exception management — suppress specific findings
python kspm_scanner.py --exceptions exceptions.yaml --html report.html

# Combined: custom policies + profile + exceptions
python kspm_scanner.py --policy-dir ./policies/ --rego-dir ./rego/ --profile production --exceptions exceptions.yaml --html report.html
```

### CLI Reference

```
usage: kspm_scanner.py [-h] [--kubeconfig FILE] [--context CTX]
                       [--contexts CTX1,CTX2,...] [--namespace NS]
                       [--severity {CRITICAL,HIGH,MEDIUM,LOW}]
                       [--json FILE] [--html FILE] [--sarif FILE]
                       [--pdf FILE] [--diff PREV_JSON] [--diff-output FILE]
                       [--baseline-save FILE] [--baseline-compare FILE]
                       [--trusted-registries LIST] [--trivy-path PATH]
                       [--policy-dir DIR] [--rego-dir DIR]
                       [--profile {dev,staging,production}]
                       [--exceptions FILE]
                       [--slack-webhook URL] [--teams-webhook URL]
                       [--verbose] [--version]

Options:
  --kubeconfig, -k FILE       Path to kubeconfig file (env: KUBECONFIG)
  --context, -c CTX           Kubernetes context to use (env: K8S_CONTEXT)
  --contexts CTX1,CTX2,...    Scan multiple contexts (comma-separated)
  --namespace, -n NS          Scan specific namespace(s), comma-separated
  --all-namespaces, -A        Scan all namespaces (default)
  --severity LEVEL            Minimum severity to report (default: LOW)
  --json FILE                 Save JSON report (or output dir for multi-cluster)
  --html FILE                 Save HTML report (or output dir for multi-cluster)
  --sarif FILE                Save SARIF v2.1.0 report for GitHub Security tab
  --pdf FILE                  Save PDF report with executive summary
  --diff PREV_JSON            Compare current scan against previous JSON report
  --diff-output FILE          Save diff report as JSON (requires --diff)
  --baseline-save FILE        Save current RBAC state as baseline
  --baseline-compare FILE     Compare current RBAC against saved baseline
  --trusted-registries LIST   Comma-separated additional trusted registries
  --trivy-path PATH           Path to trivy binary (auto-detected)
  --policy-dir DIR            Directory with custom YAML policy files (v2.0.0)
  --rego-dir DIR              Directory with OPA Rego policy files (v2.0.0)
  --profile PROFILE           Baseline profile: dev/staging/production (v2.0.0)
  --exceptions FILE           JSON/YAML exception/allow-list file (v2.0.0)
  --slack-webhook URL         Send scan summary to Slack webhook
  --teams-webhook URL         Send scan summary to Teams webhook
  --verbose, -v               Enable verbose output
  --version                   Show version and exit
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `KUBECONFIG` | Path to kubeconfig file |
| `K8S_CONTEXT` | Kubernetes context to use |

---

## Output Formats

### Console Output
Color-coded findings sorted by severity with CIS benchmark references:
```
[CRITICAL]  K8S-POD-001  Privileged container
  Resource : production/Deployment/api-server/main
  Detail   : privileged: true
  CIS      : CIS 5.2.1
  Issue    : Container runs with full host privileges, disabling all security boundaries.
  Fix      : Set privileged: false. Use specific capabilities instead.
```

### HTML Report
Interactive dark-themed report with:
- Severity summary chips
- Dropdown filters (severity, category)
- Text search across all findings
- CIS benchmark references inline
- Kubernetes blue gradient header

### JSON Report
Machine-parseable output for CI/CD integration:
```json
{
  "scanner": "kspm_scanner",
  "version": "1.0.0",
  "cluster": "production",
  "findings_count": 42,
  "summary": {"CRITICAL": 3, "HIGH": 12, "MEDIUM": 18, "LOW": 9},
  "findings": [...]
}
```

---

## CI/CD Integration

The scanner returns exit code `1` if CRITICAL or HIGH findings are present, making it suitable for pipeline gates:

```yaml
# GitHub Actions example
- name: KSPM Security Scan
  run: |
    pip install kubernetes
    python kspm_scanner.py --severity HIGH --json kspm-results.json --html kspm-report.html
  continue-on-error: false
```

---

## Required RBAC Permissions

For a read-only scan, the service account or user needs the following minimum permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kspm-scanner-reader
rules:
- apiGroups: [""]
  resources: ["namespaces", "pods", "services", "serviceaccounts",
              "configmaps", "secrets", "persistentvolumes",
              "persistentvolumeclaims", "resourcequotas", "limitranges", "nodes"]
  verbs: ["get", "list"]
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets", "daemonsets", "replicasets"]
  verbs: ["get", "list"]
- apiGroups: ["batch"]
  resources: ["jobs", "cronjobs"]
  verbs: ["get", "list"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies", "ingresses"]
  verbs: ["get", "list"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
  verbs: ["get", "list"]
- apiGroups: ["admissionregistration.k8s.io"]
  resources: ["validatingwebhookconfigurations", "mutatingwebhookconfigurations"]
  verbs: ["get", "list"]
- apiGroups: ["kyverno.io"]
  resources: ["clusterpolicies", "policies"]
  verbs: ["get", "list"]
```

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

#!/usr/bin/env python3
"""
Kubernetes Security Posture Management (KSPM) Scanner  v1.0.0

Agentless scanner that connects to a live Kubernetes cluster via the
Kubernetes API and performs comprehensive security posture checks covering
RBAC, workload hardening, network security, namespace isolation, secrets
management, image security, service accounts, cluster configuration,
persistent volumes, admission control, and CIS Benchmark alignment.

Requirements:
    pip install kubernetes

Usage:
    python kspm_scanner.py [--kubeconfig FILE] [--context CTX]
                           [--namespace NS | --all-namespaces]
                           [--severity HIGH] [--json FILE] [--html FILE]
                           [--verbose] [--version]
"""

VERSION = "1.0.0"

import os, sys, json, re, argparse, html as html_mod
from datetime import datetime, timezone

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
    HAS_K8S = True
except ImportError:
    HAS_K8S = False

# ---------------------------------------------------------------------------
# Dangerous capabilities list (CIS 5.2.8/5.2.9)
# ---------------------------------------------------------------------------
DANGEROUS_CAPS = {
    "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_RAWIO", "SYS_MODULE",
    "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID", "NET_BIND_SERVICE",
    "NET_RAW", "AUDIT_WRITE", "MKNOD", "SYS_CHROOT", "KILL",
}

TRUSTED_REGISTRIES = {
    "docker.io", "gcr.io", "ghcr.io", "registry.k8s.io",
    "quay.io", "public.ecr.aws", "mcr.microsoft.com",
}

SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease", "default"}

# High-risk RBAC verbs
DANGEROUS_VERBS = {"create", "update", "patch", "delete", "deletecollection", "escalate", "bind", "impersonate"}

# Sensitive resources
SENSITIVE_RESOURCES = {"secrets", "pods/exec", "pods/attach", "serviceaccounts/token",
                       "certificatesigningrequests/approval", "tokenreviews",
                       "nodes/proxy", "pods/portforward"}

# ---------------------------------------------------------------------------
# Finding data class
# ---------------------------------------------------------------------------
class Finding:
    __slots__ = ("rule_id", "name", "category", "severity", "file_path",
                 "line_num", "line_content", "description", "recommendation",
                 "cwe", "cve")

    def __init__(self, rule_id, name, category, severity,
                 file_path, line_num, line_content,
                 description, recommendation, cwe=None, cve=None):
        self.rule_id = rule_id
        self.name = name
        self.category = category
        self.severity = severity
        self.file_path = file_path          # repurposed: resource path (e.g. namespace/kind/name)
        self.line_num = line_num            # None for API findings
        self.line_content = line_content    # config detail string
        self.description = description
        self.recommendation = recommendation
        self.cwe = cwe
        self.cve = cve

    def to_dict(self):
        return {
            "id": self.rule_id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "resource": self.file_path,
            "line": self.line_num,
            "detail": self.line_content,
            "description": self.description,
            "recommendation": self.recommendation,
            "cwe": self.cwe or "",
            "cve": self.cve or "",
        }


# ---------------------------------------------------------------------------
# KSPM Scanner
# ---------------------------------------------------------------------------
class KSPMScanner:

    SEVERITY_ORDER = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}
    SEVERITY_COLOR = {
        "CRITICAL": "\033[91m",
        "HIGH":     "\033[93m",
        "MEDIUM":   "\033[94m",
        "LOW":      "\033[92m",
    }
    RESET = "\033[0m"
    BOLD  = "\033[1m"

    # CIS Benchmark mapping for key rules
    CIS_MAP = {
        "K8S-RBAC-001": "CIS 5.1.1",  "K8S-RBAC-002": "CIS 5.1.3",
        "K8S-RBAC-003": "CIS 5.1.3",  "K8S-RBAC-006": "CIS 5.1.5",
        "K8S-RBAC-007": "CIS 5.1.5",  "K8S-RBAC-008": "CIS 5.1.8",
        "K8S-POD-001": "CIS 5.2.1",   "K8S-POD-002": "CIS 5.2.6",
        "K8S-POD-003": "CIS 5.2.4",   "K8S-POD-004": "CIS 5.2.2",
        "K8S-POD-005": "CIS 5.2.3",   "K8S-POD-006": "CIS 5.2.5",
        "K8S-POD-007": "CIS 5.2.8",   "K8S-POD-009": "CIS 5.2.9",
        "K8S-POD-010": "CIS 5.2.7",   "K8S-POD-011": "CIS 5.2.10",
        "K8S-POD-023": "CIS 5.7.2",   "K8S-NET-001": "CIS 5.3.2",
        "K8S-NS-002": "CIS 5.7.4",    "K8S-NS-003": "CIS 5.7.4",
        "K8S-SA-002": "CIS 5.1.6",    "K8S-SECRET-001": "CIS 5.4.1",
        "K8S-IMG-001": "CIS 5.5.1",   "K8S-CLUSTER-001": "CIS 1.2.1",
        "K8S-CLUSTER-002": "CIS 1.2.19", "K8S-CLUSTER-003": "CIS 1.2.22",
        "K8S-CLUSTER-005": "CIS 1.2.29", "K8S-CLUSTER-006": "CIS 4.2.1",
    }

    def __init__(self, kubeconfig=None, context=None, namespaces=None,
                 all_namespaces=True, verbose=False):
        self.findings: list = []
        self.verbose = verbose
        self.kubeconfig = kubeconfig
        self.context_name = context
        self.target_namespaces = namespaces   # list or None
        self.all_namespaces = all_namespaces
        self.cluster_name = context or "default"

        # Load kube config
        try:
            if kubeconfig:
                config.load_kube_config(config_file=kubeconfig, context=context)
            else:
                try:
                    config.load_incluster_config()
                    self._vprint("[*] Loaded in-cluster configuration")
                except config.ConfigException:
                    config.load_kube_config(context=context)
                    self._vprint("[*] Loaded kubeconfig")
        except Exception as exc:
            print(f"[!] Failed to load Kubernetes config: {exc}", file=sys.stderr)
            sys.exit(1)

        self.core_v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()
        self.batch_v1 = client.BatchV1Api()
        self.rbac_v1 = client.RbacAuthorizationV1Api()
        self.networking_v1 = client.NetworkingV1Api()
        self.admreg_v1 = client.AdmissionregistrationV1Api()
        self.policy_v1 = None
        try:
            self.policy_v1 = client.PolicyV1Api()
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------
    def _add(self, finding: Finding):
        self.findings.append(finding)

    def _vprint(self, msg: str):
        if self.verbose:
            print(msg)

    def _warn(self, msg: str):
        print(f"  [!] {msg}", file=sys.stderr)

    def _get_namespaces(self):
        """Return list of namespace names to scan."""
        if self.target_namespaces:
            return self.target_namespaces
        try:
            ns_list = self.core_v1.list_namespace()
            if self.all_namespaces:
                return [ns.metadata.name for ns in ns_list.items]
            return [ns.metadata.name for ns in ns_list.items
                    if ns.metadata.name not in SYSTEM_NAMESPACES]
        except ApiException as e:
            self._warn(f"Cannot list namespaces: {e.reason}")
            return ["default"]

    def _res_path(self, namespace, kind, name):
        """Build a resource path string for finding.file_path."""
        if namespace:
            return f"{namespace}/{kind}/{name}"
        return f"cluster/{kind}/{name}"

    def _cis(self, rule_id):
        """Return CIS reference for a rule_id or empty string."""
        return self.CIS_MAP.get(rule_id, "")

    # -----------------------------------------------------------------------
    # Main scan entry
    # -----------------------------------------------------------------------
    def scan(self):
        B, R = self.BOLD, self.RESET
        print(f"{B}[*] Kubernetes Security Posture Management (KSPM) Scanner v{VERSION}{R}")
        print(f"[*] Cluster: {self.cluster_name}")
        print(f"[*] Timestamp: {datetime.now(timezone.utc).isoformat()}")
        print("[*] Running checks ...")

        self._check_rbac()
        self._check_workloads()
        self._check_network_security()
        self._check_namespace_security()
        self._check_secret_management()
        self._check_service_accounts()
        self._check_cluster_config()
        self._check_persistent_volumes()
        self._check_jobs()
        self._check_admission_control()

        print(f"[*] Scan complete. {len(self.findings)} findings identified.")

    # ===================================================================
    # CHECK GROUP 1: RBAC Security  (K8S-RBAC-001 to 015)
    # ===================================================================
    def _check_rbac(self):
        self._vprint("  [*] Checking RBAC security ...")

        # Collect all ClusterRoleBindings and RoleBindings
        try:
            crbs = self.rbac_v1.list_cluster_role_binding().items
        except ApiException:
            self._warn("Cannot list ClusterRoleBindings")
            crbs = []

        try:
            crs = self.rbac_v1.list_cluster_role().items
        except ApiException:
            self._warn("Cannot list ClusterRoles")
            crs = []

        try:
            rbs_all = self.rbac_v1.list_role_binding_for_all_namespaces().items
        except ApiException:
            rbs_all = []

        try:
            roles_all = self.rbac_v1.list_role_for_all_namespaces().items
        except ApiException:
            roles_all = []

        # --- K8S-RBAC-001: cluster-admin bindings ---
        for crb in crbs:
            if not crb.role_ref:
                continue
            if crb.role_ref.name == "cluster-admin":
                # Skip system bindings
                if crb.metadata.name in ("system:masters", "cluster-admin"):
                    continue
                subjects_str = ", ".join(
                    f"{s.kind}:{s.name}" for s in (crb.subjects or [])
                )
                self._add(Finding(
                    "K8S-RBAC-001", "Cluster-admin role binding", "RBAC Security",
                    "CRITICAL", self._res_path(None, "ClusterRoleBinding", crb.metadata.name),
                    None, f"subjects: {subjects_str}",
                    "Binding grants full cluster-admin privileges. Compromised subject gains unrestricted access.",
                    "Use least-privilege roles instead of cluster-admin. Create scoped ClusterRoles with only required permissions.",
                    "CWE-250",
                ))

        # --- K8S-RBAC-006/007: Anonymous / unauthenticated bindings ---
        for crb in crbs:
            for subj in (crb.subjects or []):
                if subj.name == "system:anonymous":
                    self._add(Finding(
                        "K8S-RBAC-006", "Binding to system:anonymous", "RBAC Security",
                        "CRITICAL", self._res_path(None, "ClusterRoleBinding", crb.metadata.name),
                        None, f"role: {crb.role_ref.name}",
                        "Anonymous user is granted cluster permissions, allowing unauthenticated access.",
                        "Remove bindings to system:anonymous. Ensure anonymous-auth is disabled on API server.",
                        "CWE-287",
                    ))
                if subj.name == "system:unauthenticated":
                    self._add(Finding(
                        "K8S-RBAC-007", "Binding to system:unauthenticated", "RBAC Security",
                        "CRITICAL", self._res_path(None, "ClusterRoleBinding", crb.metadata.name),
                        None, f"role: {crb.role_ref.name}",
                        "Unauthenticated group is granted cluster permissions.",
                        "Remove bindings to system:unauthenticated group.",
                        "CWE-287",
                    ))

        # Analyze ClusterRole rules
        for cr in crs:
            if cr.metadata.name.startswith("system:"):
                continue
            for rule in (cr.rules or []):
                resources = [r for r in (rule.resources or [])]
                verbs = [v for v in (rule.verbs or [])]
                api_groups = [g for g in (rule.api_groups or [])]

                # --- K8S-RBAC-002: Wildcard resource permissions ---
                if "*" in resources:
                    self._add(Finding(
                        "K8S-RBAC-002", "Wildcard resource permissions", "RBAC Security",
                        "HIGH", self._res_path(None, "ClusterRole", cr.metadata.name),
                        None, f"resources: {resources}, verbs: {verbs}",
                        "Role grants access to ALL resources via wildcard. Violates least-privilege principle.",
                        "Replace '*' with explicit resource list.",
                        "CWE-250",
                    ))

                # --- K8S-RBAC-003: Wildcard verb permissions ---
                if "*" in verbs:
                    self._add(Finding(
                        "K8S-RBAC-003", "Wildcard verb permissions", "RBAC Security",
                        "HIGH", self._res_path(None, "ClusterRole", cr.metadata.name),
                        None, f"resources: {resources}, verbs: {verbs}",
                        "Role grants ALL operations via wildcard verb. Any subject can perform any action on listed resources.",
                        "Replace '*' with explicit verbs (get, list, watch).",
                        "CWE-250",
                    ))

                # --- K8S-RBAC-004: Secrets access ---
                if "secrets" in resources and any(v in verbs for v in ["*", "get", "list", "watch"]):
                    self._add(Finding(
                        "K8S-RBAC-004", "Secrets access permission", "RBAC Security",
                        "HIGH", self._res_path(None, "ClusterRole", cr.metadata.name),
                        None, f"verbs: {verbs}",
                        "Role can read Kubernetes Secrets, potentially exposing passwords, tokens, and certificates.",
                        "Restrict secrets access to specific namespaces and service accounts that require it.",
                        "CWE-200",
                    ))

                # --- K8S-RBAC-005: Pod exec/attach ---
                for sens in ("pods/exec", "pods/attach"):
                    if sens in resources:
                        self._add(Finding(
                            "K8S-RBAC-005", f"Pod {sens.split('/')[1]} permission", "RBAC Security",
                            "HIGH", self._res_path(None, "ClusterRole", cr.metadata.name),
                            None, f"resource: {sens}, verbs: {verbs}",
                            f"Role allows {sens}, enabling interactive shell access to running containers.",
                            f"Remove {sens} permission or restrict to specific namespaces via RoleBindings.",
                            "CWE-250",
                        ))

                # --- K8S-RBAC-008: Escalate verb ---
                if "escalate" in verbs:
                    self._add(Finding(
                        "K8S-RBAC-008", "Escalate verb permission", "RBAC Security",
                        "CRITICAL", self._res_path(None, "ClusterRole", cr.metadata.name),
                        None, f"resources: {resources}",
                        "Role allows privilege escalation by modifying roles beyond own permissions.",
                        "Remove 'escalate' verb. Only cluster-admin should have escalation rights.",
                        "CWE-269",
                    ))

                # --- K8S-RBAC-009: Bind verb ---
                if "bind" in verbs and any(r in resources for r in ["roles", "clusterroles", "*"]):
                    self._add(Finding(
                        "K8S-RBAC-009", "Bind verb permission", "RBAC Security",
                        "HIGH", self._res_path(None, "ClusterRole", cr.metadata.name),
                        None, f"resources: {resources}",
                        "Role can bind arbitrary roles/clusterroles, potentially granting itself cluster-admin.",
                        "Remove 'bind' verb or limit to specific role names via resourceNames.",
                        "CWE-269",
                    ))

                # --- K8S-RBAC-010: Impersonate verb ---
                if "impersonate" in verbs:
                    self._add(Finding(
                        "K8S-RBAC-010", "Impersonate verb permission", "RBAC Security",
                        "HIGH", self._res_path(None, "ClusterRole", cr.metadata.name),
                        None, f"resources: {resources}",
                        "Role can impersonate other users/groups/service accounts, bypassing access controls.",
                        "Remove 'impersonate' verb or restrict via resourceNames to specific identities.",
                        "CWE-269",
                    ))

                # --- K8S-RBAC-011: Node/proxy access ---
                if "nodes/proxy" in resources:
                    self._add(Finding(
                        "K8S-RBAC-011", "Node proxy permission", "RBAC Security",
                        "HIGH", self._res_path(None, "ClusterRole", cr.metadata.name),
                        None, f"verbs: {verbs}",
                        "Role can proxy to kubelet API on nodes, enabling container access and host-level operations.",
                        "Remove nodes/proxy access. Use more specific RBAC rules.",
                        "CWE-250",
                    ))

                # --- K8S-RBAC-012: Create pod (container escape path) ---
                if "pods" in resources and "create" in verbs and "*" not in resources:
                    self._add(Finding(
                        "K8S-RBAC-012", "Pod creation permission", "RBAC Security",
                        "MEDIUM", self._res_path(None, "ClusterRole", cr.metadata.name),
                        None, f"verbs: {verbs}",
                        "Pod creation enables running arbitrary containers which may be used for privilege escalation.",
                        "Pair with Pod Security Admission to restrict pod capabilities.",
                        "CWE-250",
                    ))

                # --- K8S-RBAC-013: CSR approval permission ---
                if "certificatesigningrequests/approval" in resources:
                    self._add(Finding(
                        "K8S-RBAC-013", "CSR approval permission", "RBAC Security",
                        "HIGH", self._res_path(None, "ClusterRole", cr.metadata.name),
                        None, f"verbs: {verbs}",
                        "Role can approve certificate signing requests, potentially issuing trusted client certificates.",
                        "Restrict CSR approval to dedicated certificate management roles.",
                        "CWE-295",
                    ))

                # --- K8S-RBAC-014: Persistent volume create (hostPath escape) ---
                if "persistentvolumes" in resources and "create" in verbs:
                    self._add(Finding(
                        "K8S-RBAC-014", "PersistentVolume create permission", "RBAC Security",
                        "MEDIUM", self._res_path(None, "ClusterRole", cr.metadata.name),
                        None, f"verbs: {verbs}",
                        "PV creation can mount host filesystem paths, enabling container-to-host escape.",
                        "Use StorageClasses with dynamic provisioning instead of manual PV creation.",
                        "CWE-250",
                    ))

                # --- K8S-RBAC-015: Token request / SA token creation ---
                if "serviceaccounts/token" in resources and "create" in verbs:
                    self._add(Finding(
                        "K8S-RBAC-015", "Service account token creation", "RBAC Security",
                        "HIGH", self._res_path(None, "ClusterRole", cr.metadata.name),
                        None, f"resources: {resources}",
                        "Role can create tokens for any service account, potentially impersonating privileged SAs.",
                        "Restrict serviceaccounts/token creation to specific service account names via resourceNames.",
                        "CWE-269",
                    ))

        # Analyze namespace-scoped Roles for dangerous permissions
        for role in roles_all:
            if role.metadata.name.startswith("system:"):
                continue
            ns = role.metadata.namespace or "default"
            for rule in (role.rules or []):
                resources = [r for r in (rule.resources or [])]
                verbs = [v for v in (rule.verbs or [])]
                if "*" in resources and "*" in verbs:
                    self._add(Finding(
                        "K8S-RBAC-002", "Wildcard resource and verb permissions in Role",
                        "RBAC Security", "HIGH",
                        self._res_path(ns, "Role", role.metadata.name),
                        None, f"resources: *, verbs: *",
                        "Namespace Role grants full access to all resources. Compromised subject gains namespace-admin.",
                        "Replace wildcards with explicit resource and verb lists.",
                        "CWE-250",
                    ))

    # ===================================================================
    # CHECK GROUP 2: Workload Security  (K8S-POD-001 to 025, K8S-IMG-001 to 006)
    # ===================================================================
    def _check_workloads(self):
        self._vprint("  [*] Checking workload security ...")
        namespaces = self._get_namespaces()

        for ns in namespaces:
            # Collect workload controllers
            workloads = []
            try:
                for d in self.apps_v1.list_namespaced_deployment(ns).items:
                    workloads.append(("Deployment", d.metadata.name, ns, d.spec.template.spec))
            except ApiException:
                pass
            try:
                for s in self.apps_v1.list_namespaced_stateful_set(ns).items:
                    workloads.append(("StatefulSet", s.metadata.name, ns, s.spec.template.spec))
            except ApiException:
                pass
            try:
                for ds in self.apps_v1.list_namespaced_daemon_set(ns).items:
                    workloads.append(("DaemonSet", ds.metadata.name, ns, ds.spec.template.spec))
            except ApiException:
                pass
            try:
                for cj in self.batch_v1.list_namespaced_cron_job(ns).items:
                    workloads.append(("CronJob", cj.metadata.name, ns,
                                     cj.spec.job_template.spec.template.spec))
            except ApiException:
                pass
            try:
                for j in self.batch_v1.list_namespaced_job(ns).items:
                    # Skip jobs owned by CronJobs (already covered)
                    owners = j.metadata.owner_references or []
                    if any(o.kind == "CronJob" for o in owners):
                        continue
                    workloads.append(("Job", j.metadata.name, ns, j.spec.template.spec))
            except ApiException:
                pass

            for kind, name, ns, pod_spec in workloads:
                self._check_pod_spec(kind, name, ns, pod_spec)

    def _check_pod_spec(self, kind, name, ns, pod_spec):
        """Check a PodSpec against all pod/container/image security rules."""
        if not pod_spec:
            return

        res_path = self._res_path(ns, kind, name)

        # --- Pod-level checks ---
        # K8S-POD-003: Host network
        if pod_spec.host_network:
            self._add(Finding(
                "K8S-POD-003", "Host network enabled", "Workload Security",
                "HIGH", res_path, None, "hostNetwork: true",
                "Pod shares the host network namespace, bypassing network policies and exposing host services.",
                "Set hostNetwork: false. Use Services and Ingress for external access.",
                "CWE-668",
            ))

        # K8S-POD-004: Host PID
        if pod_spec.host_pid:
            self._add(Finding(
                "K8S-POD-004", "Host PID namespace enabled", "Workload Security",
                "HIGH", res_path, None, "hostPID: true",
                "Pod can view and signal all host processes, enabling process injection and information disclosure.",
                "Set hostPID: false unless absolutely required.",
                "CWE-668",
            ))

        # K8S-POD-005: Host IPC
        if pod_spec.host_ipc:
            self._add(Finding(
                "K8S-POD-005", "Host IPC namespace enabled", "Workload Security",
                "HIGH", res_path, None, "hostIPC: true",
                "Pod shares host IPC namespace, allowing access to shared memory segments of host processes.",
                "Set hostIPC: false.",
                "CWE-668",
            ))

        # K8S-POD-021: Share process namespace
        if pod_spec.share_process_namespace:
            self._add(Finding(
                "K8S-POD-021", "Shared process namespace", "Workload Security",
                "MEDIUM", res_path, None, "shareProcessNamespace: true",
                "Containers in the pod share a process namespace, enabling inter-container signal and ptrace.",
                "Disable shareProcessNamespace unless required for sidecar debugging.",
            ))

        # K8S-POD-022: Unsafe sysctls
        if pod_spec.security_context and pod_spec.security_context.sysctls:
            unsafe = [s.name for s in pod_spec.security_context.sysctls
                      if not s.name.startswith("kernel.shm_") and
                         not s.name.startswith("net.ipv4.ping_group_range") and
                         s.name not in ("net.ipv4.ip_local_port_range",
                                        "net.ipv4.tcp_syncookies")]
            if unsafe:
                self._add(Finding(
                    "K8S-POD-022", "Unsafe sysctl settings", "Workload Security",
                    "HIGH", res_path, None, f"sysctls: {unsafe}",
                    "Pod sets unsafe sysctls that may affect host kernel parameters beyond pod isolation.",
                    "Use only safe sysctls or enable them via kubelet --allowed-unsafe-sysctls.",
                    "CWE-250",
                ))

        # K8S-POD-023: Seccomp profile at pod level
        pod_sc = pod_spec.security_context
        has_pod_seccomp = (pod_sc and pod_sc.seccomp_profile and
                          pod_sc.seccomp_profile.type in ("RuntimeDefault", "Localhost"))

        # K8S-POD-018: Default service account
        sa_name = pod_spec.service_account_name or pod_spec.service_account or "default"
        if sa_name == "default" and ns not in SYSTEM_NAMESPACES:
            self._add(Finding(
                "K8S-POD-018", "Default service account used", "Workload Security",
                "MEDIUM", res_path, None, f"serviceAccountName: default",
                "Workload uses the default service account which may have unintended RBAC bindings.",
                "Create a dedicated service account with minimal permissions for each workload.",
                "CWE-250",
            ))

        # K8S-POD-019: Auto-mount service account token
        auto_mount = pod_spec.automount_service_account_token
        if auto_mount is None or auto_mount is True:
            if ns not in SYSTEM_NAMESPACES:
                self._add(Finding(
                    "K8S-POD-019", "Service account token auto-mounted", "Workload Security",
                    "MEDIUM", res_path, None,
                    f"automountServiceAccountToken: {auto_mount}",
                    "SA token is mounted into the pod, granting API access if the SA has RBAC bindings.",
                    "Set automountServiceAccountToken: false if the workload does not need API access.",
                    "CWE-250",
                ))

        # K8S-POD-025: Workload in default namespace
        if ns == "default":
            self._add(Finding(
                "K8S-POD-025", "Workload in default namespace", "Workload Security",
                "MEDIUM", res_path, None, f"namespace: default",
                "Running workloads in the default namespace bypasses namespace-scoped security controls.",
                "Deploy workloads to dedicated namespaces with appropriate RBAC and network policies.",
            ))

        # --- Container-level checks ---
        all_containers = list(pod_spec.containers or [])
        all_containers.extend(pod_spec.init_containers or [])

        for ctr in all_containers:
            ctr_path = f"{res_path}/{ctr.name}"
            sc = ctr.security_context

            # K8S-POD-001: Privileged container
            if sc and sc.privileged:
                self._add(Finding(
                    "K8S-POD-001", "Privileged container", "Workload Security",
                    "CRITICAL", ctr_path, None, "privileged: true",
                    "Container runs with full host privileges, disabling all security boundaries.",
                    "Set privileged: false. Use specific capabilities instead.",
                    "CWE-250",
                ))

            # K8S-POD-002: Running as root
            runs_as_root = False
            if sc and sc.run_as_user == 0:
                runs_as_root = True
            if sc and sc.run_as_non_root is False:
                runs_as_root = True
            if not sc or (sc.run_as_non_root is None and sc.run_as_user is None):
                # No explicit setting — may default to root
                if not (pod_sc and pod_sc.run_as_non_root):
                    runs_as_root = True
            if runs_as_root:
                self._add(Finding(
                    "K8S-POD-002", "Container may run as root", "Workload Security",
                    "HIGH", ctr_path, None, "runAsNonRoot: not set or false",
                    "Container may run as UID 0 (root), increasing impact of container escape vulnerabilities.",
                    "Set runAsNonRoot: true and runAsUser to a non-zero UID.",
                    "CWE-250",
                ))

            # K8S-POD-006: Allow privilege escalation
            if not sc or sc.allow_privilege_escalation is None or sc.allow_privilege_escalation:
                self._add(Finding(
                    "K8S-POD-006", "Privilege escalation allowed", "Workload Security",
                    "HIGH", ctr_path, None,
                    f"allowPrivilegeEscalation: {sc.allow_privilege_escalation if sc else 'not set'}",
                    "Container allows child processes to gain more privileges via setuid/setgid binaries.",
                    "Set allowPrivilegeEscalation: false.",
                    "CWE-269",
                ))

            # Capability checks
            caps_add = []
            caps_drop = []
            if sc and sc.capabilities:
                caps_add = [c.upper() for c in (sc.capabilities.add or [])]
                caps_drop = [c.upper() for c in (sc.capabilities.drop or [])]

            # K8S-POD-007: SYS_ADMIN capability
            if "SYS_ADMIN" in caps_add:
                self._add(Finding(
                    "K8S-POD-007", "SYS_ADMIN capability added", "Workload Security",
                    "CRITICAL", ctr_path, None, "capabilities.add: SYS_ADMIN",
                    "SYS_ADMIN grants near-root privileges including mount, namespace, and BPF operations.",
                    "Remove SYS_ADMIN. Use more specific capabilities.",
                    "CWE-250",
                ))

            # K8S-POD-008: NET_RAW capability
            if "NET_RAW" in caps_add or ("NET_RAW" not in caps_drop and "ALL" not in caps_drop):
                # NET_RAW is in default set, flag only if not dropped
                if "NET_RAW" in caps_add:
                    self._add(Finding(
                        "K8S-POD-008", "NET_RAW capability present", "Workload Security",
                        "MEDIUM", ctr_path, None, "capabilities.add: NET_RAW",
                        "NET_RAW allows raw socket creation, enabling ARP spoofing and network-level attacks.",
                        "Drop NET_RAW capability unless required: capabilities.drop: ['NET_RAW'].",
                        "CWE-250",
                    ))

            # K8S-POD-009: ALL capabilities
            if "ALL" in caps_add:
                self._add(Finding(
                    "K8S-POD-009", "ALL capabilities added", "Workload Security",
                    "CRITICAL", ctr_path, None, "capabilities.add: ALL",
                    "Container granted all Linux capabilities, equivalent to running as privileged.",
                    "Remove capabilities.add: ALL. Add only specific required capabilities.",
                    "CWE-250",
                ))

            # K8S-POD-010: No capabilities dropped
            if not caps_drop and not (sc and sc.privileged):
                self._add(Finding(
                    "K8S-POD-010", "No capabilities dropped", "Workload Security",
                    "MEDIUM", ctr_path, None, "capabilities.drop: not set",
                    "Container retains all default capabilities. Best practice is to drop ALL and add only needed ones.",
                    "Set capabilities.drop: ['ALL'] and add back only required capabilities.",
                    "CWE-250",
                ))

            # Check for other dangerous capabilities
            for cap in caps_add:
                if cap in DANGEROUS_CAPS and cap not in ("SYS_ADMIN", "NET_RAW", "ALL"):
                    self._add(Finding(
                        "K8S-POD-007", f"Dangerous capability: {cap}", "Workload Security",
                        "HIGH", ctr_path, None, f"capabilities.add: {cap}",
                        f"Capability {cap} grants elevated privileges that may enable container breakout.",
                        f"Remove {cap} capability unless absolutely required.",
                        "CWE-250",
                    ))

            # K8S-POD-011: Writable root filesystem
            if not sc or not sc.read_only_root_filesystem:
                self._add(Finding(
                    "K8S-POD-011", "Writable root filesystem", "Workload Security",
                    "MEDIUM", ctr_path, None,
                    f"readOnlyRootFilesystem: {sc.read_only_root_filesystem if sc else 'not set'}",
                    "Container filesystem is writable, allowing attackers to modify binaries or drop malware.",
                    "Set readOnlyRootFilesystem: true. Use emptyDir volumes for writable paths.",
                ))

            # Resource limits/requests
            res = ctr.resources
            limits = res.limits if res else None
            requests = res.requests if res else None

            # K8S-POD-012: No CPU limits
            if not limits or "cpu" not in limits:
                self._add(Finding(
                    "K8S-POD-012", "No CPU limit", "Workload Security",
                    "MEDIUM", ctr_path, None, "resources.limits.cpu: not set",
                    "Without CPU limits, a container can consume all node CPU, causing DoS to co-located pods.",
                    "Set resources.limits.cpu to an appropriate value.",
                ))

            # K8S-POD-013: No memory limits
            if not limits or "memory" not in limits:
                self._add(Finding(
                    "K8S-POD-013", "No memory limit", "Workload Security",
                    "MEDIUM", ctr_path, None, "resources.limits.memory: not set",
                    "Without memory limits, a container can trigger OOM kills on the node.",
                    "Set resources.limits.memory to an appropriate value.",
                ))

            # K8S-POD-014: No CPU requests
            if not requests or "cpu" not in requests:
                self._add(Finding(
                    "K8S-POD-014", "No CPU request", "Workload Security",
                    "LOW", ctr_path, None, "resources.requests.cpu: not set",
                    "Without CPU requests, scheduler cannot make optimal placement decisions.",
                    "Set resources.requests.cpu for proper scheduling.",
                ))

            # K8S-POD-015: No memory requests
            if not requests or "memory" not in requests:
                self._add(Finding(
                    "K8S-POD-015", "No memory request", "Workload Security",
                    "LOW", ctr_path, None, "resources.requests.memory: not set",
                    "Without memory requests, pods may be evicted first under node memory pressure.",
                    "Set resources.requests.memory for proper scheduling.",
                ))

            # K8S-POD-016: No liveness probe (skip init containers)
            if ctr not in (pod_spec.init_containers or []):
                if not ctr.liveness_probe:
                    self._add(Finding(
                        "K8S-POD-016", "No liveness probe", "Workload Security",
                        "MEDIUM", ctr_path, None, "livenessProbe: not set",
                        "Without liveness probe, Kubernetes cannot detect and restart hung containers.",
                        "Configure a livenessProbe with appropriate thresholds.",
                    ))

                # K8S-POD-017: No readiness probe
                if not ctr.readiness_probe:
                    self._add(Finding(
                        "K8S-POD-017", "No readiness probe", "Workload Security",
                        "MEDIUM", ctr_path, None, "readinessProbe: not set",
                        "Without readiness probe, traffic is sent to pods before they are ready.",
                        "Configure a readinessProbe to prevent traffic to unready pods.",
                    ))

            # K8S-POD-020: Host port
            for port in (ctr.ports or []):
                if port.host_port:
                    self._add(Finding(
                        "K8S-POD-020", "Host port used", "Workload Security",
                        "MEDIUM", ctr_path, None,
                        f"hostPort: {port.host_port} (containerPort: {port.container_port})",
                        "Host port binding bypasses Kubernetes networking and limits pod scheduling.",
                        "Use NodePort or LoadBalancer Services instead of hostPort.",
                        "CWE-668",
                    ))

            # K8S-POD-023: Seccomp profile not set
            has_ctr_seccomp = (sc and sc.seccomp_profile and
                               sc.seccomp_profile.type in ("RuntimeDefault", "Localhost"))
            if not has_pod_seccomp and not has_ctr_seccomp:
                self._add(Finding(
                    "K8S-POD-023", "Seccomp profile not set", "Workload Security",
                    "MEDIUM", ctr_path, None, "seccompProfile: not set",
                    "No Seccomp profile restricts syscalls. Container can invoke any kernel syscall.",
                    "Set seccompProfile.type to RuntimeDefault or use a custom Localhost profile.",
                ))

            # K8S-POD-024: AppArmor/SELinux not set
            if not (sc and sc.se_linux_options):
                # Check for AppArmor annotation (legacy) or securityContext
                self._add(Finding(
                    "K8S-POD-024", "No AppArmor/SELinux profile", "Workload Security",
                    "LOW", ctr_path, None, "seLinuxOptions / appArmorProfile: not set",
                    "No mandatory access control profile applied. Container runs with default MAC policy.",
                    "Apply AppArmor or SELinux profiles for defense-in-depth.",
                ))

            # --- Image security checks ---
            image = ctr.image or ""
            tag = ""
            digest = ""

            if "@sha256:" in image:
                digest = image.split("@sha256:")[1]
                img_ref = image.split("@sha256:")[0]
            else:
                img_ref = image

            if ":" in img_ref:
                parts = img_ref.rsplit(":", 1)
                tag = parts[1] if len(parts) > 1 else ""
            else:
                tag = ""  # no tag specified

            # K8S-IMG-001: Latest tag
            if tag == "latest":
                self._add(Finding(
                    "K8S-IMG-001", "Image uses 'latest' tag", "Image Security",
                    "HIGH", ctr_path, None, f"image: {image}",
                    "The 'latest' tag is mutable and may pull different versions across deployments, breaking reproducibility.",
                    "Pin images to specific version tags or SHA256 digests.",
                    "CWE-829",
                ))

            # K8S-IMG-002: No tag specified
            if not tag and not digest:
                self._add(Finding(
                    "K8S-IMG-002", "No image tag specified", "Image Security",
                    "HIGH", ctr_path, None, f"image: {image}",
                    "Image without tag defaults to 'latest', which is mutable and unpredictable.",
                    "Always specify an explicit version tag or SHA256 digest.",
                    "CWE-829",
                ))

            # K8S-IMG-003: Image pull policy not Always
            pull_policy = ctr.image_pull_policy or ""
            if pull_policy != "Always" and not digest:
                self._add(Finding(
                    "K8S-IMG-003", "Image pull policy not Always", "Image Security",
                    "MEDIUM", ctr_path, None,
                    f"imagePullPolicy: {pull_policy or 'not set'}",
                    "Cached images may be stale or tampered. Without Always, updated images may not be pulled.",
                    "Set imagePullPolicy: Always, or use immutable image digests.",
                ))

            # K8S-IMG-004: No image digest
            if not digest:
                self._add(Finding(
                    "K8S-IMG-004", "Image without digest", "Image Security",
                    "LOW", ctr_path, None, f"image: {image}",
                    "Image reference uses a mutable tag without SHA256 digest pinning.",
                    "Use image digest (@sha256:...) for immutable, verifiable deployments.",
                ))

            # K8S-IMG-005: Untrusted registry
            registry = ""
            img_no_tag = img_ref.split(":")[0] if ":" in img_ref else img_ref
            if "/" in img_no_tag:
                registry = img_no_tag.split("/")[0]
            else:
                registry = "docker.io"  # default Docker Hub

            if registry and "." in registry and registry not in TRUSTED_REGISTRIES:
                self._add(Finding(
                    "K8S-IMG-005", "Image from non-standard registry", "Image Security",
                    "MEDIUM", ctr_path, None, f"registry: {registry}",
                    f"Image pulled from {registry} which is not in the trusted registry list.",
                    "Use images from trusted registries or add this registry to your allow list.",
                    "CWE-829",
                ))

            # K8S-SECRET-001: Secrets in environment variables
            for env in (ctr.env or []):
                if env.value_from and env.value_from.secret_key_ref:
                    self._add(Finding(
                        "K8S-SECRET-001", "Secret exposed as environment variable",
                        "Secret Management", "MEDIUM", ctr_path, None,
                        f"env.{env.name} -> secret:{env.value_from.secret_key_ref.name}",
                        "Secrets in env vars are visible in process listings, logs, and crash dumps.",
                        "Mount secrets as files via volumes instead of environment variables.",
                        "CWE-200",
                    ))

            # Check envFrom for secret refs
            for ef in (ctr.env_from or []):
                if ef.secret_ref:
                    self._add(Finding(
                        "K8S-SECRET-001", "Secret bulk-exposed as environment variables",
                        "Secret Management", "MEDIUM", ctr_path, None,
                        f"envFrom -> secret:{ef.secret_ref.name}",
                        "All keys from the secret are exposed as env vars, increasing attack surface.",
                        "Mount secrets as files via volumes. Limit exposure to needed keys only.",
                        "CWE-200",
                    ))

    # ===================================================================
    # CHECK GROUP 3: Network Security  (K8S-NET-001 to 010)
    # ===================================================================
    def _check_network_security(self):
        self._vprint("  [*] Checking network security ...")
        namespaces = self._get_namespaces()

        # Collect all network policies per namespace
        ns_has_netpol = {}
        for ns in namespaces:
            try:
                netpols = self.networking_v1.list_namespaced_network_policy(ns).items
                ns_has_netpol[ns] = netpols
            except ApiException:
                ns_has_netpol[ns] = []

        # --- K8S-NET-001: Namespace without network policy ---
        for ns in namespaces:
            if ns in SYSTEM_NAMESPACES:
                continue
            if not ns_has_netpol.get(ns):
                self._add(Finding(
                    "K8S-NET-001", "Namespace without network policy", "Network Security",
                    "HIGH", self._res_path(ns, "Namespace", ns), None,
                    "networkPolicies: 0",
                    "No network policy in namespace. All pod-to-pod traffic is allowed by default.",
                    "Create default-deny ingress/egress NetworkPolicies and allow only required traffic.",
                    "CWE-284",
                ))

        # Analyze network policies
        for ns, netpols in ns_has_netpol.items():
            for np in netpols:
                res = self._res_path(ns, "NetworkPolicy", np.metadata.name)
                spec = np.spec
                if not spec:
                    continue

                # K8S-NET-002: Allow-all ingress
                if spec.ingress is not None:
                    for rule in spec.ingress:
                        if not rule._from:
                            # Empty from = allow all ingress
                            self._add(Finding(
                                "K8S-NET-002", "Allow-all ingress network policy",
                                "Network Security", "HIGH", res, None,
                                "ingress.from: [] (allow all)",
                                "Network policy allows ingress from all sources, negating network isolation.",
                                "Specify explicit ingress sources (podSelector, namespaceSelector, ipBlock).",
                                "CWE-284",
                            ))

                # K8S-NET-003: Allow-all egress
                if spec.egress is not None:
                    for rule in spec.egress:
                        if not rule.to:
                            self._add(Finding(
                                "K8S-NET-003", "Allow-all egress network policy",
                                "Network Security", "MEDIUM", res, None,
                                "egress.to: [] (allow all)",
                                "Network policy allows egress to all destinations. Data exfiltration is unrestricted.",
                                "Specify explicit egress destinations (podSelector, namespaceSelector, ipBlock).",
                                "CWE-284",
                            ))

        # Check Services
        for ns in namespaces:
            try:
                services = self.core_v1.list_namespaced_service(ns).items
            except ApiException:
                continue

            for svc in services:
                res = self._res_path(ns, "Service", svc.metadata.name)
                svc_type = svc.spec.type or "ClusterIP"

                # K8S-NET-004: LoadBalancer service
                if svc_type == "LoadBalancer":
                    self._add(Finding(
                        "K8S-NET-004", "LoadBalancer service exposed", "Network Security",
                        "MEDIUM", res, None, f"type: LoadBalancer",
                        "Service is directly exposed to the internet via cloud load balancer.",
                        "Use Ingress controllers with TLS and authentication instead of direct LoadBalancer exposure.",
                        "CWE-668",
                    ))

                # K8S-NET-005: NodePort service
                if svc_type == "NodePort":
                    self._add(Finding(
                        "K8S-NET-005", "NodePort service exposed", "Network Security",
                        "MEDIUM", res, None, f"type: NodePort",
                        "Service exposes a port on every cluster node, widening the attack surface.",
                        "Use ClusterIP with Ingress instead of NodePort.",
                        "CWE-668",
                    ))

                # K8S-NET-006: ExternalIPs
                if svc.spec.external_i_ps:
                    self._add(Finding(
                        "K8S-NET-006", "Service with ExternalIPs", "Network Security",
                        "HIGH", res, None,
                        f"externalIPs: {svc.spec.external_i_ps}",
                        "ExternalIPs can be used for man-in-the-middle attacks if not properly controlled.",
                        "Avoid ExternalIPs. Use LoadBalancer or Ingress controllers.",
                        "CWE-668",
                    ))

                # K8S-NET-010: ExternalName service
                if svc_type == "ExternalName":
                    self._add(Finding(
                        "K8S-NET-010", "ExternalName service", "Network Security",
                        "LOW", res, None,
                        f"externalName: {svc.spec.external_name}",
                        "ExternalName services can redirect traffic to arbitrary external hosts, enabling SSRF.",
                        "Validate ExternalName targets. Consider using Egress NetworkPolicies.",
                    ))

        # Check Ingresses
        for ns in namespaces:
            try:
                ingresses = self.networking_v1.list_namespaced_ingress(ns).items
            except ApiException:
                continue

            for ing in ingresses:
                res = self._res_path(ns, "Ingress", ing.metadata.name)

                # K8S-NET-008: Ingress without TLS
                if not ing.spec.tls:
                    self._add(Finding(
                        "K8S-NET-008", "Ingress without TLS", "Network Security",
                        "HIGH", res, None, "tls: not configured",
                        "Ingress serves traffic over HTTP without TLS encryption.",
                        "Configure TLS with a valid certificate for all Ingress resources.",
                        "CWE-319",
                    ))

                # K8S-NET-009: Wildcard ingress host
                for rule in (ing.spec.rules or []):
                    host = rule.host or ""
                    if host.startswith("*") or not host:
                        self._add(Finding(
                            "K8S-NET-009", "Wildcard or empty Ingress host", "Network Security",
                            "MEDIUM", res, None, f"host: {host or '(empty)'}",
                            "Wildcard/empty host matches all requests, potentially exposing internal services.",
                            "Specify explicit hostnames for each Ingress rule.",
                        ))

    # ===================================================================
    # CHECK GROUP 4: Namespace Security  (K8S-NS-001 to 008)
    # ===================================================================
    def _check_namespace_security(self):
        self._vprint("  [*] Checking namespace security ...")

        try:
            ns_list = self.core_v1.list_namespace().items
        except ApiException:
            self._warn("Cannot list namespaces")
            return

        for ns_obj in ns_list:
            ns = ns_obj.metadata.name
            if ns in {"kube-system", "kube-public", "kube-node-lease"}:
                continue

            res = self._res_path(None, "Namespace", ns)
            labels = ns_obj.metadata.labels or {}

            # --- K8S-NS-004: No Pod Security Admission label ---
            psa_enforce = labels.get("pod-security.kubernetes.io/enforce")
            psa_warn = labels.get("pod-security.kubernetes.io/warn")
            psa_audit = labels.get("pod-security.kubernetes.io/audit")

            if not psa_enforce and not psa_warn and not psa_audit:
                self._add(Finding(
                    "K8S-NS-004", "No Pod Security Admission labels", "Namespace Security",
                    "HIGH", res, None, "pod-security.kubernetes.io/*: not set",
                    "Namespace has no PSA labels. Privileged pods can be created without restriction.",
                    "Add pod-security.kubernetes.io/enforce: restricted (or baseline) label.",
                    "CWE-250",
                ))
            else:
                # K8S-NS-005: PSA mode set to warn only
                if not psa_enforce and psa_warn:
                    self._add(Finding(
                        "K8S-NS-005", "PSA set to warn-only mode", "Namespace Security",
                        "MEDIUM", res, None,
                        f"enforce: not set, warn: {psa_warn}",
                        "PSA warnings are logged but not enforced. Insecure pods can still be created.",
                        "Set pod-security.kubernetes.io/enforce to baseline or restricted.",
                    ))

                # K8S-NS-006: PSA not restricted
                if psa_enforce and psa_enforce not in ("restricted",):
                    self._add(Finding(
                        "K8S-NS-006", "PSA enforce level not restricted", "Namespace Security",
                        "MEDIUM", res, None,
                        f"enforce: {psa_enforce}",
                        f"PSA enforce level is '{psa_enforce}'. The 'restricted' level provides strongest security.",
                        "Consider upgrading to pod-security.kubernetes.io/enforce: restricted.",
                    ))

            # --- K8S-NS-002: No resource quota ---
            try:
                quotas = self.core_v1.list_namespaced_resource_quota(ns).items
            except ApiException:
                quotas = []
            if not quotas and ns != "default":
                self._add(Finding(
                    "K8S-NS-002", "No ResourceQuota", "Namespace Security",
                    "MEDIUM", res, None, "resourceQuotas: 0",
                    "Without ResourceQuota, a single namespace can exhaust cluster resources.",
                    "Create ResourceQuota to limit CPU, memory, and object counts per namespace.",
                ))

            # --- K8S-NS-003: No LimitRange ---
            try:
                limits = self.core_v1.list_namespaced_limit_range(ns).items
            except ApiException:
                limits = []
            if not limits and ns != "default":
                self._add(Finding(
                    "K8S-NS-003", "No LimitRange", "Namespace Security",
                    "MEDIUM", res, None, "limitRanges: 0",
                    "Without LimitRange, pods can request unlimited resources.",
                    "Create LimitRange to set default and max resource limits for containers.",
                ))

    # ===================================================================
    # CHECK GROUP 5: Secret Management  (K8S-SECRET-002 to 006)
    # ===================================================================
    def _check_secret_management(self):
        self._vprint("  [*] Checking secret management ...")
        namespaces = self._get_namespaces()

        for ns in namespaces:
            if ns in SYSTEM_NAMESPACES:
                continue

            # --- K8S-SECRET-004/005: ConfigMap with sensitive data ---
            try:
                cms = self.core_v1.list_namespaced_config_map(ns).items
            except ApiException:
                continue

            sensitive_patterns = re.compile(
                r'(password|secret|api_key|apikey|api-key|token|private_key|'
                r'private-key|access_key|secret_key|credentials|conn_string|'
                r'connection_string|database_url|db_password|jwt_secret)',
                re.IGNORECASE,
            )

            for cm in cms:
                if cm.metadata.name.startswith("kube-"):
                    continue
                data = cm.data or {}
                for key, value in data.items():
                    if sensitive_patterns.search(key):
                        self._add(Finding(
                            "K8S-SECRET-005", "Potential credentials in ConfigMap",
                            "Secret Management", "HIGH",
                            self._res_path(ns, "ConfigMap", cm.metadata.name),
                            None, f"key: {key}",
                            "ConfigMap key name suggests sensitive data. ConfigMaps are not encrypted at rest.",
                            "Move sensitive data to Secrets (or external vault) and enable encryption at rest.",
                            "CWE-312",
                        ))

            # --- K8S-SECRET-006: TLS secrets analysis ---
            try:
                secrets = self.core_v1.list_namespaced_secret(ns).items
            except ApiException:
                continue

            for sec in secrets:
                if sec.type == "kubernetes.io/tls":
                    res = self._res_path(ns, "Secret", sec.metadata.name)
                    # Check if certificate data exists
                    data = sec.data or {}
                    if "tls.crt" not in data or "tls.key" not in data:
                        self._add(Finding(
                            "K8S-SECRET-006", "Incomplete TLS secret",
                            "Secret Management", "MEDIUM", res, None,
                            "missing tls.crt or tls.key",
                            "TLS secret is missing certificate or key data.",
                            "Ensure TLS secrets contain both tls.crt and tls.key.",
                            "CWE-295",
                        ))

    # ===================================================================
    # CHECK GROUP 6: Service Account Security  (K8S-SA-001 to 006)
    # ===================================================================
    def _check_service_accounts(self):
        self._vprint("  [*] Checking service account security ...")
        namespaces = self._get_namespaces()

        # Collect all cluster role bindings
        try:
            crbs = self.rbac_v1.list_cluster_role_binding().items
        except ApiException:
            crbs = []

        # Build SA -> CRB mapping
        sa_crb_map = {}  # (ns, sa_name) -> list of (crb_name, role_name)
        for crb in crbs:
            for subj in (crb.subjects or []):
                if subj.kind == "ServiceAccount":
                    key = (subj.namespace or "default", subj.name)
                    sa_crb_map.setdefault(key, []).append(
                        (crb.metadata.name, crb.role_ref.name))

        for ns in namespaces:
            if ns in {"kube-system", "kube-node-lease"}:
                continue

            try:
                sas = self.core_v1.list_namespaced_service_account(ns).items
            except ApiException:
                continue

            # Collect pods in namespace to find which SAs are used
            try:
                pods = self.core_v1.list_namespaced_pod(ns).items
                used_sas = {(p.spec.service_account_name or
                             p.spec.service_account or "default")
                            for p in pods if p.spec}
            except ApiException:
                used_sas = set()

            for sa in sas:
                sa_name = sa.metadata.name
                res = self._res_path(ns, "ServiceAccount", sa_name)

                # --- K8S-SA-001: Default SA with extra bindings ---
                if sa_name == "default":
                    bindings = sa_crb_map.get((ns, "default"), [])
                    if bindings:
                        roles = ", ".join(r for _, r in bindings)
                        self._add(Finding(
                            "K8S-SA-001", "Default SA has ClusterRoleBindings",
                            "Service Account Security", "HIGH", res, None,
                            f"bound to: {roles}",
                            "Default service account has extra cluster-level bindings. All pods without explicit SA inherit these.",
                            "Remove bindings from the default SA. Create dedicated SAs for workloads.",
                            "CWE-250",
                        ))

                # --- K8S-SA-002: SA auto-mount token ---
                if sa.automount_service_account_token is None or sa.automount_service_account_token:
                    if sa_name != "default" and ns not in SYSTEM_NAMESPACES:
                        self._add(Finding(
                            "K8S-SA-002", "SA auto-mounts API token",
                            "Service Account Security", "MEDIUM", res, None,
                            f"automountServiceAccountToken: {sa.automount_service_account_token}",
                            "Service account token is auto-mounted to pods, granting API access.",
                            "Set automountServiceAccountToken: false on the ServiceAccount.",
                            "CWE-250",
                        ))

                # --- K8S-SA-003: SA with cluster-admin ---
                bindings = sa_crb_map.get((ns, sa_name), [])
                for crb_name, role_name in bindings:
                    if role_name == "cluster-admin":
                        self._add(Finding(
                            "K8S-SA-003", "SA bound to cluster-admin",
                            "Service Account Security", "CRITICAL", res, None,
                            f"via ClusterRoleBinding: {crb_name}",
                            "Service account has cluster-admin privileges. Any pod using this SA has full cluster access.",
                            "Replace cluster-admin with a scoped role containing only needed permissions.",
                            "CWE-250",
                        ))

                # --- K8S-SA-004: Unused service account ---
                if sa_name != "default" and sa_name not in used_sas:
                    # Check if it's a recent SA (skip if metadata has no creationTimestamp)
                    self._add(Finding(
                        "K8S-SA-004", "Potentially unused service account",
                        "Service Account Security", "LOW", res, None,
                        "no pods reference this SA",
                        "Service account exists but no running pods use it. Unused SAs increase attack surface.",
                        "Review and delete unused service accounts periodically.",
                    ))

    # ===================================================================
    # CHECK GROUP 7: Cluster Configuration  (K8S-CLUSTER-001 to 010)
    # ===================================================================
    def _check_cluster_config(self):
        self._vprint("  [*] Checking cluster configuration ...")

        # --- K8S-CLUSTER-008: Kubernetes Dashboard exposed ---
        try:
            svcs = self.core_v1.list_service_for_all_namespaces().items
            for svc in svcs:
                name = svc.metadata.name.lower()
                if "dashboard" in name and "kubernetes" in name:
                    svc_type = svc.spec.type or "ClusterIP"
                    if svc_type in ("NodePort", "LoadBalancer"):
                        self._add(Finding(
                            "K8S-CLUSTER-008", "Kubernetes Dashboard externally exposed",
                            "Cluster Configuration", "HIGH",
                            self._res_path(svc.metadata.namespace, "Service", svc.metadata.name),
                            None, f"type: {svc_type}",
                            "Kubernetes Dashboard is exposed externally. It provides full cluster management UI.",
                            "Set Dashboard service type to ClusterIP. Access via kubectl proxy or port-forward.",
                            "CWE-668",
                        ))
                    else:
                        self._add(Finding(
                            "K8S-CLUSTER-008", "Kubernetes Dashboard deployed",
                            "Cluster Configuration", "MEDIUM",
                            self._res_path(svc.metadata.namespace, "Service", svc.metadata.name),
                            None, f"type: {svc_type}",
                            "Kubernetes Dashboard is deployed. Ensure RBAC is properly configured for Dashboard SA.",
                            "Use minimal RBAC for Dashboard. Consider removing if not needed.",
                        ))
        except ApiException:
            pass

        # --- K8S-CLUSTER-009: Tiller (Helm v2) deployed ---
        try:
            pods = self.core_v1.list_namespaced_pod("kube-system").items
            for pod in pods:
                if "tiller" in (pod.metadata.name or "").lower():
                    self._add(Finding(
                        "K8S-CLUSTER-009", "Tiller (Helm v2) detected",
                        "Cluster Configuration", "CRITICAL",
                        self._res_path("kube-system", "Pod", pod.metadata.name),
                        None, f"pod: {pod.metadata.name}",
                        "Tiller runs with cluster-admin privileges by default. Helm v2 is deprecated and insecure.",
                        "Migrate to Helm v3 which is tillerless. Remove Tiller deployment immediately.",
                        "CWE-250",
                    ))
        except ApiException:
            pass

        # --- K8S-CLUSTER-010: Pods in kube-system with hostNetwork ---
        try:
            pods = self.core_v1.list_namespaced_pod("kube-system").items
            for pod in pods:
                if pod.spec and pod.spec.host_network:
                    # System components often need hostNetwork, only flag non-standard ones
                    known_system = {"kube-proxy", "kube-apiserver", "kube-controller-manager",
                                    "kube-scheduler", "etcd", "calico-node", "cilium",
                                    "aws-node", "kube-flannel"}
                    pod_name = pod.metadata.name or ""
                    if not any(pod_name.startswith(k) for k in known_system):
                        self._add(Finding(
                            "K8S-CLUSTER-010", "Non-system pod with hostNetwork in kube-system",
                            "Cluster Configuration", "MEDIUM",
                            self._res_path("kube-system", "Pod", pod.metadata.name),
                            None, "hostNetwork: true",
                            "Non-standard pod in kube-system uses hostNetwork, exposing host networking stack.",
                            "Review if this pod requires hostNetwork. Move to a dedicated namespace if possible.",
                            "CWE-668",
                        ))
        except ApiException:
            pass

        # --- K8S-CLUSTER-001 to 007: API Server config checks ---
        # These checks inspect API server pod spec in kube-system
        try:
            pods = self.core_v1.list_namespaced_pod("kube-system").items
            for pod in pods:
                if not (pod.metadata.name or "").startswith("kube-apiserver"):
                    continue
                containers = (pod.spec.containers or []) if pod.spec else []
                for ctr in containers:
                    args = list(ctr.command or []) + list(ctr.args or [])
                    args_str = " ".join(args)

                    # K8S-CLUSTER-001: Anonymous auth
                    if "--anonymous-auth=true" in args_str:
                        self._add(Finding(
                            "K8S-CLUSTER-001", "API server anonymous auth enabled",
                            "Cluster Configuration", "CRITICAL",
                            self._res_path("kube-system", "Pod", pod.metadata.name),
                            None, "--anonymous-auth=true",
                            "API server accepts unauthenticated requests. Attackers can query the API without credentials.",
                            "Set --anonymous-auth=false on the API server.",
                            "CWE-287",
                        ))

                    # K8S-CLUSTER-002: Insecure port
                    insecure_match = re.search(r'--insecure-port=(\d+)', args_str)
                    if insecure_match and insecure_match.group(1) != "0":
                        self._add(Finding(
                            "K8S-CLUSTER-002", "API server insecure port enabled",
                            "Cluster Configuration", "CRITICAL",
                            self._res_path("kube-system", "Pod", pod.metadata.name),
                            None, f"--insecure-port={insecure_match.group(1)}",
                            "API server listens on an unauthenticated, unencrypted port.",
                            "Set --insecure-port=0 to disable the insecure port.",
                            "CWE-319",
                        ))

                    # K8S-CLUSTER-003: Audit logging
                    if "--audit-policy-file" not in args_str:
                        self._add(Finding(
                            "K8S-CLUSTER-003", "Audit logging not configured",
                            "Cluster Configuration", "HIGH",
                            self._res_path("kube-system", "Pod", pod.metadata.name),
                            None, "--audit-policy-file: not set",
                            "API server audit logging is not configured. Security events are not recorded.",
                            "Configure --audit-policy-file and --audit-log-path for API audit logging.",
                            "CWE-778",
                        ))

                    # K8S-CLUSTER-004: Admission controllers
                    ac_match = re.search(r'--enable-admission-plugins=([^\s]+)', args_str)
                    if ac_match:
                        plugins = ac_match.group(1).split(",")
                        required = {"NodeRestriction"}
                        missing = required - set(plugins)
                        if missing:
                            self._add(Finding(
                                "K8S-CLUSTER-004", "Required admission controllers missing",
                                "Cluster Configuration", "HIGH",
                                self._res_path("kube-system", "Pod", pod.metadata.name),
                                None, f"missing: {missing}",
                                "Critical admission controllers are not enabled on the API server.",
                                f"Add {', '.join(missing)} to --enable-admission-plugins.",
                                "CWE-284",
                            ))

                        # Check for dangerous disabled plugins
                        disable_match = re.search(r'--disable-admission-plugins=([^\s]+)', args_str)
                        if disable_match:
                            disabled = disable_match.group(1).split(",")
                            dangerous_disable = {"PodSecurity", "NodeRestriction",
                                                  "ServiceAccount", "NamespaceLifecycle"}
                            bad = dangerous_disable & set(disabled)
                            if bad:
                                self._add(Finding(
                                    "K8S-CLUSTER-004",
                                    "Security admission controllers disabled",
                                    "Cluster Configuration", "HIGH",
                                    self._res_path("kube-system", "Pod", pod.metadata.name),
                                    None, f"disabled: {bad}",
                                    "Critical admission controllers have been explicitly disabled.",
                                    f"Remove {', '.join(bad)} from --disable-admission-plugins.",
                                    "CWE-284",
                                ))

                    # K8S-CLUSTER-005: Encryption at rest
                    if "--encryption-provider-config" not in args_str:
                        self._add(Finding(
                            "K8S-CLUSTER-005", "Encryption at rest not configured",
                            "Cluster Configuration", "HIGH",
                            self._res_path("kube-system", "Pod", pod.metadata.name),
                            None, "--encryption-provider-config: not set",
                            "Secrets and other resources are stored unencrypted in etcd.",
                            "Configure --encryption-provider-config with aescbc or kms provider.",
                            "CWE-312",
                        ))

                    # K8S-CLUSTER-007: Profiling enabled
                    if "--profiling=true" in args_str or "--profiling" not in args_str:
                        self._add(Finding(
                            "K8S-CLUSTER-007", "API server profiling enabled",
                            "Cluster Configuration", "MEDIUM",
                            self._res_path("kube-system", "Pod", pod.metadata.name),
                            None, "--profiling: enabled (default)",
                            "Profiling endpoint exposes internal performance data that aids attackers.",
                            "Set --profiling=false on the API server.",
                        ))

            # Kubelet config check via node annotations
            try:
                nodes = self.core_v1.list_node().items
                for node in nodes:
                    annotations = node.metadata.annotations or {}
                    # K8S-CLUSTER-006: Kubelet anonymous auth
                    kubelet_config = annotations.get(
                        "kubeadm.alpha.kubernetes.io/cri-socket", "")
                    # We can't directly read kubelet config via API in most setups,
                    # but we can flag nodes for manual review
                    # This is a reminder check
            except ApiException:
                pass

        except ApiException:
            self._vprint("  [*] Cannot access kube-system pods (managed cluster?)")
            # For managed clusters (EKS/GKE/AKS), API server is not visible as pods
            # Flag this as informational
            self._add(Finding(
                "K8S-CLUSTER-003", "API server audit logging status unknown",
                "Cluster Configuration", "MEDIUM",
                self._res_path(None, "Cluster", "api-server"),
                None, "managed cluster - cannot inspect API server pod",
                "API server configuration is not directly accessible. Verify audit logging via cloud provider console.",
                "Enable audit logging in your managed Kubernetes service (EKS CloudTrail, GKE Audit Logs, AKS Diagnostic Settings).",
                "CWE-778",
            ))

    # ===================================================================
    # CHECK GROUP 8: Persistent Volumes  (K8S-PV-001 to 004)
    # ===================================================================
    def _check_persistent_volumes(self):
        self._vprint("  [*] Checking persistent volume security ...")

        try:
            pvs = self.core_v1.list_persistent_volume().items
        except ApiException:
            self._warn("Cannot list PersistentVolumes")
            return

        for pv in pvs:
            res = self._res_path(None, "PersistentVolume", pv.metadata.name)

            # K8S-PV-001: hostPath volume
            if pv.spec.host_path:
                path = pv.spec.host_path.path or "/"
                severity = "CRITICAL" if path in ("/", "/etc", "/var", "/root") else "HIGH"
                self._add(Finding(
                    "K8S-PV-001", "PersistentVolume uses hostPath", "Storage Security",
                    severity, res, None, f"hostPath: {path}",
                    f"PV mounts host filesystem path '{path}'. Pods using this PV can access/modify host files.",
                    "Use CSI drivers, cloud volumes, or NFS instead of hostPath PVs.",
                    "CWE-668",
                ))

            # K8S-PV-002: No reclaim policy
            policy = pv.spec.persistent_volume_reclaim_policy or "Retain"
            if policy == "Recycle":
                self._add(Finding(
                    "K8S-PV-002", "PV uses deprecated Recycle policy", "Storage Security",
                    "MEDIUM", res, None, f"reclaimPolicy: {policy}",
                    "Recycle policy is deprecated and performs basic rm -rf which may leave data remnants.",
                    "Use Delete or Retain reclaim policy. Use dynamic provisioning with StorageClasses.",
                ))

        # Check PVCs for ReadWriteMany
        namespaces = self._get_namespaces()
        for ns in namespaces:
            try:
                pvcs = self.core_v1.list_namespaced_persistent_volume_claim(ns).items
            except ApiException:
                continue
            for pvc in pvcs:
                modes = pvc.spec.access_modes or []
                if "ReadWriteMany" in modes:
                    self._add(Finding(
                        "K8S-PV-003", "PVC with ReadWriteMany access", "Storage Security",
                        "MEDIUM",
                        self._res_path(ns, "PersistentVolumeClaim", pvc.metadata.name),
                        None, f"accessModes: {modes}",
                        "ReadWriteMany allows multiple nodes to mount the volume simultaneously, increasing data exposure.",
                        "Use ReadWriteOnce unless multi-node write access is required.",
                    ))

        # Check for emptyDir without size limits in workloads
        for ns in namespaces:
            try:
                deployments = self.apps_v1.list_namespaced_deployment(ns).items
            except ApiException:
                continue
            for dep in deployments:
                volumes = dep.spec.template.spec.volumes or []
                for vol in volumes:
                    if vol.empty_dir and not vol.empty_dir.size_limit:
                        self._add(Finding(
                            "K8S-PV-004", "EmptyDir without size limit", "Storage Security",
                            "LOW",
                            self._res_path(ns, "Deployment", dep.metadata.name),
                            None, f"volume: {vol.name}, sizeLimit: not set",
                            "EmptyDir without size limit can consume all available node disk space.",
                            "Set sizeLimit on emptyDir volumes to prevent disk exhaustion.",
                        ))

    # ===================================================================
    # CHECK GROUP 9: Jobs & CronJobs  (K8S-JOB-001 to 003)
    # ===================================================================
    def _check_jobs(self):
        self._vprint("  [*] Checking job security ...")
        namespaces = self._get_namespaces()

        for ns in namespaces:
            try:
                cronjobs = self.batch_v1.list_namespaced_cron_job(ns).items
            except ApiException:
                continue

            for cj in cronjobs:
                res = self._res_path(ns, "CronJob", cj.metadata.name)

                # K8S-JOB-001: No starting deadline
                if not cj.spec.starting_deadline_seconds:
                    self._add(Finding(
                        "K8S-JOB-001", "CronJob without starting deadline",
                        "Job Security", "LOW", res, None,
                        "startingDeadlineSeconds: not set",
                        "Without a deadline, missed CronJob runs accumulate and may trigger cascading job creation.",
                        "Set startingDeadlineSeconds to prevent runaway job creation.",
                    ))

                # K8S-JOB-003: Concurrency Allow (default)
                policy = cj.spec.concurrency_policy or "Allow"
                if policy == "Allow":
                    self._add(Finding(
                        "K8S-JOB-003", "CronJob allows concurrent runs",
                        "Job Security", "LOW", res, None,
                        f"concurrencyPolicy: {policy}",
                        "Multiple instances of this CronJob can run simultaneously, potentially causing resource contention.",
                        "Set concurrencyPolicy to Forbid or Replace if concurrent runs are not intended.",
                    ))

            # Jobs
            try:
                jobs = self.batch_v1.list_namespaced_job(ns).items
            except ApiException:
                continue

            for job in jobs:
                owners = job.metadata.owner_references or []
                if any(o.kind == "CronJob" for o in owners):
                    continue

                # K8S-JOB-002: No backoff limit
                if job.spec.backoff_limit is None or job.spec.backoff_limit > 10:
                    limit = job.spec.backoff_limit
                    self._add(Finding(
                        "K8S-JOB-002", "Job with high/no backoff limit",
                        "Job Security", "LOW",
                        self._res_path(ns, "Job", job.metadata.name),
                        None, f"backoffLimit: {limit}",
                        "Job may retry excessively on failure, consuming cluster resources.",
                        "Set backoffLimit to a reasonable value (e.g., 3-6).",
                    ))

    # ===================================================================
    # CHECK GROUP 10: Admission Control  (K8S-ADM-001 to 005)
    # ===================================================================
    def _check_admission_control(self):
        self._vprint("  [*] Checking admission control ...")

        # Check ValidatingWebhookConfigurations
        try:
            vwcs = self.admreg_v1.list_validating_webhook_configuration().items
        except ApiException:
            vwcs = []

        # Check MutatingWebhookConfigurations
        try:
            mwcs = self.admreg_v1.list_mutating_webhook_configuration().items
        except ApiException:
            mwcs = []

        for wc in vwcs + mwcs:
            kind = ("ValidatingWebhookConfiguration"
                    if wc in vwcs else "MutatingWebhookConfiguration")
            res = self._res_path(None, kind, wc.metadata.name)

            webhooks = wc.webhooks or []
            for wh in webhooks:
                # K8S-ADM-001: Webhook with failurePolicy Ignore
                if wh.failure_policy == "Ignore":
                    self._add(Finding(
                        "K8S-ADM-001", "Webhook failurePolicy set to Ignore",
                        "Admission Control", "HIGH", res, None,
                        f"webhook: {wh.name}, failurePolicy: Ignore",
                        "If the webhook is unavailable, requests bypass validation. Attackers can exploit outages.",
                        "Set failurePolicy to Fail to enforce security even during webhook downtime.",
                        "CWE-636",
                    ))

                # K8S-ADM-002: Webhook without namespace selector
                if not wh.namespace_selector:
                    self._add(Finding(
                        "K8S-ADM-002", "Webhook without namespace selector",
                        "Admission Control", "MEDIUM", res, None,
                        f"webhook: {wh.name}, namespaceSelector: not set",
                        "Webhook applies to all namespaces including kube-system, which may cause bootstrap issues.",
                        "Add namespaceSelector to exclude system namespaces if appropriate.",
                    ))

                # K8S-ADM-003: Webhook with broad scope
                for rule in (wh.rules or []):
                    resources = rule.resources or []
                    operations = rule.operations or []
                    if "*" in resources and "*" in operations:
                        self._add(Finding(
                            "K8S-ADM-003", "Webhook intercepts all resources and operations",
                            "Admission Control", "MEDIUM", res, None,
                            f"webhook: {wh.name}, resources: *, operations: *",
                            "Overly broad webhook scope may cause performance degradation and blocking.",
                            "Narrow webhook rules to specific resources and operations.",
                        ))

                # K8S-ADM-004: Webhook timeout too high
                timeout = wh.timeout_seconds or 10
                if timeout > 15:
                    self._add(Finding(
                        "K8S-ADM-004", "Webhook timeout too high",
                        "Admission Control", "LOW", res, None,
                        f"webhook: {wh.name}, timeoutSeconds: {timeout}",
                        "High webhook timeout can delay API server responses and degrade cluster performance.",
                        "Set timeoutSeconds to 10 or less.",
                    ))

        # K8S-ADM-005: No validating webhooks at all
        non_system_vwc = [w for w in vwcs
                          if not (w.metadata.name or "").startswith("system")]
        if not non_system_vwc:
            self._add(Finding(
                "K8S-ADM-005", "No validating admission webhooks configured",
                "Admission Control", "MEDIUM",
                self._res_path(None, "Cluster", "admission-control"),
                None, "validatingWebhookConfigurations: 0",
                "No custom admission validation. Consider policy engines like OPA/Gatekeeper, Kyverno, or built-in PSA.",
                "Deploy a policy engine or configure Pod Security Admission for workload validation.",
                "CWE-284",
            ))

    # ===================================================================
    # Reporting
    # ===================================================================
    def summary(self) -> dict:
        counts = {s: 0 for s in self.SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def filter_severity(self, min_severity: str):
        threshold = self.SEVERITY_ORDER.get(min_severity.upper(), 4)
        self.findings = [
            f for f in self.findings
            if self.SEVERITY_ORDER.get(f.severity, 4) <= threshold
        ]

    def print_report(self):
        B, R = self.BOLD, self.RESET
        print(f"\n{B}{'=' * 76}{R}")
        print(f"{B}  KSPM Scanner v{VERSION}  --  Kubernetes Security Posture Report{R}")
        print(f"{'=' * 76}")
        print(f"  Cluster   : {self.cluster_name}")
        print(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Findings  : {len(self.findings)}")
        print(f"{'=' * 76}\n")

        sorted_findings = sorted(
            self.findings,
            key=lambda f: (self.SEVERITY_ORDER.get(f.severity, 4),
                           f.category, f.rule_id),
        )

        for f in sorted_findings:
            c = self.SEVERITY_COLOR.get(f.severity, "")
            cis = self._cis(f.rule_id)
            cis_str = f"  CIS      : {cis}\n" if cis else ""
            cwe_str = f"  CWE      : {f.cwe}\n" if f.cwe else ""
            print(f"{c}{B}[{f.severity}]{R}  {f.rule_id}  {f.name}")
            print(f"  Resource : {f.file_path}")
            print(f"  Detail   : {f.line_content}")
            print(f"{cis_str}{cwe_str}"
                  f"  Issue    : {f.description}\n"
                  f"  Fix      : {f.recommendation}\n")

        counts = self.summary()
        print(f"{B}{'=' * 76}{R}")
        print(f"{B}  SUMMARY{R}")
        print("=" * 76)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            c = self.SEVERITY_COLOR.get(sev, "")
            print(f"  {c}{sev:<10}{R}  {counts.get(sev, 0)}")
        print("=" * 76)

    def save_json(self, path: str):
        report = {
            "scanner": "kspm_scanner",
            "version": VERSION,
            "generated": datetime.now(timezone.utc).isoformat(),
            "cluster": self.cluster_name,
            "findings_count": len(self.findings),
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\n[+] JSON report saved to: {os.path.abspath(path)}")

    def save_html(self, path: str):
        esc = html_mod.escape
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        counts = self.summary()

        sev_badge = {
            "CRITICAL": "background:#c0392b;color:#fff",
            "HIGH":     "background:#e67e22;color:#fff",
            "MEDIUM":   "background:#2980b9;color:#fff",
            "LOW":      "background:#27ae60;color:#fff",
        }
        row_border = {
            "CRITICAL": "border-left:4px solid #c0392b",
            "HIGH":     "border-left:4px solid #e67e22",
            "MEDIUM":   "border-left:4px solid #2980b9",
            "LOW":      "border-left:4px solid #27ae60",
        }

        # Summary chips
        chips = ""
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            c = counts.get(sev, 0)
            st = sev_badge[sev]
            chips += (f'<span style="{st};padding:4px 14px;border-radius:12px;'
                      f'font-weight:bold;font-size:0.9em;margin:0 6px">'
                      f'{esc(sev)}: {c}</span>')

        sorted_findings = sorted(
            self.findings,
            key=lambda f: (self.SEVERITY_ORDER.get(f.severity, 4),
                           f.category, f.rule_id),
        )

        # Category options
        categories = sorted({f.category for f in self.findings})
        cat_options = "".join(f'<option>{esc(c)}</option>' for c in categories)

        # Table rows
        rows = ""
        for i, f in enumerate(sorted_findings):
            bg = "#1e1e2e" if i % 2 == 0 else "#252535"
            rb = row_border.get(f.severity, "")
            sb = sev_badge.get(f.severity, "")
            cis = self._cis(f.rule_id)
            cis_html = f' <span style="color:#89b4fa;font-size:0.85em">[{esc(cis)}]</span>' if cis else ""
            rows += (
                f'<tr style="background:{bg};{rb}" '
                f'data-severity="{esc(f.severity)}" data-category="{esc(f.category)}">'
                f'<td style="padding:10px 14px;text-align:center">'
                f'<span style="{sb};padding:3px 10px;border-radius:8px;font-weight:bold;'
                f'font-size:0.85em">{esc(f.severity)}</span></td>'
                f'<td style="padding:10px 8px;color:#f9e2af;font-family:monospace">{esc(f.rule_id)}{cis_html}</td>'
                f'<td style="padding:10px 8px">{esc(f.category)}</td>'
                f'<td style="padding:10px 8px;font-weight:600">{esc(f.name)}</td>'
                f'<td style="padding:10px 8px;font-family:monospace;font-size:0.9em;'
                f'color:#a6adc8;max-width:280px;overflow:hidden;text-overflow:ellipsis;'
                f'white-space:nowrap" title="{esc(f.file_path)}">{esc(f.file_path)}</td>'
                f'<td style="padding:10px 8px;font-family:monospace;font-size:0.85em;'
                f'color:#bac2de;max-width:280px;overflow:hidden;text-overflow:ellipsis;'
                f'white-space:nowrap" title="{esc(f.line_content or "")}">'
                f'{esc(f.line_content or "")}</td>'
                f'<td style="padding:10px 8px;color:#89b4fa">{esc(f.cwe or "")}</td>'
                f'</tr>'
                f'<tr style="background:{bg}" data-severity="{esc(f.severity)}" '
                f'data-category="{esc(f.category)}">'
                f'<td colspan="7" style="padding:4px 14px 14px 50px;font-size:0.92em;'
                f'border-bottom:1px solid #313244">'
                f'<div style="color:#cdd6f4"><b>Issue:</b> {esc(f.description)}</div>'
                f'<div style="color:#a6e3a1;margin-top:3px"><b>Fix:</b> {esc(f.recommendation)}</div>'
                f'</td></tr>'
            )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>KSPM Scan Report — {esc(self.cluster_name)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#1a1b2e;color:#cdd6f4}}
header{{background:linear-gradient(135deg,#1a3a5c 0%,#326ce5 50%,#1a1b2e 100%);padding:28px 36px}}
header h1{{font-size:1.7em;color:#fff}}
header p{{color:#bac2de;margin-top:4px}}
header strong{{color:#89b4fa}}
.chips{{padding:18px 36px;background:#181825;display:flex;flex-wrap:wrap;gap:10px;align-items:center}}
.chips label{{color:#a6adc8;font-weight:600;margin-right:8px}}
.filters{{padding:14px 36px;background:#1e1e2e;display:flex;gap:12px;flex-wrap:wrap;align-items:center}}
.filters select,.filters input{{background:#313244;color:#cdd6f4;border:1px solid #45475a;
padding:6px 12px;border-radius:6px;font-size:0.92em}}
.filters label{{color:#a6adc8;font-size:0.9em}}
.container{{padding:20px 36px 40px}}
table{{width:100%;border-collapse:collapse}}
th{{background:#313244;color:#89b4fa;padding:12px 14px;position:sticky;top:0;
text-align:left;font-size:0.92em;z-index:1}}
tr:hover td{{filter:brightness(1.15)}}
.footer{{text-align:center;padding:18px;color:#585b70;font-size:0.85em}}
</style>
</head>
<body>
<header>
<h1>Kubernetes Security Posture Report</h1>
<p>Scanner: <strong>kspm_scanner v{esc(VERSION)}</strong></p>
<p>Cluster: <strong>{esc(self.cluster_name)}</strong></p>
<p>Generated: <strong>{esc(now)}</strong></p>
<p>Total Findings: <strong>{len(self.findings)}</strong></p>
</header>
<div class="chips">
<label>Severity:</label>
{chips}
</div>
<div class="filters">
<label>Filter:</label>
<select id="sevF" onchange="af()">
<option value="">All Severities</option>
<option value="CRITICAL">CRITICAL</option>
<option value="HIGH">HIGH</option>
<option value="MEDIUM">MEDIUM</option>
<option value="LOW">LOW</option>
</select>
<select id="catF" onchange="af()">
<option value="">All Categories</option>
{cat_options}
</select>
<input type="text" id="txtF" placeholder="Search rule ID / name ..." oninput="af()">
</div>
<div class="container">
<table id="ft">
<thead><tr>
<th>Severity</th><th>Rule ID</th><th>Category</th><th>Name</th>
<th>Resource</th><th>Detail</th><th>CWE</th>
</tr></thead>
<tbody>
{rows}
</tbody>
</table>
</div>
<div class="footer">KSPM Scanner v{esc(VERSION)} &mdash; Kubernetes Security Posture Management</div>
<script>
function af(){{
var s=document.getElementById('sevF').value.toUpperCase();
var c=document.getElementById('catF').value.toLowerCase();
var t=document.getElementById('txtF').value.toLowerCase();
document.querySelectorAll('#ft tbody tr').forEach(function(r){{
var rs=(r.getAttribute('data-severity')||'').toUpperCase();
var rc=(r.getAttribute('data-category')||'').toLowerCase();
var rt=r.textContent.toLowerCase();
var ok=(!s||rs===s)&&(!c||rc.includes(c))&&(!t||rt.includes(t));
r.style.display=ok?'':'none';
}});
}}
</script>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        print(f"\n[+] HTML report saved to: {os.path.abspath(path)}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        prog="kspm_scanner",
        description=(
            f"Kubernetes Security Posture Management (KSPM) Scanner v{VERSION}\n"
            "Agentless scanner for Kubernetes cluster security assessment.\n\n"
            "Covers: RBAC, Workload Hardening, Network Security, Namespace\n"
            "Isolation, Secret Management, Image Security, Service Accounts,\n"
            "Cluster Configuration, Storage, Jobs, and Admission Control."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--kubeconfig", "-k",
                        default=os.environ.get("KUBECONFIG", ""),
                        metavar="FILE",
                        help="Path to kubeconfig file. Env: KUBECONFIG")
    parser.add_argument("--context", "-c",
                        default=os.environ.get("K8S_CONTEXT", ""),
                        metavar="CTX",
                        help="Kubernetes context to use. Env: K8S_CONTEXT")
    parser.add_argument("--namespace", "-n",
                        default="",
                        metavar="NS",
                        help="Scan only this namespace (repeatable via comma)")
    parser.add_argument("--all-namespaces", "-A",
                        action="store_true", default=True,
                        help="Scan all namespaces (default)")
    parser.add_argument("--severity",
                        default="LOW",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        help="Minimum severity to report (default: LOW)")
    parser.add_argument("--json", metavar="FILE",
                        help="Save findings as JSON to FILE")
    parser.add_argument("--html", metavar="FILE",
                        help="Save findings as HTML report to FILE")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    parser.add_argument("--version", action="version",
                        version=f"kspm_scanner v{VERSION}")

    args = parser.parse_args()

    if not HAS_K8S:
        parser.error(
            "The 'kubernetes' library is required.\n"
            "  Install with: pip install kubernetes"
        )

    namespaces = None
    if args.namespace:
        namespaces = [ns.strip() for ns in args.namespace.split(",") if ns.strip()]

    scanner = KSPMScanner(
        kubeconfig=args.kubeconfig or None,
        context=args.context or None,
        namespaces=namespaces,
        all_namespaces=args.all_namespaces,
        verbose=args.verbose,
    )

    scanner.scan()
    scanner.filter_severity(args.severity)
    scanner.print_report()

    if args.json:
        scanner.save_json(args.json)
    if args.html:
        scanner.save_html(args.html)

    has_critical_high = any(
        f.severity in ("CRITICAL", "HIGH") for f in scanner.findings
    )
    sys.exit(1 if has_critical_high else 0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Test harness for KSPM Scanner — mocks the Kubernetes API with deliberately
insecure cluster data to exercise every check group.

Usage:
    PYTHONIOENCODING=utf-8 python test_data/run_test.py
"""

import sys
import os
import types
import json
from unittest.mock import MagicMock, patch, PropertyMock
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# 1. Build a comprehensive fake kubernetes.client module BEFORE importing
#    the scanner, because the scanner does "from kubernetes import client, config"
# ---------------------------------------------------------------------------

# Helper: simple namespace class that supports attribute access
class Obj:
    """Lightweight object that accepts keyword args as attributes."""
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)

    def __getattr__(self, name):
        return None

    def __repr__(self):
        attrs = ", ".join(f"{k}={v!r}" for k, v in self.__dict__.items())
        return f"Obj({attrs})"

    # Allow dict-style access too (some k8s client code uses .get)
    def get(self, key, default=None):
        return getattr(self, key, default)


def make_metadata(name, namespace=None, labels=None, annotations=None,
                  owner_references=None, creation_timestamp=None):
    return Obj(
        name=name,
        namespace=namespace,
        labels=labels or {},
        annotations=annotations or {},
        owner_references=owner_references or [],
        creation_timestamp=creation_timestamp or datetime.now(timezone.utc).isoformat(),
        uid=f"uid-{name}",
    )


# ---------------------------------------------------------------------------
# 2. Build fake Kubernetes objects — deliberately insecure
# ---------------------------------------------------------------------------

# ---- Namespaces ----
NAMESPACES = [
    # Production NS without PSA labels, no quota, no limit range
    Obj(metadata=make_metadata("production", labels={})),
    # Staging NS with warn-only PSA
    Obj(metadata=make_metadata("staging", labels={
        "pod-security.kubernetes.io/warn": "baseline",
    })),
    # Dev NS with enforce=baseline (not restricted)
    Obj(metadata=make_metadata("dev", labels={
        "pod-security.kubernetes.io/enforce": "baseline",
    })),
    # Default namespace (workloads here get flagged)
    Obj(metadata=make_metadata("default", labels={})),
    # System namespaces
    Obj(metadata=make_metadata("kube-system", labels={})),
    Obj(metadata=make_metadata("kube-public", labels={})),
    Obj(metadata=make_metadata("kube-node-lease", labels={})),
    # Istio system NS (to trigger mesh checks)
    Obj(metadata=make_metadata("istio-system", labels={})),
]

# ---- ClusterRoleBindings ----
CLUSTER_ROLE_BINDINGS = [
    # CRB granting cluster-admin to a dev user (K8S-RBAC-001)
    Obj(
        metadata=make_metadata("dev-admin-binding"),
        role_ref=Obj(name="cluster-admin", kind="ClusterRole", api_group="rbac.authorization.k8s.io"),
        subjects=[Obj(kind="User", name="dev-user", namespace=None, api_group="rbac.authorization.k8s.io")],
    ),
    # CRB granting role to system:anonymous (K8S-RBAC-006)
    Obj(
        metadata=make_metadata("anon-binding"),
        role_ref=Obj(name="view", kind="ClusterRole", api_group="rbac.authorization.k8s.io"),
        subjects=[Obj(kind="User", name="system:anonymous", namespace=None, api_group="rbac.authorization.k8s.io")],
    ),
    # CRB granting role to system:unauthenticated (K8S-RBAC-007)
    Obj(
        metadata=make_metadata("unauth-binding"),
        role_ref=Obj(name="edit", kind="ClusterRole", api_group="rbac.authorization.k8s.io"),
        subjects=[Obj(kind="Group", name="system:unauthenticated", namespace=None, api_group="rbac.authorization.k8s.io")],
    ),
    # CRB for default SA with cluster-admin (K8S-SA-001, K8S-SA-003)
    Obj(
        metadata=make_metadata("default-sa-admin"),
        role_ref=Obj(name="cluster-admin", kind="ClusterRole", api_group="rbac.authorization.k8s.io"),
        subjects=[Obj(kind="ServiceAccount", name="default", namespace="production", api_group="")],
    ),
    # System CRBs (should be skipped)
    Obj(
        metadata=make_metadata("system:masters"),
        role_ref=Obj(name="cluster-admin", kind="ClusterRole", api_group="rbac.authorization.k8s.io"),
        subjects=[Obj(kind="Group", name="system:masters", namespace=None, api_group="rbac.authorization.k8s.io")],
    ),
]

# ---- ClusterRoles ----
CLUSTER_ROLES = [
    # CR with wildcard resources (K8S-RBAC-002)
    Obj(
        metadata=make_metadata("overpermissive-role"),
        rules=[
            Obj(resources=["*"], verbs=["get", "list", "watch"], api_groups=["*"]),
        ],
    ),
    # CR with wildcard verbs (K8S-RBAC-003) + secrets access (K8S-RBAC-004)
    Obj(
        metadata=make_metadata("dangerous-role"),
        rules=[
            Obj(resources=["secrets"], verbs=["*"], api_groups=[""]),
            Obj(resources=["pods/exec", "pods/attach"], verbs=["create"], api_groups=[""]),
        ],
    ),
    # CR with escalate, bind, impersonate (K8S-RBAC-008, 009, 010)
    Obj(
        metadata=make_metadata("escalation-role"),
        rules=[
            Obj(resources=["clusterroles"], verbs=["escalate", "bind"], api_groups=["rbac.authorization.k8s.io"]),
            Obj(resources=["users", "groups"], verbs=["impersonate"], api_groups=[""]),
            Obj(resources=["nodes/proxy"], verbs=["*"], api_groups=[""]),
            Obj(resources=["certificatesigningrequests/approval"], verbs=["update"], api_groups=["certificates.k8s.io"]),
            Obj(resources=["persistentvolumes"], verbs=["create", "delete"], api_groups=[""]),
            Obj(resources=["serviceaccounts/token"], verbs=["create"], api_groups=[""]),
        ],
    ),
    # CR with pod create (K8S-RBAC-012)
    Obj(
        metadata=make_metadata("pod-creator-role"),
        rules=[
            Obj(resources=["pods"], verbs=["create", "get", "list"], api_groups=[""]),
        ],
    ),
    # System role (should be skipped)
    Obj(
        metadata=make_metadata("system:controller:foo"),
        rules=[Obj(resources=["*"], verbs=["*"], api_groups=["*"])],
    ),
]

# ---- Namespace-scoped Roles ----
ROLES_ALL = [
    # Role with wildcard everything (K8S-RBAC-002 for namespace)
    Obj(
        metadata=make_metadata("ns-admin", namespace="production"),
        rules=[Obj(resources=["*"], verbs=["*"], api_groups=["*"])],
    ),
]

# ---- RoleBindings (namespace-scoped) ----
ROLE_BINDINGS_ALL = []

# ---- Deployments ----
def make_container(name, image, privileged=False, run_as_root=False,
                   allow_priv_esc=None, caps_add=None, caps_drop=None,
                   read_only_root=False, resources=None,
                   liveness_probe=None, readiness_probe=None,
                   env=None, volume_mounts=None):
    sc = None
    if privileged or run_as_root or allow_priv_esc is not None or caps_add or caps_drop or read_only_root:
        caps = None
        if caps_add or caps_drop:
            caps = Obj(add=caps_add or [], drop=caps_drop or [])
        sc = Obj(
            privileged=privileged,
            run_as_user=0 if run_as_root else None,
            run_as_non_root=None,
            allow_privilege_escalation=allow_priv_esc,
            capabilities=caps,
            read_only_root_filesystem=read_only_root,
            seccomp_profile=None,
        )
    return Obj(
        name=name,
        image=image,
        security_context=sc,
        resources=resources,
        liveness_probe=liveness_probe,
        readiness_probe=readiness_probe,
        env=env or [],
        env_from=[],
        ports=[Obj(container_port=8080)],
        volume_mounts=volume_mounts or [],
        command=None,
        args=None,
    )


def make_pod_spec(containers, init_containers=None, host_network=False,
                  host_pid=False, host_ipc=False, sa_name="default",
                  automount=None, share_process_ns=False, volumes=None,
                  runtime_class_name=None, security_context=None,
                  ephemeral_containers=None):
    return Obj(
        containers=containers,
        init_containers=init_containers or [],
        host_network=host_network,
        host_pid=host_pid,
        host_ipc=host_ipc,
        service_account_name=sa_name,
        service_account=sa_name,
        automount_service_account_token=automount,
        share_process_namespace=share_process_ns,
        volumes=volumes or [],
        runtime_class_name=runtime_class_name,
        security_context=security_context,
        ephemeral_containers=ephemeral_containers or [],
        node_selector=None,
        tolerations=[],
        affinity=None,
        topology_spread_constraints=None,
    )


# Insecure deployment — production namespace
INSECURE_DEPLOYMENT = Obj(
    metadata=make_metadata("insecure-app", namespace="production"),
    spec=Obj(
        replicas=3,
        selector=Obj(match_labels={"app": "insecure-app"}),
        template=Obj(
            spec=make_pod_spec(
                containers=[
                    # Privileged container, root, latest tag, no probes, no limits
                    make_container(
                        "web", "nginx:latest",
                        privileged=True,
                        run_as_root=True,
                        allow_priv_esc=True,
                        caps_add=["SYS_ADMIN", "NET_ADMIN", "ALL"],
                    ),
                    # EOL image, env with secrets
                    make_container(
                        "backend", "python:2.7",
                        env=[
                            Obj(name="DB_PASSWORD", value="s3cret", value_from=None),
                            Obj(name="API_KEY", value="key123", value_from=None),
                        ],
                    ),
                ],
                host_network=True,
                host_pid=True,
                host_ipc=True,
                sa_name="default",
                automount=True,
                share_process_ns=True,
                volumes=[
                    Obj(name="host-vol", host_path=Obj(path="/", type="Directory"),
                        empty_dir=None, secret=None, config_map=None,
                        persistent_volume_claim=None, projected=None),
                    Obj(name="cache", empty_dir=Obj(size_limit=None, medium=None),
                        host_path=None, secret=None, config_map=None,
                        persistent_volume_claim=None, projected=None),
                ],
            ),
        ),
    ),
)

# Deployment in default namespace
DEFAULT_NS_DEPLOYMENT = Obj(
    metadata=make_metadata("legacy-app", namespace="default"),
    spec=Obj(
        replicas=2,
        selector=Obj(match_labels={"app": "legacy-app"}),
        template=Obj(
            spec=make_pod_spec(
                containers=[
                    make_container("app", "centos:7",
                                   caps_add=["NET_RAW", "SYS_PTRACE"]),
                ],
                sa_name="default",
            ),
        ),
    ),
)

# Untrusted registry deployment
UNTRUSTED_DEPLOYMENT = Obj(
    metadata=make_metadata("sketchy-app", namespace="production"),
    spec=Obj(
        replicas=1,
        selector=Obj(match_labels={"app": "sketchy-app"}),
        template=Obj(
            spec=make_pod_spec(
                containers=[
                    make_container("app", "evil-registry.io/backdoor:v1"),
                ],
            ),
        ),
    ),
)

DEPLOYMENTS_BY_NS = {
    "production": [INSECURE_DEPLOYMENT, UNTRUSTED_DEPLOYMENT],
    "default": [DEFAULT_NS_DEPLOYMENT],
    "staging": [],
    "dev": [],
    "kube-system": [],
    "kube-public": [],
    "kube-node-lease": [],
    "istio-system": [],
}

# ---- StatefulSets ----
STATEFULSET_PROD = Obj(
    metadata=make_metadata("database", namespace="production"),
    spec=Obj(
        replicas=3,
        selector=Obj(match_labels={"app": "database"}),
        template=Obj(
            spec=make_pod_spec(
                containers=[
                    make_container("postgres", "postgres:13",
                                   resources=Obj(requests={"cpu": "500m", "memory": "1Gi"},
                                                 limits={"cpu": "2", "memory": "4Gi"})),
                ],
                sa_name="db-service-account",
                automount=False,
            ),
        ),
    ),
)

STATEFULSETS_BY_NS = {
    "production": [STATEFULSET_PROD],
    "default": [],
    "staging": [],
    "dev": [],
    "kube-system": [],
    "kube-public": [],
    "kube-node-lease": [],
    "istio-system": [],
}

# ---- DaemonSets ----
DAEMONSETS_BY_NS = {ns: [] for ns in [
    "production", "default", "staging", "dev",
    "kube-system", "kube-public", "kube-node-lease", "istio-system"
]}

# ---- CronJobs ----
CRONJOB = Obj(
    metadata=make_metadata("data-cleanup", namespace="production",
                           owner_references=[]),
    spec=Obj(
        starting_deadline_seconds=None,  # K8S-JOB-001
        concurrency_policy="Allow",       # K8S-JOB-003
        job_template=Obj(
            spec=Obj(
                template=Obj(
                    spec=make_pod_spec(
                        containers=[make_container("cleanup", "busybox:latest")],
                    ),
                ),
            ),
        ),
    ),
)

CRONJOBS_BY_NS = {ns: [] for ns in [
    "production", "default", "staging", "dev",
    "kube-system", "kube-public", "kube-node-lease", "istio-system"
]}
CRONJOBS_BY_NS["production"] = [CRONJOB]

# ---- Jobs ----
JOB = Obj(
    metadata=make_metadata("migration-job", namespace="production",
                           owner_references=[]),
    spec=Obj(
        backoff_limit=100,  # K8S-JOB-002
        template=Obj(
            spec=make_pod_spec(
                containers=[make_container("migrate", "flyway/flyway:latest")],
            ),
        ),
    ),
)

JOBS_BY_NS = {ns: [] for ns in [
    "production", "default", "staging", "dev",
    "kube-system", "kube-public", "kube-node-lease", "istio-system"
]}
JOBS_BY_NS["production"] = [JOB]

# ---- Services ----
SERVICES = {
    "production": [
        # LoadBalancer (K8S-NET-004)
        Obj(metadata=make_metadata("web-lb", namespace="production", labels={}),
            spec=Obj(type="LoadBalancer", external_i_ps=None, external_name=None,
                     ports=[Obj(port=80, target_port=8080, protocol="TCP", node_port=None)])),
        # NodePort (K8S-NET-005)
        Obj(metadata=make_metadata("api-nodeport", namespace="production", labels={}),
            spec=Obj(type="NodePort", external_i_ps=None, external_name=None,
                     ports=[Obj(port=8080, target_port=8080, protocol="TCP", node_port=30080)])),
        # ExternalIPs (K8S-NET-006)
        Obj(metadata=make_metadata("external-svc", namespace="production", labels={}),
            spec=Obj(type="ClusterIP", external_i_ps=["1.2.3.4"], external_name=None,
                     ports=[Obj(port=443, target_port=443, protocol="TCP", node_port=None)])),
        # ExternalName (K8S-NET-010)
        Obj(metadata=make_metadata("ext-db", namespace="production", labels={}),
            spec=Obj(type="ExternalName", external_i_ps=None,
                     external_name="db.evil-corp.com",
                     ports=[])),
    ],
    "default": [],
    "staging": [],
    "dev": [],
    "kube-system": [
        # Dashboard exposed as NodePort (K8S-CLUSTER-008)
        Obj(metadata=make_metadata("kubernetes-dashboard", namespace="kube-system", labels={}),
            spec=Obj(type="NodePort", external_i_ps=None, external_name=None,
                     ports=[Obj(port=443, target_port=8443, protocol="TCP", node_port=30443)])),
    ],
    "kube-public": [],
    "kube-node-lease": [],
    "istio-system": [
        # Mesh gateway exposed (K8S-MESH-004)
        Obj(metadata=make_metadata("istio-ingressgateway", namespace="istio-system",
                                   labels={"istio": "ingressgateway", "app": "istio-ingressgateway"}),
            spec=Obj(type="LoadBalancer", external_i_ps=None, external_name=None,
                     ports=[Obj(port=80, target_port=8080, protocol="TCP", node_port=None)])),
    ],
}

ALL_SERVICES = []
for svcs in SERVICES.values():
    ALL_SERVICES.extend(svcs)

# ---- NetworkPolicies ----
NETPOLS = {
    "production": [
        # Allow-all ingress (K8S-NET-002)
        Obj(metadata=make_metadata("allow-all-ingress", namespace="production"),
            spec=Obj(
                ingress=[Obj(_from=None)],  # empty from = allow all
                egress=[Obj(to=None)],      # empty to = allow all (K8S-NET-003)
                pod_selector=Obj(match_labels={}),
                policy_types=["Ingress", "Egress"],
            )),
    ],
    "default": [],   # No netpol (K8S-NET-001)
    "staging": [],   # No netpol
    "dev": [],       # No netpol
    "kube-system": [],
    "kube-public": [],
    "kube-node-lease": [],
    "istio-system": [],
}

# ---- Ingresses ----
INGRESSES = {
    "production": [
        # No TLS (K8S-NET-008) and wildcard host (K8S-NET-009)
        Obj(metadata=make_metadata("app-ingress", namespace="production"),
            spec=Obj(
                tls=None,
                rules=[
                    Obj(host=""),    # empty host
                    Obj(host="*.example.com"),  # wildcard
                ],
            )),
    ],
}

# ---- ConfigMaps ----
CONFIGMAPS = {
    "production": [
        # ConfigMap with sensitive keys (K8S-SECRET-005)
        Obj(metadata=make_metadata("app-config", namespace="production"),
            data={
                "database_url": "postgres://admin:password@db:5432/prod",
                "api_key": "sk-live-abc123xyz",
                "jwt_secret": "super-secret-jwt-key",
                "log_level": "info",
            }),
    ],
}

# ---- Secrets ----
SECRETS = {
    "production": [
        # Incomplete TLS secret (K8S-SECRET-006)
        Obj(metadata=make_metadata("bad-tls", namespace="production"),
            type="kubernetes.io/tls",
            data={"tls.crt": "base64cert"}),  # missing tls.key
    ],
}

# ---- ServiceAccounts ----
SERVICE_ACCOUNTS = {
    "production": [
        Obj(metadata=make_metadata("default", namespace="production"),
            automount_service_account_token=True),
        Obj(metadata=make_metadata("db-service-account", namespace="production"),
            automount_service_account_token=None),
        Obj(metadata=make_metadata("unused-sa", namespace="production"),
            automount_service_account_token=True),
    ],
    "default": [
        Obj(metadata=make_metadata("default", namespace="default"),
            automount_service_account_token=True),
    ],
    "staging": [
        Obj(metadata=make_metadata("default", namespace="staging"),
            automount_service_account_token=True),
    ],
}

# ---- Pods (for SA check, ephemeral containers, kube-system checks) ----
PODS = {
    "production": [
        Obj(metadata=make_metadata("insecure-app-pod-1", namespace="production"),
            spec=Obj(
                service_account_name="default",
                service_account="default",
                containers=[],
                ephemeral_containers=[
                    Obj(name="debug-shell",
                        security_context=Obj(privileged=True)),
                ],
                host_network=False,
            ),
            status=Obj(phase="Running")),
    ],
    "default": [
        Obj(metadata=make_metadata("legacy-pod", namespace="default"),
            spec=Obj(
                service_account_name="default",
                service_account="default",
                containers=[],
                ephemeral_containers=[],
                host_network=False,
            ),
            status=Obj(phase="Running")),
    ],
    "kube-system": [
        # API server with insecure config (K8S-CLUSTER-001 to 007)
        Obj(metadata=make_metadata("kube-apiserver-master", namespace="kube-system"),
            spec=Obj(
                containers=[
                    Obj(name="kube-apiserver",
                        command=["kube-apiserver"],
                        args=[
                            "--anonymous-auth=true",
                            "--insecure-port=8080",
                            "--enable-admission-plugins=NamespaceLifecycle,ServiceAccount",
                            # Missing: --audit-policy-file, --encryption-provider-config
                        ],
                        image="registry.k8s.io/kube-apiserver:v1.28.0",
                        security_context=None,
                        resources=None,
                        env=[],
                        env_from=[],
                        ports=[],
                        volume_mounts=[],
                        liveness_probe=None,
                        readiness_probe=None,
                    ),
                ],
                init_containers=[],
                ephemeral_containers=[],
                host_network=True,
                host_pid=False,
                host_ipc=False,
                service_account_name="kube-apiserver",
                service_account="kube-apiserver",
                automount_service_account_token=True,
                share_process_namespace=False,
                volumes=[],
                security_context=None,
                runtime_class_name=None,
            ),
            status=Obj(phase="Running")),
        # Tiller pod (K8S-CLUSTER-009)
        Obj(metadata=make_metadata("tiller-deploy-abc123", namespace="kube-system"),
            spec=Obj(
                containers=[],
                init_containers=[],
                ephemeral_containers=[],
                host_network=False,
                host_pid=False,
                host_ipc=False,
                service_account_name="tiller",
                service_account="tiller",
                automount_service_account_token=True,
                share_process_namespace=False,
                volumes=[],
                security_context=None,
                runtime_class_name=None,
            ),
            status=Obj(phase="Running")),
        # Non-system pod with hostNetwork (K8S-CLUSTER-010)
        Obj(metadata=make_metadata("suspicious-pod", namespace="kube-system"),
            spec=Obj(
                containers=[],
                init_containers=[],
                ephemeral_containers=[],
                host_network=True,
                host_pid=False,
                host_ipc=False,
                service_account_name="default",
                service_account="default",
                automount_service_account_token=True,
                share_process_namespace=False,
                volumes=[],
                security_context=None,
                runtime_class_name=None,
            ),
            status=Obj(phase="Running")),
    ],
}

# ---- Nodes ----
NODES = [
    # Outdated K8s version, old kernel, old runtime, NotReady, no zone label,
    # control-plane without taint
    Obj(
        metadata=make_metadata("master-1", labels={
            "node-role.kubernetes.io/control-plane": "",
            "kubernetes.io/hostname": "master-1",
        }),
        spec=Obj(taints=[]),  # Missing control-plane taint (K8S-NODE-005)
        status=Obj(
            node_info=Obj(
                kubelet_version="v1.25.0",       # Outdated (K8S-NODE-001)
                container_runtime_version="containerd://1.5.0",  # Outdated (K8S-NODE-002)
                kernel_version="4.15.0-generic",  # Old kernel (K8S-NODE-006)
                os_image="Ubuntu 18.04",
                operating_system="linux",
                architecture="amd64",
            ),
            conditions=[
                Obj(type="Ready", status="False", reason="KubeletNotReady",
                    message="container runtime not ready"),
                Obj(type="DiskPressure", status="True", reason="DiskPressure",
                    message="disk usage above threshold"),
                Obj(type="MemoryPressure", status="False", reason="",
                    message=""),
                Obj(type="PIDPressure", status="False", reason="",
                    message=""),
            ],
        ),
    ),
    # Worker node without issues but old version
    Obj(
        metadata=make_metadata("worker-1", labels={
            "kubernetes.io/hostname": "worker-1",
        }),
        spec=Obj(taints=[]),
        status=Obj(
            node_info=Obj(
                kubelet_version="v1.26.5",
                container_runtime_version="docker://19.03.15",  # Outdated docker
                kernel_version="5.4.0-generic",
                os_image="Ubuntu 20.04",
                operating_system="linux",
                architecture="amd64",
            ),
            conditions=[
                Obj(type="Ready", status="True", reason="KubeletReady",
                    message="kubelet is ready"),
            ],
        ),
    ),
]

# ---- PersistentVolumes ----
PERSISTENT_VOLUMES = [
    # hostPath to / (K8S-PV-001 CRITICAL)
    Obj(metadata=make_metadata("pv-hostpath-root"),
        spec=Obj(host_path=Obj(path="/", type="Directory"),
                 persistent_volume_reclaim_policy="Recycle",  # K8S-PV-002
                 access_modes=["ReadWriteOnce"],
                 capacity={"storage": "100Gi"})),
    # hostPath to /etc
    Obj(metadata=make_metadata("pv-hostpath-etc"),
        spec=Obj(host_path=Obj(path="/etc", type="Directory"),
                 persistent_volume_reclaim_policy="Retain",
                 access_modes=["ReadWriteOnce"],
                 capacity={"storage": "10Gi"})),
]

# ---- PVCs ----
PVCS = {
    "production": [
        Obj(metadata=make_metadata("shared-data", namespace="production"),
            spec=Obj(access_modes=["ReadWriteMany"])),  # K8S-PV-003
    ],
}

# ---- ResourceQuotas ----
RESOURCE_QUOTAS = {ns: [] for ns in [
    "production", "default", "staging", "dev",
    "kube-system", "kube-public", "kube-node-lease", "istio-system"
]}

# ---- LimitRanges ----
LIMIT_RANGES = {ns: [] for ns in [
    "production", "default", "staging", "dev",
    "kube-system", "kube-public", "kube-node-lease", "istio-system"
]}

# ---- ValidatingWebhookConfigurations ----
VALIDATING_WEBHOOKS = []  # Empty = K8S-ADM-005

# ---- MutatingWebhookConfigurations ----
MUTATING_WEBHOOKS = [
    Obj(metadata=make_metadata("bad-webhook"),
        webhooks=[
            Obj(name="bad.webhook.io",
                failure_policy="Ignore",      # K8S-ADM-001
                namespace_selector=None,       # K8S-ADM-002
                rules=[Obj(resources=["*"], operations=["*"], api_groups=["*"])],  # K8S-ADM-003
                timeout_seconds=30),           # K8S-ADM-004
        ]),
]

# ---- PodDisruptionBudgets ----
PDBS = {
    "production": [
        Obj(metadata=make_metadata("bad-pdb", namespace="production"),
            spec=Obj(
                selector=Obj(match_labels={"app": "something-else"}),
                max_unavailable="0",     # K8S-PDB-002
                min_available=None,
            )),
    ],
}

# ---- HPAs ----
HPAS = {
    "production": [
        Obj(metadata=make_metadata("web-hpa", namespace="production"),
            spec=Obj(
                min_replicas=1,       # K8S-HPA-001
                max_replicas=1,       # K8S-HPA-002 (min==max)
                scale_target_ref=Obj(kind="Deployment", name="insecure-app", api_version="apps/v1"),
                behavior=None,        # K8S-HPA-004 (no scale-down stabilization)
                metrics=[],
            )),
    ],
}


# ---------------------------------------------------------------------------
# 3. Build mock Kubernetes client
# ---------------------------------------------------------------------------
def build_mock_k8s():
    """Return patched kubernetes module objects."""

    # --- CoreV1Api ---
    core = MagicMock()
    core.list_namespace.return_value = Obj(items=NAMESPACES)
    core.read_namespace = lambda ns: next(
        (n for n in NAMESPACES if n.metadata.name == ns),
        Obj(metadata=make_metadata(ns, annotations={})))
    core.list_node.return_value = Obj(items=NODES)
    core.list_persistent_volume.return_value = Obj(items=PERSISTENT_VOLUMES)
    core.list_service_for_all_namespaces.return_value = Obj(items=ALL_SERVICES)

    def list_ns_svc(ns): return Obj(items=SERVICES.get(ns, []))
    def list_ns_pod(ns): return Obj(items=PODS.get(ns, []))
    def list_ns_sa(ns): return Obj(items=SERVICE_ACCOUNTS.get(ns, []))
    def list_ns_cm(ns): return Obj(items=CONFIGMAPS.get(ns, []))
    def list_ns_secret(ns): return Obj(items=SECRETS.get(ns, []))
    def list_ns_pvc(ns): return Obj(items=PVCS.get(ns, []))
    def list_ns_quota(ns): return Obj(items=RESOURCE_QUOTAS.get(ns, []))
    def list_ns_limit(ns): return Obj(items=LIMIT_RANGES.get(ns, []))

    core.list_namespaced_service = list_ns_svc
    core.list_namespaced_pod = list_ns_pod
    core.list_namespaced_service_account = list_ns_sa
    core.list_namespaced_config_map = list_ns_cm
    core.list_namespaced_secret = list_ns_secret
    core.list_namespaced_persistent_volume_claim = list_ns_pvc
    core.list_namespaced_resource_quota = list_ns_quota
    core.list_namespaced_limit_range = list_ns_limit

    # --- AppsV1Api ---
    apps = MagicMock()

    def list_ns_deploy(ns): return Obj(items=DEPLOYMENTS_BY_NS.get(ns, []))
    def list_ns_sts(ns): return Obj(items=STATEFULSETS_BY_NS.get(ns, []))
    def list_ns_ds(ns): return Obj(items=DAEMONSETS_BY_NS.get(ns, []))

    apps.list_namespaced_deployment = list_ns_deploy
    apps.list_namespaced_stateful_set = list_ns_sts
    apps.list_namespaced_daemon_set = list_ns_ds

    # For HPA target read
    def read_ns_deploy(name, ns):
        for d in DEPLOYMENTS_BY_NS.get(ns, []):
            if d.metadata.name == name:
                return d
        from kubernetes.client.rest import ApiException
        raise ApiException(status=404, reason="Not Found")

    def read_ns_sts(name, ns):
        for s in STATEFULSETS_BY_NS.get(ns, []):
            if s.metadata.name == name:
                return s
        from kubernetes.client.rest import ApiException
        raise ApiException(status=404, reason="Not Found")

    apps.read_namespaced_deployment = read_ns_deploy
    apps.read_namespaced_stateful_set = read_ns_sts

    # --- BatchV1Api ---
    batch = MagicMock()
    def list_ns_cj(ns): return Obj(items=CRONJOBS_BY_NS.get(ns, []))
    def list_ns_job(ns): return Obj(items=JOBS_BY_NS.get(ns, []))
    batch.list_namespaced_cron_job = list_ns_cj
    batch.list_namespaced_job = list_ns_job

    # --- RbacAuthorizationV1Api ---
    rbac = MagicMock()
    rbac.list_cluster_role_binding.return_value = Obj(items=CLUSTER_ROLE_BINDINGS)
    rbac.list_cluster_role.return_value = Obj(items=CLUSTER_ROLES)
    rbac.list_role_binding_for_all_namespaces.return_value = Obj(items=ROLE_BINDINGS_ALL)
    rbac.list_role_for_all_namespaces.return_value = Obj(items=ROLES_ALL)

    # --- NetworkingV1Api ---
    networking = MagicMock()
    def list_ns_netpol(ns): return Obj(items=NETPOLS.get(ns, []))
    def list_ns_ingress(ns): return Obj(items=INGRESSES.get(ns, []))
    networking.list_namespaced_network_policy = list_ns_netpol
    networking.list_namespaced_ingress = list_ns_ingress

    # --- AdmissionregistrationV1Api ---
    admreg = MagicMock()
    admreg.list_validating_webhook_configuration.return_value = Obj(items=VALIDATING_WEBHOOKS)
    admreg.list_mutating_webhook_configuration.return_value = Obj(items=MUTATING_WEBHOOKS)

    # --- PolicyV1Api ---
    policy = MagicMock()
    def list_ns_pdb(ns): return Obj(items=PDBS.get(ns, []))
    policy.list_namespaced_pod_disruption_budget = list_ns_pdb

    # --- AutoscalingV2Api ---
    autoscaling = MagicMock()
    def list_ns_hpa(ns): return Obj(items=HPAS.get(ns, []))
    autoscaling.list_namespaced_horizontal_pod_autoscaler = list_ns_hpa

    # --- CustomObjectsApi ---
    custom = MagicMock()

    def list_cluster_custom_object(group, version, plural):
        # RuntimeClasses
        if group == "node.k8s.io" and plural == "runtimeclasses":
            return {"items": []}
        # Istio PeerAuthentication
        if group == "security.istio.io" and plural == "peerauthentications":
            return {"items": [
                {"metadata": {"name": "default", "namespace": "istio-system"},
                 "spec": {"mtls": {"mode": "PERMISSIVE"}}},
            ]}
        # Istio AuthorizationPolicy
        if group == "security.istio.io" and plural == "authorizationpolicies":
            return {"items": []}
        # Kyverno ClusterPolicies
        if group == "kyverno.io" and plural == "clusterpolicies":
            return {"items": []}
        return {"items": []}

    def list_ns_custom_object(group, version, namespace, plural):
        # Kyverno namespace policies
        if group == "kyverno.io" and plural == "policies":
            return {"items": []}
        return {"items": []}

    custom.list_cluster_custom_object = list_cluster_custom_object
    custom.list_namespaced_custom_object = list_ns_custom_object

    # --- VersionApi ---
    version = MagicMock()
    version.get_code.return_value = Obj(
        major="1", minor="28", git_version="v1.28.0",
        platform="linux/amd64",
    )

    return core, apps, batch, rbac, networking, admreg, policy, autoscaling, custom, version


# ---------------------------------------------------------------------------
# 4. Run the scanner with mocked APIs
# ---------------------------------------------------------------------------
def main():
    # Ensure output directory exists
    os.makedirs(os.path.join(os.path.dirname(__file__)), exist_ok=True)

    # Add the parent directory to sys.path so we can import the scanner
    scanner_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if scanner_dir not in sys.path:
        sys.path.insert(0, scanner_dir)

    # We need to mock the kubernetes import before importing the scanner
    # Create a fake kubernetes module
    k8s_mod = types.ModuleType("kubernetes")
    k8s_client = types.ModuleType("kubernetes.client")
    k8s_config = types.ModuleType("kubernetes.config")
    k8s_rest = types.ModuleType("kubernetes.client.rest")

    # ConfigException
    class ConfigException(Exception):
        pass

    class ApiException(Exception):
        def __init__(self, status=500, reason="Error"):
            self.status = status
            self.reason = reason
            super().__init__(f"({status}) Reason: {reason}")

    k8s_config.ConfigException = ConfigException
    k8s_config.load_kube_config = lambda **kw: None
    k8s_config.load_incluster_config = lambda: (_ for _ in ()).throw(ConfigException("not in cluster"))

    k8s_rest.ApiException = ApiException

    # Build mock API clients
    core, apps, batch, rbac, networking, admreg, policy_api, autoscaling, custom, version = build_mock_k8s()

    # Mock the api_client for deprecated API checks
    mock_api_client = MagicMock()
    def call_api(path, method, **kwargs):
        # Return empty for deprecated API paths
        return {"groups": [], "resources": [], "items": []}
    mock_api_client.call_api = call_api
    core.api_client = mock_api_client

    k8s_client.CoreV1Api = lambda: core
    k8s_client.AppsV1Api = lambda: apps
    k8s_client.BatchV1Api = lambda: batch
    k8s_client.RbacAuthorizationV1Api = lambda: rbac
    k8s_client.NetworkingV1Api = lambda: networking
    k8s_client.AdmissionregistrationV1Api = lambda: admreg
    k8s_client.PolicyV1Api = lambda: policy_api
    k8s_client.AutoscalingV2Api = lambda: autoscaling
    k8s_client.CustomObjectsApi = lambda: custom
    k8s_client.VersionApi = lambda: version
    k8s_client.rest = k8s_rest

    k8s_mod.client = k8s_client
    k8s_mod.config = k8s_config

    # Register fake modules
    sys.modules["kubernetes"] = k8s_mod
    sys.modules["kubernetes.client"] = k8s_client
    sys.modules["kubernetes.config"] = k8s_config
    sys.modules["kubernetes.client.rest"] = k8s_rest

    # Now import the scanner
    import kspm_scanner

    # Override the ApiException in the scanner's namespace
    kspm_scanner.ApiException = ApiException

    # Create scanner instance — bypass __init__ connection logic
    scanner = object.__new__(kspm_scanner.KSPMScanner)
    scanner.findings = []
    scanner.verbose = True
    scanner.kubeconfig = None
    scanner.context_name = "test-cluster"
    scanner.target_namespaces = None
    scanner.all_namespaces = True
    scanner.cluster_name = "test-cluster"
    scanner.trusted_registries = set()
    scanner.trivy_path = None
    scanner.policy_dir = None
    scanner.rego_dir = None
    scanner.profile = None
    scanner.exceptions = []

    # Assign mock API clients
    scanner.core_v1 = core
    scanner.apps_v1 = apps
    scanner.batch_v1 = batch
    scanner.rbac_v1 = rbac
    scanner.networking_v1 = networking
    scanner.admreg_v1 = admreg
    scanner.policy_v1 = policy_api
    scanner.autoscaling_v2 = autoscaling
    scanner.custom_api = custom
    scanner.version_api = version

    # Run the scan!
    print("=" * 80)
    print("  KSPM Scanner Test Run — Mock Insecure Cluster")
    print("=" * 80)

    scanner.scan()

    # Filter and report
    scanner.filter_severity("LOW")
    scanner.print_report()

    # Save outputs
    test_dir = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(test_dir, "kspm_report.json")
    html_path = os.path.join(test_dir, "kspm_report.html")

    scanner.save_json(json_path)
    scanner.save_html(html_path)

    print(f"\n[*] JSON report saved: {json_path}")
    print(f"[*] HTML report saved: {html_path}")

    # Summary statistics
    print("\n" + "=" * 80)
    print("  SUMMARY")
    print("=" * 80)

    severity_counts = {}
    category_counts = {}
    for f in scanner.findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        category_counts[f.category] = category_counts.get(f.category, 0) + 1

    print(f"\n  Total findings: {len(scanner.findings)}")
    print("\n  By Severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_counts.get(sev, 0)
        print(f"    {sev:10s}: {count}")

    print("\n  By Category:")
    for cat in sorted(category_counts.keys()):
        print(f"    {cat:35s}: {category_counts[cat]}")

    # Compliance summary
    comp = scanner.compliance_summary()
    print("\n  Compliance Framework Coverage:")
    for framework, stats in comp.items():
        print(f"    {framework:35s}: {stats['findings_triggered']}/{stats['total_controls']} "
              f"controls triggered ({stats['coverage_pct']}%)")

    print("\n" + "=" * 80)
    return len(scanner.findings)


if __name__ == "__main__":
    count = main()
    sys.exit(0 if count > 0 else 1)

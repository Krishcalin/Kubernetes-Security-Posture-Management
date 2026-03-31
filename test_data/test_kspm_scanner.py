#!/usr/bin/env python3
"""
Test suite for KSPM Scanner - uses mock Kubernetes API data to validate
all check groups produce expected findings.
"""

import sys
import os
import types
import json
import unittest
from unittest.mock import MagicMock
from datetime import datetime, timezone

# Helper: simple namespace class that supports attribute access
class Obj:
    """Lightweight object that accepts keyword args as attributes."""
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)
    def __repr__(self):
        attrs = ", ".join(f"{k}={v!r}" for k, v in self.__dict__.items())
        return f"Obj({attrs})"
    def get(self, key, default=None):
        return getattr(self, key, default)


def make_metadata(name, namespace=None, labels=None, annotations=None,
                  owner_references=None, creation_timestamp=None):
    return Obj(
        name=name, namespace=namespace, labels=labels or {},
        annotations=annotations or {}, owner_references=owner_references or [],
        creation_timestamp=creation_timestamp or datetime.now(timezone.utc).isoformat(),
        uid=f"uid-{name}",
    )


# ---- Namespaces ----
NAMESPACES = [
    Obj(metadata=make_metadata("production", labels={})),
    Obj(metadata=make_metadata("staging", labels={"pod-security.kubernetes.io/warn": "baseline"})),
    Obj(metadata=make_metadata("dev", labels={"pod-security.kubernetes.io/enforce": "baseline"})),
    Obj(metadata=make_metadata("default", labels={})),
    Obj(metadata=make_metadata("kube-system", labels={})),
    Obj(metadata=make_metadata("kube-public", labels={})),
    Obj(metadata=make_metadata("kube-node-lease", labels={})),
    Obj(metadata=make_metadata("istio-system", labels={})),
]

# ---- ClusterRoleBindings ----
CLUSTER_ROLE_BINDINGS = [
    Obj(metadata=make_metadata("dev-admin-binding"),
        role_ref=Obj(name="cluster-admin", kind="ClusterRole", api_group="rbac.authorization.k8s.io"),
        subjects=[Obj(kind="User", name="dev-user", namespace=None, api_group="rbac.authorization.k8s.io")]),
    Obj(metadata=make_metadata("anon-binding"),
        role_ref=Obj(name="view", kind="ClusterRole", api_group="rbac.authorization.k8s.io"),
        subjects=[Obj(kind="User", name="system:anonymous", namespace=None, api_group="rbac.authorization.k8s.io")]),
    Obj(metadata=make_metadata("unauth-binding"),
        role_ref=Obj(name="edit", kind="ClusterRole", api_group="rbac.authorization.k8s.io"),
        subjects=[Obj(kind="Group", name="system:unauthenticated", namespace=None, api_group="rbac.authorization.k8s.io")]),
    Obj(metadata=make_metadata("default-sa-admin"),
        role_ref=Obj(name="cluster-admin", kind="ClusterRole", api_group="rbac.authorization.k8s.io"),
        subjects=[Obj(kind="ServiceAccount", name="default", namespace="production", api_group="")]),
    Obj(metadata=make_metadata("system:masters"),
        role_ref=Obj(name="cluster-admin", kind="ClusterRole", api_group="rbac.authorization.k8s.io"),
        subjects=[Obj(kind="Group", name="system:masters", namespace=None, api_group="rbac.authorization.k8s.io")]),
]

# ---- ClusterRoles ----
CLUSTER_ROLES = [
    Obj(metadata=make_metadata("overpermissive-role"),
        rules=[Obj(resources=["*"], verbs=["get", "list", "watch"], api_groups=["*"])]),
    Obj(metadata=make_metadata("dangerous-role"),
        rules=[
            Obj(resources=["secrets"], verbs=["*"], api_groups=[""]),
            Obj(resources=["pods/exec", "pods/attach"], verbs=["create"], api_groups=[""]),
        ]),
    Obj(metadata=make_metadata("escalation-role"),
        rules=[
            Obj(resources=["clusterroles"], verbs=["escalate", "bind"], api_groups=["rbac.authorization.k8s.io"]),
            Obj(resources=["users", "groups"], verbs=["impersonate"], api_groups=[""]),
            Obj(resources=["nodes/proxy"], verbs=["*"], api_groups=[""]),
            Obj(resources=["certificatesigningrequests/approval"], verbs=["update"], api_groups=["certificates.k8s.io"]),
            Obj(resources=["persistentvolumes"], verbs=["create", "delete"], api_groups=[""]),
            Obj(resources=["serviceaccounts/token"], verbs=["create"], api_groups=[""]),
        ]),
    Obj(metadata=make_metadata("pod-creator-role"),
        rules=[Obj(resources=["pods"], verbs=["create", "get", "list"], api_groups=[""])]),
    Obj(metadata=make_metadata("system:controller:foo"),
        rules=[Obj(resources=["*"], verbs=["*"], api_groups=["*"])]),
]

ROLES_ALL = [
    Obj(metadata=make_metadata("ns-admin", namespace="production"),
        rules=[Obj(resources=["*"], verbs=["*"], api_groups=["*"])]),
]

ROLE_BINDINGS_ALL = []

# ---- Container/Pod helpers ----
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
        sc = Obj(privileged=privileged, run_as_user=0 if run_as_root else None,
                 run_as_non_root=None, allow_privilege_escalation=allow_priv_esc,
                 capabilities=caps, read_only_root_filesystem=read_only_root,
                 seccomp_profile=None)
    return Obj(name=name, image=image, security_context=sc, resources=resources,
               liveness_probe=liveness_probe, readiness_probe=readiness_probe,
               env=env or [], env_from=[], ports=[Obj(container_port=8080)],
               volume_mounts=volume_mounts or [], command=None, args=None)


def make_pod_spec(containers, init_containers=None, host_network=False,
                  host_pid=False, host_ipc=False, sa_name="default",
                  automount=None, share_process_ns=False, volumes=None,
                  runtime_class_name=None, security_context=None,
                  ephemeral_containers=None):
    return Obj(containers=containers, init_containers=init_containers or [],
               host_network=host_network, host_pid=host_pid, host_ipc=host_ipc,
               service_account_name=sa_name, service_account=sa_name,
               automount_service_account_token=automount,
               share_process_namespace=share_process_ns, volumes=volumes or [],
               runtime_class_name=runtime_class_name,
               security_context=security_context,
               ephemeral_containers=ephemeral_containers or [],
               node_selector=None, tolerations=[], affinity=None,
               topology_spread_constraints=None)


# ---- Workloads ----
INSECURE_DEPLOYMENT = Obj(
    metadata=make_metadata("insecure-app", namespace="production"),
    spec=Obj(replicas=3, selector=Obj(match_labels={"app": "insecure-app"}),
             template=Obj(spec=make_pod_spec(
                 containers=[
                     make_container("web", "nginx:latest", privileged=True, run_as_root=True,
                                    allow_priv_esc=True, caps_add=["SYS_ADMIN", "NET_ADMIN", "ALL"]),
                     make_container("backend", "python:2.7",
                                    env=[Obj(name="DB_PASSWORD", value="s3cret", value_from=None),
                                         Obj(name="API_KEY", value="key123", value_from=None)]),
                 ],
                 host_network=True, host_pid=True, host_ipc=True,
                 sa_name="default", automount=True, share_process_ns=True,
                 volumes=[
                     Obj(name="host-vol", host_path=Obj(path="/", type="Directory"),
                         empty_dir=None, secret=None, config_map=None,
                         persistent_volume_claim=None, projected=None),
                     Obj(name="cache", empty_dir=Obj(size_limit=None, medium=None),
                         host_path=None, secret=None, config_map=None,
                         persistent_volume_claim=None, projected=None),
                 ],
             ))))

DEFAULT_NS_DEPLOYMENT = Obj(
    metadata=make_metadata("legacy-app", namespace="default"),
    spec=Obj(replicas=2, selector=Obj(match_labels={"app": "legacy-app"}),
             template=Obj(spec=make_pod_spec(
                 containers=[make_container("app", "centos:7", caps_add=["NET_RAW", "SYS_PTRACE"])],
                 sa_name="default"))))

UNTRUSTED_DEPLOYMENT = Obj(
    metadata=make_metadata("sketchy-app", namespace="production"),
    spec=Obj(replicas=1, selector=Obj(match_labels={"app": "sketchy-app"}),
             template=Obj(spec=make_pod_spec(
                 containers=[make_container("app", "evil-registry.io/backdoor:v1")]))))

DEPLOYMENTS_BY_NS = {
    "production": [INSECURE_DEPLOYMENT, UNTRUSTED_DEPLOYMENT],
    "default": [DEFAULT_NS_DEPLOYMENT],
    "staging": [], "dev": [], "kube-system": [],
    "kube-public": [], "kube-node-lease": [], "istio-system": [],
}

STATEFULSET_PROD = Obj(
    metadata=make_metadata("database", namespace="production"),
    spec=Obj(replicas=3, selector=Obj(match_labels={"app": "database"}),
             template=Obj(spec=make_pod_spec(
                 containers=[make_container("postgres", "postgres:13",
                     resources=Obj(requests={"cpu": "500m", "memory": "1Gi"},
                                   limits={"cpu": "2", "memory": "4Gi"}))],
                 sa_name="db-service-account", automount=False))))

STATEFULSETS_BY_NS = {"production": [STATEFULSET_PROD], "default": [], "staging": [], "dev": [],
                      "kube-system": [], "kube-public": [], "kube-node-lease": [], "istio-system": []}
DAEMONSETS_BY_NS = {ns: [] for ns in STATEFULSETS_BY_NS}

CRONJOB = Obj(
    metadata=make_metadata("data-cleanup", namespace="production", owner_references=[]),
    spec=Obj(starting_deadline_seconds=None, concurrency_policy="Allow",
             job_template=Obj(spec=Obj(template=Obj(
                 spec=make_pod_spec(containers=[make_container("cleanup", "busybox:latest")]))))))
CRONJOBS_BY_NS = {ns: [] for ns in STATEFULSETS_BY_NS}
CRONJOBS_BY_NS["production"] = [CRONJOB]

JOB = Obj(
    metadata=make_metadata("migration-job", namespace="production", owner_references=[]),
    spec=Obj(backoff_limit=100,
             template=Obj(spec=make_pod_spec(containers=[make_container("migrate", "flyway/flyway:latest")]))))
JOBS_BY_NS = {ns: [] for ns in STATEFULSETS_BY_NS}
JOBS_BY_NS["production"] = [JOB]

# ---- Services ----
SERVICES = {
    "production": [
        Obj(metadata=make_metadata("web-lb", namespace="production", labels={}),
            spec=Obj(type="LoadBalancer", external_i_ps=None, external_name=None,
                     ports=[Obj(port=80, target_port=8080, protocol="TCP", node_port=None)])),
        Obj(metadata=make_metadata("api-nodeport", namespace="production", labels={}),
            spec=Obj(type="NodePort", external_i_ps=None, external_name=None,
                     ports=[Obj(port=8080, target_port=8080, protocol="TCP", node_port=30080)])),
        Obj(metadata=make_metadata("external-svc", namespace="production", labels={}),
            spec=Obj(type="ClusterIP", external_i_ps=["1.2.3.4"], external_name=None,
                     ports=[Obj(port=443, target_port=443, protocol="TCP", node_port=None)])),
        Obj(metadata=make_metadata("ext-db", namespace="production", labels={}),
            spec=Obj(type="ExternalName", external_i_ps=None, external_name="db.evil-corp.com", ports=[])),
    ],
    "default": [], "staging": [], "dev": [],
    "kube-system": [
        Obj(metadata=make_metadata("kubernetes-dashboard", namespace="kube-system", labels={}),
            spec=Obj(type="NodePort", external_i_ps=None, external_name=None,
                     ports=[Obj(port=443, target_port=8443, protocol="TCP", node_port=30443)])),
    ],
    "kube-public": [], "kube-node-lease": [],
    "istio-system": [
        Obj(metadata=make_metadata("istio-ingressgateway", namespace="istio-system",
                                   labels={"istio": "ingressgateway", "app": "istio-ingressgateway"}),
            spec=Obj(type="LoadBalancer", external_i_ps=None, external_name=None,
                     ports=[Obj(port=80, target_port=8080, protocol="TCP", node_port=None)])),
    ],
}
ALL_SERVICES = [s for svcs in SERVICES.values() for s in svcs]

# ---- Network Policies ----
NETPOLS = {
    "production": [
        Obj(metadata=make_metadata("allow-all-ingress", namespace="production"),
            spec=Obj(ingress=[Obj(_from=None)], egress=[Obj(to=None)],
                     pod_selector=Obj(match_labels={}), policy_types=["Ingress", "Egress"])),
    ],
    "default": [], "staging": [], "dev": [], "kube-system": [],
    "kube-public": [], "kube-node-lease": [], "istio-system": [],
}

INGRESSES = {
    "production": [
        Obj(metadata=make_metadata("app-ingress", namespace="production"),
            spec=Obj(tls=None, rules=[Obj(host=""), Obj(host="*.example.com")])),
    ],
}

CONFIGMAPS = {
    "production": [
        Obj(metadata=make_metadata("app-config", namespace="production"),
            data={"database_url": "postgres://admin:password@db:5432/prod",
                  "api_key": "sk-live-abc123xyz", "jwt_secret": "super-secret-jwt-key",
                  "log_level": "info"}),
    ],
}

SECRETS = {
    "production": [
        Obj(metadata=make_metadata("bad-tls", namespace="production"),
            type="kubernetes.io/tls", data={"tls.crt": "base64cert"}),
    ],
}

SERVICE_ACCOUNTS = {
    "production": [
        Obj(metadata=make_metadata("default", namespace="production"), automount_service_account_token=True),
        Obj(metadata=make_metadata("db-service-account", namespace="production"), automount_service_account_token=None),
        Obj(metadata=make_metadata("unused-sa", namespace="production"), automount_service_account_token=True),
    ],
    "default": [Obj(metadata=make_metadata("default", namespace="default"), automount_service_account_token=True)],
    "staging": [Obj(metadata=make_metadata("default", namespace="staging"), automount_service_account_token=True)],
}

PODS = {
    "production": [
        Obj(metadata=make_metadata("insecure-app-pod-1", namespace="production"),
            spec=Obj(service_account_name="default", service_account="default", containers=[],
                     ephemeral_containers=[Obj(name="debug-shell", security_context=Obj(privileged=True))],
                     host_network=False),
            status=Obj(phase="Running")),
    ],
    "default": [
        Obj(metadata=make_metadata("legacy-pod", namespace="default"),
            spec=Obj(service_account_name="default", service_account="default", containers=[],
                     ephemeral_containers=[], host_network=False),
            status=Obj(phase="Running")),
    ],
    "kube-system": [
        Obj(metadata=make_metadata("kube-apiserver-master", namespace="kube-system"),
            spec=Obj(containers=[
                Obj(name="kube-apiserver", command=["kube-apiserver"],
                    args=["--anonymous-auth=true", "--insecure-port=8080",
                          "--enable-admission-plugins=NamespaceLifecycle,ServiceAccount"],
                    image="registry.k8s.io/kube-apiserver:v1.28.0",
                    security_context=None, resources=None, env=[], env_from=[], ports=[],
                    volume_mounts=[], liveness_probe=None, readiness_probe=None)],
                init_containers=[], ephemeral_containers=[], host_network=True,
                host_pid=False, host_ipc=False, service_account_name="kube-apiserver",
                service_account="kube-apiserver", automount_service_account_token=True,
                share_process_namespace=False, volumes=[], security_context=None,
                runtime_class_name=None),
            status=Obj(phase="Running")),
        Obj(metadata=make_metadata("tiller-deploy-abc123", namespace="kube-system"),
            spec=Obj(containers=[], init_containers=[], ephemeral_containers=[],
                     host_network=False, host_pid=False, host_ipc=False,
                     service_account_name="tiller", service_account="tiller",
                     automount_service_account_token=True, share_process_namespace=False,
                     volumes=[], security_context=None, runtime_class_name=None),
            status=Obj(phase="Running")),
        Obj(metadata=make_metadata("suspicious-pod", namespace="kube-system"),
            spec=Obj(containers=[], init_containers=[], ephemeral_containers=[],
                     host_network=True, host_pid=False, host_ipc=False,
                     service_account_name="default", service_account="default",
                     automount_service_account_token=True, share_process_namespace=False,
                     volumes=[], security_context=None, runtime_class_name=None),
            status=Obj(phase="Running")),
    ],
}

NODES = [
    Obj(metadata=make_metadata("master-1", labels={
            "node-role.kubernetes.io/control-plane": "", "kubernetes.io/hostname": "master-1"}),
        spec=Obj(taints=[]),
        status=Obj(node_info=Obj(kubelet_version="v1.25.0",
                                  container_runtime_version="containerd://1.5.0",
                                  kernel_version="4.15.0-generic", os_image="Ubuntu 18.04",
                                  operating_system="linux", architecture="amd64"),
                   conditions=[
                       Obj(type="Ready", status="False", reason="KubeletNotReady", message="runtime not ready"),
                       Obj(type="DiskPressure", status="True", reason="DiskPressure", message="above threshold"),
                       Obj(type="MemoryPressure", status="False", reason="", message=""),
                       Obj(type="PIDPressure", status="False", reason="", message="")])),
    Obj(metadata=make_metadata("worker-1", labels={"kubernetes.io/hostname": "worker-1"}),
        spec=Obj(taints=[]),
        status=Obj(node_info=Obj(kubelet_version="v1.26.5",
                                  container_runtime_version="docker://19.03.15",
                                  kernel_version="5.4.0-generic", os_image="Ubuntu 20.04",
                                  operating_system="linux", architecture="amd64"),
                   conditions=[Obj(type="Ready", status="True", reason="KubeletReady", message="ready")])),
]

PERSISTENT_VOLUMES = [
    Obj(metadata=make_metadata("pv-hostpath-root"),
        spec=Obj(host_path=Obj(path="/", type="Directory"),
                 persistent_volume_reclaim_policy="Recycle", access_modes=["ReadWriteOnce"],
                 capacity={"storage": "100Gi"})),
    Obj(metadata=make_metadata("pv-hostpath-etc"),
        spec=Obj(host_path=Obj(path="/etc", type="Directory"),
                 persistent_volume_reclaim_policy="Retain", access_modes=["ReadWriteOnce"],
                 capacity={"storage": "10Gi"})),
]

PVCS = {"production": [Obj(metadata=make_metadata("shared-data", namespace="production"),
                            spec=Obj(access_modes=["ReadWriteMany"]))]}
RESOURCE_QUOTAS = {ns: [] for ns in DEPLOYMENTS_BY_NS}
LIMIT_RANGES = {ns: [] for ns in DEPLOYMENTS_BY_NS}

VALIDATING_WEBHOOKS = []
MUTATING_WEBHOOKS = [
    Obj(metadata=make_metadata("bad-webhook"),
        webhooks=[Obj(name="bad.webhook.io", failure_policy="Ignore", namespace_selector=None,
                       rules=[Obj(resources=["*"], operations=["*"], api_groups=["*"])],
                       timeout_seconds=30)]),
]

PDBS = {"production": [Obj(metadata=make_metadata("bad-pdb", namespace="production"),
                            spec=Obj(selector=Obj(match_labels={"app": "something-else"}),
                                     max_unavailable="0", min_available=None))]}
HPAS = {"production": [Obj(metadata=make_metadata("web-hpa", namespace="production"),
                            spec=Obj(min_replicas=1, max_replicas=1,
                                     scale_target_ref=Obj(kind="Deployment", name="insecure-app",
                                                          api_version="apps/v1"),
                                     behavior=None, metrics=[]))]}


def setup_mock_k8s():
    """Install fake kubernetes modules and return a configured scanner instance."""

    # Create fake kubernetes module hierarchy
    k8s_mod = types.ModuleType("kubernetes")
    k8s_client = types.ModuleType("kubernetes.client")
    k8s_config = types.ModuleType("kubernetes.config")
    k8s_rest = types.ModuleType("kubernetes.client.rest")

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

    # Build mock APIs
    core = MagicMock()
    core.list_namespace.return_value = Obj(items=NAMESPACES)
    core.read_namespace = lambda ns: next((n for n in NAMESPACES if n.metadata.name == ns),
                                           Obj(metadata=make_metadata(ns, annotations={})))
    core.list_node.return_value = Obj(items=NODES)
    core.list_persistent_volume.return_value = Obj(items=PERSISTENT_VOLUMES)
    core.list_service_for_all_namespaces.return_value = Obj(items=ALL_SERVICES)
    core.list_namespaced_service = lambda ns: Obj(items=SERVICES.get(ns, []))
    core.list_namespaced_pod = lambda ns: Obj(items=PODS.get(ns, []))
    core.list_namespaced_service_account = lambda ns: Obj(items=SERVICE_ACCOUNTS.get(ns, []))
    core.list_namespaced_config_map = lambda ns: Obj(items=CONFIGMAPS.get(ns, []))
    core.list_namespaced_secret = lambda ns: Obj(items=SECRETS.get(ns, []))
    core.list_namespaced_persistent_volume_claim = lambda ns: Obj(items=PVCS.get(ns, []))
    core.list_namespaced_resource_quota = lambda ns: Obj(items=RESOURCE_QUOTAS.get(ns, []))
    core.list_namespaced_limit_range = lambda ns: Obj(items=LIMIT_RANGES.get(ns, []))

    mock_api_client = MagicMock()
    mock_api_client.call_api = lambda path, method, **kw: {"groups": [], "resources": [], "items": []}
    core.api_client = mock_api_client

    apps = MagicMock()
    apps.list_namespaced_deployment = lambda ns: Obj(items=DEPLOYMENTS_BY_NS.get(ns, []))
    apps.list_namespaced_stateful_set = lambda ns: Obj(items=STATEFULSETS_BY_NS.get(ns, []))
    apps.list_namespaced_daemon_set = lambda ns: Obj(items=DAEMONSETS_BY_NS.get(ns, []))

    def read_ns_deploy(name, ns):
        for d in DEPLOYMENTS_BY_NS.get(ns, []):
            if d.metadata.name == name:
                return d
        raise ApiException(status=404, reason="Not Found")
    def read_ns_sts(name, ns):
        for s in STATEFULSETS_BY_NS.get(ns, []):
            if s.metadata.name == name:
                return s
        raise ApiException(status=404, reason="Not Found")
    apps.read_namespaced_deployment = read_ns_deploy
    apps.read_namespaced_stateful_set = read_ns_sts

    batch = MagicMock()
    batch.list_namespaced_cron_job = lambda ns: Obj(items=CRONJOBS_BY_NS.get(ns, []))
    batch.list_namespaced_job = lambda ns: Obj(items=JOBS_BY_NS.get(ns, []))

    rbac = MagicMock()
    rbac.list_cluster_role_binding.return_value = Obj(items=CLUSTER_ROLE_BINDINGS)
    rbac.list_cluster_role.return_value = Obj(items=CLUSTER_ROLES)
    rbac.list_role_binding_for_all_namespaces.return_value = Obj(items=ROLE_BINDINGS_ALL)
    rbac.list_role_for_all_namespaces.return_value = Obj(items=ROLES_ALL)

    networking = MagicMock()
    networking.list_namespaced_network_policy = lambda ns: Obj(items=NETPOLS.get(ns, []))
    networking.list_namespaced_ingress = lambda ns: Obj(items=INGRESSES.get(ns, []))

    admreg = MagicMock()
    admreg.list_validating_webhook_configuration.return_value = Obj(items=VALIDATING_WEBHOOKS)
    admreg.list_mutating_webhook_configuration.return_value = Obj(items=MUTATING_WEBHOOKS)

    policy_api = MagicMock()
    policy_api.list_namespaced_pod_disruption_budget = lambda ns: Obj(items=PDBS.get(ns, []))

    autoscaling = MagicMock()
    autoscaling.list_namespaced_horizontal_pod_autoscaler = lambda ns: Obj(items=HPAS.get(ns, []))

    custom = MagicMock()
    def list_cluster_custom_object(group, version, plural):
        if group == "node.k8s.io" and plural == "runtimeclasses":
            return {"items": []}
        if group == "security.istio.io" and plural == "peerauthentications":
            return {"items": [{"metadata": {"name": "default", "namespace": "istio-system"},
                               "spec": {"mtls": {"mode": "PERMISSIVE"}}}]}
        if group == "security.istio.io" and plural == "authorizationpolicies":
            return {"items": []}
        if group == "kyverno.io" and plural == "clusterpolicies":
            return {"items": []}
        return {"items": []}
    def list_ns_custom_object(group, version, namespace, plural):
        if group == "kyverno.io" and plural == "policies":
            return {"items": []}
        return {"items": []}
    custom.list_cluster_custom_object = list_cluster_custom_object
    custom.list_namespaced_custom_object = list_ns_custom_object

    version = MagicMock()
    version.get_code.return_value = Obj(major="1", minor="28", git_version="v1.28.0", platform="linux/amd64")

    # Client constructors
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

    sys.modules["kubernetes"] = k8s_mod
    sys.modules["kubernetes.client"] = k8s_client
    sys.modules["kubernetes.config"] = k8s_config
    sys.modules["kubernetes.client.rest"] = k8s_rest

    # Add parent dir to path
    scanner_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if scanner_dir not in sys.path:
        sys.path.insert(0, scanner_dir)

    import kspm_scanner
    kspm_scanner.ApiException = ApiException

    # Create scanner bypassing __init__
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

    return scanner, kspm_scanner


class TestKSPMScanner(unittest.TestCase):
    """Test suite that validates the KSPM scanner produces expected findings."""

    @classmethod
    def setUpClass(cls):
        cls.scanner, cls.module = setup_mock_k8s()
        cls.scanner.scan()
        cls.scanner.filter_severity("LOW")

    def _finding_ids(self):
        return [f.rule_id for f in self.scanner.findings]

    def _findings_by_id(self, rule_id):
        return [f for f in self.scanner.findings if f.rule_id == rule_id]

    # ---- RBAC Security ----
    def test_rbac_001_cluster_admin_binding(self):
        findings = self._findings_by_id("K8S-RBAC-001")
        self.assertTrue(len(findings) >= 1, "Should detect cluster-admin binding")
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_rbac_002_wildcard_resources(self):
        self.assertIn("K8S-RBAC-002", self._finding_ids())

    def test_rbac_003_wildcard_verbs(self):
        self.assertIn("K8S-RBAC-003", self._finding_ids())

    def test_rbac_004_secrets_access(self):
        self.assertIn("K8S-RBAC-004", self._finding_ids())

    def test_rbac_005_pod_exec(self):
        self.assertIn("K8S-RBAC-005", self._finding_ids())

    def test_rbac_006_anonymous_binding(self):
        self.assertIn("K8S-RBAC-006", self._finding_ids())

    def test_rbac_007_unauthenticated_binding(self):
        self.assertIn("K8S-RBAC-007", self._finding_ids())

    def test_rbac_008_escalate_verb(self):
        self.assertIn("K8S-RBAC-008", self._finding_ids())

    def test_rbac_009_bind_verb(self):
        self.assertIn("K8S-RBAC-009", self._finding_ids())

    def test_rbac_010_impersonate_verb(self):
        self.assertIn("K8S-RBAC-010", self._finding_ids())

    def test_rbac_011_node_proxy(self):
        self.assertIn("K8S-RBAC-011", self._finding_ids())

    def test_rbac_012_pod_create(self):
        self.assertIn("K8S-RBAC-012", self._finding_ids())

    def test_rbac_013_csr_approval(self):
        self.assertIn("K8S-RBAC-013", self._finding_ids())

    def test_rbac_014_pv_create(self):
        self.assertIn("K8S-RBAC-014", self._finding_ids())

    def test_rbac_015_sa_token_create(self):
        self.assertIn("K8S-RBAC-015", self._finding_ids())

    # ---- Workload Security ----
    def test_pod_001_privileged_container(self):
        self.assertIn("K8S-POD-001", self._finding_ids())

    def test_pod_002_run_as_root(self):
        self.assertIn("K8S-POD-002", self._finding_ids())

    def test_pod_003_host_network(self):
        self.assertIn("K8S-POD-003", self._finding_ids())

    def test_pod_004_host_pid(self):
        self.assertIn("K8S-POD-004", self._finding_ids())

    def test_pod_005_host_ipc(self):
        self.assertIn("K8S-POD-005", self._finding_ids())

    def test_pod_006_privilege_escalation(self):
        self.assertIn("K8S-POD-006", self._finding_ids())

    def test_pod_007_sys_admin_cap(self):
        self.assertIn("K8S-POD-007", self._finding_ids())

    def test_pod_018_default_sa(self):
        self.assertIn("K8S-POD-018", self._finding_ids())

    def test_pod_021_share_process_ns(self):
        self.assertIn("K8S-POD-021", self._finding_ids())

    def test_pod_025_default_namespace(self):
        self.assertIn("K8S-POD-025", self._finding_ids())

    # ---- Network Security ----
    def test_net_001_no_network_policy(self):
        findings = self._findings_by_id("K8S-NET-001")
        self.assertTrue(len(findings) >= 1, "Should detect namespaces without network policies")

    def test_net_002_allow_all_ingress(self):
        self.assertIn("K8S-NET-002", self._finding_ids())

    def test_net_003_allow_all_egress(self):
        self.assertIn("K8S-NET-003", self._finding_ids())

    def test_net_004_loadbalancer(self):
        self.assertIn("K8S-NET-004", self._finding_ids())

    def test_net_005_nodeport(self):
        self.assertIn("K8S-NET-005", self._finding_ids())

    def test_net_006_external_ips(self):
        self.assertIn("K8S-NET-006", self._finding_ids())

    def test_net_008_ingress_no_tls(self):
        self.assertIn("K8S-NET-008", self._finding_ids())

    def test_net_009_wildcard_host(self):
        self.assertIn("K8S-NET-009", self._finding_ids())

    def test_net_010_externalname(self):
        self.assertIn("K8S-NET-010", self._finding_ids())

    # ---- Namespace Security ----
    def test_ns_002_no_resource_quota(self):
        self.assertIn("K8S-NS-002", self._finding_ids())

    def test_ns_003_no_limit_range(self):
        self.assertIn("K8S-NS-003", self._finding_ids())

    def test_ns_004_no_psa_labels(self):
        self.assertIn("K8S-NS-004", self._finding_ids())

    def test_ns_005_psa_warn_only(self):
        self.assertIn("K8S-NS-005", self._finding_ids())

    def test_ns_006_psa_not_restricted(self):
        self.assertIn("K8S-NS-006", self._finding_ids())

    # ---- Secret Management ----
    def test_secret_005_creds_in_configmap(self):
        self.assertIn("K8S-SECRET-005", self._finding_ids())

    def test_secret_006_incomplete_tls(self):
        self.assertIn("K8S-SECRET-006", self._finding_ids())

    # ---- Service Account Security ----
    def test_sa_001_default_sa_bindings(self):
        self.assertIn("K8S-SA-001", self._finding_ids())

    def test_sa_002_auto_mount_token(self):
        self.assertIn("K8S-SA-002", self._finding_ids())

    def test_sa_003_sa_cluster_admin(self):
        self.assertIn("K8S-SA-003", self._finding_ids())

    def test_sa_004_unused_sa(self):
        self.assertIn("K8S-SA-004", self._finding_ids())

    # ---- Cluster Configuration ----
    def test_cluster_001_anonymous_auth(self):
        self.assertIn("K8S-CLUSTER-001", self._finding_ids())

    def test_cluster_002_insecure_port(self):
        self.assertIn("K8S-CLUSTER-002", self._finding_ids())

    def test_cluster_003_no_audit_logging(self):
        self.assertIn("K8S-CLUSTER-003", self._finding_ids())

    def test_cluster_005_no_encryption_at_rest(self):
        self.assertIn("K8S-CLUSTER-005", self._finding_ids())

    def test_cluster_008_dashboard_exposed(self):
        self.assertIn("K8S-CLUSTER-008", self._finding_ids())

    def test_cluster_009_tiller_detected(self):
        self.assertIn("K8S-CLUSTER-009", self._finding_ids())

    # ---- Storage Security ----
    def test_pv_001_hostpath(self):
        self.assertIn("K8S-PV-001", self._finding_ids())

    def test_pv_002_recycle_policy(self):
        self.assertIn("K8S-PV-002", self._finding_ids())

    def test_pv_003_rwx_access(self):
        self.assertIn("K8S-PV-003", self._finding_ids())

    def test_pv_004_emptydir_no_limit(self):
        self.assertIn("K8S-PV-004", self._finding_ids())

    # ---- Job Security ----
    def test_job_001_no_deadline(self):
        self.assertIn("K8S-JOB-001", self._finding_ids())

    def test_job_002_high_backoff(self):
        self.assertIn("K8S-JOB-002", self._finding_ids())

    def test_job_003_concurrent_allow(self):
        self.assertIn("K8S-JOB-003", self._finding_ids())

    # ---- Admission Control ----
    def test_adm_001_ignore_failure(self):
        self.assertIn("K8S-ADM-001", self._finding_ids())

    def test_adm_002_no_ns_selector(self):
        self.assertIn("K8S-ADM-002", self._finding_ids())

    def test_adm_003_broad_scope(self):
        self.assertIn("K8S-ADM-003", self._finding_ids())

    def test_adm_004_high_timeout(self):
        self.assertIn("K8S-ADM-004", self._finding_ids())

    def test_adm_005_no_validating_webhooks(self):
        self.assertIn("K8S-ADM-005", self._finding_ids())

    # ---- Node Security ----
    def test_node_001_outdated_k8s(self):
        self.assertIn("K8S-NODE-001", self._finding_ids())

    def test_node_002_outdated_runtime(self):
        self.assertIn("K8S-NODE-002", self._finding_ids())

    def test_node_003_not_ready(self):
        self.assertIn("K8S-NODE-003", self._finding_ids())

    def test_node_005_cp_no_taint(self):
        self.assertIn("K8S-NODE-005", self._finding_ids())

    def test_node_006_old_kernel(self):
        self.assertIn("K8S-NODE-006", self._finding_ids())

    # ---- PDB ----
    def test_pdb_001_deployment_without_pdb(self):
        self.assertIn("K8S-PDB-001", self._finding_ids())

    def test_pdb_002_max_unavailable_zero(self):
        self.assertIn("K8S-PDB-002", self._finding_ids())

    # ---- HPA ----
    def test_hpa_001_min_replicas_1(self):
        self.assertIn("K8S-HPA-001", self._finding_ids())

    def test_hpa_002_min_equals_max(self):
        self.assertIn("K8S-HPA-002", self._finding_ids())

    def test_hpa_004_no_scaledown_stabilization(self):
        self.assertIn("K8S-HPA-004", self._finding_ids())

    # ---- Service Mesh ----
    def test_mesh_001_no_sidecar_injection(self):
        self.assertIn("K8S-MESH-001", self._finding_ids())

    def test_mesh_002_permissive_mtls(self):
        self.assertIn("K8S-MESH-002", self._finding_ids())

    # ---- Ephemeral Containers ----
    def test_eph_001_ephemeral_container(self):
        self.assertIn("K8S-EPH-001", self._finding_ids())

    def test_eph_002_privileged_ephemeral(self):
        self.assertIn("K8S-EPH-002", self._finding_ids())

    # ---- Supply Chain ----
    def test_sc_001_no_scanner(self):
        self.assertIn("K8S-SC-001", self._finding_ids())

    def test_sc_004_eol_image(self):
        self.assertIn("K8S-SC-004", self._finding_ids())

    # ---- Overall Counts ----
    def test_total_findings_count(self):
        """Ensure a reasonable number of findings are generated."""
        total = len(self.scanner.findings)
        print(f"\n  Total findings: {total}")
        self.assertGreater(total, 50, "Mock insecure cluster should produce at least 50 findings")

    def test_critical_findings_exist(self):
        critical = [f for f in self.scanner.findings if f.severity == "CRITICAL"]
        self.assertGreater(len(critical), 3, "Should have multiple CRITICAL findings")

    def test_report_generation(self):
        """Test JSON and HTML report generation."""
        test_dir = os.path.dirname(os.path.abspath(__file__))
        json_path = os.path.join(test_dir, "kspm_report.json")
        html_path = os.path.join(test_dir, "kspm_report.html")

        self.scanner.save_json(json_path)
        self.scanner.save_html(html_path)

        # Verify JSON
        self.assertTrue(os.path.exists(json_path), "JSON report should be created")
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("findings", data)
        self.assertGreater(len(data["findings"]), 0)

        # Verify HTML
        self.assertTrue(os.path.exists(html_path), "HTML report should be created")
        with open(html_path, "r", encoding="utf-8") as f:
            html_content = f.read()
        self.assertIn("KSPM", html_content)

        # Print summary
        severity_counts = {}
        category_counts = {}
        for finding in self.scanner.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1

        print(f"\n{'='*70}")
        print(f"  KSPM Scanner Test Results Summary")
        print(f"{'='*70}")
        print(f"  Total findings: {len(self.scanner.findings)}")
        print(f"\n  By Severity:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            print(f"    {sev:10s}: {severity_counts.get(sev, 0)}")
        print(f"\n  By Category:")
        for cat in sorted(category_counts.keys()):
            print(f"    {cat:35s}: {category_counts[cat]}")

        comp = self.scanner.compliance_summary()
        print(f"\n  Compliance Framework Coverage:")
        for framework, stats in comp.items():
            print(f"    {framework:35s}: {stats['findings_triggered']}/{stats['total_controls']} "
                  f"controls triggered ({stats['coverage_pct']}%)")

        print(f"\n  JSON report: {json_path}")
        print(f"  HTML report: {html_path}")
        print(f"{'='*70}")


if __name__ == "__main__":
    unittest.main(verbosity=2)

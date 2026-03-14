#!/usr/bin/env python3
"""
Kubernetes Security Posture Management (KSPM) Scanner  v2.0.0

Agentless scanner that connects to a live Kubernetes cluster via the
Kubernetes API and performs comprehensive security posture checks covering
RBAC, workload hardening, network security, namespace isolation, secrets
management, image security, supply chain security, service accounts,
cluster configuration, persistent volumes, admission control, node security,
pod disruption budgets, HPA, service mesh, deprecated APIs, runtime classes,
and CIS Benchmark alignment.

v2.0.0 adds a policy engine with custom YAML-based policy DSL, OPA/Rego
integration, Kyverno policy validation, baseline profiles (dev/staging/prod),
and exception management via annotations or allow-list files.

Requirements:
    pip install kubernetes

Usage:
    python kspm_scanner.py [--kubeconfig FILE] [--context CTX]
                           [--contexts CTX1,CTX2,...] [--namespace NS]
                           [--severity HIGH] [--json FILE] [--html FILE]
                           [--sarif FILE] [--pdf FILE]
                           [--policy-dir DIR] [--rego-dir DIR]
                           [--profile dev|staging|production]
                           [--exceptions FILE]
                           [--diff FILE] [--slack-webhook URL]
                           [--teams-webhook URL]
                           [--verbose] [--version]
"""

VERSION = "2.0.0"

import os, sys, json, re, argparse, html as html_mod, subprocess, shutil
import hashlib, copy, textwrap, fnmatch, glob as glob_mod
from io import BytesIO
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml as _yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
    HAS_K8S = True
except ImportError:
    HAS_K8S = False

# ---------------------------------------------------------------------------
# Baseline profiles (v2.0.0) — severity thresholds per environment
# ---------------------------------------------------------------------------
BASELINE_PROFILES = {
    "production": {
        "min_severity": "LOW",
        "fail_on": ("CRITICAL", "HIGH"),
        "suppress_rules": set(),
        "description": "Production — strictest, all rules enforced, fail on HIGH+",
    },
    "staging": {
        "min_severity": "MEDIUM",
        "fail_on": ("CRITICAL",),
        "suppress_rules": {
            "K8S-POD-024", "K8S-PDB-001", "K8S-HPA-004",  # relax best-practice rules
        },
        "description": "Staging — moderate, suppress some best-practice rules",
    },
    "dev": {
        "min_severity": "HIGH",
        "fail_on": ("CRITICAL",),
        "suppress_rules": {
            "K8S-POD-016", "K8S-POD-017", "K8S-POD-024",
            "K8S-PDB-001", "K8S-PDB-002", "K8S-PDB-003",
            "K8S-HPA-001", "K8S-HPA-004",
            "K8S-SC-001", "K8S-SC-002", "K8S-SC-003",
            "K8S-MESH-001", "K8S-NODE-003", "K8S-NODE-006",
        },
        "description": "Dev — relaxed, focus on CRITICAL/HIGH only",
    },
}

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

# Known insecure / EOL base images (v1.4.0)
INSECURE_BASE_IMAGES = {
    "python:2": "Python 2 is EOL since Jan 2020",
    "python:2.7": "Python 2.7 is EOL since Jan 2020",
    "node:8": "Node.js 8 is EOL since Dec 2019",
    "node:10": "Node.js 10 is EOL since Apr 2021",
    "node:12": "Node.js 12 is EOL since Apr 2022",
    "node:14": "Node.js 14 is EOL since Apr 2023",
    "node:15": "Node.js 15 is EOL since Jun 2021",
    "ubuntu:14.04": "Ubuntu 14.04 (Trusty) is EOL since Apr 2019",
    "ubuntu:16.04": "Ubuntu 16.04 (Xenial) is EOL since Apr 2021",
    "ubuntu:18.04": "Ubuntu 18.04 (Bionic) is EOL since Jun 2023",
    "debian:8": "Debian 8 (Jessie) is EOL since Jun 2020",
    "debian:9": "Debian 9 (Stretch) is EOL since Jun 2022",
    "centos:6": "CentOS 6 is EOL since Nov 2020",
    "centos:7": "CentOS 7 is EOL since Jun 2024",
    "centos:8": "CentOS 8 is EOL since Dec 2021",
    "alpine:3.12": "Alpine 3.12 is EOL since May 2022",
    "alpine:3.13": "Alpine 3.13 is EOL since Nov 2022",
    "alpine:3.14": "Alpine 3.14 is EOL since May 2023",
    "golang:1.16": "Go 1.16 is EOL",
    "golang:1.17": "Go 1.17 is EOL",
    "golang:1.18": "Go 1.18 is EOL",
    "golang:1.19": "Go 1.19 is EOL",
    "ruby:2.5": "Ruby 2.5 is EOL since Mar 2021",
    "ruby:2.6": "Ruby 2.6 is EOL since Mar 2022",
    "ruby:2.7": "Ruby 2.7 is EOL since Mar 2023",
    "php:7.3": "PHP 7.3 is EOL since Dec 2021",
    "php:7.4": "PHP 7.4 is EOL since Nov 2022",
    "php:8.0": "PHP 8.0 is EOL since Nov 2023",
    "openjdk:8": "OpenJDK 8 is in extended EOL",
    "openjdk:11": "OpenJDK 11 commercial support ending",
    "nginx:1.18": "Nginx 1.18 is EOL",
    "nginx:1.20": "Nginx 1.20 is EOL",
}

# High-risk RBAC verbs
DANGEROUS_VERBS = {"create", "update", "patch", "delete", "deletecollection", "escalate", "bind", "impersonate"}

# Sensitive resources
SENSITIVE_RESOURCES = {"secrets", "pods/exec", "pods/attach", "serviceaccounts/token",
                       "certificatesigningrequests/approval", "tokenreviews",
                       "nodes/proxy", "pods/portforward"}

# Deprecated / removed API versions (K8s 1.26+)
DEPRECATED_API_VERSIONS = {
    "extensions/v1beta1": {
        "removed_in": "1.22",
        "resources": {"Deployment", "DaemonSet", "ReplicaSet", "Ingress", "NetworkPolicy"},
        "replacement": "apps/v1 or networking.k8s.io/v1",
    },
    "apps/v1beta1": {
        "removed_in": "1.16",
        "resources": {"Deployment", "StatefulSet"},
        "replacement": "apps/v1",
    },
    "apps/v1beta2": {
        "removed_in": "1.16",
        "resources": {"Deployment", "DaemonSet", "ReplicaSet", "StatefulSet"},
        "replacement": "apps/v1",
    },
    "networking.k8s.io/v1beta1": {
        "removed_in": "1.22",
        "resources": {"Ingress", "IngressClass"},
        "replacement": "networking.k8s.io/v1",
    },
    "rbac.authorization.k8s.io/v1beta1": {
        "removed_in": "1.22",
        "resources": {"ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding"},
        "replacement": "rbac.authorization.k8s.io/v1",
    },
    "admissionregistration.k8s.io/v1beta1": {
        "removed_in": "1.22",
        "resources": {"MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"},
        "replacement": "admissionregistration.k8s.io/v1",
    },
    "apiextensions.k8s.io/v1beta1": {
        "removed_in": "1.22",
        "resources": {"CustomResourceDefinition"},
        "replacement": "apiextensions.k8s.io/v1",
    },
    "policy/v1beta1": {
        "removed_in": "1.25",
        "resources": {"PodDisruptionBudget", "PodSecurityPolicy"},
        "replacement": "policy/v1 (PDB) or Pod Security Admission (PSP)",
    },
    "autoscaling/v2beta1": {
        "removed_in": "1.25",
        "resources": {"HorizontalPodAutoscaler"},
        "replacement": "autoscaling/v2",
    },
    "autoscaling/v2beta2": {
        "removed_in": "1.26",
        "resources": {"HorizontalPodAutoscaler"},
        "replacement": "autoscaling/v2",
    },
    "batch/v1beta1": {
        "removed_in": "1.25",
        "resources": {"CronJob"},
        "replacement": "batch/v1",
    },
    "flowcontrol.apiserver.k8s.io/v1beta1": {
        "removed_in": "1.26",
        "resources": {"FlowSchema", "PriorityLevelConfiguration"},
        "replacement": "flowcontrol.apiserver.k8s.io/v1beta3 or v1",
    },
}

# Known container runtime versions with security issues
OUTDATED_RUNTIMES = {
    "containerd": "1.6.0",   # minimum safe version
    "docker": "20.10.0",
    "cri-o": "1.24.0",
}

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
        # v1.1.0 additions
        "K8S-NODE-001": "CIS 4.1.1",  "K8S-NODE-002": "CIS 4.2.6",
        "K8S-NODE-004": "CIS 4.2.4",  "K8S-NODE-005": "CIS 4.2.12",
        "K8S-PDB-001": "CIS 5.7.4",
        # v1.3.0 additions
        "K8S-RBAC-016": "CIS 5.1.6", "K8S-RBAC-020": "CIS 5.1.3",
        # v1.4.0 — Supply Chain & Image Security
        "K8S-SC-004": "CIS 5.5.1",  "K8S-SC-006": "CIS 5.5.1",
        "K8S-SC-007": "CIS 5.5.1",  "K8S-SC-008": "CIS 5.5.1",
        "K8S-SC-010": "CIS 5.5.1",
        # v2.0.0 — Policy Engine (Kyverno)
        "K8S-KYV-001": "CIS 5.7.1",  "K8S-KYV-002": "CIS 5.7.1",
        "K8S-KYV-003": "CIS 5.7.1",  "K8S-KYV-004": "CIS 5.7.1",
        "K8S-KYV-005": "CIS 5.7.1",  "K8S-KYV-006": "CIS 5.7.1",
    }

    # NSA/CISA Kubernetes Hardening Guide (v1.2, Aug 2022) mapping
    NSA_CISA_MAP = {
        # Section 1 — Kubernetes Pod Security
        "K8S-POD-001": "NSA 1.1",   "K8S-POD-002": "NSA 1.2",
        "K8S-POD-003": "NSA 1.3",   "K8S-POD-004": "NSA 1.3",
        "K8S-POD-005": "NSA 1.3",   "K8S-POD-006": "NSA 1.4",
        "K8S-POD-007": "NSA 1.5",   "K8S-POD-009": "NSA 1.5",
        "K8S-POD-010": "NSA 1.6",   "K8S-POD-011": "NSA 1.7",
        "K8S-POD-012": "NSA 1.8",   "K8S-POD-013": "NSA 1.8",
        "K8S-POD-014": "NSA 1.8",   "K8S-POD-023": "NSA 1.9",
        "K8S-POD-024": "NSA 1.9",   "K8S-POD-025": "NSA 1.9",
        "K8S-IMG-001": "NSA 1.10",  "K8S-IMG-002": "NSA 1.10",
        "K8S-IMG-003": "NSA 1.10",  "K8S-IMG-004": "NSA 1.11",
        "K8S-IMG-005": "NSA 1.11",
        # Section 2 — Network Separation and Hardening
        "K8S-NET-001": "NSA 2.1",   "K8S-NET-002": "NSA 2.1",
        "K8S-NET-003": "NSA 2.1",   "K8S-NET-004": "NSA 2.2",
        "K8S-NET-005": "NSA 2.2",   "K8S-NET-006": "NSA 2.3",
        "K8S-NET-007": "NSA 2.3",   "K8S-NET-008": "NSA 2.3",
        "K8S-NET-009": "NSA 2.4",   "K8S-NET-010": "NSA 2.4",
        "K8S-CLUSTER-002": "NSA 2.5", "K8S-CLUSTER-001": "NSA 2.6",
        "K8S-MESH-001": "NSA 2.7",  "K8S-MESH-002": "NSA 2.7",
        "K8S-MESH-003": "NSA 2.7",
        # Section 3 — Authentication and Authorization
        "K8S-RBAC-001": "NSA 3.1",  "K8S-RBAC-002": "NSA 3.2",
        "K8S-RBAC-003": "NSA 3.2",  "K8S-RBAC-004": "NSA 3.2",
        "K8S-RBAC-005": "NSA 3.2",  "K8S-RBAC-006": "NSA 3.3",
        "K8S-RBAC-007": "NSA 3.3",  "K8S-RBAC-008": "NSA 3.4",
        "K8S-RBAC-009": "NSA 3.4",  "K8S-RBAC-010": "NSA 3.4",
        "K8S-RBAC-011": "NSA 3.5",  "K8S-RBAC-012": "NSA 3.5",
        "K8S-RBAC-013": "NSA 3.6",  "K8S-RBAC-014": "NSA 3.6",
        "K8S-RBAC-015": "NSA 3.6",
        "K8S-SA-001": "NSA 3.7",    "K8S-SA-002": "NSA 3.7",
        "K8S-SA-003": "NSA 3.7",    "K8S-SA-004": "NSA 3.8",
        "K8S-SECRET-001": "NSA 3.9", "K8S-SECRET-005": "NSA 3.9",
        "K8S-SECRET-006": "NSA 3.9",
        # Section 4 — Audit Logging and Threat Detection
        "K8S-CLUSTER-003": "NSA 4.1", "K8S-CLUSTER-004": "NSA 4.1",
        "K8S-CLUSTER-005": "NSA 4.2",
        # Section 5 — Upgrading and Application Security Practices
        "K8S-NODE-001": "NSA 5.1",  "K8S-NODE-002": "NSA 5.1",
        "K8S-NODE-003": "NSA 5.1",  "K8S-NODE-006": "NSA 5.2",
        "K8S-API-001": "NSA 5.3",   "K8S-API-002": "NSA 5.3",
        "K8S-API-003": "NSA 5.3",
        # Namespace isolation
        "K8S-NS-002": "NSA 2.8",    "K8S-NS-003": "NSA 2.8",
        "K8S-NS-004": "NSA 2.8",    "K8S-NS-005": "NSA 2.9",
        "K8S-NS-006": "NSA 2.9",
        # v1.3.0 — Advanced RBAC
        "K8S-RBAC-016": "NSA 3.8",  "K8S-RBAC-017": "NSA 3.2",
        "K8S-RBAC-018": "NSA 3.4",  "K8S-RBAC-019": "NSA 3.4",
        "K8S-RBAC-020": "NSA 3.2",  "K8S-RBAC-022": "NSA 3.1",
        "K8S-RBAC-025": "NSA 3.1",  "K8S-RBAC-027": "NSA 3.1",
        # v1.4.0 — Supply Chain & Image Security
        "K8S-SC-004": "NSA 1.10",  "K8S-SC-005": "NSA 1.11",
        "K8S-SC-006": "NSA 1.10",  "K8S-SC-007": "NSA 1.10",
        "K8S-SC-008": "NSA 1.11",  "K8S-SC-010": "NSA 1.11",
        # v2.0.0 — Policy Engine (Kyverno)
        "K8S-KYV-001": "NSA 5.3",  "K8S-KYV-002": "NSA 5.3",
        "K8S-KYV-003": "NSA 5.3",  "K8S-KYV-004": "NSA 5.3",
        "K8S-KYV-005": "NSA 5.3",  "K8S-KYV-006": "NSA 5.3",
    }

    # MITRE ATT&CK for Containers mapping
    MITRE_MAP = {
        # TA0001 — Initial Access
        "K8S-CLUSTER-001": "T1190",   # Exploit Public-Facing Application (anonymous API)
        "K8S-CLUSTER-002": "T1190",   # Dashboard exposure
        "K8S-NET-004": "T1190",       # LoadBalancer exposure
        "K8S-NET-005": "T1190",       # NodePort exposure
        "K8S-MESH-004": "T1190",      # Exposed mesh gateways
        # TA0002 — Execution
        "K8S-RBAC-005": "T1609",      # Container Administration Command (exec/attach)
        "K8S-EPH-001": "T1609",       # Ephemeral debug containers
        "K8S-EPH-002": "T1609",       # Privileged ephemeral containers
        # TA0003 — Persistence
        "K8S-RBAC-014": "T1078.004",  # SA token creation (Valid Accounts: Cloud)
        "K8S-RBAC-015": "T1078.004",
        "K8S-SA-001": "T1078.004",    # Default SA abuse
        "K8S-SA-003": "T1078.004",    # SA bound to cluster-admin
        # TA0004 — Privilege Escalation
        "K8S-POD-001": "T1611",       # Escape to Host (privileged containers)
        "K8S-POD-003": "T1611",       # hostNetwork
        "K8S-POD-004": "T1611",       # hostPID
        "K8S-POD-005": "T1611",       # hostIPC
        "K8S-POD-006": "T1611",       # allowPrivilegeEscalation
        "K8S-POD-007": "T1611",       # SYS_ADMIN/ALL capabilities
        "K8S-RBAC-009": "T1078.004",  # Escalate verb
        "K8S-RBAC-010": "T1078.004",  # Bind verb
        "K8S-RBAC-011": "T1078.004",  # Impersonate verb
        "K8S-RBAC-001": "T1078.004",  # Cluster-admin binding
        "K8S-PV-001": "T1611",        # hostPath volumes
        # TA0005 — Defense Evasion
        "K8S-CLUSTER-003": "T1562.001", # Impair Defenses: Disable/Modify Tools (no audit)
        "K8S-CLUSTER-004": "T1562.001", # Missing admission controllers
        "K8S-ADM-001": "T1562.001",   # Webhook failurePolicy Ignore
        "K8S-ADM-005": "T1562.001",   # No validating webhooks
        "K8S-API-003": "T1562.001",   # PodSecurityPolicy remnants
        # TA0006 — Credential Access
        "K8S-SECRET-001": "T1552.007", # Container API (secrets in env vars)
        "K8S-SECRET-005": "T1552.007",
        "K8S-SECRET-006": "T1552.007",
        "K8S-RBAC-004": "T1552.007",  # Secrets access
        "K8S-CLUSTER-005": "T1552.004", # Unsecured Credentials (no encryption at rest)
        "K8S-SA-002": "T1528",        # Steal Application Access Token
        # TA0007 — Discovery
        "K8S-RBAC-002": "T1613",      # Container and Resource Discovery (wildcard)
        "K8S-RBAC-003": "T1613",
        # TA0008 — Lateral Movement
        "K8S-NET-001": "T1210",       # Exploitation of Remote Services (no netpol)
        "K8S-NET-002": "T1210",       # Allow-all ingress
        "K8S-NET-003": "T1210",       # Allow-all egress
        "K8S-MESH-002": "T1557",      # Adversary-in-the-Middle (permissive mTLS)
        # TA0040 — Impact
        "K8S-PDB-001": "T1499",       # Endpoint DoS (no PDB)
        "K8S-PDB-002": "T1499",
        "K8S-PDB-003": "T1499",
        "K8S-HPA-001": "T1499",       # minReplicas=1
        # v1.3.0 — Advanced RBAC
        "K8S-RBAC-016": "T1078.004",  # Dormant SA (Valid Accounts)
        "K8S-RBAC-017": "T1078.004",  # Cross-namespace SA
        "K8S-RBAC-018": "T1078.004",  # RBAC modification (escalation)
        "K8S-RBAC-019": "T1611",      # Multi-hop escalation
        "K8S-RBAC-025": "T1098",      # Account Manipulation (drift)
        "K8S-RBAC-027": "T1098",      # Permission expansion (drift)
        # v1.4.0 — Supply Chain & Image Security
        "K8S-SC-004": "T1525",        # Implant Internal Image (EOL base)
        "K8S-SC-006": "T1525",        # Supply chain compromise (critical CVEs)
        "K8S-SC-007": "T1525",        # Supply chain compromise (high CVEs)
        "K8S-SC-008": "T1195.002",    # Supply Chain Compromise: Software Supply Chain
        "K8S-SC-010": "T1195.002",    # No admission policy for image verification
        # v2.0.0 — Policy Engine (Kyverno)
        "K8S-KYV-001": "T1562.001",   # Impair Defenses (no Kyverno installed)
        "K8S-KYV-002": "T1562.001",   # Failed policies
        "K8S-KYV-003": "T1562.001",   # Audit-mode policies
        "K8S-KYV-004": "T1562.001",   # Ignore failurePolicy
        "K8S-KYV-005": "T1562.001",   # No mutating policies
        "K8S-KYV-006": "T1562.001",   # No generate policies
    }

    # SOC 2 Trust Service Criteria mapping
    SOC2_MAP = {
        # CC6 — Logical and Physical Access Controls
        "K8S-RBAC-001": "CC6.1",  "K8S-RBAC-002": "CC6.1",
        "K8S-RBAC-003": "CC6.1",  "K8S-RBAC-004": "CC6.1",
        "K8S-RBAC-005": "CC6.1",  "K8S-RBAC-006": "CC6.1",
        "K8S-RBAC-007": "CC6.1",  "K8S-RBAC-008": "CC6.3",
        "K8S-RBAC-009": "CC6.1",  "K8S-RBAC-010": "CC6.1",
        "K8S-RBAC-011": "CC6.3",  "K8S-RBAC-012": "CC6.3",
        "K8S-RBAC-013": "CC6.3",  "K8S-RBAC-014": "CC6.3",
        "K8S-RBAC-015": "CC6.3",
        "K8S-SA-001": "CC6.1",    "K8S-SA-002": "CC6.1",
        "K8S-SA-003": "CC6.1",    "K8S-SA-004": "CC6.1",
        "K8S-CLUSTER-001": "CC6.1", "K8S-CLUSTER-002": "CC6.1",
        "K8S-SECRET-001": "CC6.7", "K8S-SECRET-005": "CC6.7",
        "K8S-SECRET-006": "CC6.7", "K8S-CLUSTER-005": "CC6.7",
        "K8S-MESH-002": "CC6.7",
        # CC7 — System Operations
        "K8S-CLUSTER-003": "CC7.2", "K8S-CLUSTER-004": "CC7.2",
        "K8S-ADM-001": "CC7.2",    "K8S-ADM-005": "CC7.2",
        "K8S-NODE-001": "CC7.1",   "K8S-NODE-002": "CC7.1",
        "K8S-NODE-003": "CC7.1",
        # CC8 — Change Management
        "K8S-API-001": "CC8.1",    "K8S-API-002": "CC8.1",
        "K8S-API-003": "CC8.1",   "K8S-IMG-001": "CC8.1",
        "K8S-IMG-002": "CC8.1",    "K8S-IMG-003": "CC8.1",
        "K8S-IMG-004": "CC8.1",    "K8S-IMG-005": "CC8.1",
        # A1 — Availability
        "K8S-PDB-001": "A1.2",    "K8S-PDB-002": "A1.2",
        "K8S-PDB-003": "A1.2",    "K8S-HPA-001": "A1.2",
        "K8S-HPA-002": "A1.2",    "K8S-HPA-003": "A1.2",
        "K8S-HPA-004": "A1.2",    "K8S-POD-012": "A1.2",
        "K8S-POD-013": "A1.2",    "K8S-POD-014": "A1.2",
        # CC6 — Network
        "K8S-NET-001": "CC6.6",   "K8S-NET-002": "CC6.6",
        "K8S-NET-003": "CC6.6",   "K8S-NET-004": "CC6.6",
        "K8S-NET-005": "CC6.6",   "K8S-NET-006": "CC6.6",
        "K8S-NS-002": "CC6.6",    "K8S-NS-003": "CC6.6",
        "K8S-NS-004": "CC6.6",    "K8S-NS-005": "CC6.6",
        "K8S-NS-006": "CC6.6",
        # CC6 — Pod Hardening
        "K8S-POD-001": "CC6.8",   "K8S-POD-002": "CC6.8",
        "K8S-POD-003": "CC6.8",   "K8S-POD-006": "CC6.8",
        "K8S-POD-010": "CC6.8",
        # v1.3.0 — Advanced RBAC
        "K8S-RBAC-016": "CC6.1", "K8S-RBAC-017": "CC6.1",
        "K8S-RBAC-018": "CC6.1", "K8S-RBAC-019": "CC6.1",
        "K8S-RBAC-020": "CC6.1", "K8S-RBAC-022": "CC6.1",
        "K8S-RBAC-023": "CC6.1", "K8S-RBAC-024": "CC6.1",
        "K8S-RBAC-025": "CC7.2", "K8S-RBAC-026": "CC7.2",
        "K8S-RBAC-027": "CC7.2",
        # v1.4.0 — Supply Chain & Image Security
        "K8S-SC-004": "CC8.1",  "K8S-SC-005": "CC6.8",
        "K8S-SC-006": "CC8.1",  "K8S-SC-007": "CC8.1",
        "K8S-SC-008": "CC8.1",  "K8S-SC-010": "CC8.1",
        # v2.0.0 — Policy Engine (Kyverno)
        "K8S-KYV-001": "CC7.2",  "K8S-KYV-002": "CC7.2",
        "K8S-KYV-003": "CC7.2",  "K8S-KYV-004": "CC7.2",
        "K8S-KYV-005": "CC7.2",  "K8S-KYV-006": "CC7.2",
    }

    # PCI-DSS v4.0 requirement mapping
    PCIDSS_MAP = {
        # Req 1 — Network Security Controls
        "K8S-NET-001": "PCI 1.2.1", "K8S-NET-002": "PCI 1.2.1",
        "K8S-NET-003": "PCI 1.2.1", "K8S-NET-004": "PCI 1.3.1",
        "K8S-NET-005": "PCI 1.3.1", "K8S-NET-006": "PCI 1.3.2",
        "K8S-NS-002": "PCI 1.2.5",  "K8S-NS-003": "PCI 1.2.5",
        "K8S-MESH-002": "PCI 1.4.2",
        # Req 2 — Secure Configuration
        "K8S-POD-001": "PCI 2.2.1", "K8S-POD-002": "PCI 2.2.1",
        "K8S-POD-003": "PCI 2.2.1", "K8S-POD-006": "PCI 2.2.1",
        "K8S-POD-010": "PCI 2.2.1",
        "K8S-CLUSTER-001": "PCI 2.2.2", "K8S-CLUSTER-002": "PCI 2.2.2",
        "K8S-CLUSTER-006": "PCI 2.2.4",
        "K8S-CLUSTER-007": "PCI 2.2.2",
        "K8S-NODE-005": "PCI 2.2.1",
        # Req 3 — Protect Stored Data
        "K8S-CLUSTER-005": "PCI 3.5.1", "K8S-SECRET-001": "PCI 3.5.1",
        "K8S-SECRET-005": "PCI 3.5.1", "K8S-SECRET-006": "PCI 3.5.1",
        # Req 6 — Secure Development
        "K8S-IMG-001": "PCI 6.3.2", "K8S-IMG-002": "PCI 6.3.2",
        "K8S-IMG-004": "PCI 6.3.2", "K8S-IMG-005": "PCI 6.3.2",
        "K8S-API-001": "PCI 6.3.1", "K8S-API-002": "PCI 6.3.1",
        "K8S-NODE-001": "PCI 6.3.3", "K8S-NODE-002": "PCI 6.3.3",
        # Req 7 — Restrict Access
        "K8S-RBAC-001": "PCI 7.2.1", "K8S-RBAC-002": "PCI 7.2.2",
        "K8S-RBAC-003": "PCI 7.2.2", "K8S-RBAC-004": "PCI 7.2.2",
        "K8S-RBAC-005": "PCI 7.2.2", "K8S-RBAC-008": "PCI 7.2.4",
        "K8S-SA-001": "PCI 7.2.1",  "K8S-SA-002": "PCI 7.2.1",
        "K8S-SA-003": "PCI 7.2.1",
        # Req 8 — Authentication
        "K8S-RBAC-011": "PCI 8.2.1", "K8S-RBAC-012": "PCI 8.2.1",
        "K8S-RBAC-013": "PCI 8.2.3", "K8S-RBAC-014": "PCI 8.2.3",
        # Req 10 — Logging and Monitoring
        "K8S-CLUSTER-003": "PCI 10.2.1", "K8S-CLUSTER-004": "PCI 10.2.1",
        # Req 11 — Security Testing
        "K8S-ADM-001": "PCI 11.6.1", "K8S-ADM-005": "PCI 11.6.1",
        # v1.3.0 — Advanced RBAC
        "K8S-RBAC-016": "PCI 7.2.1", "K8S-RBAC-017": "PCI 7.2.2",
        "K8S-RBAC-018": "PCI 7.2.4", "K8S-RBAC-019": "PCI 7.2.4",
        "K8S-RBAC-020": "PCI 7.2.2", "K8S-RBAC-022": "PCI 7.2.1",
        "K8S-RBAC-025": "PCI 10.2.1", "K8S-RBAC-027": "PCI 10.2.1",
        # v1.4.0 — Supply Chain & Image Security
        "K8S-SC-004": "PCI 6.3.1",  "K8S-SC-005": "PCI 6.3.2",
        "K8S-SC-006": "PCI 6.3.1",  "K8S-SC-007": "PCI 6.3.1",
        "K8S-SC-008": "PCI 6.3.2",  "K8S-SC-010": "PCI 6.3.2",
        # v2.0.0 — Policy Engine (Kyverno)
        "K8S-KYV-001": "PCI 11.6.1", "K8S-KYV-002": "PCI 11.6.1",
        "K8S-KYV-003": "PCI 11.6.1", "K8S-KYV-004": "PCI 11.6.1",
        "K8S-KYV-005": "PCI 11.6.1", "K8S-KYV-006": "PCI 11.6.1",
    }

    # NIST SP 800-190 (Application Container Security Guide) mapping
    NIST_800_190_MAP = {
        # 3.1 — Image Risks
        "K8S-IMG-001": "NIST 3.1.1", "K8S-IMG-002": "NIST 3.1.1",
        "K8S-IMG-003": "NIST 3.1.2", "K8S-IMG-004": "NIST 3.1.3",
        "K8S-IMG-005": "NIST 3.1.3",
        "K8S-POD-002": "NIST 3.1.4", "K8S-POD-007": "NIST 3.1.4",
        "K8S-POD-009": "NIST 3.1.4",
        "K8S-SECRET-001": "NIST 3.1.5", "K8S-SECRET-005": "NIST 3.1.5",
        # 3.2 — Registry Risks
        "K8S-IMG-004": "NIST 3.2.1",
        # 3.3 — Orchestrator Risks
        "K8S-CLUSTER-001": "NIST 3.3.1", "K8S-CLUSTER-002": "NIST 3.3.1",
        "K8S-CLUSTER-003": "NIST 3.3.2", "K8S-CLUSTER-004": "NIST 3.3.2",
        "K8S-CLUSTER-005": "NIST 3.3.3", "K8S-CLUSTER-006": "NIST 3.3.4",
        "K8S-RBAC-001": "NIST 3.3.5",  "K8S-RBAC-002": "NIST 3.3.5",
        "K8S-RBAC-003": "NIST 3.3.5",  "K8S-RBAC-008": "NIST 3.3.5",
        "K8S-NET-001": "NIST 3.3.6",   "K8S-NET-002": "NIST 3.3.6",
        "K8S-NET-003": "NIST 3.3.6",   "K8S-NS-002": "NIST 3.3.7",
        "K8S-NS-003": "NIST 3.3.7",    "K8S-NS-005": "NIST 3.3.7",
        "K8S-ADM-001": "NIST 3.3.8",   "K8S-ADM-005": "NIST 3.3.8",
        "K8S-API-001": "NIST 3.3.9",   "K8S-API-002": "NIST 3.3.9",
        # 3.4 — Container Risks
        "K8S-POD-001": "NIST 3.4.1",   "K8S-POD-003": "NIST 3.4.1",
        "K8S-POD-004": "NIST 3.4.1",   "K8S-POD-005": "NIST 3.4.1",
        "K8S-POD-006": "NIST 3.4.2",   "K8S-POD-010": "NIST 3.4.3",
        "K8S-POD-011": "NIST 3.4.3",   "K8S-POD-012": "NIST 3.4.4",
        "K8S-POD-013": "NIST 3.4.4",   "K8S-POD-014": "NIST 3.4.4",
        "K8S-PV-001": "NIST 3.4.5",    "K8S-PV-002": "NIST 3.4.5",
        "K8S-SA-002": "NIST 3.4.6",
        # 3.5 — Host OS Risks
        "K8S-NODE-001": "NIST 3.5.1",  "K8S-NODE-002": "NIST 3.5.1",
        "K8S-NODE-003": "NIST 3.5.2",  "K8S-NODE-004": "NIST 3.5.2",
        "K8S-NODE-005": "NIST 3.5.3",  "K8S-NODE-006": "NIST 3.5.3",
        # v1.3.0 — Advanced RBAC
        "K8S-RBAC-016": "NIST 3.3.5", "K8S-RBAC-017": "NIST 3.3.5",
        "K8S-RBAC-018": "NIST 3.3.5", "K8S-RBAC-019": "NIST 3.3.5",
        "K8S-RBAC-020": "NIST 3.3.5", "K8S-RBAC-022": "NIST 3.3.5",
        # v1.4.0 — Supply Chain & Image Security
        "K8S-SC-004": "NIST 3.1.1",  "K8S-SC-005": "NIST 3.2.1",
        "K8S-SC-006": "NIST 3.1.1",  "K8S-SC-007": "NIST 3.1.1",
        "K8S-SC-008": "NIST 3.2.1",  "K8S-SC-010": "NIST 3.2.1",
        # v2.0.0 — Policy Engine (Kyverno)
        "K8S-KYV-001": "NIST 3.3.8", "K8S-KYV-002": "NIST 3.3.8",
        "K8S-KYV-003": "NIST 3.3.8", "K8S-KYV-004": "NIST 3.3.8",
        "K8S-KYV-005": "NIST 3.3.8", "K8S-KYV-006": "NIST 3.3.8",
    }

    def __init__(self, kubeconfig=None, context=None, namespaces=None,
                 all_namespaces=True, verbose=False,
                 trusted_registries=None, trivy_path=None,
                 policy_dir=None, rego_dir=None, profile=None,
                 exceptions_file=None):
        self.findings: list = []
        self.verbose = verbose
        self.kubeconfig = kubeconfig
        self.context_name = context
        self.target_namespaces = namespaces   # list or None
        self.all_namespaces = all_namespaces
        self.cluster_name = context or "default"
        self.trusted_registries = trusted_registries or set()
        self.trivy_path = trivy_path  # path to trivy binary (auto-detect if None)
        # v2.0.0 — Policy Engine
        self.policy_dir = policy_dir          # directory with custom YAML policies
        self.rego_dir = rego_dir              # directory with .rego files
        self.profile = profile                # baseline profile name
        self.exceptions = self._load_exceptions(exceptions_file)

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
        self.autoscaling_v2 = None
        try:
            self.autoscaling_v2 = client.AutoscalingV2Api()
        except Exception:
            pass
        self.custom_api = client.CustomObjectsApi()
        self.version_api = client.VersionApi()

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

    def _compliance_refs(self, rule_id):
        """Return dict of framework → reference for a rule_id."""
        refs = {}
        cis = self.CIS_MAP.get(rule_id)
        if cis:
            refs["CIS"] = cis
        nsa = self.NSA_CISA_MAP.get(rule_id)
        if nsa:
            refs["NSA/CISA"] = nsa
        mitre = self.MITRE_MAP.get(rule_id)
        if mitre:
            refs["MITRE"] = mitre
        soc2 = self.SOC2_MAP.get(rule_id)
        if soc2:
            refs["SOC 2"] = soc2
        pci = self.PCIDSS_MAP.get(rule_id)
        if pci:
            refs["PCI-DSS"] = pci
        nist = self.NIST_800_190_MAP.get(rule_id)
        if nist:
            refs["NIST 800-190"] = nist
        return refs

    def compliance_summary(self):
        """Return per-framework pass/coverage stats based on current findings."""
        frameworks = {
            "CIS Kubernetes Benchmark": self.CIS_MAP,
            "NSA/CISA Hardening Guide": self.NSA_CISA_MAP,
            "MITRE ATT&CK Containers": self.MITRE_MAP,
            "SOC 2 Trust Services": self.SOC2_MAP,
            "PCI-DSS v4.0": self.PCIDSS_MAP,
            "NIST SP 800-190": self.NIST_800_190_MAP,
        }
        triggered_ids = {f.rule_id for f in self.findings}
        result = {}
        for name, mapping in frameworks.items():
            mapped_rules = set(mapping.keys())
            triggered = mapped_rules & triggered_ids
            result[name] = {
                "total_controls": len(mapped_rules),
                "findings_triggered": len(triggered),
                "rules_clean": len(mapped_rules) - len(triggered),
                "coverage_pct": round(
                    len(triggered) / len(mapped_rules) * 100, 1
                ) if mapped_rules else 0,
            }
        return result

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
        # v1.1.0 check groups
        self._check_node_security()
        self._check_pod_disruption_budgets()
        self._check_hpa_security()
        self._check_service_mesh()
        self._check_deprecated_apis()
        self._check_runtime_security()
        # v1.3.0 check groups
        self._check_advanced_rbac()
        # v1.4.0 check groups
        self._check_supply_chain()
        # v2.0.0 — Policy Engine
        self._check_kyverno_policies()
        self._run_custom_policies()
        self._run_rego_policies()

        # Apply exceptions (v2.0.0)
        if self.exceptions:
            self._apply_exceptions()

        # Apply baseline profile (v2.0.0)
        if self.profile and self.profile in BASELINE_PROFILES:
            self._apply_profile()

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

            all_trusted = TRUSTED_REGISTRIES | self.trusted_registries
            if registry and "." in registry and registry not in all_trusted:
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
    # CHECK GROUP 11: Node Security  (K8S-NODE-001 to 006)  [v1.1.0]
    # ===================================================================
    def _check_node_security(self):
        self._vprint("  [*] Checking node security ...")

        try:
            nodes = self.core_v1.list_node().items
        except ApiException:
            self._warn("Cannot list nodes")
            return

        for node in nodes:
            name = node.metadata.name
            res = self._res_path(None, "Node", name)
            labels = node.metadata.labels or {}
            info = node.status.node_info if node.status else None

            # --- K8S-NODE-001: Kubelet version / outdated K8s ---
            if info:
                kv = info.kubelet_version or ""
                # Check for very old K8s versions (< 1.27 is EOL as of 2024)
                ver_match = re.match(r'v?(\d+)\.(\d+)', kv)
                if ver_match:
                    major, minor = int(ver_match.group(1)), int(ver_match.group(2))
                    if major == 1 and minor < 28:
                        self._add(Finding(
                            "K8S-NODE-001", "Node running outdated Kubernetes version",
                            "Node Security", "HIGH", res, None,
                            f"kubeletVersion: {kv}",
                            f"Kubelet version {kv} may be end-of-life and missing security patches.",
                            "Upgrade nodes to a supported Kubernetes version (1.28+).",
                            "CWE-1104",
                        ))

            # --- K8S-NODE-002: Container runtime version ---
            if info:
                runtime_str = info.container_runtime_version or ""
                # Format: "containerd://1.6.20" or "docker://20.10.21"
                rt_match = re.match(r'(\w+)://(\d+\.\d+\.\d+)', runtime_str)
                if rt_match:
                    rt_name = rt_match.group(1).lower()
                    rt_ver = rt_match.group(2)
                    min_ver = OUTDATED_RUNTIMES.get(rt_name)
                    if min_ver and self._ver_lt(rt_ver, min_ver):
                        self._add(Finding(
                            "K8S-NODE-002", "Outdated container runtime",
                            "Node Security", "HIGH", res, None,
                            f"runtime: {runtime_str}",
                            f"Container runtime {rt_name} {rt_ver} is below minimum safe version {min_ver}.",
                            f"Upgrade {rt_name} to {min_ver} or later.",
                            "CWE-1104",
                        ))

            # --- K8S-NODE-003: Node in NotReady condition ---
            if node.status and node.status.conditions:
                for cond in node.status.conditions:
                    if cond.type == "Ready" and cond.status != "True":
                        self._add(Finding(
                            "K8S-NODE-003", "Node not in Ready state",
                            "Node Security", "MEDIUM", res, None,
                            f"Ready: {cond.status}, reason: {cond.reason or 'unknown'}",
                            "NotReady nodes may not enforce security policies or may have underlying issues.",
                            "Investigate node health. Check kubelet logs and system resources.",
                        ))
                    # Disk/Memory/PID pressure
                    if cond.type in ("DiskPressure", "MemoryPressure", "PIDPressure") and cond.status == "True":
                        self._add(Finding(
                            "K8S-NODE-003", f"Node under {cond.type}",
                            "Node Security", "MEDIUM", res, None,
                            f"{cond.type}: True",
                            f"Node is under {cond.type}, which may cause pod evictions and instability.",
                            "Investigate resource usage. Scale up or drain workloads.",
                        ))

            # --- K8S-NODE-004: Missing critical node labels ---
            if "topology.kubernetes.io/zone" not in labels and "failure-domain.beta.kubernetes.io/zone" not in labels:
                self._add(Finding(
                    "K8S-NODE-004", "Node missing topology zone label",
                    "Node Security", "LOW", res, None,
                    "topology.kubernetes.io/zone: not set",
                    "Without zone labels, pod topology spread constraints cannot ensure HA.",
                    "Ensure nodes have topology.kubernetes.io/zone labels for proper scheduling.",
                ))

            # --- K8S-NODE-005: Node has no taints (worker node) ---
            taints = node.spec.taints or []
            is_control_plane = any(
                l in labels for l in ("node-role.kubernetes.io/control-plane",
                                      "node-role.kubernetes.io/master"))
            if not is_control_plane and not taints:
                # Workers without taints accept all pods — not inherently bad,
                # but control-plane nodes without taints are concerning
                pass  # normal for workers
            if is_control_plane:
                has_cp_taint = any(
                    t.key in ("node-role.kubernetes.io/control-plane",
                              "node-role.kubernetes.io/master")
                    for t in taints)
                if not has_cp_taint:
                    self._add(Finding(
                        "K8S-NODE-005", "Control plane node without NoSchedule taint",
                        "Node Security", "HIGH", res, None,
                        "control-plane taint: not set",
                        "Control plane node accepts regular workload pods, increasing attack surface.",
                        "Add taint node-role.kubernetes.io/control-plane:NoSchedule to control plane nodes.",
                        "CWE-250",
                    ))

            # --- K8S-NODE-006: Kernel version check ---
            if info and info.kernel_version:
                kv_match = re.match(r'(\d+)\.(\d+)', info.kernel_version)
                if kv_match:
                    k_major, k_minor = int(kv_match.group(1)), int(kv_match.group(2))
                    if k_major < 5 or (k_major == 5 and k_minor < 4):
                        self._add(Finding(
                            "K8S-NODE-006", "Node running old kernel version",
                            "Node Security", "MEDIUM", res, None,
                            f"kernelVersion: {info.kernel_version}",
                            "Kernel versions below 5.4 lack important security features (eBPF, cgroup v2, seccomp improvements).",
                            "Upgrade node OS to a distribution with kernel 5.4+.",
                            "CWE-1104",
                        ))

    @staticmethod
    def _ver_lt(v1: str, v2: str) -> bool:
        """Return True if version v1 < v2 (simple dotted comparison)."""
        def parts(v):
            return [int(x) for x in re.findall(r'\d+', v)]
        return parts(v1) < parts(v2)

    # ===================================================================
    # CHECK GROUP 12: Pod Disruption Budgets  (K8S-PDB-001 to 003) [v1.1.0]
    # ===================================================================
    def _check_pod_disruption_budgets(self):
        self._vprint("  [*] Checking Pod Disruption Budgets ...")

        if not self.policy_v1:
            self._vprint("    [*] PolicyV1 API not available, skipping PDB checks")
            return

        namespaces = self._get_namespaces()

        for ns in namespaces:
            if ns in SYSTEM_NAMESPACES:
                continue

            # Get PDBs in this namespace
            try:
                pdbs = self.policy_v1.list_namespaced_pod_disruption_budget(ns).items
            except ApiException:
                continue

            # Get Deployments and StatefulSets (workloads that should have PDBs)
            deployments = []
            statefulsets = []
            try:
                deployments = self.apps_v1.list_namespaced_deployment(ns).items
            except ApiException:
                pass
            try:
                statefulsets = self.apps_v1.list_namespaced_stateful_set(ns).items
            except ApiException:
                pass

            # Build a set of label selectors covered by PDBs
            pdb_selectors = []
            for pdb in pdbs:
                if pdb.spec and pdb.spec.selector:
                    match_labels = pdb.spec.selector.match_labels or {}
                    pdb_selectors.append(match_labels)

                    res = self._res_path(ns, "PodDisruptionBudget", pdb.metadata.name)

                    # --- K8S-PDB-002: PDB with maxUnavailable=0 ---
                    max_unavail = pdb.spec.max_unavailable
                    if max_unavail is not None and str(max_unavail) == "0":
                        self._add(Finding(
                            "K8S-PDB-002", "PDB blocks all voluntary disruptions",
                            "Availability", "HIGH", res, None,
                            "maxUnavailable: 0",
                            "PDB with maxUnavailable=0 blocks all voluntary disruptions including node drains and upgrades.",
                            "Set maxUnavailable to at least 1 or use a percentage.",
                        ))

                    # --- K8S-PDB-003: PDB with minAvailable equal to replicas ---
                    min_avail = pdb.spec.min_available
                    if min_avail is not None and str(min_avail) == "100%":
                        self._add(Finding(
                            "K8S-PDB-003", "PDB requires 100% availability",
                            "Availability", "HIGH", res, None,
                            "minAvailable: 100%",
                            "PDB requires all pods to be available, blocking voluntary disruptions.",
                            "Reduce minAvailable to allow at least 1 pod to be disrupted.",
                        ))

            # --- K8S-PDB-001: Deployment/StatefulSet without PDB ---
            for dep in deployments:
                replicas = dep.spec.replicas or 1
                if replicas < 2:
                    continue  # single-replica doesn't benefit from PDB

                dep_labels = dep.spec.selector.match_labels or {} if dep.spec.selector else {}
                covered = any(
                    all(dep_labels.get(k) == v for k, v in sel.items())
                    for sel in pdb_selectors if sel
                )
                if not covered:
                    self._add(Finding(
                        "K8S-PDB-001", "Deployment without PodDisruptionBudget",
                        "Availability", "MEDIUM",
                        self._res_path(ns, "Deployment", dep.metadata.name),
                        None, f"replicas: {replicas}, pdb: none",
                        "Multi-replica Deployment has no PDB. Node drains may disrupt all replicas simultaneously.",
                        "Create a PodDisruptionBudget matching this Deployment's labels.",
                    ))

            for sts in statefulsets:
                replicas = sts.spec.replicas or 1
                if replicas < 2:
                    continue
                sts_labels = sts.spec.selector.match_labels or {} if sts.spec.selector else {}
                covered = any(
                    all(sts_labels.get(k) == v for k, v in sel.items())
                    for sel in pdb_selectors if sel
                )
                if not covered:
                    self._add(Finding(
                        "K8S-PDB-001", "StatefulSet without PodDisruptionBudget",
                        "Availability", "MEDIUM",
                        self._res_path(ns, "StatefulSet", sts.metadata.name),
                        None, f"replicas: {replicas}, pdb: none",
                        "Multi-replica StatefulSet has no PDB. Voluntary disruptions may cause data unavailability.",
                        "Create a PodDisruptionBudget matching this StatefulSet's labels.",
                    ))

    # ===================================================================
    # CHECK GROUP 13: HPA Security  (K8S-HPA-001 to 004)  [v1.1.0]
    # ===================================================================
    def _check_hpa_security(self):
        self._vprint("  [*] Checking HPA security ...")

        if not self.autoscaling_v2:
            self._vprint("    [*] AutoscalingV2 API not available, skipping HPA checks")
            return

        namespaces = self._get_namespaces()

        for ns in namespaces:
            if ns in SYSTEM_NAMESPACES:
                continue

            try:
                hpas = self.autoscaling_v2.list_namespaced_horizontal_pod_autoscaler(ns).items
            except ApiException:
                continue

            for hpa in hpas:
                res = self._res_path(ns, "HorizontalPodAutoscaler", hpa.metadata.name)
                spec = hpa.spec
                if not spec:
                    continue

                min_r = spec.min_replicas or 1
                max_r = spec.max_replicas

                # --- K8S-HPA-001: HPA with minReplicas=1 ---
                if min_r == 1:
                    self._add(Finding(
                        "K8S-HPA-001", "HPA minReplicas is 1",
                        "Availability", "MEDIUM", res, None,
                        f"minReplicas: {min_r}, maxReplicas: {max_r}",
                        "HPA can scale down to a single replica, eliminating redundancy.",
                        "Set minReplicas to at least 2 for production workloads.",
                    ))

                # --- K8S-HPA-002: HPA minReplicas equals maxReplicas ---
                if min_r == max_r:
                    self._add(Finding(
                        "K8S-HPA-002", "HPA min equals max replicas",
                        "Availability", "LOW", res, None,
                        f"minReplicas: {min_r}, maxReplicas: {max_r}",
                        "HPA cannot scale — min and max replicas are identical. Autoscaler is effectively disabled.",
                        "Increase maxReplicas above minReplicas, or remove the HPA if scaling is not needed.",
                    ))

                # --- K8S-HPA-003: HPA targets workload without resource requests ---
                target_ref = spec.scale_target_ref
                if target_ref and target_ref.kind in ("Deployment", "StatefulSet"):
                    try:
                        if target_ref.kind == "Deployment":
                            wl = self.apps_v1.read_namespaced_deployment(target_ref.name, ns)
                        else:
                            wl = self.apps_v1.read_namespaced_stateful_set(target_ref.name, ns)
                        containers = wl.spec.template.spec.containers or []
                        for ctr in containers:
                            req = ctr.resources.requests if ctr.resources else None
                            if not req or ("cpu" not in req and "memory" not in req):
                                self._add(Finding(
                                    "K8S-HPA-003",
                                    "HPA target has no resource requests",
                                    "Availability", "HIGH", res, None,
                                    f"target: {target_ref.kind}/{target_ref.name}, "
                                    f"container: {ctr.name}",
                                    "HPA cannot calculate utilization without resource requests. "
                                    "Scaling decisions will be unreliable.",
                                    "Set resources.requests.cpu and/or memory on all containers "
                                    "targeted by the HPA.",
                                ))
                                break  # one finding per HPA is enough
                    except ApiException:
                        pass

                # --- K8S-HPA-004: No scale-down stabilization ---
                behavior = spec.behavior
                has_scaledown_policy = False
                if behavior and behavior.scale_down:
                    if behavior.scale_down.stabilization_window_seconds:
                        has_scaledown_policy = True
                    if behavior.scale_down.policies:
                        has_scaledown_policy = True
                if not has_scaledown_policy:
                    self._add(Finding(
                        "K8S-HPA-004", "HPA without scale-down stabilization",
                        "Availability", "LOW", res, None,
                        "behavior.scaleDown: not configured",
                        "Without scale-down stabilization, HPA may rapidly remove replicas causing brief outages.",
                        "Configure behavior.scaleDown.stabilizationWindowSeconds (e.g., 300).",
                    ))

    # ===================================================================
    # CHECK GROUP 14: Service Mesh  (K8S-MESH-001 to 004)  [v1.1.0]
    # ===================================================================
    def _check_service_mesh(self):
        self._vprint("  [*] Checking service mesh security ...")

        namespaces = self._get_namespaces()
        mesh_detected = {"istio": False, "linkerd": False}

        # Detect Istio
        try:
            ns_list = self.core_v1.list_namespace().items
            ns_names = {ns.metadata.name for ns in ns_list}
            ns_labels_map = {ns.metadata.name: (ns.metadata.labels or {}) for ns in ns_list}
            if "istio-system" in ns_names:
                mesh_detected["istio"] = True
            if any("linkerd" in n for n in ns_names):
                mesh_detected["linkerd"] = True
        except ApiException:
            pass

        if not any(mesh_detected.values()):
            self._vprint("    [*] No service mesh detected, skipping mesh checks")
            return

        # --- Istio-specific checks ---
        if mesh_detected["istio"]:
            # K8S-MESH-001: Namespace without sidecar injection
            for ns in namespaces:
                if ns in SYSTEM_NAMESPACES or ns == "istio-system":
                    continue
                labels = ns_labels_map.get(ns, {})
                injection = labels.get("istio-injection", "")
                rev_label = labels.get("istio.io/rev", "")
                if injection != "enabled" and not rev_label:
                    self._add(Finding(
                        "K8S-MESH-001", "Namespace without Istio sidecar injection",
                        "Service Mesh", "MEDIUM",
                        self._res_path(None, "Namespace", ns), None,
                        f"istio-injection: {injection or 'not set'}",
                        "Namespace is not configured for automatic Istio sidecar injection. "
                        "Pods will not get mTLS or traffic management.",
                        "Add label istio-injection=enabled or istio.io/rev=<tag> to the namespace.",
                    ))

            # K8S-MESH-002: Check for permissive mTLS (PeerAuthentication)
            try:
                pas = self.custom_api.list_cluster_custom_object(
                    "security.istio.io", "v1beta1", "peerauthentications")
                for pa in pas.get("items", []):
                    mtls_mode = (pa.get("spec", {}).get("mtls", {}).get("mode", "")).upper()
                    pa_ns = pa.get("metadata", {}).get("namespace", "istio-system")
                    pa_name = pa.get("metadata", {}).get("name", "unknown")
                    if mtls_mode == "PERMISSIVE":
                        self._add(Finding(
                            "K8S-MESH-002", "Istio mTLS set to PERMISSIVE",
                            "Service Mesh", "HIGH",
                            self._res_path(pa_ns, "PeerAuthentication", pa_name),
                            None, f"mtls.mode: PERMISSIVE",
                            "PERMISSIVE mode accepts both plaintext and mTLS traffic. "
                            "Attackers can bypass encryption by sending unencrypted requests.",
                            "Set mTLS mode to STRICT to enforce mutual TLS for all traffic.",
                            "CWE-319",
                        ))
                    if mtls_mode == "DISABLE":
                        self._add(Finding(
                            "K8S-MESH-002", "Istio mTLS disabled",
                            "Service Mesh", "CRITICAL",
                            self._res_path(pa_ns, "PeerAuthentication", pa_name),
                            None, f"mtls.mode: DISABLE",
                            "mTLS is disabled. All service-to-service traffic is unencrypted.",
                            "Set mTLS mode to STRICT.",
                            "CWE-319",
                        ))
            except ApiException:
                self._vprint("    [*] Cannot query PeerAuthentication resources")

            # K8S-MESH-003: Check for missing AuthorizationPolicy
            try:
                authz = self.custom_api.list_cluster_custom_object(
                    "security.istio.io", "v1beta1", "authorizationpolicies")
                authz_namespaces = {
                    item.get("metadata", {}).get("namespace", "")
                    for item in authz.get("items", [])
                }
                for ns in namespaces:
                    if ns in SYSTEM_NAMESPACES or ns == "istio-system":
                        continue
                    labels = ns_labels_map.get(ns, {})
                    if labels.get("istio-injection") == "enabled" or labels.get("istio.io/rev"):
                        if ns not in authz_namespaces:
                            self._add(Finding(
                                "K8S-MESH-003", "Istio namespace without AuthorizationPolicy",
                                "Service Mesh", "MEDIUM",
                                self._res_path(None, "Namespace", ns), None,
                                "authorizationPolicies: 0",
                                "Mesh-enabled namespace has no AuthorizationPolicy. "
                                "All traffic between services is allowed.",
                                "Create AuthorizationPolicies to enforce least-privilege service access.",
                                "CWE-284",
                            ))
            except ApiException:
                pass

        # --- Linkerd-specific checks ---
        if mesh_detected["linkerd"]:
            for ns in namespaces:
                if ns in SYSTEM_NAMESPACES:
                    continue
                labels = ns_labels_map.get(ns, {})
                annotations = {}
                try:
                    ns_obj = self.core_v1.read_namespace(ns)
                    annotations = ns_obj.metadata.annotations or {}
                except ApiException:
                    pass
                if labels.get("linkerd.io/inject") != "enabled":
                    self._add(Finding(
                        "K8S-MESH-001", "Namespace without Linkerd injection",
                        "Service Mesh", "MEDIUM",
                        self._res_path(None, "Namespace", ns), None,
                        f"linkerd.io/inject: {labels.get('linkerd.io/inject', 'not set')}",
                        "Namespace is not configured for Linkerd proxy injection.",
                        "Add annotation linkerd.io/inject=enabled to the namespace.",
                    ))

        # K8S-MESH-004: Service mesh gateway exposed without auth
        for ns in namespaces:
            try:
                svcs = self.core_v1.list_namespaced_service(ns).items
                for svc in svcs:
                    svc_name = svc.metadata.name.lower()
                    labels = svc.metadata.labels or {}
                    is_gateway = ("gateway" in svc_name or "ingress" in svc_name or
                                  labels.get("istio") == "ingressgateway" or
                                  labels.get("app") == "istio-ingressgateway")
                    if is_gateway and svc.spec.type in ("LoadBalancer", "NodePort"):
                        self._add(Finding(
                            "K8S-MESH-004", "Mesh gateway externally exposed",
                            "Service Mesh", "MEDIUM",
                            self._res_path(ns, "Service", svc.metadata.name),
                            None, f"type: {svc.spec.type}",
                            "Service mesh gateway is exposed externally. Ensure mTLS and "
                            "AuthorizationPolicies protect backend services.",
                            "Verify gateway has proper VirtualService routing and "
                            "RequestAuthentication configured.",
                        ))
            except ApiException:
                pass

    # ===================================================================
    # CHECK GROUP 15: Deprecated APIs  (K8S-API-001 to 003)  [v1.1.0]
    # ===================================================================
    def _check_deprecated_apis(self):
        self._vprint("  [*] Checking for deprecated API versions ...")

        # Get cluster version to determine which APIs are actually removed
        cluster_minor = 0
        try:
            ver = self.version_api.get_code()
            ver_match = re.match(r'(\d+)', ver.minor.rstrip("+"))
            if ver_match:
                cluster_minor = int(ver_match.group(1))
        except Exception:
            pass

        # Query the API server for resource lists to find deprecated apiVersions
        api_client = self.core_v1.api_client

        try:
            # Get all API groups and versions
            api_groups_resp = api_client.call_api(
                '/apis', 'GET', response_type='object',
                _return_http_data_only=True)
            groups = api_groups_resp.get("groups", []) if isinstance(api_groups_resp, dict) else []
        except Exception:
            groups = []

        for api_version, info in DEPRECATED_API_VERSIONS.items():
            removed_in = info["removed_in"]
            removed_minor = int(removed_in.split(".")[1]) if "." in removed_in else 0
            replacement = info["replacement"]

            # Try listing resources using the deprecated API
            group_version = api_version
            parts = group_version.split("/")
            if len(parts) == 2:
                group, version = parts
            else:
                continue

            try:
                path = f"/apis/{group}/{version}"
                resp = api_client.call_api(
                    path, 'GET', response_type='object',
                    _return_http_data_only=True)
                resources = resp.get("resources", []) if isinstance(resp, dict) else []

                if resources:
                    resource_names = [r.get("kind", "") for r in resources if r.get("kind")]
                    expected = info["resources"]
                    found_resources = expected & set(resource_names)

                    if found_resources:
                        # Determine severity based on whether it's just deprecated or removed
                        if cluster_minor > 0 and cluster_minor >= removed_minor:
                            severity = "HIGH"
                            rule_id = "K8S-API-002"
                            desc = (f"API version {api_version} was removed in Kubernetes {removed_in}. "
                                    f"Resources using it will fail on cluster upgrade.")
                        else:
                            severity = "MEDIUM"
                            rule_id = "K8S-API-001"
                            desc = (f"API version {api_version} is deprecated and will be removed in "
                                    f"Kubernetes {removed_in}.")

                        self._add(Finding(
                            rule_id,
                            f"Deprecated API version: {api_version}",
                            "Deprecated APIs", severity,
                            self._res_path(None, "APIVersion", api_version),
                            None,
                            f"resources: {', '.join(sorted(found_resources))}",
                            desc,
                            f"Migrate to {replacement}.",
                            "CWE-1104",
                        ))
            except Exception:
                pass

        # --- K8S-API-003: PodSecurityPolicy still in use (removed in 1.25) ---
        try:
            path = "/apis/policy/v1beta1/podsecuritypolicies"
            resp = api_client.call_api(
                path, 'GET', response_type='object',
                _return_http_data_only=True)
            items = resp.get("items", []) if isinstance(resp, dict) else []
            if items:
                for psp in items:
                    psp_name = psp.get("metadata", {}).get("name", "unknown")
                    self._add(Finding(
                        "K8S-API-003", "PodSecurityPolicy still in use",
                        "Deprecated APIs", "HIGH",
                        self._res_path(None, "PodSecurityPolicy", psp_name),
                        None, f"apiVersion: policy/v1beta1",
                        "PodSecurityPolicy is removed in Kubernetes 1.25. "
                        "Existing PSPs have no effect on newer clusters.",
                        "Migrate to Pod Security Admission (PSA) with namespace labels.",
                        "CWE-1104",
                    ))
        except Exception:
            pass

    # ===================================================================
    # CHECK GROUP 16: Runtime & Ephemeral  (K8S-RC/EPH)  [v1.1.0]
    # ===================================================================
    def _check_runtime_security(self):
        self._vprint("  [*] Checking runtime classes and ephemeral containers ...")

        # --- K8S-RC-001/002: RuntimeClass checks ---
        try:
            rcs = self.custom_api.list_cluster_custom_object(
                "node.k8s.io", "v1", "runtimeclasses")
            rc_names = {
                item.get("metadata", {}).get("name", "")
                for item in rcs.get("items", [])
            }
            rc_handlers = {
                item.get("metadata", {}).get("name", ""): item.get("handler", "")
                for item in rcs.get("items", [])
            }
        except Exception:
            rc_names = set()
            rc_handlers = {}

        sandboxed_rcs = set()
        for name, handler in rc_handlers.items():
            if any(s in handler.lower() for s in ("gvisor", "kata", "runsc", "firecracker")):
                sandboxed_rcs.add(name)

        # Check workloads for RuntimeClass usage
        namespaces = self._get_namespaces()
        for ns in namespaces:
            if ns in SYSTEM_NAMESPACES:
                continue

            workloads = []
            try:
                for d in self.apps_v1.list_namespaced_deployment(ns).items:
                    workloads.append(("Deployment", d.metadata.name, d.spec.template.spec))
            except ApiException:
                pass
            try:
                for s in self.apps_v1.list_namespaced_stateful_set(ns).items:
                    workloads.append(("StatefulSet", s.metadata.name, s.spec.template.spec))
            except ApiException:
                pass

            for kind, name, pod_spec in workloads:
                if not pod_spec:
                    continue
                rc_name = pod_spec.runtime_class_name

                # K8S-RC-001: Workload using non-existent RuntimeClass
                if rc_name and rc_names and rc_name not in rc_names:
                    self._add(Finding(
                        "K8S-RC-001", "Workload references non-existent RuntimeClass",
                        "Runtime Security", "HIGH",
                        self._res_path(ns, kind, name), None,
                        f"runtimeClassName: {rc_name}",
                        f"RuntimeClass '{rc_name}' does not exist. Pods will fail to schedule.",
                        "Create the RuntimeClass or update the workload to use an existing one.",
                    ))

                # K8S-RC-002: Workload not using sandboxed runtime (informational)
                # Only flag if sandboxed runtimes are available but not used
                if sandboxed_rcs and not rc_name:
                    # Check if workload handles untrusted input (heuristic: external-facing)
                    pass  # Too noisy to flag all workloads; skip unless targeted

        # --- K8S-EPH-001: Active ephemeral containers ---
        for ns in namespaces:
            if ns in SYSTEM_NAMESPACES:
                continue
            try:
                pods = self.core_v1.list_namespaced_pod(ns).items
            except ApiException:
                continue

            for pod in pods:
                eph_containers = pod.spec.ephemeral_containers or [] if pod.spec else []
                if eph_containers:
                    for ec in eph_containers:
                        self._add(Finding(
                            "K8S-EPH-001", "Ephemeral debug container present",
                            "Runtime Security", "MEDIUM",
                            self._res_path(ns, "Pod", pod.metadata.name),
                            None, f"ephemeralContainer: {ec.name}",
                            "An ephemeral debug container is attached to this pod. "
                            "Debug containers may have elevated access and should be temporary.",
                            "Remove ephemeral containers after debugging is complete. "
                            "Monitor kubectl debug usage via audit logs.",
                            "CWE-250",
                        ))

                        # Check if ephemeral container is privileged
                        ec_sc = ec.security_context
                        if ec_sc and ec_sc.privileged:
                            self._add(Finding(
                                "K8S-EPH-002", "Privileged ephemeral container",
                                "Runtime Security", "CRITICAL",
                                self._res_path(ns, "Pod", pod.metadata.name),
                                None, f"ephemeralContainer: {ec.name}, privileged: true",
                                "Privileged ephemeral container has full host access. "
                                "This is a significant security risk even for debugging.",
                                "Use non-privileged ephemeral containers. "
                                "Restrict debug container capabilities via admission control.",
                                "CWE-250",
                            ))

    # ===================================================================
    # CHECK GROUP 17: Advanced RBAC Analysis  (K8S-RBAC-016 to 027)  [v1.3.0]
    # ===================================================================
    def _check_advanced_rbac(self):
        self._vprint("  [*] Checking advanced RBAC analysis ...")

        # --- Collect all RBAC objects ---
        try:
            crbs = self.rbac_v1.list_cluster_role_binding().items
        except ApiException:
            crbs = []
        try:
            crs = self.rbac_v1.list_cluster_role().items
        except ApiException:
            crs = []
        try:
            rbs_all = self.rbac_v1.list_role_binding_for_all_namespaces().items
        except ApiException:
            rbs_all = []
        try:
            roles_all = self.rbac_v1.list_role_for_all_namespaces().items
        except ApiException:
            roles_all = []

        namespaces = self._get_namespaces()

        # --- Build role rules lookup: (kind, ns, name) → [rules] ---
        role_rules = {}
        for cr in crs:
            role_rules[("ClusterRole", None, cr.metadata.name)] = cr.rules or []
        for r in roles_all:
            role_rules[("Role", r.metadata.namespace, r.metadata.name)] = r.rules or []

        # --- Build RBAC graph: subject → [(binding, role_key, scope)] ---
        # subject key: (kind, namespace, name)
        rbac_graph = {}  # subject_key → list of {binding, role_key, scope, binding_ns}

        for crb in crbs:
            if not crb.role_ref:
                continue
            role_key = ("ClusterRole", None, crb.role_ref.name)
            for subj in (crb.subjects or []):
                sk = (subj.kind, subj.namespace or "", subj.name)
                rbac_graph.setdefault(sk, []).append({
                    "binding": crb.metadata.name,
                    "binding_kind": "ClusterRoleBinding",
                    "role_key": role_key,
                    "scope": "cluster",
                    "binding_ns": None,
                })

        for rb in rbs_all:
            if not rb.role_ref:
                continue
            rb_ns = rb.metadata.namespace or "default"
            if rb.role_ref.kind == "ClusterRole":
                role_key = ("ClusterRole", None, rb.role_ref.name)
            else:
                role_key = ("Role", rb_ns, rb.role_ref.name)
            for subj in (rb.subjects or []):
                sk = (subj.kind, subj.namespace or rb_ns, subj.name)
                rbac_graph.setdefault(sk, []).append({
                    "binding": rb.metadata.name,
                    "binding_kind": "RoleBinding",
                    "role_key": role_key,
                    "scope": f"namespace:{rb_ns}",
                    "binding_ns": rb_ns,
                })

        # --- Collect running SAs per namespace ---
        running_sas = set()  # (namespace, sa_name)
        for ns in namespaces:
            try:
                pods = self.core_v1.list_namespaced_pod(ns).items
                for p in pods:
                    if p.spec:
                        sa = p.spec.service_account_name or p.spec.service_account or "default"
                        running_sas.add((ns, sa))
            except ApiException:
                pass

        # --- Helper: extract effective permissions from a role ---
        def _get_permissions(role_key):
            rules = role_rules.get(role_key, [])
            perms = []
            for rule in rules:
                verbs = list(rule.verbs or [])
                resources = list(rule.resources or [])
                api_groups = list(rule.api_groups or [])
                perms.append({"verbs": verbs, "resources": resources, "api_groups": api_groups})
            return perms

        # --- Helper: check if permissions are dangerous ---
        def _has_dangerous_perms(perms):
            for p in perms:
                if "*" in p["verbs"] and "*" in p["resources"]:
                    return True
                for r in p["resources"]:
                    if r in SENSITIVE_RESOURCES and any(
                        v in p["verbs"] for v in ["*", "create", "get", "list"]
                    ):
                        return True
            return False

        # --- Helper: check if role can create/modify roles/bindings ---
        def _can_escalate(perms):
            for p in perms:
                rbac_resources = {"roles", "clusterroles", "rolebindings", "clusterrolebindings"}
                mutate_verbs = {"create", "update", "patch", "*"}
                if rbac_resources & set(p["resources"]) and mutate_verbs & set(p["verbs"]):
                    return True
                if "escalate" in p["verbs"] or "bind" in p["verbs"]:
                    return True
            return False

        # =====================================================================
        # K8S-RBAC-016: Dormant service accounts (bindings but no running pods)
        # =====================================================================
        for (sk_kind, sk_ns, sk_name), edges in rbac_graph.items():
            if sk_kind != "ServiceAccount":
                continue
            if sk_name.startswith("system:"):
                continue
            if sk_ns in SYSTEM_NAMESPACES:
                continue
            if (sk_ns, sk_name) not in running_sas:
                # Has bindings but no pod uses it
                roles_bound = ", ".join(
                    f"{e['role_key'][2]} ({e['scope']})" for e in edges
                )
                has_dangerous = any(
                    _has_dangerous_perms(_get_permissions(e["role_key"]))
                    for e in edges
                )
                severity = "HIGH" if has_dangerous else "MEDIUM"
                self._add(Finding(
                    "K8S-RBAC-016", "Dormant service account with active bindings",
                    "Advanced RBAC", severity,
                    self._res_path(sk_ns, "ServiceAccount", sk_name),
                    None, f"bound roles: {roles_bound}",
                    "Service account has RBAC bindings but no running pods reference it. "
                    "Dormant SAs with permissions are latent attack vectors.",
                    "Remove unused bindings or delete the service account if it is no longer needed.",
                    "CWE-269",
                ))

        # =====================================================================
        # K8S-RBAC-017: SA with cross-namespace ClusterRole access
        # =====================================================================
        for (sk_kind, sk_ns, sk_name), edges in rbac_graph.items():
            if sk_kind != "ServiceAccount":
                continue
            if sk_name.startswith("system:") or sk_ns in SYSTEM_NAMESPACES:
                continue
            cluster_scope_edges = [e for e in edges if e["scope"] == "cluster"]
            if cluster_scope_edges:
                for e in cluster_scope_edges:
                    perms = _get_permissions(e["role_key"])
                    if _has_dangerous_perms(perms):
                        self._add(Finding(
                            "K8S-RBAC-017",
                            "SA has dangerous cluster-wide permissions",
                            "Advanced RBAC", "HIGH",
                            self._res_path(sk_ns, "ServiceAccount", sk_name),
                            None,
                            f"via {e['binding_kind']}/{e['binding']} → {e['role_key'][2]}",
                            f"Service account in namespace '{sk_ns}' has cluster-wide access to "
                            f"sensitive resources via ClusterRoleBinding, enabling cross-namespace access.",
                            "Replace ClusterRoleBinding with namespace-scoped RoleBindings. "
                            "Restrict to only the namespaces the SA needs.",
                            "CWE-269",
                        ))

        # =====================================================================
        # K8S-RBAC-018: Privilege escalation path — SA can modify RBAC
        # =====================================================================
        for (sk_kind, sk_ns, sk_name), edges in rbac_graph.items():
            if sk_kind != "ServiceAccount":
                continue
            if sk_name.startswith("system:") or sk_ns in SYSTEM_NAMESPACES:
                continue
            for e in edges:
                perms = _get_permissions(e["role_key"])
                if _can_escalate(perms):
                    self._add(Finding(
                        "K8S-RBAC-018",
                        "SA can modify RBAC objects (escalation path)",
                        "Advanced RBAC", "CRITICAL",
                        self._res_path(sk_ns, "ServiceAccount", sk_name),
                        None,
                        f"via {e['role_key'][2]} ({e['scope']}): can create/modify roles/bindings",
                        "Service account can create or modify Roles, ClusterRoles, or their bindings. "
                        "This enables privilege escalation by granting itself additional permissions.",
                        "Remove RBAC mutation permissions. Use dedicated admin SAs with break-glass procedures.",
                        "CWE-269",
                    ))

        # =====================================================================
        # K8S-RBAC-019: Multi-hop escalation — SA can create pods + has elevated role
        # =====================================================================
        for (sk_kind, sk_ns, sk_name), edges in rbac_graph.items():
            if sk_kind != "ServiceAccount":
                continue
            if sk_name.startswith("system:") or sk_ns in SYSTEM_NAMESPACES:
                continue
            all_perms = []
            for e in edges:
                all_perms.extend(_get_permissions(e["role_key"]))
            can_create_pods = any(
                "pods" in p["resources"] and
                any(v in p["verbs"] for v in ["create", "*"])
                for p in all_perms
            )
            has_elevated = _has_dangerous_perms(all_perms)
            if can_create_pods and has_elevated:
                self._add(Finding(
                    "K8S-RBAC-019",
                    "Multi-hop escalation: pod creation + elevated permissions",
                    "Advanced RBAC", "CRITICAL",
                    self._res_path(sk_ns, "ServiceAccount", sk_name),
                    None, "can create pods AND has access to sensitive resources",
                    "Service account can both create pods and access sensitive resources. "
                    "An attacker can create a pod with this SA to inherit its elevated permissions.",
                    "Separate pod-creation and data-access roles. Use Pod Security Admission to restrict SA usage.",
                    "CWE-269",
                ))

        # =====================================================================
        # K8S-RBAC-020: Overly broad Role (> 10 resources or > 5 write verbs)
        # =====================================================================
        for role_key, rules in role_rules.items():
            kind, ns, name = role_key
            if name.startswith("system:") or name in ("cluster-admin", "admin", "edit", "view"):
                continue
            total_resources = set()
            total_write_verbs = set()
            for rule in rules:
                for r in (rule.resources or []):
                    total_resources.add(r)
                for v in (rule.verbs or []):
                    if v in DANGEROUS_VERBS or v == "*":
                        total_write_verbs.add(v)
            if len(total_resources) > 10 or (
                len(total_write_verbs) >= 4 and len(total_resources) > 5
            ):
                res_path = self._res_path(ns, kind, name)
                self._add(Finding(
                    "K8S-RBAC-020",
                    "Overly broad role (least-privilege violation)",
                    "Advanced RBAC", "MEDIUM", res_path, None,
                    f"resources: {len(total_resources)}, dangerous verbs: {sorted(total_write_verbs)}",
                    f"Role '{name}' grants access to {len(total_resources)} resources with "
                    f"dangerous verbs. Consider splitting into narrower purpose-specific roles.",
                    "Apply least-privilege: create separate roles for read-only, write, and admin operations.",
                    "CWE-250",
                ))

        # =====================================================================
        # K8S-RBAC-021: Role grants same permissions across all namespaces
        # =====================================================================
        # Find RoleBindings that bind the same ClusterRole in 3+ namespaces
        cr_ns_usage = {}  # clusterrole_name → set of namespaces
        for rb in rbs_all:
            if rb.role_ref and rb.role_ref.kind == "ClusterRole":
                cr_name = rb.role_ref.name
                rb_ns = rb.metadata.namespace or "default"
                if rb_ns not in SYSTEM_NAMESPACES:
                    cr_ns_usage.setdefault(cr_name, set()).add(rb_ns)
        for cr_name, ns_set in cr_ns_usage.items():
            if cr_name.startswith("system:") or cr_name in ("admin", "edit", "view"):
                continue
            if len(ns_set) >= 3:
                self._add(Finding(
                    "K8S-RBAC-021",
                    "ClusterRole bound in many namespaces via RoleBindings",
                    "Advanced RBAC", "LOW",
                    self._res_path(None, "ClusterRole", cr_name),
                    None,
                    f"bound in {len(ns_set)} namespaces: {', '.join(sorted(ns_set)[:5])}{'...' if len(ns_set) > 5 else ''}",
                    "ClusterRole is bound via RoleBindings in multiple namespaces. "
                    "Consider using a ClusterRoleBinding if cluster-wide access is intended, "
                    "or audit whether each namespace truly needs this role.",
                    "Review per-namespace necessity. Consolidate or replace with namespace-specific Roles.",
                ))

        # =====================================================================
        # K8S-RBAC-022: User/Group with admin across namespaces
        # =====================================================================
        for (sk_kind, sk_ns, sk_name), edges in rbac_graph.items():
            if sk_kind not in ("User", "Group"):
                continue
            if sk_name.startswith("system:"):
                continue
            admin_scopes = []
            for e in edges:
                role_name = e["role_key"][2]
                if role_name in ("cluster-admin", "admin") or "admin" in role_name.lower():
                    admin_scopes.append(e["scope"])
            if len(admin_scopes) >= 3:
                self._add(Finding(
                    "K8S-RBAC-022",
                    f"{sk_kind} has admin in multiple scopes",
                    "Advanced RBAC", "HIGH",
                    self._res_path(None, sk_kind, sk_name),
                    None,
                    f"admin in {len(admin_scopes)} scopes: {', '.join(admin_scopes[:5])}",
                    f"{sk_kind} '{sk_name}' holds admin-level roles across {len(admin_scopes)} scopes, "
                    f"creating a high-impact blast radius if the account is compromised.",
                    "Apply least-privilege per namespace. Use separate identities per team/scope.",
                    "CWE-250",
                ))

        # =====================================================================
        # K8S-RBAC-023: Binding references non-existent role
        # =====================================================================
        existing_roles = set(role_rules.keys())
        for crb in crbs:
            if not crb.role_ref or crb.metadata.name.startswith("system:"):
                continue
            key = ("ClusterRole", None, crb.role_ref.name)
            if key not in existing_roles:
                self._add(Finding(
                    "K8S-RBAC-023",
                    "ClusterRoleBinding references non-existent ClusterRole",
                    "Advanced RBAC", "MEDIUM",
                    self._res_path(None, "ClusterRoleBinding", crb.metadata.name),
                    None, f"roleRef: {crb.role_ref.name}",
                    "Binding references a ClusterRole that does not exist. "
                    "This may indicate a deleted role or misconfiguration.",
                    "Delete orphaned bindings or create the missing ClusterRole.",
                ))
        for rb in rbs_all:
            if not rb.role_ref or rb.metadata.name.startswith("system:"):
                continue
            rb_ns = rb.metadata.namespace or "default"
            if rb.role_ref.kind == "ClusterRole":
                key = ("ClusterRole", None, rb.role_ref.name)
            else:
                key = ("Role", rb_ns, rb.role_ref.name)
            if key not in existing_roles:
                self._add(Finding(
                    "K8S-RBAC-023",
                    "RoleBinding references non-existent role",
                    "Advanced RBAC", "MEDIUM",
                    self._res_path(rb_ns, "RoleBinding", rb.metadata.name),
                    None, f"roleRef: {rb.role_ref.kind}/{rb.role_ref.name}",
                    "Binding references a role that does not exist in its namespace. "
                    "This may indicate stale configuration.",
                    "Delete orphaned bindings or create the missing role.",
                ))

        # =====================================================================
        # K8S-RBAC-024: Aggregate ClusterRole with broad label selectors
        # =====================================================================
        for cr in crs:
            if cr.metadata.name.startswith("system:"):
                continue
            agg = cr.aggregation_rule
            if agg and agg.cluster_role_selectors:
                for sel in agg.cluster_role_selectors:
                    labels = sel.match_labels or {}
                    exprs = sel.match_expressions or []
                    if not labels and not exprs:
                        self._add(Finding(
                            "K8S-RBAC-024",
                            "Aggregate ClusterRole with empty selector",
                            "Advanced RBAC", "HIGH",
                            self._res_path(None, "ClusterRole", cr.metadata.name),
                            None, "aggregationRule with empty matchLabels",
                            "Aggregate ClusterRole uses an empty label selector, which matches ALL ClusterRoles. "
                            "Any ClusterRole created in the cluster will be aggregated into this role.",
                            "Add specific matchLabels to the aggregation rule to limit scope.",
                            "CWE-269",
                        ))

        # Store the RBAC graph for baseline operations
        self._rbac_graph = rbac_graph
        self._role_rules = role_rules

    def save_rbac_baseline(self, path: str):
        """Save current RBAC state as a JSON baseline for drift comparison."""
        if not hasattr(self, "_rbac_graph"):
            self._warn("Run scan() before saving baseline")
            return

        baseline = {"version": VERSION, "generated": datetime.now(timezone.utc).isoformat(),
                     "cluster": self.cluster_name, "subjects": {}, "roles": {}}

        for (sk_kind, sk_ns, sk_name), edges in self._rbac_graph.items():
            key = f"{sk_kind}:{sk_ns}:{sk_name}"
            baseline["subjects"][key] = [
                {"binding": e["binding"], "role": e["role_key"][2],
                 "scope": e["scope"]}
                for e in edges
            ]

        for (kind, ns, name), rules in self._role_rules.items():
            key = f"{kind}:{ns or ''}:{name}"
            baseline["roles"][key] = [
                {"verbs": list(r.verbs or []),
                 "resources": list(r.resources or []),
                 "api_groups": list(r.api_groups or [])}
                for r in rules
            ]

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(baseline, fh, indent=2)
        print(f"\n[+] RBAC baseline saved to: {os.path.abspath(path)}")

    def compare_rbac_baseline(self, path: str):
        """Compare current RBAC state against a saved baseline and emit drift findings."""
        if not hasattr(self, "_rbac_graph"):
            self._warn("Run scan() before comparing baseline")
            return

        try:
            with open(path, "r", encoding="utf-8") as fh:
                baseline = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            self._warn(f"Cannot load baseline: {exc}")
            return

        baseline_subjects = baseline.get("subjects", {})
        baseline_roles = baseline.get("roles", {})

        # --- K8S-RBAC-025: New bindings since baseline ---
        current_subjects = {}
        for (sk_kind, sk_ns, sk_name), edges in self._rbac_graph.items():
            key = f"{sk_kind}:{sk_ns}:{sk_name}"
            current_subjects[key] = set(
                f"{e['binding']}→{e['role_key'][2]}" for e in edges
            )

        for subj_key, current_edges in current_subjects.items():
            old_edges = set(
                f"{e['binding']}→{e['role']}"
                for e in baseline_subjects.get(subj_key, [])
            )
            new_edges = current_edges - old_edges
            if new_edges:
                parts = subj_key.split(":", 2)
                sk_kind, sk_ns, sk_name = parts[0], parts[1], parts[2]
                self._add(Finding(
                    "K8S-RBAC-025",
                    "New RBAC binding since baseline (drift detected)",
                    "RBAC Drift", "HIGH",
                    self._res_path(sk_ns or None, sk_kind, sk_name),
                    None, f"new bindings: {', '.join(sorted(new_edges))}",
                    "Subject has new role bindings that did not exist in the saved baseline. "
                    "This may indicate unauthorized permission expansion.",
                    "Review new bindings. If authorized, update the baseline with --baseline-save.",
                    "CWE-269",
                ))

        # --- K8S-RBAC-026: Removed bindings since baseline ---
        for subj_key, old_data in baseline_subjects.items():
            old_edges = set(f"{e['binding']}→{e['role']}" for e in old_data)
            current_edges = current_subjects.get(subj_key, set())
            removed = old_edges - current_edges
            if removed and subj_key in current_subjects:
                parts = subj_key.split(":", 2)
                sk_kind, sk_ns, sk_name = parts[0], parts[1], parts[2]
                self._add(Finding(
                    "K8S-RBAC-026",
                    "RBAC binding removed since baseline (drift detected)",
                    "RBAC Drift", "LOW",
                    self._res_path(sk_ns or None, sk_kind, sk_name),
                    None, f"removed bindings: {', '.join(sorted(removed))}",
                    "Subject lost bindings compared to baseline. Verify this was intentional.",
                    "If intentional, update the baseline with --baseline-save.",
                ))

        # --- K8S-RBAC-027: Role permissions expanded since baseline ---
        for role_key_str, old_rules in baseline_roles.items():
            parts = role_key_str.split(":", 2)
            kind, ns, name = parts[0], parts[1] or None, parts[2]
            current_rules_raw = self._role_rules.get((kind, ns, name), [])
            current_verbs = set()
            current_resources = set()
            for rule in current_rules_raw:
                for v in (rule.verbs or []):
                    current_verbs.add(v)
                for r in (rule.resources or []):
                    current_resources.add(r)
            old_verbs = set()
            old_resources = set()
            for rule in old_rules:
                for v in rule.get("verbs", []):
                    old_verbs.add(v)
                for r in rule.get("resources", []):
                    old_resources.add(r)
            new_verbs = current_verbs - old_verbs
            new_resources = current_resources - old_resources
            if new_verbs or new_resources:
                detail_parts = []
                if new_verbs:
                    detail_parts.append(f"new verbs: {sorted(new_verbs)}")
                if new_resources:
                    detail_parts.append(f"new resources: {sorted(new_resources)}")
                self._add(Finding(
                    "K8S-RBAC-027",
                    "Role permissions expanded since baseline (drift detected)",
                    "RBAC Drift", "HIGH",
                    self._res_path(ns, kind, name),
                    None, "; ".join(detail_parts),
                    f"Role '{name}' has gained additional verbs or resources compared to the baseline. "
                    f"This may indicate unauthorized permission creep.",
                    "Review expanded permissions. If authorized, update the baseline.",
                    "CWE-269",
                ))

        gen = baseline.get("generated", "unknown")
        print(f"[*] Baseline comparison complete (baseline from: {gen})")

    # ===================================================================
    # CHECK GROUP 18: Supply Chain & Image Security (v1.4.0)
    # K8S-SC-001 to SC-010
    # ===================================================================
    def _check_supply_chain(self):
        self._vprint("  [*] Checking supply chain & image security ...")

        # --- Discover tool availability ---
        trivy_bin = self.trivy_path or shutil.which("trivy")
        grype_bin = shutil.which("grype")
        cosign_bin = shutil.which("cosign")
        syft_bin = shutil.which("syft")

        has_trivy = trivy_bin is not None
        has_grype = grype_bin is not None
        has_cosign = cosign_bin is not None
        has_syft = syft_bin is not None

        self._vprint(f"    trivy={has_trivy}  grype={has_grype}  cosign={has_cosign}  syft={has_syft}")

        # K8S-SC-001: No vulnerability scanner available
        if not has_trivy and not has_grype:
            self._add(Finding(
                "K8S-SC-001", "No image vulnerability scanner available",
                "Supply Chain Security", "MEDIUM",
                "cluster/ToolChain/scanner-host", None,
                "trivy: not found, grype: not found",
                "Neither Trivy nor Grype is installed on the scanner host. "
                "Image CVE scanning cannot be performed.",
                "Install Trivy (https://trivy.dev) or Grype (https://github.com/anchore/grype) "
                "for automated image vulnerability scanning.",
            ))

        # K8S-SC-002: No signature verifier available
        if not has_cosign:
            self._add(Finding(
                "K8S-SC-002", "No image signature verifier available",
                "Supply Chain Security", "LOW",
                "cluster/ToolChain/scanner-host", None,
                "cosign: not found",
                "Cosign is not installed. Image signature verification cannot be performed.",
                "Install cosign (https://docs.sigstore.dev/cosign) for image provenance verification.",
            ))

        # K8S-SC-003: No SBOM generator available
        if not has_trivy and not has_syft:
            self._add(Finding(
                "K8S-SC-003", "No SBOM generator available",
                "Supply Chain Security", "LOW",
                "cluster/ToolChain/scanner-host", None,
                "trivy: not found, syft: not found",
                "Neither Trivy nor Syft is installed. SBOM generation is unavailable.",
                "Install Trivy or Syft (https://github.com/anchore/syft) for SBOM generation.",
            ))

        # --- Collect unique images from all workloads ---
        namespaces = self._get_namespaces()
        image_map = {}  # image_ref -> list of (ns, kind, name) using it

        for ns in namespaces:
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

            for kind, wl_name, wl_ns, pod_spec in workloads:
                if not pod_spec:
                    continue
                all_ctrs = list(pod_spec.containers or []) + list(pod_spec.init_containers or [])
                for ctr in all_ctrs:
                    img = ctr.image or ""
                    if img:
                        image_map.setdefault(img, []).append((wl_ns, kind, wl_name))

        unique_images = set(image_map.keys())
        self._vprint(f"    Unique images found: {len(unique_images)}")

        # --- K8S-SC-004: Insecure / EOL base image ---
        for image_ref in sorted(unique_images):
            img_no_digest = image_ref.split("@")[0]
            # Try exact match first, then prefix match
            for pattern, reason in INSECURE_BASE_IMAGES.items():
                # Match "python:2" against "python:2", "python:2-slim", etc.
                if img_no_digest == pattern or img_no_digest.startswith(pattern + "-"):
                    loc = image_map[image_ref][0]
                    res_path = self._res_path(loc[0], loc[1], loc[2])
                    workload_count = len(image_map[image_ref])
                    count_note = f" (used by {workload_count} workloads)" if workload_count > 1 else ""
                    self._add(Finding(
                        "K8S-SC-004", "Insecure/EOL base image detected",
                        "Supply Chain Security", "HIGH",
                        res_path, None,
                        f"image: {image_ref}{count_note}",
                        f"{reason}. Running EOL images means no security patches, "
                        f"leaving known vulnerabilities unpatched.",
                        "Upgrade to a supported base image version with active security updates.",
                        "CWE-1104",
                    ))
                    break

        # --- K8S-SC-005: Registry allow-list enforcement ---
        if self.trusted_registries:
            all_trusted = TRUSTED_REGISTRIES | self.trusted_registries
            for image_ref in sorted(unique_images):
                img_no_digest = image_ref.split("@")[0]
                img_no_tag = img_no_digest.split(":")[0]
                if "/" in img_no_tag:
                    registry = img_no_tag.split("/")[0]
                else:
                    registry = "docker.io"
                if registry and "." in registry and registry not in all_trusted:
                    loc = image_map[image_ref][0]
                    res_path = self._res_path(loc[0], loc[1], loc[2])
                    self._add(Finding(
                        "K8S-SC-005", "Image from untrusted registry (allow-list)",
                        "Supply Chain Security", "HIGH",
                        res_path, None,
                        f"registry: {registry} | image: {image_ref}",
                        f"Image pulled from '{registry}' which is not in the configured "
                        f"trusted registry allow-list.",
                        "Use images from approved registries or update the --trusted-registries list.",
                        "CWE-829",
                    ))

        # --- K8S-SC-006: Image vulnerability scanning (Trivy/Grype) ---
        scanned_images = set()
        vuln_scanner_bin = trivy_bin or grype_bin
        vuln_scanner_name = "trivy" if trivy_bin else "grype"

        if vuln_scanner_bin and unique_images:
            # Limit scanning to avoid long runtimes
            scan_limit = 20
            images_to_scan = sorted(unique_images)[:scan_limit]
            if len(unique_images) > scan_limit:
                self._vprint(f"    Limiting CVE scan to first {scan_limit} of {len(unique_images)} images")

            for image_ref in images_to_scan:
                try:
                    if trivy_bin:
                        cmd = [trivy_bin, "image", "--severity",
                               "CRITICAL,HIGH", "--format", "json",
                               "--quiet", "--timeout", "120s", image_ref]
                    else:
                        cmd = [grype_bin, image_ref, "-o", "json",
                               "--only-fixed", "--fail-on", "low"]

                    self._vprint(f"    Scanning: {image_ref}")
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=180,
                    )
                    scanned_images.add(image_ref)

                    if result.returncode != 0 and not result.stdout:
                        self._vprint(f"    [!] {vuln_scanner_name} error for {image_ref}: "
                                     f"{result.stderr[:200]}")
                        continue

                    vuln_data = json.loads(result.stdout) if result.stdout.strip() else {}
                    vulns = self._extract_vulns(vuln_data, vuln_scanner_name)

                    if vulns:
                        critical_count = sum(1 for v in vulns if v["severity"] == "CRITICAL")
                        high_count = sum(1 for v in vulns if v["severity"] == "HIGH")
                        cve_list = [v["id"] for v in vulns[:10]]
                        cve_str = ", ".join(cve_list)
                        if len(vulns) > 10:
                            cve_str += f" ... +{len(vulns) - 10} more"

                        loc = image_map[image_ref][0]
                        res_path = self._res_path(loc[0], loc[1], loc[2])

                        if critical_count > 0:
                            self._add(Finding(
                                "K8S-SC-006",
                                "Critical vulnerabilities in container image",
                                "Supply Chain Security", "CRITICAL",
                                res_path, None,
                                f"image: {image_ref} | critical={critical_count} high={high_count}",
                                f"Image contains {critical_count} CRITICAL and {high_count} HIGH "
                                f"vulnerabilities. CVEs: {cve_str}",
                                "Update the base image and packages to patch known CVEs. "
                                "Rebuild and redeploy the image.",
                                "CWE-1395",
                            ))
                        elif high_count > 0:
                            self._add(Finding(
                                "K8S-SC-007",
                                "High vulnerabilities in container image",
                                "Supply Chain Security", "HIGH",
                                res_path, None,
                                f"image: {image_ref} | high={high_count}",
                                f"Image contains {high_count} HIGH vulnerabilities. CVEs: {cve_str}",
                                "Update the base image and packages to patch known CVEs.",
                                "CWE-1395",
                            ))
                except subprocess.TimeoutExpired:
                    self._vprint(f"    [!] Timeout scanning {image_ref}")
                except (json.JSONDecodeError, OSError) as exc:
                    self._vprint(f"    [!] Error scanning {image_ref}: {exc}")

        # --- K8S-SC-008: Image signature verification (cosign) ---
        if has_cosign and unique_images:
            unsigned_count = 0
            unsigned_examples = []
            scan_limit = 20
            images_to_verify = sorted(unique_images)[:scan_limit]

            for image_ref in images_to_verify:
                try:
                    result = subprocess.run(
                        [cosign_bin, "verify", "--certificate-identity-regexp", ".*",
                         "--certificate-oidc-issuer-regexp", ".*", image_ref],
                        capture_output=True, text=True, timeout=30,
                    )
                    if result.returncode != 0:
                        unsigned_count += 1
                        if len(unsigned_examples) < 5:
                            unsigned_examples.append(image_ref)
                except (subprocess.TimeoutExpired, OSError):
                    pass

            if unsigned_count > 0:
                examples = ", ".join(unsigned_examples)
                if unsigned_count > 5:
                    examples += f" ... +{unsigned_count - 5} more"
                self._add(Finding(
                    "K8S-SC-008", "Container images without signatures",
                    "Supply Chain Security", "MEDIUM",
                    "cluster/Images/unsigned", None,
                    f"unsigned: {unsigned_count}/{len(images_to_verify)} | examples: {examples}",
                    f"{unsigned_count} of {len(images_to_verify)} scanned images have no "
                    f"verifiable cosign signature. Image provenance cannot be validated.",
                    "Sign container images with cosign during CI/CD and enforce signature "
                    "verification via admission controllers (e.g., Kyverno, OPA/Gatekeeper).",
                    "CWE-345",
                ))

        # --- K8S-SC-009: SBOM availability check ---
        if (has_trivy or has_syft) and unique_images:
            sbom_tool = trivy_bin if has_trivy else syft_bin
            sbom_tool_name = "trivy" if has_trivy else "syft"
            sample_image = sorted(unique_images)[0]
            try:
                if sbom_tool_name == "trivy":
                    cmd = [sbom_tool, "image", "--format", "cyclonedx",
                           "--quiet", "--timeout", "120s", sample_image]
                else:
                    cmd = [sbom_tool, sample_image, "-o", "cyclonedx-json"]

                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=180,
                )
                if result.returncode == 0 and result.stdout.strip():
                    sbom_data = json.loads(result.stdout)
                    comp_count = len(sbom_data.get("components", []))
                    self._vprint(f"    SBOM for {sample_image}: {comp_count} components")
                else:
                    self._vprint(f"    [!] SBOM generation failed for {sample_image}")
            except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
                self._vprint(f"    [!] SBOM generation error: {exc}")

        # --- K8S-SC-010: No admission policy enforcing image verification ---
        has_image_policy = False
        try:
            vwhs = self.admreg_v1.list_validating_webhook_configuration().items
            for wh in vwhs:
                wh_name = (wh.metadata.name or "").lower()
                if any(kw in wh_name for kw in (
                    "cosign", "sigstore", "notary", "connaisseur",
                    "kyverno", "gatekeeper", "image-policy",
                    "image-verification",
                )):
                    has_image_policy = True
                    break
        except ApiException:
            pass

        if not has_image_policy:
            try:
                mwhs = self.admreg_v1.list_mutating_webhook_configuration().items
                for wh in mwhs:
                    wh_name = (wh.metadata.name or "").lower()
                    if any(kw in wh_name for kw in (
                        "cosign", "sigstore", "notary", "connaisseur",
                        "kyverno", "image-policy", "image-verification",
                    )):
                        has_image_policy = True
                        break
            except ApiException:
                pass

        if not has_image_policy:
            self._add(Finding(
                "K8S-SC-010",
                "No admission policy enforcing image signature verification",
                "Supply Chain Security", "HIGH",
                "cluster/AdmissionControl/image-policy", None,
                "ValidatingWebhookConfiguration / MutatingWebhookConfiguration: "
                "no image verification webhook found",
                "No admission controller is configured to enforce image signature verification. "
                "Unsigned or tampered images can be deployed without restriction.",
                "Deploy an image verification admission controller such as Kyverno "
                "(verifyImages), OPA/Gatekeeper with cosign, or Connaisseur.",
                "CWE-345",
            ))

    def _extract_vulns(self, data: dict, scanner: str) -> list:
        """Extract vulnerability list from Trivy or Grype JSON output."""
        vulns = []
        if scanner == "trivy":
            for result in data.get("Results", []):
                for v in result.get("Vulnerabilities", []):
                    vulns.append({
                        "id": v.get("VulnerabilityID", ""),
                        "severity": v.get("Severity", "UNKNOWN").upper(),
                        "pkg": v.get("PkgName", ""),
                        "installed": v.get("InstalledVersion", ""),
                        "fixed": v.get("FixedVersion", ""),
                    })
        elif scanner == "grype":
            for match in data.get("matches", []):
                vuln = match.get("vulnerability", {})
                vulns.append({
                    "id": vuln.get("id", ""),
                    "severity": vuln.get("severity", "UNKNOWN").upper(),
                    "pkg": match.get("artifact", {}).get("name", ""),
                    "installed": match.get("artifact", {}).get("version", ""),
                    "fixed": vuln.get("fix", {}).get("versions", [""])[0]
                        if vuln.get("fix", {}).get("versions") else "",
                })
        return vulns

    # ===================================================================
    # CHECK GROUP 19: Kyverno Policy Validation (v2.0.0)
    # K8S-KYV-001 to KYV-006
    # ===================================================================
    def _check_kyverno_policies(self):
        self._vprint("  [*] Checking Kyverno policy configuration ...")

        # Detect if Kyverno is installed
        kyverno_policies = []
        cluster_policies = []
        try:
            kyverno_policies = self.custom_api.list_namespaced_custom_object(
                "kyverno.io", "v1", "default", "policies",
            ).get("items", [])
        except Exception:
            pass
        try:
            cluster_policies = self.custom_api.list_cluster_custom_object(
                "kyverno.io", "v1", "clusterpolicies",
            ).get("items", [])
        except Exception:
            pass

        all_policies = kyverno_policies + cluster_policies
        if not all_policies:
            self._vprint("    Kyverno not detected or no policies found.")
            return

        self._vprint(f"    Found {len(all_policies)} Kyverno policies")

        for pol in all_policies:
            metadata = pol.get("metadata", {})
            pol_name = metadata.get("name", "unknown")
            pol_ns = metadata.get("namespace")
            spec = pol.get("spec", {})
            kind = "ClusterPolicy" if not pol_ns else "Policy"
            res_path = self._res_path(pol_ns, kind, pol_name)

            # K8S-KYV-001: Policy in audit mode (not enforce)
            validation_failure = spec.get("validationFailureAction", "Audit")
            if validation_failure.lower() == "audit":
                self._add(Finding(
                    "K8S-KYV-001", "Kyverno policy in Audit mode",
                    "Policy Engine", "MEDIUM", res_path, None,
                    f"validationFailureAction: {validation_failure}",
                    "Policy is in Audit mode — violations are logged but not blocked. "
                    "This means non-compliant resources can still be created.",
                    "Set validationFailureAction to 'Enforce' for production clusters.",
                ))

            # K8S-KYV-002: Policy with no rules
            rules = spec.get("rules", [])
            if not rules:
                self._add(Finding(
                    "K8S-KYV-002", "Kyverno policy with no rules",
                    "Policy Engine", "LOW", res_path, None,
                    "rules: []",
                    "Policy has no rules defined. It has no effect on the cluster.",
                    "Add rules to the policy or remove the empty policy.",
                ))
                continue

            for rule in rules:
                rule_name = rule.get("name", "unnamed")

                # K8S-KYV-003: Rule with overly broad match (all resources)
                match = rule.get("match", {})
                any_match = match.get("any", match.get("resources", {}))
                if isinstance(any_match, dict):
                    kinds = any_match.get("kinds", [])
                    if "*" in kinds or "Pod" in kinds and len(kinds) == 1:
                        pass  # normal
                elif isinstance(any_match, list):
                    for m in any_match:
                        res = m.get("resources", {})
                        kinds = res.get("kinds", [])
                        if "*" in kinds:
                            self._add(Finding(
                                "K8S-KYV-003",
                                "Kyverno rule matches all resource kinds",
                                "Policy Engine", "MEDIUM", res_path, None,
                                f"rule: {rule_name} | match.kinds: [*]",
                                "Rule applies to all resource kinds which may cause "
                                "excessive webhook load and unexpected denials.",
                                "Scope the rule to specific resource kinds.",
                            ))

                # K8S-KYV-004: Exclude that bypasses important namespaces
                exclude = rule.get("exclude", {})
                exclude_ns = []
                if isinstance(exclude, dict):
                    exc_res = exclude.get("resources", exclude.get("any", []))
                    if isinstance(exc_res, dict):
                        exclude_ns = exc_res.get("namespaces", [])
                    elif isinstance(exc_res, list):
                        for e in exc_res:
                            exclude_ns.extend(e.get("resources", {}).get("namespaces", []))
                if any(ns not in ("kube-system", "kube-public", "kube-node-lease")
                       for ns in exclude_ns if ns != "*"):
                    excluded = ", ".join(exclude_ns)
                    self._add(Finding(
                        "K8S-KYV-004",
                        "Kyverno rule excludes non-system namespaces",
                        "Policy Engine", "MEDIUM", res_path, None,
                        f"rule: {rule_name} | exclude.namespaces: [{excluded}]",
                        "Rule exclusion covers non-system namespaces, reducing policy coverage.",
                        "Review excluded namespaces. Only exclude system namespaces.",
                    ))

            # K8S-KYV-005: Background scanning disabled
            if spec.get("background") is False:
                self._add(Finding(
                    "K8S-KYV-005", "Kyverno background scanning disabled",
                    "Policy Engine", "LOW", res_path, None,
                    "background: false",
                    "Background scanning is disabled. Existing non-compliant resources "
                    "will not be detected in policy reports.",
                    "Enable background scanning (background: true) for compliance visibility.",
                ))

        # K8S-KYV-006: No Kyverno policies in enforce mode
        enforce_count = sum(
            1 for p in all_policies
            if p.get("spec", {}).get("validationFailureAction", "").lower() == "enforce"
        )
        if enforce_count == 0 and len(all_policies) > 0:
            self._add(Finding(
                "K8S-KYV-006", "No Kyverno policies in Enforce mode",
                "Policy Engine", "HIGH",
                "cluster/Kyverno/policies", None,
                f"total policies: {len(all_policies)}, enforce mode: 0",
                "All Kyverno policies are in Audit mode. No policy is actively "
                "blocking non-compliant resources.",
                "Set validationFailureAction to 'Enforce' on critical policies.",
            ))

    # ===================================================================
    # Custom Policy DSL Engine (v2.0.0)
    # Loads YAML policy files and evaluates them against cluster resources
    # ===================================================================
    def _run_custom_policies(self):
        if not self.policy_dir:
            return
        if not HAS_YAML:
            self._warn("PyYAML not installed. Custom policies require: pip install pyyaml")
            return
        policy_path = Path(self.policy_dir)
        if not policy_path.is_dir():
            self._warn(f"Policy directory not found: {self.policy_dir}")
            return

        policy_files = list(policy_path.glob("*.yaml")) + list(policy_path.glob("*.yml"))
        if not policy_files:
            self._vprint(f"    No policy files found in {self.policy_dir}")
            return

        self._vprint(f"  [*] Running {len(policy_files)} custom policies ...")

        for pf in sorted(policy_files):
            try:
                with open(pf, "r", encoding="utf-8") as fh:
                    docs = list(_yaml.safe_load_all(fh))
                for doc in docs:
                    if not doc or not isinstance(doc, dict):
                        continue
                    self._evaluate_custom_policy(doc, str(pf))
            except Exception as exc:
                self._warn(f"Error loading policy {pf.name}: {exc}")

    def _evaluate_custom_policy(self, policy: dict, source_file: str):
        """Evaluate a single custom YAML policy against cluster resources.

        Policy format:
            rule_id: K8S-CUSTOM-001
            name: "My custom check"
            category: "Custom Policies"
            severity: HIGH
            description: "What this checks"
            recommendation: "How to fix"
            cwe: CWE-xxx  (optional)
            target:
                api_group: apps/v1       # or v1 for core
                resource: deployments    # plural lowercase
                namespaced: true
            match:
                field: spec.template.spec.containers[*].securityContext.runAsNonRoot
                operator: equals|not_equals|exists|not_exists|contains|regex|gt|lt
                value: true              # expected value
        """
        rule_id = policy.get("rule_id")
        name = policy.get("name")
        severity = policy.get("severity", "MEDIUM")
        description = policy.get("description", "")
        recommendation = policy.get("recommendation", "")
        category = policy.get("category", "Custom Policies")
        cwe = policy.get("cwe")
        target = policy.get("target", {})
        match_spec = policy.get("match", {})

        if not rule_id or not name or not target:
            self._vprint(f"    Skipping incomplete policy in {source_file}")
            return

        api_group = target.get("api_group", "v1")
        resource = target.get("resource", "")
        namespaced = target.get("namespaced", True)

        # Fetch resources from the cluster
        try:
            if namespaced:
                namespaces = self._get_namespaces()
                items = []
                for ns in namespaces:
                    try:
                        if "/" in api_group:
                            group, version = api_group.rsplit("/", 1)
                            result = self.custom_api.list_namespaced_custom_object(
                                group, version, ns, resource,
                            )
                        elif api_group == "v1":
                            result = self.core_v1.api_client.call_api(
                                f"/api/v1/namespaces/{ns}/{resource}",
                                "GET", response_type="object",
                                _return_http_data_only=True,
                            )
                        else:
                            result = self.custom_api.list_namespaced_custom_object(
                                api_group.split("/")[0] if "/" in api_group else "",
                                api_group, ns, resource,
                            )
                        for item in result.get("items", []):
                            item["_namespace"] = ns
                            items.append(item)
                    except Exception:
                        pass
            else:
                try:
                    if "/" in api_group:
                        group, version = api_group.rsplit("/", 1)
                        result = self.custom_api.list_cluster_custom_object(
                            group, version, resource,
                        )
                    else:
                        result = self.core_v1.api_client.call_api(
                            f"/api/{api_group}/{resource}",
                            "GET", response_type="object",
                            _return_http_data_only=True,
                        )
                    items = result.get("items", [])
                except Exception:
                    items = []
        except Exception:
            items = []

        if not items:
            self._vprint(f"    {rule_id}: no {resource} found")
            return

        field_path = match_spec.get("field", "")
        operator = match_spec.get("operator", "equals")
        expected = match_spec.get("value")

        for item in items:
            item_name = item.get("metadata", {}).get("name", "unknown")
            item_ns = item.get("_namespace", item.get("metadata", {}).get("namespace"))
            res_path = self._res_path(item_ns, resource, item_name)

            actual = self._resolve_field(item, field_path)

            violated = self._check_operator(actual, operator, expected)
            if violated:
                detail = f"{field_path}: {actual}" if actual is not None else f"{field_path}: <not set>"
                self._add(Finding(
                    rule_id, name, category, severity,
                    res_path, None, detail,
                    description, recommendation, cwe,
                ))

    def _resolve_field(self, obj, field_path: str):
        """Resolve a dotted field path with [*] array wildcard support."""
        if not field_path:
            return obj
        parts = field_path.replace("[*]", ".[*]").split(".")
        current = [obj]
        for part in parts:
            if not part:
                continue
            next_items = []
            for item in current:
                if part == "[*]":
                    if isinstance(item, list):
                        next_items.extend(item)
                elif isinstance(item, dict):
                    val = item.get(part)
                    if val is not None:
                        if isinstance(val, list) and "[*]" not in field_path:
                            next_items.append(val)
                        elif isinstance(val, list):
                            next_items.append(val)
                        else:
                            next_items.append(val)
            current = next_items
            if not current:
                return None
        return current[0] if len(current) == 1 else current if current else None

    @staticmethod
    def _check_operator(actual, operator: str, expected) -> bool:
        """Return True if the condition indicates a violation."""
        if operator == "equals":
            return actual != expected
        elif operator == "not_equals":
            return actual == expected
        elif operator == "exists":
            return actual is None
        elif operator == "not_exists":
            return actual is not None
        elif operator == "contains":
            if isinstance(actual, (list, str)):
                return expected not in actual
            return True
        elif operator == "not_contains":
            if isinstance(actual, (list, str)):
                return expected in actual
            return False
        elif operator == "regex":
            if isinstance(actual, str) and expected:
                return not re.search(str(expected), actual)
            return True
        elif operator == "gt":
            try:
                return float(actual) <= float(expected)
            except (TypeError, ValueError):
                return True
        elif operator == "lt":
            try:
                return float(actual) >= float(expected)
            except (TypeError, ValueError):
                return True
        return False

    # ===================================================================
    # OPA / Rego Policy Evaluation (v2.0.0)
    # ===================================================================
    def _run_rego_policies(self):
        if not self.rego_dir:
            return
        rego_path = Path(self.rego_dir)
        if not rego_path.is_dir():
            self._warn(f"Rego directory not found: {self.rego_dir}")
            return

        opa_bin = shutil.which("opa")
        if not opa_bin:
            self._warn("OPA binary not found. Install OPA: https://www.openpolicyagent.org/docs/latest/#1-download-opa")
            self._add(Finding(
                "K8S-OPA-001", "OPA binary not available",
                "Policy Engine", "LOW",
                "cluster/ToolChain/scanner-host", None,
                "opa: not found",
                "The OPA binary is not installed. Rego policy evaluation is unavailable.",
                "Install OPA (https://www.openpolicyagent.org) for custom Rego policy evaluation.",
            ))
            return

        rego_files = list(rego_path.glob("*.rego"))
        if not rego_files:
            self._vprint(f"    No .rego files found in {self.rego_dir}")
            return

        self._vprint(f"  [*] Running {len(rego_files)} Rego policies ...")

        # Collect cluster data as JSON input
        input_data = self._collect_rego_input()
        import tempfile
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False, encoding="utf-8"
        ) as tmp:
            json.dump(input_data, tmp)
            input_file = tmp.name

        try:
            for rf in sorted(rego_files):
                try:
                    cmd = [
                        opa_bin, "eval",
                        "--input", input_file,
                        "--data", str(rf),
                        "--format", "json",
                        "data.kspm.deny",
                    ]
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=30,
                    )
                    if result.returncode != 0:
                        self._vprint(f"    [!] OPA error for {rf.name}: {result.stderr[:200]}")
                        continue

                    output = json.loads(result.stdout) if result.stdout.strip() else {}
                    results = output.get("result", [])
                    for res in results:
                        expressions = res.get("expressions", [])
                        for expr in expressions:
                            denials = expr.get("value", [])
                            if isinstance(denials, list):
                                for denial in denials:
                                    if isinstance(denial, dict):
                                        self._add(Finding(
                                            denial.get("rule_id", f"K8S-REGO-{rf.stem[:8].upper()}"),
                                            denial.get("name", rf.stem),
                                            denial.get("category", "Rego Policy"),
                                            denial.get("severity", "MEDIUM"),
                                            denial.get("resource", "cluster/Rego/" + rf.name),
                                            None,
                                            denial.get("detail", ""),
                                            denial.get("description", "Rego policy violation"),
                                            denial.get("recommendation", "Review the Rego policy"),
                                            denial.get("cwe"),
                                        ))
                                    elif isinstance(denial, str):
                                        self._add(Finding(
                                            f"K8S-REGO-{rf.stem[:8].upper()}",
                                            rf.stem, "Rego Policy", "MEDIUM",
                                            "cluster/Rego/" + rf.name, None,
                                            denial, denial,
                                            "Review and remediate the Rego policy violation.",
                                        ))
                except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
                    self._vprint(f"    [!] Error running {rf.name}: {exc}")
        finally:
            os.unlink(input_file)

    def _collect_rego_input(self) -> dict:
        """Collect key cluster resources as JSON for Rego policy evaluation."""
        data = {"namespaces": [], "deployments": [], "services": [],
                "pods": [], "cluster_roles": [], "cluster_role_bindings": []}
        try:
            for ns in self.core_v1.list_namespace().items:
                data["namespaces"].append({
                    "name": ns.metadata.name,
                    "labels": ns.metadata.labels or {},
                    "annotations": ns.metadata.annotations or {},
                })
        except Exception:
            pass
        try:
            for dep in self.apps_v1.list_deployment_for_all_namespaces().items:
                data["deployments"].append({
                    "name": dep.metadata.name,
                    "namespace": dep.metadata.namespace,
                    "replicas": dep.spec.replicas,
                    "labels": dep.metadata.labels or {},
                    "annotations": dep.metadata.annotations or {},
                })
        except Exception:
            pass
        try:
            for cr in self.rbac_v1.list_cluster_role().items:
                rules_data = []
                for rule in (cr.rules or []):
                    rules_data.append({
                        "verbs": rule.verbs or [],
                        "resources": rule.resources or [],
                        "api_groups": rule.api_groups or [],
                    })
                data["cluster_roles"].append({
                    "name": cr.metadata.name,
                    "rules": rules_data,
                })
        except Exception:
            pass
        return data

    # ===================================================================
    # Exception Management (v2.0.0)
    # ===================================================================
    @staticmethod
    def _load_exceptions(exceptions_file):
        """Load exception rules from a JSON or YAML file.

        Format:
            exceptions:
              - rule_id: K8S-POD-001
                resource: "default/Deployment/test-app"
                reason: "Accepted risk for dev workload"
              - rule_id: K8S-IMG-001
                reason: "Latest tag allowed for internal images"
              - resource: "kube-system/*"
                reason: "System namespace excluded"
        """
        if not exceptions_file:
            return []
        try:
            with open(exceptions_file, "r", encoding="utf-8") as fh:
                content = fh.read()
            if exceptions_file.endswith((".yaml", ".yml")):
                if not HAS_YAML:
                    print("[!] PyYAML required for YAML exceptions: pip install pyyaml",
                          file=sys.stderr)
                    return []
                data = _yaml.safe_load(content)
            else:
                data = json.loads(content)
            return data.get("exceptions", []) if isinstance(data, dict) else []
        except Exception as exc:
            print(f"[!] Failed to load exceptions file: {exc}", file=sys.stderr)
            return []

    def _apply_exceptions(self):
        """Remove findings that match exception rules."""
        if not self.exceptions:
            return
        original_count = len(self.findings)
        filtered = []
        for f in self.findings:
            excepted = False
            for exc in self.exceptions:
                exc_rule = exc.get("rule_id", "")
                exc_resource = exc.get("resource", "")
                # Match rule_id (exact or glob)
                rule_match = (not exc_rule or
                              f.rule_id == exc_rule or
                              fnmatch.fnmatch(f.rule_id, exc_rule))
                # Match resource (exact or glob)
                resource_match = (not exc_resource or
                                  f.file_path == exc_resource or
                                  fnmatch.fnmatch(f.file_path, exc_resource))
                if rule_match and resource_match and (exc_rule or exc_resource):
                    excepted = True
                    break
            if not excepted:
                filtered.append(f)
        self.findings = filtered
        suppressed = original_count - len(self.findings)
        if suppressed > 0:
            self._vprint(f"  [*] Exceptions applied: {suppressed} findings suppressed")

    # ===================================================================
    # Baseline Profile Application (v2.0.0)
    # ===================================================================
    def _apply_profile(self):
        """Apply a baseline profile to suppress rules and adjust severity threshold."""
        profile_cfg = BASELINE_PROFILES.get(self.profile)
        if not profile_cfg:
            return
        self._vprint(f"  [*] Applying profile: {self.profile} — {profile_cfg['description']}")
        suppress = profile_cfg.get("suppress_rules", set())
        if suppress:
            original = len(self.findings)
            self.findings = [f for f in self.findings if f.rule_id not in suppress]
            suppressed = original - len(self.findings)
            if suppressed > 0:
                self._vprint(f"    Profile suppressed {suppressed} findings")

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
            refs = self._compliance_refs(f.rule_id)
            refs_str = ""
            if refs:
                tags = ", ".join(f"{k}: {v}" for k, v in refs.items())
                refs_str = f"  Compliance: {tags}\n"
            cwe_str = f"  CWE      : {f.cwe}\n" if f.cwe else ""
            print(f"{c}{B}[{f.severity}]{R}  {f.rule_id}  {f.name}")
            print(f"  Resource : {f.file_path}")
            print(f"  Detail   : {f.line_content}")
            print(f"{refs_str}{cwe_str}"
                  f"  Issue    : {f.description}\n"
                  f"  Fix      : {f.recommendation}\n")

        counts = self.summary()
        print(f"{B}{'=' * 76}{R}")
        print(f"{B}  SEVERITY SUMMARY{R}")
        print("=" * 76)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            c = self.SEVERITY_COLOR.get(sev, "")
            print(f"  {c}{sev:<10}{R}  {counts.get(sev, 0)}")
        print("=" * 76)

        # Compliance framework summary
        comp = self.compliance_summary()
        print(f"\n{B}{'=' * 76}{R}")
        print(f"{B}  COMPLIANCE FRAMEWORK COVERAGE{R}")
        print("=" * 76)
        print(f"  {'Framework':<30} {'Controls':<10} {'Findings':<10} {'Clean':<8} {'Coverage'}")
        print(f"  {'-' * 72}")
        for name, stats in comp.items():
            print(f"  {name:<30} {stats['total_controls']:<10} "
                  f"{stats['findings_triggered']:<10} {stats['rules_clean']:<8} "
                  f"{stats['coverage_pct']}%")
        print("=" * 76)

    def save_json(self, path: str):
        findings_with_compliance = []
        for f in self.findings:
            fd = f.to_dict()
            refs = self._compliance_refs(f.rule_id)
            if refs:
                fd["compliance"] = refs
            findings_with_compliance.append(fd)

        report = {
            "scanner": "kspm_scanner",
            "version": VERSION,
            "generated": datetime.now(timezone.utc).isoformat(),
            "cluster": self.cluster_name,
            "findings_count": len(self.findings),
            "summary": self.summary(),
            "compliance_summary": self.compliance_summary(),
            "findings": findings_with_compliance,
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

        # Compliance dashboard cards
        comp = self.compliance_summary()
        comp_cards = ""
        fw_colors = {
            "CIS Kubernetes Benchmark": "#326ce5",
            "NSA/CISA Hardening Guide": "#2ecc71",
            "MITRE ATT&CK Containers": "#e74c3c",
            "SOC 2 Trust Services": "#9b59b6",
            "PCI-DSS v4.0": "#f39c12",
            "NIST SP 800-190": "#1abc9c",
        }
        for name, stats in comp.items():
            clr = fw_colors.get(name, "#89b4fa")
            pct = stats["coverage_pct"]
            bar_w = min(pct, 100)
            comp_cards += (
                f'<div style="background:#1e1e2e;border:1px solid #313244;border-radius:10px;'
                f'padding:16px 20px;min-width:220px;flex:1">'
                f'<div style="font-weight:700;color:{clr};font-size:0.95em;margin-bottom:8px">'
                f'{esc(name)}</div>'
                f'<div style="display:flex;justify-content:space-between;font-size:0.85em;'
                f'color:#a6adc8;margin-bottom:4px">'
                f'<span>Controls: {stats["total_controls"]}</span>'
                f'<span>Findings: {stats["findings_triggered"]}</span></div>'
                f'<div style="background:#313244;border-radius:6px;height:8px;overflow:hidden;'
                f'margin-bottom:6px">'
                f'<div style="background:{clr};height:100%;width:{bar_w}%;border-radius:6px"></div></div>'
                f'<div style="text-align:right;font-size:0.8em;color:#585b70">'
                f'{pct}% rules triggered</div></div>'
            )

        # Table rows
        rows = ""
        for i, f in enumerate(sorted_findings):
            bg = "#1e1e2e" if i % 2 == 0 else "#252535"
            rb = row_border.get(f.severity, "")
            sb = sev_badge.get(f.severity, "")
            refs = self._compliance_refs(f.rule_id)
            ref_tags = ""
            if refs:
                for fw, ref in refs.items():
                    ref_tags += (f' <span style="background:#313244;color:#89b4fa;'
                                 f'padding:1px 6px;border-radius:4px;font-size:0.78em;'
                                 f'margin-left:3px">{esc(fw)}: {esc(ref)}</span>')
            comp_line = (f'<div style="margin-top:4px">{ref_tags}</div>'
                         if ref_tags else "")
            rows += (
                f'<tr style="background:{bg};{rb}" '
                f'data-severity="{esc(f.severity)}" data-category="{esc(f.category)}">'
                f'<td style="padding:10px 14px;text-align:center">'
                f'<span style="{sb};padding:3px 10px;border-radius:8px;font-weight:bold;'
                f'font-size:0.85em">{esc(f.severity)}</span></td>'
                f'<td style="padding:10px 8px;color:#f9e2af;font-family:monospace">'
                f'{esc(f.rule_id)}</td>'
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
                f'{comp_line}'
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
<div style="padding:20px 36px;background:#181825">
<div style="font-weight:700;color:#89b4fa;font-size:1.05em;margin-bottom:14px">
Compliance Framework Coverage</div>
<div style="display:flex;flex-wrap:wrap;gap:14px">
{comp_cards}
</div>
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

    # ===================================================================
    # SARIF Output (v1.5.0) — Static Analysis Results Interchange Format
    # ===================================================================
    def save_sarif(self, path: str):
        """Export findings in SARIF v2.1.0 format for GitHub Security tab."""
        rules_seen = {}
        results = []
        for f in self.findings:
            if f.rule_id not in rules_seen:
                refs = self._compliance_refs(f.rule_id)
                help_text = f"{f.description}\n\nRemediation: {f.recommendation}"
                if refs:
                    help_text += "\n\nCompliance: " + ", ".join(
                        f"{k}: {v}" for k, v in refs.items()
                    )
                rule_def = {
                    "id": f.rule_id,
                    "name": re.sub(r'[^A-Za-z0-9]', '', f.name.title()),
                    "shortDescription": {"text": f.name},
                    "fullDescription": {"text": f.description},
                    "help": {"text": help_text, "markdown": help_text},
                    "defaultConfiguration": {
                        "level": {
                            "CRITICAL": "error",
                            "HIGH": "error",
                            "MEDIUM": "warning",
                            "LOW": "note",
                        }.get(f.severity, "note"),
                    },
                    "properties": {"tags": [f.category]},
                }
                if f.cwe:
                    cwe_num = re.search(r'\d+', f.cwe)
                    if cwe_num:
                        rule_def["properties"]["tags"].append(f"external/cwe/cwe-{cwe_num.group()}")
                rules_seen[f.rule_id] = rule_def

            result = {
                "ruleId": f.rule_id,
                "level": {
                    "CRITICAL": "error", "HIGH": "error",
                    "MEDIUM": "warning", "LOW": "note",
                }.get(f.severity, "note"),
                "message": {
                    "text": f"{f.description} — {f.recommendation}",
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file_path.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                    },
                    "logicalLocations": [{
                        "name": f.file_path,
                        "kind": "resource",
                    }],
                }],
                "properties": {
                    "severity": f.severity,
                    "category": f.category,
                    "detail": f.line_content or "",
                },
            }
            results.append(result)

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "kspm_scanner",
                        "version": VERSION,
                        "informationUri": "https://github.com/Krishcalin/Kubernetes-Security-Posture-Management",
                        "rules": list(rules_seen.values()),
                    },
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    "properties": {
                        "cluster": self.cluster_name,
                    },
                }],
            }],
        }

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(sarif, fh, indent=2)
        print(f"\n[+] SARIF report saved to: {os.path.abspath(path)}")

    # ===================================================================
    # Diff / Trend Reporting (v1.5.0)
    # ===================================================================
    @staticmethod
    def diff_reports(current_path: str, previous_path: str, output_path: str = None):
        """Compare two JSON scan reports and produce a diff report."""
        with open(previous_path, "r", encoding="utf-8") as fh:
            prev = json.load(fh)
        with open(current_path, "r", encoding="utf-8") as fh:
            curr = json.load(fh)

        def finding_key(f):
            return f"{f['rule_id']}|{f.get('file_path', '')}|{f.get('line_content', '')}"

        prev_set = {finding_key(f): f for f in prev.get("findings", [])}
        curr_set = {finding_key(f): f for f in curr.get("findings", [])}

        prev_keys = set(prev_set.keys())
        curr_keys = set(curr_set.keys())

        new_findings = [curr_set[k] for k in sorted(curr_keys - prev_keys)]
        resolved_findings = [prev_set[k] for k in sorted(prev_keys - curr_keys)]
        persistent_findings = [curr_set[k] for k in sorted(curr_keys & prev_keys)]

        prev_summary = prev.get("summary", {})
        curr_summary = curr.get("summary", {})
        trend = {}
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            p = prev_summary.get(sev, 0)
            c = curr_summary.get(sev, 0)
            trend[sev] = {"previous": p, "current": c, "delta": c - p}

        diff_report = {
            "scanner": "kspm_scanner",
            "version": VERSION,
            "generated": datetime.now(timezone.utc).isoformat(),
            "diff_type": "scan_comparison",
            "previous_scan": {
                "file": os.path.basename(previous_path),
                "cluster": prev.get("cluster", "unknown"),
                "generated": prev.get("generated", "unknown"),
                "total_findings": len(prev.get("findings", [])),
            },
            "current_scan": {
                "file": os.path.basename(current_path),
                "cluster": curr.get("cluster", "unknown"),
                "generated": curr.get("generated", "unknown"),
                "total_findings": len(curr.get("findings", [])),
            },
            "trend": trend,
            "new_findings_count": len(new_findings),
            "resolved_findings_count": len(resolved_findings),
            "persistent_findings_count": len(persistent_findings),
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
        }

        B = "\033[1m"
        R = "\033[0m"
        print(f"\n{B}{'=' * 76}{R}")
        print(f"{B}  KSPM Scanner — Diff / Trend Report{R}")
        print(f"{'=' * 76}")
        print(f"  Previous : {os.path.basename(previous_path)} "
              f"({diff_report['previous_scan']['total_findings']} findings)")
        print(f"  Current  : {os.path.basename(current_path)} "
              f"({diff_report['current_scan']['total_findings']} findings)")
        print(f"{'-' * 76}")
        print(f"  {'Severity':<12} {'Previous':>10} {'Current':>10} {'Delta':>10}")
        print(f"  {'-' * 46}")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            t = trend[sev]
            delta_str = f"+{t['delta']}" if t['delta'] > 0 else str(t['delta'])
            print(f"  {sev:<12} {t['previous']:>10} {t['current']:>10} {delta_str:>10}")
        print(f"{'-' * 76}")
        print(f"  New findings       : {len(new_findings)}")
        print(f"  Resolved findings  : {len(resolved_findings)}")
        print(f"  Persistent findings: {len(persistent_findings)}")
        print(f"{'=' * 76}")

        if new_findings:
            print(f"\n{B}  NEW FINDINGS ({len(new_findings)}):{R}")
            for f in new_findings[:20]:
                print(f"    [{f.get('severity', '?')}] {f.get('rule_id', '?')}  "
                      f"{f.get('name', '')}  — {f.get('file_path', '')}")
            if len(new_findings) > 20:
                print(f"    ... +{len(new_findings) - 20} more")

        if resolved_findings:
            print(f"\n{B}  RESOLVED FINDINGS ({len(resolved_findings)}):{R}")
            for f in resolved_findings[:20]:
                print(f"    [{f.get('severity', '?')}] {f.get('rule_id', '?')}  "
                      f"{f.get('name', '')}  — {f.get('file_path', '')}")
            if len(resolved_findings) > 20:
                print(f"    ... +{len(resolved_findings) - 20} more")

        if output_path:
            with open(output_path, "w", encoding="utf-8") as fh:
                json.dump(diff_report, fh, indent=2)
            print(f"\n[+] Diff report saved to: {os.path.abspath(output_path)}")

        return diff_report

    # ===================================================================
    # Webhook Notifications (v1.5.0) — Slack & Teams
    # ===================================================================
    def notify_slack(self, webhook_url: str):
        """Send scan summary to a Slack incoming webhook."""
        import urllib.request
        counts = self.summary()
        total = sum(counts.values())
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "KSPM Security Scan Report"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Cluster:*\n{self.cluster_name}"},
                    {"type": "mrkdwn", "text": f"*Total Findings:*\n{total}"},
                    {"type": "mrkdwn", "text": f"*:red_circle: Critical:*\n{counts.get('CRITICAL', 0)}"},
                    {"type": "mrkdwn", "text": f"*:large_orange_circle: High:*\n{counts.get('HIGH', 0)}"},
                    {"type": "mrkdwn", "text": f"*:large_blue_circle: Medium:*\n{counts.get('MEDIUM', 0)}"},
                    {"type": "mrkdwn", "text": f"*:large_green_circle: Low:*\n{counts.get('LOW', 0)}"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Scanner:* kspm_scanner v{VERSION}\n"
                            f"*Time:* {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
                },
            },
        ]

        # Top 5 critical/high findings
        top_findings = [f for f in self.findings if f.severity in ("CRITICAL", "HIGH")][:5]
        if top_findings:
            lines = []
            for f in top_findings:
                emoji = ":red_circle:" if f.severity == "CRITICAL" else ":large_orange_circle:"
                lines.append(f"{emoji} `{f.rule_id}` {f.name} — _{f.file_path}_")
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Top Critical/High Findings:*\n" + "\n".join(lines),
                },
            })

        payload = json.dumps({"blocks": blocks}).encode("utf-8")
        req = urllib.request.Request(
            webhook_url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status == 200:
                    print("[+] Slack notification sent successfully.")
                else:
                    print(f"[!] Slack webhook returned status {resp.status}",
                          file=sys.stderr)
        except Exception as exc:
            print(f"[!] Failed to send Slack notification: {exc}",
                  file=sys.stderr)

    def notify_teams(self, webhook_url: str):
        """Send scan summary to a Microsoft Teams incoming webhook."""
        import urllib.request
        counts = self.summary()
        total = sum(counts.values())

        facts = [
            {"name": "Cluster", "value": self.cluster_name},
            {"name": "Total Findings", "value": str(total)},
            {"name": "Critical", "value": str(counts.get("CRITICAL", 0))},
            {"name": "High", "value": str(counts.get("HIGH", 0))},
            {"name": "Medium", "value": str(counts.get("MEDIUM", 0))},
            {"name": "Low", "value": str(counts.get("LOW", 0))},
            {"name": "Scanner", "value": f"kspm_scanner v{VERSION}"},
            {"name": "Time", "value": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")},
        ]

        top_findings = [f for f in self.findings if f.severity in ("CRITICAL", "HIGH")][:5]
        top_text = ""
        if top_findings:
            lines = [f"- **[{f.severity}]** `{f.rule_id}` {f.name}" for f in top_findings]
            top_text = "\n\n**Top Critical/High Findings:**\n" + "\n".join(lines)

        card = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": f"KSPM Scan: {total} findings on {self.cluster_name}",
            "themeColor": "c0392b" if counts.get("CRITICAL", 0) > 0 else (
                "e67e22" if counts.get("HIGH", 0) > 0 else "326ce5"
            ),
            "title": "KSPM Security Scan Report",
            "sections": [{
                "activityTitle": f"Cluster: {self.cluster_name}",
                "facts": facts,
                "text": top_text,
            }],
        }

        payload = json.dumps(card).encode("utf-8")
        req = urllib.request.Request(
            webhook_url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status == 200:
                    print("[+] Teams notification sent successfully.")
                else:
                    print(f"[!] Teams webhook returned status {resp.status}",
                          file=sys.stderr)
        except Exception as exc:
            print(f"[!] Failed to send Teams notification: {exc}",
                  file=sys.stderr)

    # ===================================================================
    # PDF Report Generation (v1.5.0)
    # ===================================================================
    def save_pdf(self, path: str):
        """Generate a professional PDF report with executive summary.

        Uses reportlab if available, otherwise falls back to a simple
        text-based PDF using only the standard library.
        """
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.units import mm
            from reportlab.lib import colors
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                PageBreak,
            )
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            self._save_pdf_reportlab(path, A4, mm, colors, SimpleDocTemplate,
                                     Paragraph, Spacer, Table, TableStyle,
                                     PageBreak, getSampleStyleSheet,
                                     ParagraphStyle)
        except ImportError:
            self._save_pdf_fallback(path)

    def _save_pdf_reportlab(self, path, A4, mm, colors, SimpleDocTemplate,
                            Paragraph, Spacer, Table, TableStyle,
                            PageBreak, getSampleStyleSheet, ParagraphStyle):
        """Generate PDF using reportlab (professional layout)."""
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "KSPMTitle", parent=styles["Title"],
            fontSize=22, textColor=colors.HexColor("#326ce5"),
            spaceAfter=6,
        )
        heading_style = ParagraphStyle(
            "KSPMHeading", parent=styles["Heading2"],
            fontSize=14, textColor=colors.HexColor("#326ce5"),
            spaceBefore=14, spaceAfter=8,
        )
        body_style = styles["Normal"]

        doc = SimpleDocTemplate(path, pagesize=A4,
                                leftMargin=20*mm, rightMargin=20*mm,
                                topMargin=20*mm, bottomMargin=20*mm)
        story = []

        # Title page
        story.append(Paragraph("Kubernetes Security Posture Report", title_style))
        story.append(Spacer(1, 6*mm))
        story.append(Paragraph(f"Scanner: kspm_scanner v{VERSION}", body_style))
        story.append(Paragraph(f"Cluster: {self.cluster_name}", body_style))
        story.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
        story.append(Paragraph(f"Total Findings: {len(self.findings)}", body_style))
        story.append(Spacer(1, 10*mm))

        # Executive summary
        story.append(Paragraph("Executive Summary", heading_style))
        counts = self.summary()
        summary_data = [["Severity", "Count"]]
        sev_colors = {
            "CRITICAL": colors.HexColor("#c0392b"),
            "HIGH": colors.HexColor("#e67e22"),
            "MEDIUM": colors.HexColor("#2980b9"),
            "LOW": colors.HexColor("#27ae60"),
        }
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            summary_data.append([sev, str(counts.get(sev, 0))])

        t = Table(summary_data, colWidths=[80*mm, 40*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#326ce5")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#f8f8f8"), colors.white]),
        ]))
        story.append(t)
        story.append(Spacer(1, 8*mm))

        # Compliance summary
        story.append(Paragraph("Compliance Framework Coverage", heading_style))
        comp = self.compliance_summary()
        comp_data = [["Framework", "Controls", "Findings", "Clean", "Coverage"]]
        for name, stats in comp.items():
            comp_data.append([
                name, str(stats["total_controls"]),
                str(stats["findings_triggered"]),
                str(stats["rules_clean"]),
                f"{stats['coverage_pct']}%",
            ])
        ct = Table(comp_data, colWidths=[55*mm, 22*mm, 22*mm, 18*mm, 22*mm])
        ct.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#326ce5")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ALIGN", (1, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#f8f8f8"), colors.white]),
        ]))
        story.append(ct)
        story.append(PageBreak())

        # Findings table
        story.append(Paragraph("Detailed Findings", heading_style))
        sorted_findings = sorted(
            self.findings,
            key=lambda f: (self.SEVERITY_ORDER.get(f.severity, 4),
                           f.category, f.rule_id),
        )

        for f in sorted_findings:
            sev_clr = sev_colors.get(f.severity, colors.grey)
            story.append(Paragraph(
                f'<font color="{sev_clr.hexval()}">[{f.severity}]</font> '
                f'<b>{f.rule_id}</b> — {f.name}',
                body_style,
            ))
            story.append(Paragraph(
                f'<font size="8">Resource: {f.file_path} | '
                f'Detail: {f.line_content or "—"}</font>',
                body_style,
            ))
            desc_text = f.description[:200] + ("..." if len(f.description) > 200 else "")
            rec_text = f.recommendation[:200] + ("..." if len(f.recommendation) > 200 else "")
            story.append(Paragraph(
                f'<font size="8" color="#555555">Issue: {desc_text}</font>',
                body_style,
            ))
            story.append(Paragraph(
                f'<font size="8" color="#27ae60">Fix: {rec_text}</font>',
                body_style,
            ))
            story.append(Spacer(1, 3*mm))

        # Footer
        story.append(Spacer(1, 10*mm))
        story.append(Paragraph(
            f"<font size='8' color='#888888'>Generated by kspm_scanner v{VERSION} "
            f"— Kubernetes Security Posture Management</font>",
            body_style,
        ))

        doc.build(story)
        print(f"\n[+] PDF report saved to: {os.path.abspath(path)}")

    def _save_pdf_fallback(self, path: str):
        """Generate a minimal PDF without reportlab (stdlib only)."""
        counts = self.summary()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        lines = []
        lines.append(f"KSPM Scanner v{VERSION} - Security Posture Report")
        lines.append(f"Cluster: {self.cluster_name}")
        lines.append(f"Generated: {now}")
        lines.append(f"Total Findings: {len(self.findings)}")
        lines.append("")
        lines.append("SEVERITY SUMMARY")
        lines.append("-" * 40)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            lines.append(f"  {sev:<12} {counts.get(sev, 0)}")
        lines.append("")
        lines.append("FINDINGS")
        lines.append("=" * 72)

        sorted_findings = sorted(
            self.findings,
            key=lambda f: (self.SEVERITY_ORDER.get(f.severity, 4),
                           f.category, f.rule_id),
        )
        for f in sorted_findings:
            lines.append(f"[{f.severity}] {f.rule_id}  {f.name}")
            lines.append(f"  Resource: {f.file_path}")
            lines.append(f"  Detail:   {f.line_content or '-'}")
            lines.append(f"  Issue:    {f.description[:120]}")
            lines.append(f"  Fix:      {f.recommendation[:120]}")
            lines.append("")

        # Minimal PDF 1.4 generation (text only, no external library)
        text_content = "\n".join(lines)
        wrapped_lines = []
        for line in text_content.split("\n"):
            if len(line) > 95:
                wrapped_lines.extend(textwrap.wrap(line, 95))
            else:
                wrapped_lines.append(line)

        page_height = 792
        page_width = 612
        margin_top = 50
        margin_left = 50
        line_height = 12
        usable_height = page_height - 100
        lines_per_page = usable_height // line_height

        pages = []
        for i in range(0, len(wrapped_lines), lines_per_page):
            pages.append(wrapped_lines[i:i + lines_per_page])

        objects = []
        obj_id = 0

        def next_id():
            nonlocal obj_id
            obj_id += 1
            return obj_id

        catalog_id = next_id()
        pages_id = next_id()
        font_id = next_id()

        page_ids = []
        content_ids = []
        for _ in pages:
            page_ids.append(next_id())
            content_ids.append(next_id())

        pdf_bytes = bytearray()

        def write(s):
            pdf_bytes.extend(s.encode("latin-1"))

        def write_obj(oid, content):
            objects.append(len(pdf_bytes))
            write(f"{oid} 0 obj\n{content}\nendobj\n")

        write("%PDF-1.4\n")

        # Catalog
        write_obj(catalog_id, f"<< /Type /Catalog /Pages {pages_id} 0 R >>")

        # Pages
        kids = " ".join(f"{pid} 0 R" for pid in page_ids)
        write_obj(pages_id,
                  f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>")

        # Font
        write_obj(font_id,
                  "<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

        # Page and stream objects
        for idx, page_lines in enumerate(pages):
            stream_lines = [f"BT /F1 9 Tf {margin_left} {page_height - margin_top} Td "
                            f"{line_height} TL"]
            for pl in page_lines:
                escaped = pl.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
                stream_lines.append(f"({escaped}) '")
            stream_lines.append("ET")
            stream_data = "\n".join(stream_lines)

            write_obj(content_ids[idx],
                      f"<< /Length {len(stream_data)} >>\nstream\n{stream_data}\nendstream")

            write_obj(page_ids[idx],
                      f"<< /Type /Page /Parent {pages_id} 0 R "
                      f"/MediaBox [0 0 {page_width} {page_height}] "
                      f"/Contents {content_ids[idx]} 0 R "
                      f"/Resources << /Font << /F1 {font_id} 0 R >> >> >>")

        # Xref
        xref_offset = len(pdf_bytes)
        write(f"xref\n0 {obj_id + 1}\n")
        write("0000000000 65535 f \n")
        for off in objects:
            write(f"{off:010d} 00000 n \n")

        write(f"trailer\n<< /Size {obj_id + 1} /Root {catalog_id} 0 R >>\n")
        write(f"startxref\n{xref_offset}\n%%EOF\n")

        with open(path, "wb") as fh:
            fh.write(bytes(pdf_bytes))
        print(f"\n[+] PDF report saved to: {os.path.abspath(path)}")
        print("    (Install 'reportlab' for enhanced PDF layout: pip install reportlab)")


# ---------------------------------------------------------------------------
# Multi-Cluster Scanner (v1.5.0)
# ---------------------------------------------------------------------------
def scan_multiple_contexts(contexts, kubeconfig=None, namespaces=None,
                           all_namespaces=True, verbose=False,
                           trusted_registries=None, trivy_path=None,
                           severity="LOW", json_dir=None, html_dir=None,
                           sarif_dir=None, pdf_dir=None,
                           baseline_save=None, baseline_compare=None,
                           slack_webhook=None, teams_webhook=None,
                           policy_dir=None, rego_dir=None,
                           profile=None, exceptions_file=None):
    """Scan multiple Kubernetes contexts in a single run."""
    B = "\033[1m"
    R = "\033[0m"
    all_results = {}

    print(f"{B}[*] KSPM Multi-Cluster Scan — {len(contexts)} clusters{R}")
    print(f"[*] Contexts: {', '.join(contexts)}\n")

    for idx, ctx in enumerate(contexts, 1):
        print(f"{B}{'=' * 76}{R}")
        print(f"{B}  Cluster {idx}/{len(contexts)}: {ctx}{R}")
        print(f"{'=' * 76}")

        try:
            scanner = KSPMScanner(
                kubeconfig=kubeconfig,
                context=ctx,
                namespaces=namespaces,
                all_namespaces=all_namespaces,
                verbose=verbose,
                trusted_registries=trusted_registries,
                trivy_path=trivy_path,
                policy_dir=policy_dir,
                rego_dir=rego_dir,
                profile=profile,
                exceptions_file=exceptions_file,
            )
            scanner.scan()

            if baseline_compare:
                scanner.compare_rbac_baseline(baseline_compare)

            scanner.filter_severity(severity)
            scanner.print_report()

            if baseline_save:
                ctx_safe = re.sub(r'[^A-Za-z0-9_-]', '_', ctx)
                bf = baseline_save.replace(".json", f"_{ctx_safe}.json")
                scanner.save_rbac_baseline(bf)

            if json_dir:
                os.makedirs(json_dir, exist_ok=True)
                ctx_safe = re.sub(r'[^A-Za-z0-9_-]', '_', ctx)
                scanner.save_json(os.path.join(json_dir, f"kspm_{ctx_safe}.json"))
            if html_dir:
                os.makedirs(html_dir, exist_ok=True)
                ctx_safe = re.sub(r'[^A-Za-z0-9_-]', '_', ctx)
                scanner.save_html(os.path.join(html_dir, f"kspm_{ctx_safe}.html"))
            if sarif_dir:
                os.makedirs(sarif_dir, exist_ok=True)
                ctx_safe = re.sub(r'[^A-Za-z0-9_-]', '_', ctx)
                scanner.save_sarif(os.path.join(sarif_dir, f"kspm_{ctx_safe}.sarif"))
            if pdf_dir:
                os.makedirs(pdf_dir, exist_ok=True)
                ctx_safe = re.sub(r'[^A-Za-z0-9_-]', '_', ctx)
                scanner.save_pdf(os.path.join(pdf_dir, f"kspm_{ctx_safe}.pdf"))

            if slack_webhook:
                scanner.notify_slack(slack_webhook)
            if teams_webhook:
                scanner.notify_teams(teams_webhook)

            all_results[ctx] = {
                "findings_count": len(scanner.findings),
                "summary": scanner.summary(),
            }
        except Exception as exc:
            print(f"[!] Failed to scan context '{ctx}': {exc}", file=sys.stderr)
            all_results[ctx] = {"error": str(exc)}

    # Print consolidated summary
    print(f"\n{B}{'=' * 76}{R}")
    print(f"{B}  MULTI-CLUSTER SUMMARY{R}")
    print(f"{'=' * 76}")
    print(f"  {'Context':<30} {'Total':>8} {'CRIT':>6} {'HIGH':>6} {'MED':>6} {'LOW':>6}")
    print(f"  {'-' * 68}")
    for ctx, res in all_results.items():
        if "error" in res:
            print(f"  {ctx:<30} {'ERROR':>8}  {res['error'][:30]}")
        else:
            s = res["summary"]
            print(f"  {ctx:<30} {res['findings_count']:>8} "
                  f"{s.get('CRITICAL', 0):>6} {s.get('HIGH', 0):>6} "
                  f"{s.get('MEDIUM', 0):>6} {s.get('LOW', 0):>6}")
    print(f"{'=' * 76}")

    return all_results


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
    parser.add_argument("--baseline-save", metavar="FILE",
                        help="Save current RBAC state as baseline for drift detection")
    parser.add_argument("--baseline-compare", metavar="FILE",
                        help="Compare current RBAC against a saved baseline")
    parser.add_argument("--trusted-registries", metavar="LIST",
                        help="Comma-separated list of additional trusted image registries")
    parser.add_argument("--trivy-path", metavar="PATH",
                        help="Path to trivy binary (auto-detected if not set)")
    # v2.0.0 args — Policy Engine
    parser.add_argument("--policy-dir", metavar="DIR",
                        help="Directory containing custom YAML policy files")
    parser.add_argument("--rego-dir", metavar="DIR",
                        help="Directory containing OPA Rego policy files (.rego)")
    parser.add_argument("--profile",
                        choices=["dev", "staging", "production"],
                        help="Baseline profile to apply (dev/staging/production)")
    parser.add_argument("--exceptions", metavar="FILE",
                        help="JSON/YAML file with exception/allow-list rules")
    # v1.5.0 args
    parser.add_argument("--contexts", metavar="CTX1,CTX2,...",
                        help="Scan multiple contexts (comma-separated)")
    parser.add_argument("--sarif", metavar="FILE",
                        help="Save findings in SARIF v2.1.0 format")
    parser.add_argument("--pdf", metavar="FILE",
                        help="Save findings as PDF report")
    parser.add_argument("--diff", metavar="PREV_JSON",
                        help="Compare current scan against a previous JSON report")
    parser.add_argument("--diff-output", metavar="FILE",
                        help="Save diff report as JSON (requires --diff)")
    parser.add_argument("--slack-webhook", metavar="URL",
                        help="Send scan summary to Slack webhook URL")
    parser.add_argument("--teams-webhook", metavar="URL",
                        help="Send scan summary to Teams webhook URL")
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

    trusted_regs = set()
    if args.trusted_registries:
        trusted_regs = {r.strip() for r in args.trusted_registries.split(",") if r.strip()}

    # --- Multi-cluster mode ---
    if args.contexts:
        contexts = [c.strip() for c in args.contexts.split(",") if c.strip()]
        scan_multiple_contexts(
            contexts=contexts,
            kubeconfig=args.kubeconfig or None,
            namespaces=namespaces,
            all_namespaces=args.all_namespaces,
            verbose=args.verbose,
            trusted_registries=trusted_regs,
            trivy_path=args.trivy_path or None,
            severity=args.severity,
            json_dir=args.json,
            html_dir=args.html,
            sarif_dir=args.sarif,
            pdf_dir=args.pdf,
            baseline_save=args.baseline_save,
            baseline_compare=args.baseline_compare,
            slack_webhook=args.slack_webhook,
            teams_webhook=args.teams_webhook,
            policy_dir=args.policy_dir,
            rego_dir=args.rego_dir,
            profile=args.profile,
            exceptions_file=args.exceptions,
        )
        sys.exit(0)

    # --- Single-cluster mode ---
    scanner = KSPMScanner(
        kubeconfig=args.kubeconfig or None,
        context=args.context or None,
        namespaces=namespaces,
        all_namespaces=args.all_namespaces,
        verbose=args.verbose,
        trusted_registries=trusted_regs,
        trivy_path=args.trivy_path or None,
        policy_dir=args.policy_dir,
        rego_dir=args.rego_dir,
        profile=args.profile,
        exceptions_file=args.exceptions,
    )

    scanner.scan()

    if args.baseline_compare:
        scanner.compare_rbac_baseline(args.baseline_compare)

    scanner.filter_severity(args.severity)
    scanner.print_report()

    if args.baseline_save:
        scanner.save_rbac_baseline(args.baseline_save)
    if args.json:
        scanner.save_json(args.json)
    if args.html:
        scanner.save_html(args.html)
    if args.sarif:
        scanner.save_sarif(args.sarif)
    if args.pdf:
        scanner.save_pdf(args.pdf)
    if args.slack_webhook:
        scanner.notify_slack(args.slack_webhook)
    if args.teams_webhook:
        scanner.notify_teams(args.teams_webhook)

    # Diff reporting (requires --json to have current scan, and --diff for previous)
    if args.diff:
        if args.json:
            KSPMScanner.diff_reports(args.json, args.diff, args.diff_output)
        else:
            # Save temp JSON for comparison, then diff
            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
                tmp_path = tmp.name
            scanner.save_json(tmp_path)
            KSPMScanner.diff_reports(tmp_path, args.diff, args.diff_output)
            os.unlink(tmp_path)

    has_critical_high = any(
        f.severity in ("CRITICAL", "HIGH") for f in scanner.findings
    )
    sys.exit(1 if has_critical_high else 0)


if __name__ == "__main__":
    main()

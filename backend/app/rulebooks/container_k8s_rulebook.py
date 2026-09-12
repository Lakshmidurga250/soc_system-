"""
SentinelAI - Kubernetes & Container Security Detection Rulebook
Evaluates K8s API audit logs and container runtime events for privilege escalation,
hostPath volume mounts, cluster-admin role bindings, and container escapes.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Any
import datetime

@dataclass
class K8sSecurityRule:
    rule_id: str
    name: str
    mitre_technique: str
    severity: str
    category: str
    description: str

K8S_RULES = [
    K8sSecurityRule(
        rule_id="K8S-SEC-001",
        name="Privileged Pod Creation with Host PID / Host Network",
        mitre_technique="T1611",
        severity="CRITICAL",
        category="Container Escape",
        description="Detects creation of a pod with securityContext.privileged=true or hostPID=true."
    ),
    K8sSecurityRule(
        rule_id="K8S-SEC-002",
        name="ClusterRoleBinding to Cluster-Admin for Anonymous / Default SA",
        mitre_technique="T1078.001",
        severity="CRITICAL",
        category="Privilege Escalation",
        description="Detects granting cluster-admin privileges to system:anonymous or default service account."
    ),
    K8sSecurityRule(
        rule_id="K8S-SEC-003",
        name="Sensitive Host Path Mount (/etc, /var/run/docker.sock, /proc)",
        mitre_technique="T1611",
        severity="HIGH",
        category="Defense Evasion",
        description="Detects mounting host filesystem root or container daemon socket inside pod container."
    ),
    K8sSecurityRule(
        rule_id="K8S-SEC-004",
        name="Interactive Exec Into Production Namespace Pod",
        mitre_technique="T1059",
        severity="MEDIUM",
        category="Execution",
        description="Detects kubectl exec sessions into sensitive production pods (e.g. payment, db)."
    ),
]

class K8sSecurityEngine:
    """Dissects Kubernetes API server audit logs for compliance & intrusion indicators."""

    def evaluate_audit_event(self, audit_event: Dict[str, Any]) -> List[Dict[str, Any]]:
        alerts = []
        verb = audit_event.get("verb", "")
        object_ref = audit_event.get("objectRef", {})
        resource = object_ref.get("resource", "")
        req_obj = audit_event.get("requestObject", {})

        # Rule 1: Privileged container
        if verb == "create" and resource == "pods":
            spec = req_obj.get("spec", {})
            containers = spec.get("containers", [])
            for c in containers:
                sec_ctx = c.get("securityContext", {})
                if sec_ctx.get("privileged") is True or spec.get("hostPID") is True:
                    alerts.append({
                        "rule_id": "K8S-SEC-001",
                        "severity": "CRITICAL",
                        "mitre": "T1611",
                        "pod": object_ref.get("name", "unknown"),
                        "namespace": object_ref.get("namespace", "default"),
                        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
                    })

        # Rule 2: ClusterRoleBinding
        if verb == "create" and resource == "clusterrolebindings":
            role_ref = req_obj.get("roleRef", {}).get("name", "")
            if role_ref == "cluster-admin":
                alerts.append({
                    "rule_id": "K8S-SEC-002",
                    "severity": "CRITICAL",
                    "mitre": "T1078.001",
                    "binding_name": object_ref.get("name", ""),
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
                })

        return alerts

k8s_engine = K8sSecurityEngine()

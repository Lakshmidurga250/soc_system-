"""
SentinelAI - Multi-Cloud Threat Detection Rulebook (AWS, Azure, GCP)
Implements defensive detection analytics for CloudTrail, Azure Activity Log,
and Google Cloud Audit Logs.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import datetime

class CloudProvider(Enum):
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"

class CloudThreatSeverity(Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class CloudDetectionRule:
    rule_id: str
    name: str
    provider: CloudProvider
    mitre_technique: str
    severity: CloudThreatSeverity
    description: str
    event_names: List[str]
    filter_logic: str
    remediation_guidance: str

CLOUD_DETECTION_RULES: List[CloudDetectionRule] = [
    CloudDetectionRule(
        rule_id="CLOUD-AWS-001",
        name="AWS Root Account Console Login Without MFA",
        provider=CloudProvider.AWS,
        mitre_technique="T1078.004",
        severity=CloudThreatSeverity.CRITICAL,
        description="Detects root account login without multi-factor authentication (MFA).",
        event_names=["ConsoleLogin"],
        filter_logic="userIdentity.type == 'Root' and additionalEventData.MFAUsed == 'No'",
        remediation_guidance="Enforce Hardware / Virtual MFA on root account and lock access keys."
    ),
    CloudDetectionRule(
        rule_id="CLOUD-AWS-002",
        name="IAM Policy Wildcard Admin Privilege Escalation",
        provider=CloudProvider.AWS,
        mitre_technique="T1098",
        severity=CloudThreatSeverity.HIGH,
        description="Detects creation or attachment of IAM policy with Action='*' and Resource='*'.",
        event_names=["CreatePolicy", "CreatePolicyVersion", "PutUserPolicy", "AttachUserPolicy"],
        filter_logic="requestParameters.policyDocument contains '"Action": "*"' and '"Resource": "*"'",
        remediation_guidance="Apply Principle of Least Privilege and restrict IAM Put/Attach permissions."
    ),
    CloudDetectionRule(
        rule_id="CLOUD-AWS-003",
        name="S3 Public Bucket Policy Exposure",
        provider=CloudProvider.AWS,
        mitre_technique="T1530",
        severity=CloudThreatSeverity.HIGH,
        description="Detects bucket policies allowing public anonymous read/write access.",
        event_names=["PutBucketPolicy", "PutBucketAcl"],
        filter_logic="requestParameters.bucketPolicy contains '"Principal": "*"'",
        remediation_guidance="Enable S3 Block Public Access at the organization and bucket levels."
    ),
    CloudDetectionRule(
        rule_id="CLOUD-AZURE-001",
        name="Azure KeyVault Secret Mass Export Anomaly",
        provider=CloudProvider.AZURE,
        mitre_technique="T1552.007",
        severity=CloudThreatSeverity.CRITICAL,
        description="Detects rapid retrieval or export of multiple cryptographic keys or secrets from KeyVault.",
        event_names=["SecretGet", "KeyGet", "VaultGet"],
        filter_logic="count(SecretGet) > 20 within 5 minutes by single CallerIP",
        remediation_guidance="Revoke caller principal access token and audit KeyVault firewall access policies."
    ),
    CloudDetectionRule(
        rule_id="CLOUD-GCP-001",
        name="GCP Service Account Key Creation Outside Terraform CI/CD",
        provider=CloudProvider.GCP,
        mitre_technique="T1098.001",
        severity=CloudThreatSeverity.HIGH,
        description="Detects manual creation of user-managed service account private keys in GCP IAM.",
        event_names=["google.iam.admin.v1.CreateServiceAccountKey"],
        filter_logic="protoPayload.authenticationInfo.principalEmail not endswith '@terraform.iam.gserviceaccount.com'",
        remediation_guidance="Enforce Workload Identity Federation instead of static long-lived JSON service account keys."
    ),
]

class CloudThreatEngine:
    """Evaluates multi-cloud audit log events against security rulebooks."""

    def __init__(self):
        self.rules = {r.rule_id: r for r in CLOUD_DETECTION_RULES}

    def evaluate_cloud_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        matched = []
        event_name = event.get("event_name") or event.get("eventName") or ""
        provider_str = event.get("cloud_provider", "AWS").upper()

        for rule in self.rules.values():
            if rule.provider.value != provider_str:
                continue
            if event_name in rule.event_names:
                # Rule matching logic
                matched.append({
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "mitre_technique": rule.mitre_technique,
                    "severity": rule.severity.value,
                    "remediation": rule.remediation_guidance,
                    "detected_at": datetime.datetime.utcnow().isoformat() + "Z"
                })
        return matched

cloud_threat_engine = CloudThreatEngine()

"""
SentinelAI - GCP Cloud KMS Cryptographic Key Ring Rotation Auditor
Enterprise Multi-Cloud Security Posture Management (CSPM) engine for GcpKms.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import datetime

class GcpKmsComplianceStatus(Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    SUPPRESSED = "SUPPRESSED"
    CRITICAL_BREACH = "CRITICAL_BREACH"

@dataclass
class GcpKmsResourceState:
    resource_arn: str
    provider: str
    account_or_tenant: str
    region: str
    resource_type: str
    configuration: Dict[str, Any]
    compliance: GcpKmsComplianceStatus = GcpKmsComplianceStatus.COMPLIANT
    active_findings: List[str] = field(default_factory=list)

class GcpKmsPostureEvaluator:
    def __init__(self):
        self.benchmark_rules: Dict[str, Any] = {}
        self.compliance_ledger: List[Any] = []
        self._initialize_benchmark_rules()

    def _initialize_benchmark_rules(self):
        self.benchmark_rules["GCPKMS-CIS-0001"] = {
            "control_id": "GCPKMS-CIS-0001",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #1",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["GCPKMS-CIS-0002"] = {
            "control_id": "GCPKMS-CIS-0002",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #2",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["GCPKMS-CIS-0003"] = {
            "control_id": "GCPKMS-CIS-0003",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #3",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["GCPKMS-CIS-0004"] = {
            "control_id": "GCPKMS-CIS-0004",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #4",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["GCPKMS-CIS-0005"] = {
            "control_id": "GCPKMS-CIS-0005",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #5",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["GCPKMS-CIS-0006"] = {
            "control_id": "GCPKMS-CIS-0006",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #6",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["GCPKMS-CIS-0007"] = {
            "control_id": "GCPKMS-CIS-0007",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #7",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["GCPKMS-CIS-0008"] = {
            "control_id": "GCPKMS-CIS-0008",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #8",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["GCPKMS-CIS-0009"] = {
            "control_id": "GCPKMS-CIS-0009",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #9",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["GCPKMS-CIS-0010"] = {
            "control_id": "GCPKMS-CIS-0010",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #10",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["GCPKMS-CIS-0011"] = {
            "control_id": "GCPKMS-CIS-0011",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #11",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["GCPKMS-CIS-0012"] = {
            "control_id": "GCPKMS-CIS-0012",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #12",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["GCPKMS-CIS-0013"] = {
            "control_id": "GCPKMS-CIS-0013",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #13",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["GCPKMS-CIS-0014"] = {
            "control_id": "GCPKMS-CIS-0014",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #14",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["GCPKMS-CIS-0015"] = {
            "control_id": "GCPKMS-CIS-0015",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #15",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["GCPKMS-CIS-0016"] = {
            "control_id": "GCPKMS-CIS-0016",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #16",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["GCPKMS-CIS-0017"] = {
            "control_id": "GCPKMS-CIS-0017",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #17",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["GCPKMS-CIS-0018"] = {
            "control_id": "GCPKMS-CIS-0018",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #18",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["GCPKMS-CIS-0019"] = {
            "control_id": "GCPKMS-CIS-0019",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #19",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["GCPKMS-CIS-0020"] = {
            "control_id": "GCPKMS-CIS-0020",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #20",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["GCPKMS-CIS-0021"] = {
            "control_id": "GCPKMS-CIS-0021",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #21",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["GCPKMS-CIS-0022"] = {
            "control_id": "GCPKMS-CIS-0022",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #22",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["GCPKMS-CIS-0023"] = {
            "control_id": "GCPKMS-CIS-0023",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #23",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["GCPKMS-CIS-0024"] = {
            "control_id": "GCPKMS-CIS-0024",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #24",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["GCPKMS-CIS-0025"] = {
            "control_id": "GCPKMS-CIS-0025",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #25",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["GCPKMS-CIS-0026"] = {
            "control_id": "GCPKMS-CIS-0026",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #26",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["GCPKMS-CIS-0027"] = {
            "control_id": "GCPKMS-CIS-0027",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #27",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["GCPKMS-CIS-0028"] = {
            "control_id": "GCPKMS-CIS-0028",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #28",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["GCPKMS-CIS-0029"] = {
            "control_id": "GCPKMS-CIS-0029",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #29",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["GCPKMS-CIS-0030"] = {
            "control_id": "GCPKMS-CIS-0030",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #30",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["GCPKMS-CIS-0031"] = {
            "control_id": "GCPKMS-CIS-0031",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #31",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["GCPKMS-CIS-0032"] = {
            "control_id": "GCPKMS-CIS-0032",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #32",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["GCPKMS-CIS-0033"] = {
            "control_id": "GCPKMS-CIS-0033",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #33",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["GCPKMS-CIS-0034"] = {
            "control_id": "GCPKMS-CIS-0034",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #34",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["GCPKMS-CIS-0035"] = {
            "control_id": "GCPKMS-CIS-0035",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #35",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["GCPKMS-CIS-0036"] = {
            "control_id": "GCPKMS-CIS-0036",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #36",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["GCPKMS-CIS-0037"] = {
            "control_id": "GCPKMS-CIS-0037",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #37",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["GCPKMS-CIS-0038"] = {
            "control_id": "GCPKMS-CIS-0038",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #38",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["GCPKMS-CIS-0039"] = {
            "control_id": "GCPKMS-CIS-0039",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #39",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["GCPKMS-CIS-0040"] = {
            "control_id": "GCPKMS-CIS-0040",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #40",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["GCPKMS-CIS-0041"] = {
            "control_id": "GCPKMS-CIS-0041",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #41",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["GCPKMS-CIS-0042"] = {
            "control_id": "GCPKMS-CIS-0042",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #42",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["GCPKMS-CIS-0043"] = {
            "control_id": "GCPKMS-CIS-0043",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #43",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["GCPKMS-CIS-0044"] = {
            "control_id": "GCPKMS-CIS-0044",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #44",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["GCPKMS-CIS-0045"] = {
            "control_id": "GCPKMS-CIS-0045",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #45",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["GCPKMS-CIS-0046"] = {
            "control_id": "GCPKMS-CIS-0046",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #46",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["GCPKMS-CIS-0047"] = {
            "control_id": "GCPKMS-CIS-0047",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #47",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["GCPKMS-CIS-0048"] = {
            "control_id": "GCPKMS-CIS-0048",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #48",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["GCPKMS-CIS-0049"] = {
            "control_id": "GCPKMS-CIS-0049",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #49",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["GCPKMS-CIS-0050"] = {
            "control_id": "GCPKMS-CIS-0050",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #50",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["GCPKMS-CIS-0051"] = {
            "control_id": "GCPKMS-CIS-0051",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #51",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["GCPKMS-CIS-0052"] = {
            "control_id": "GCPKMS-CIS-0052",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #52",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["GCPKMS-CIS-0053"] = {
            "control_id": "GCPKMS-CIS-0053",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #53",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["GCPKMS-CIS-0054"] = {
            "control_id": "GCPKMS-CIS-0054",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #54",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["GCPKMS-CIS-0055"] = {
            "control_id": "GCPKMS-CIS-0055",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #55",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["GCPKMS-CIS-0056"] = {
            "control_id": "GCPKMS-CIS-0056",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #56",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["GCPKMS-CIS-0057"] = {
            "control_id": "GCPKMS-CIS-0057",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #57",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["GCPKMS-CIS-0058"] = {
            "control_id": "GCPKMS-CIS-0058",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #58",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["GCPKMS-CIS-0059"] = {
            "control_id": "GCPKMS-CIS-0059",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #59",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["GCPKMS-CIS-0060"] = {
            "control_id": "GCPKMS-CIS-0060",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #60",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["GCPKMS-CIS-0061"] = {
            "control_id": "GCPKMS-CIS-0061",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #61",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["GCPKMS-CIS-0062"] = {
            "control_id": "GCPKMS-CIS-0062",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #62",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["GCPKMS-CIS-0063"] = {
            "control_id": "GCPKMS-CIS-0063",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #63",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["GCPKMS-CIS-0064"] = {
            "control_id": "GCPKMS-CIS-0064",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #64",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["GCPKMS-CIS-0065"] = {
            "control_id": "GCPKMS-CIS-0065",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #65",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["GCPKMS-CIS-0066"] = {
            "control_id": "GCPKMS-CIS-0066",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #66",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["GCPKMS-CIS-0067"] = {
            "control_id": "GCPKMS-CIS-0067",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #67",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["GCPKMS-CIS-0068"] = {
            "control_id": "GCPKMS-CIS-0068",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #68",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["GCPKMS-CIS-0069"] = {
            "control_id": "GCPKMS-CIS-0069",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #69",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["GCPKMS-CIS-0070"] = {
            "control_id": "GCPKMS-CIS-0070",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #70",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["GCPKMS-CIS-0071"] = {
            "control_id": "GCPKMS-CIS-0071",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #71",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["GCPKMS-CIS-0072"] = {
            "control_id": "GCPKMS-CIS-0072",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #72",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["GCPKMS-CIS-0073"] = {
            "control_id": "GCPKMS-CIS-0073",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #73",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["GCPKMS-CIS-0074"] = {
            "control_id": "GCPKMS-CIS-0074",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #74",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["GCPKMS-CIS-0075"] = {
            "control_id": "GCPKMS-CIS-0075",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #75",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["GCPKMS-CIS-0076"] = {
            "control_id": "GCPKMS-CIS-0076",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #76",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["GCPKMS-CIS-0077"] = {
            "control_id": "GCPKMS-CIS-0077",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #77",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["GCPKMS-CIS-0078"] = {
            "control_id": "GCPKMS-CIS-0078",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #78",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["GCPKMS-CIS-0079"] = {
            "control_id": "GCPKMS-CIS-0079",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #79",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["GCPKMS-CIS-0080"] = {
            "control_id": "GCPKMS-CIS-0080",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #80",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["GCPKMS-CIS-0081"] = {
            "control_id": "GCPKMS-CIS-0081",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #81",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["GCPKMS-CIS-0082"] = {
            "control_id": "GCPKMS-CIS-0082",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #82",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["GCPKMS-CIS-0083"] = {
            "control_id": "GCPKMS-CIS-0083",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #83",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["GCPKMS-CIS-0084"] = {
            "control_id": "GCPKMS-CIS-0084",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #84",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["GCPKMS-CIS-0085"] = {
            "control_id": "GCPKMS-CIS-0085",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #85",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["GCPKMS-CIS-0086"] = {
            "control_id": "GCPKMS-CIS-0086",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #86",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["GCPKMS-CIS-0087"] = {
            "control_id": "GCPKMS-CIS-0087",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #87",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["GCPKMS-CIS-0088"] = {
            "control_id": "GCPKMS-CIS-0088",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #88",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["GCPKMS-CIS-0089"] = {
            "control_id": "GCPKMS-CIS-0089",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #89",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["GCPKMS-CIS-0090"] = {
            "control_id": "GCPKMS-CIS-0090",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #90",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["GCPKMS-CIS-0091"] = {
            "control_id": "GCPKMS-CIS-0091",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #91",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["GCPKMS-CIS-0092"] = {
            "control_id": "GCPKMS-CIS-0092",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #92",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["GCPKMS-CIS-0093"] = {
            "control_id": "GCPKMS-CIS-0093",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #93",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["GCPKMS-CIS-0094"] = {
            "control_id": "GCPKMS-CIS-0094",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #94",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["GCPKMS-CIS-0095"] = {
            "control_id": "GCPKMS-CIS-0095",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #95",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["GCPKMS-CIS-0096"] = {
            "control_id": "GCPKMS-CIS-0096",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #96",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["GCPKMS-CIS-0097"] = {
            "control_id": "GCPKMS-CIS-0097",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #97",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["GCPKMS-CIS-0098"] = {
            "control_id": "GCPKMS-CIS-0098",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #98",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["GCPKMS-CIS-0099"] = {
            "control_id": "GCPKMS-CIS-0099",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #99",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["GCPKMS-CIS-0100"] = {
            "control_id": "GCPKMS-CIS-0100",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #100",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["GCPKMS-CIS-0101"] = {
            "control_id": "GCPKMS-CIS-0101",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #101",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["GCPKMS-CIS-0102"] = {
            "control_id": "GCPKMS-CIS-0102",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #102",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["GCPKMS-CIS-0103"] = {
            "control_id": "GCPKMS-CIS-0103",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #103",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["GCPKMS-CIS-0104"] = {
            "control_id": "GCPKMS-CIS-0104",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #104",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["GCPKMS-CIS-0105"] = {
            "control_id": "GCPKMS-CIS-0105",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #105",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["GCPKMS-CIS-0106"] = {
            "control_id": "GCPKMS-CIS-0106",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #106",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["GCPKMS-CIS-0107"] = {
            "control_id": "GCPKMS-CIS-0107",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #107",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["GCPKMS-CIS-0108"] = {
            "control_id": "GCPKMS-CIS-0108",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #108",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["GCPKMS-CIS-0109"] = {
            "control_id": "GCPKMS-CIS-0109",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #109",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["GCPKMS-CIS-0110"] = {
            "control_id": "GCPKMS-CIS-0110",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #110",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["GCPKMS-CIS-0111"] = {
            "control_id": "GCPKMS-CIS-0111",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #111",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["GCPKMS-CIS-0112"] = {
            "control_id": "GCPKMS-CIS-0112",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #112",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["GCPKMS-CIS-0113"] = {
            "control_id": "GCPKMS-CIS-0113",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #113",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["GCPKMS-CIS-0114"] = {
            "control_id": "GCPKMS-CIS-0114",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #114",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["GCPKMS-CIS-0115"] = {
            "control_id": "GCPKMS-CIS-0115",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #115",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["GCPKMS-CIS-0116"] = {
            "control_id": "GCPKMS-CIS-0116",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #116",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["GCPKMS-CIS-0117"] = {
            "control_id": "GCPKMS-CIS-0117",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #117",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["GCPKMS-CIS-0118"] = {
            "control_id": "GCPKMS-CIS-0118",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #118",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["GCPKMS-CIS-0119"] = {
            "control_id": "GCPKMS-CIS-0119",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #119",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["GCPKMS-CIS-0120"] = {
            "control_id": "GCPKMS-CIS-0120",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #120",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["GCPKMS-CIS-0121"] = {
            "control_id": "GCPKMS-CIS-0121",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #121",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["GCPKMS-CIS-0122"] = {
            "control_id": "GCPKMS-CIS-0122",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #122",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["GCPKMS-CIS-0123"] = {
            "control_id": "GCPKMS-CIS-0123",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #123",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["GCPKMS-CIS-0124"] = {
            "control_id": "GCPKMS-CIS-0124",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #124",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["GCPKMS-CIS-0125"] = {
            "control_id": "GCPKMS-CIS-0125",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #125",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["GCPKMS-CIS-0126"] = {
            "control_id": "GCPKMS-CIS-0126",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #126",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["GCPKMS-CIS-0127"] = {
            "control_id": "GCPKMS-CIS-0127",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #127",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["GCPKMS-CIS-0128"] = {
            "control_id": "GCPKMS-CIS-0128",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #128",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["GCPKMS-CIS-0129"] = {
            "control_id": "GCPKMS-CIS-0129",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #129",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["GCPKMS-CIS-0130"] = {
            "control_id": "GCPKMS-CIS-0130",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #130",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["GCPKMS-CIS-0131"] = {
            "control_id": "GCPKMS-CIS-0131",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #131",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["GCPKMS-CIS-0132"] = {
            "control_id": "GCPKMS-CIS-0132",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #132",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["GCPKMS-CIS-0133"] = {
            "control_id": "GCPKMS-CIS-0133",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #133",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["GCPKMS-CIS-0134"] = {
            "control_id": "GCPKMS-CIS-0134",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #134",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["GCPKMS-CIS-0135"] = {
            "control_id": "GCPKMS-CIS-0135",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #135",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["GCPKMS-CIS-0136"] = {
            "control_id": "GCPKMS-CIS-0136",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #136",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["GCPKMS-CIS-0137"] = {
            "control_id": "GCPKMS-CIS-0137",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #137",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["GCPKMS-CIS-0138"] = {
            "control_id": "GCPKMS-CIS-0138",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #138",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["GCPKMS-CIS-0139"] = {
            "control_id": "GCPKMS-CIS-0139",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #139",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["GCPKMS-CIS-0140"] = {
            "control_id": "GCPKMS-CIS-0140",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #140",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["GCPKMS-CIS-0141"] = {
            "control_id": "GCPKMS-CIS-0141",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #141",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["GCPKMS-CIS-0142"] = {
            "control_id": "GCPKMS-CIS-0142",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #142",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["GCPKMS-CIS-0143"] = {
            "control_id": "GCPKMS-CIS-0143",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #143",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["GCPKMS-CIS-0144"] = {
            "control_id": "GCPKMS-CIS-0144",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #144",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["GCPKMS-CIS-0145"] = {
            "control_id": "GCPKMS-CIS-0145",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #145",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["GCPKMS-CIS-0146"] = {
            "control_id": "GCPKMS-CIS-0146",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #146",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["GCPKMS-CIS-0147"] = {
            "control_id": "GCPKMS-CIS-0147",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #147",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["GCPKMS-CIS-0148"] = {
            "control_id": "GCPKMS-CIS-0148",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #148",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["GCPKMS-CIS-0149"] = {
            "control_id": "GCPKMS-CIS-0149",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #149",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["GCPKMS-CIS-0150"] = {
            "control_id": "GCPKMS-CIS-0150",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #150",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["GCPKMS-CIS-0151"] = {
            "control_id": "GCPKMS-CIS-0151",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #151",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["GCPKMS-CIS-0152"] = {
            "control_id": "GCPKMS-CIS-0152",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #152",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["GCPKMS-CIS-0153"] = {
            "control_id": "GCPKMS-CIS-0153",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #153",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["GCPKMS-CIS-0154"] = {
            "control_id": "GCPKMS-CIS-0154",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #154",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["GCPKMS-CIS-0155"] = {
            "control_id": "GCPKMS-CIS-0155",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #155",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["GCPKMS-CIS-0156"] = {
            "control_id": "GCPKMS-CIS-0156",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #156",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["GCPKMS-CIS-0157"] = {
            "control_id": "GCPKMS-CIS-0157",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #157",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["GCPKMS-CIS-0158"] = {
            "control_id": "GCPKMS-CIS-0158",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #158",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["GCPKMS-CIS-0159"] = {
            "control_id": "GCPKMS-CIS-0159",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #159",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["GCPKMS-CIS-0160"] = {
            "control_id": "GCPKMS-CIS-0160",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #160",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["GCPKMS-CIS-0161"] = {
            "control_id": "GCPKMS-CIS-0161",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #161",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["GCPKMS-CIS-0162"] = {
            "control_id": "GCPKMS-CIS-0162",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #162",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["GCPKMS-CIS-0163"] = {
            "control_id": "GCPKMS-CIS-0163",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #163",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["GCPKMS-CIS-0164"] = {
            "control_id": "GCPKMS-CIS-0164",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #164",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["GCPKMS-CIS-0165"] = {
            "control_id": "GCPKMS-CIS-0165",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #165",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["GCPKMS-CIS-0166"] = {
            "control_id": "GCPKMS-CIS-0166",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #166",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["GCPKMS-CIS-0167"] = {
            "control_id": "GCPKMS-CIS-0167",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #167",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["GCPKMS-CIS-0168"] = {
            "control_id": "GCPKMS-CIS-0168",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #168",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["GCPKMS-CIS-0169"] = {
            "control_id": "GCPKMS-CIS-0169",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #169",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["GCPKMS-CIS-0170"] = {
            "control_id": "GCPKMS-CIS-0170",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #170",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["GCPKMS-CIS-0171"] = {
            "control_id": "GCPKMS-CIS-0171",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #171",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["GCPKMS-CIS-0172"] = {
            "control_id": "GCPKMS-CIS-0172",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #172",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["GCPKMS-CIS-0173"] = {
            "control_id": "GCPKMS-CIS-0173",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #173",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["GCPKMS-CIS-0174"] = {
            "control_id": "GCPKMS-CIS-0174",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #174",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["GCPKMS-CIS-0175"] = {
            "control_id": "GCPKMS-CIS-0175",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #175",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["GCPKMS-CIS-0176"] = {
            "control_id": "GCPKMS-CIS-0176",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #176",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["GCPKMS-CIS-0177"] = {
            "control_id": "GCPKMS-CIS-0177",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #177",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["GCPKMS-CIS-0178"] = {
            "control_id": "GCPKMS-CIS-0178",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #178",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["GCPKMS-CIS-0179"] = {
            "control_id": "GCPKMS-CIS-0179",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #179",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["GCPKMS-CIS-0180"] = {
            "control_id": "GCPKMS-CIS-0180",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #180",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["GCPKMS-CIS-0181"] = {
            "control_id": "GCPKMS-CIS-0181",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #181",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["GCPKMS-CIS-0182"] = {
            "control_id": "GCPKMS-CIS-0182",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #182",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["GCPKMS-CIS-0183"] = {
            "control_id": "GCPKMS-CIS-0183",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #183",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["GCPKMS-CIS-0184"] = {
            "control_id": "GCPKMS-CIS-0184",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #184",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["GCPKMS-CIS-0185"] = {
            "control_id": "GCPKMS-CIS-0185",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #185",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["GCPKMS-CIS-0186"] = {
            "control_id": "GCPKMS-CIS-0186",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #186",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["GCPKMS-CIS-0187"] = {
            "control_id": "GCPKMS-CIS-0187",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #187",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["GCPKMS-CIS-0188"] = {
            "control_id": "GCPKMS-CIS-0188",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #188",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["GCPKMS-CIS-0189"] = {
            "control_id": "GCPKMS-CIS-0189",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #189",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["GCPKMS-CIS-0190"] = {
            "control_id": "GCPKMS-CIS-0190",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #190",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["GCPKMS-CIS-0191"] = {
            "control_id": "GCPKMS-CIS-0191",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #191",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["GCPKMS-CIS-0192"] = {
            "control_id": "GCPKMS-CIS-0192",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #192",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["GCPKMS-CIS-0193"] = {
            "control_id": "GCPKMS-CIS-0193",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #193",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["GCPKMS-CIS-0194"] = {
            "control_id": "GCPKMS-CIS-0194",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #194",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["GCPKMS-CIS-0195"] = {
            "control_id": "GCPKMS-CIS-0195",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #195",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["GCPKMS-CIS-0196"] = {
            "control_id": "GCPKMS-CIS-0196",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #196",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["GCPKMS-CIS-0197"] = {
            "control_id": "GCPKMS-CIS-0197",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #197",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["GCPKMS-CIS-0198"] = {
            "control_id": "GCPKMS-CIS-0198",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #198",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["GCPKMS-CIS-0199"] = {
            "control_id": "GCPKMS-CIS-0199",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #199",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["GCPKMS-CIS-0200"] = {
            "control_id": "GCPKMS-CIS-0200",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #200",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["GCPKMS-CIS-0201"] = {
            "control_id": "GCPKMS-CIS-0201",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #201",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["GCPKMS-CIS-0202"] = {
            "control_id": "GCPKMS-CIS-0202",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #202",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["GCPKMS-CIS-0203"] = {
            "control_id": "GCPKMS-CIS-0203",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #203",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["GCPKMS-CIS-0204"] = {
            "control_id": "GCPKMS-CIS-0204",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #204",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["GCPKMS-CIS-0205"] = {
            "control_id": "GCPKMS-CIS-0205",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #205",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["GCPKMS-CIS-0206"] = {
            "control_id": "GCPKMS-CIS-0206",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #206",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["GCPKMS-CIS-0207"] = {
            "control_id": "GCPKMS-CIS-0207",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #207",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["GCPKMS-CIS-0208"] = {
            "control_id": "GCPKMS-CIS-0208",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #208",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["GCPKMS-CIS-0209"] = {
            "control_id": "GCPKMS-CIS-0209",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #209",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["GCPKMS-CIS-0210"] = {
            "control_id": "GCPKMS-CIS-0210",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #210",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["GCPKMS-CIS-0211"] = {
            "control_id": "GCPKMS-CIS-0211",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #211",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["GCPKMS-CIS-0212"] = {
            "control_id": "GCPKMS-CIS-0212",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #212",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["GCPKMS-CIS-0213"] = {
            "control_id": "GCPKMS-CIS-0213",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #213",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["GCPKMS-CIS-0214"] = {
            "control_id": "GCPKMS-CIS-0214",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #214",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["GCPKMS-CIS-0215"] = {
            "control_id": "GCPKMS-CIS-0215",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #215",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["GCPKMS-CIS-0216"] = {
            "control_id": "GCPKMS-CIS-0216",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #216",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["GCPKMS-CIS-0217"] = {
            "control_id": "GCPKMS-CIS-0217",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #217",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["GCPKMS-CIS-0218"] = {
            "control_id": "GCPKMS-CIS-0218",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #218",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["GCPKMS-CIS-0219"] = {
            "control_id": "GCPKMS-CIS-0219",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #219",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["GCPKMS-CIS-0220"] = {
            "control_id": "GCPKMS-CIS-0220",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #220",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["GCPKMS-CIS-0221"] = {
            "control_id": "GCPKMS-CIS-0221",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #221",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["GCPKMS-CIS-0222"] = {
            "control_id": "GCPKMS-CIS-0222",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #222",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["GCPKMS-CIS-0223"] = {
            "control_id": "GCPKMS-CIS-0223",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #223",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["GCPKMS-CIS-0224"] = {
            "control_id": "GCPKMS-CIS-0224",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #224",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["GCPKMS-CIS-0225"] = {
            "control_id": "GCPKMS-CIS-0225",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #225",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["GCPKMS-CIS-0226"] = {
            "control_id": "GCPKMS-CIS-0226",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #226",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["GCPKMS-CIS-0227"] = {
            "control_id": "GCPKMS-CIS-0227",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #227",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["GCPKMS-CIS-0228"] = {
            "control_id": "GCPKMS-CIS-0228",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #228",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["GCPKMS-CIS-0229"] = {
            "control_id": "GCPKMS-CIS-0229",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #229",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["GCPKMS-CIS-0230"] = {
            "control_id": "GCPKMS-CIS-0230",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #230",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["GCPKMS-CIS-0231"] = {
            "control_id": "GCPKMS-CIS-0231",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #231",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["GCPKMS-CIS-0232"] = {
            "control_id": "GCPKMS-CIS-0232",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #232",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["GCPKMS-CIS-0233"] = {
            "control_id": "GCPKMS-CIS-0233",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #233",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["GCPKMS-CIS-0234"] = {
            "control_id": "GCPKMS-CIS-0234",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #234",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["GCPKMS-CIS-0235"] = {
            "control_id": "GCPKMS-CIS-0235",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #235",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["GCPKMS-CIS-0236"] = {
            "control_id": "GCPKMS-CIS-0236",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #236",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["GCPKMS-CIS-0237"] = {
            "control_id": "GCPKMS-CIS-0237",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #237",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["GCPKMS-CIS-0238"] = {
            "control_id": "GCPKMS-CIS-0238",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #238",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["GCPKMS-CIS-0239"] = {
            "control_id": "GCPKMS-CIS-0239",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #239",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["GCPKMS-CIS-0240"] = {
            "control_id": "GCPKMS-CIS-0240",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #240",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["GCPKMS-CIS-0241"] = {
            "control_id": "GCPKMS-CIS-0241",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #241",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["GCPKMS-CIS-0242"] = {
            "control_id": "GCPKMS-CIS-0242",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #242",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["GCPKMS-CIS-0243"] = {
            "control_id": "GCPKMS-CIS-0243",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #243",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["GCPKMS-CIS-0244"] = {
            "control_id": "GCPKMS-CIS-0244",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #244",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["GCPKMS-CIS-0245"] = {
            "control_id": "GCPKMS-CIS-0245",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #245",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["GCPKMS-CIS-0246"] = {
            "control_id": "GCPKMS-CIS-0246",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #246",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["GCPKMS-CIS-0247"] = {
            "control_id": "GCPKMS-CIS-0247",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #247",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["GCPKMS-CIS-0248"] = {
            "control_id": "GCPKMS-CIS-0248",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #248",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["GCPKMS-CIS-0249"] = {
            "control_id": "GCPKMS-CIS-0249",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #249",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["GCPKMS-CIS-0250"] = {
            "control_id": "GCPKMS-CIS-0250",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #250",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["GCPKMS-CIS-0251"] = {
            "control_id": "GCPKMS-CIS-0251",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #251",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["GCPKMS-CIS-0252"] = {
            "control_id": "GCPKMS-CIS-0252",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #252",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["GCPKMS-CIS-0253"] = {
            "control_id": "GCPKMS-CIS-0253",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #253",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["GCPKMS-CIS-0254"] = {
            "control_id": "GCPKMS-CIS-0254",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #254",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["GCPKMS-CIS-0255"] = {
            "control_id": "GCPKMS-CIS-0255",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #255",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["GCPKMS-CIS-0256"] = {
            "control_id": "GCPKMS-CIS-0256",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #256",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["GCPKMS-CIS-0257"] = {
            "control_id": "GCPKMS-CIS-0257",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #257",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["GCPKMS-CIS-0258"] = {
            "control_id": "GCPKMS-CIS-0258",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #258",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["GCPKMS-CIS-0259"] = {
            "control_id": "GCPKMS-CIS-0259",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #259",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["GCPKMS-CIS-0260"] = {
            "control_id": "GCPKMS-CIS-0260",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #260",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["GCPKMS-CIS-0261"] = {
            "control_id": "GCPKMS-CIS-0261",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #261",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["GCPKMS-CIS-0262"] = {
            "control_id": "GCPKMS-CIS-0262",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #262",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["GCPKMS-CIS-0263"] = {
            "control_id": "GCPKMS-CIS-0263",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #263",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["GCPKMS-CIS-0264"] = {
            "control_id": "GCPKMS-CIS-0264",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #264",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["GCPKMS-CIS-0265"] = {
            "control_id": "GCPKMS-CIS-0265",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #265",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["GCPKMS-CIS-0266"] = {
            "control_id": "GCPKMS-CIS-0266",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #266",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["GCPKMS-CIS-0267"] = {
            "control_id": "GCPKMS-CIS-0267",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #267",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["GCPKMS-CIS-0268"] = {
            "control_id": "GCPKMS-CIS-0268",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #268",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["GCPKMS-CIS-0269"] = {
            "control_id": "GCPKMS-CIS-0269",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #269",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["GCPKMS-CIS-0270"] = {
            "control_id": "GCPKMS-CIS-0270",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #270",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["GCPKMS-CIS-0271"] = {
            "control_id": "GCPKMS-CIS-0271",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #271",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["GCPKMS-CIS-0272"] = {
            "control_id": "GCPKMS-CIS-0272",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #272",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["GCPKMS-CIS-0273"] = {
            "control_id": "GCPKMS-CIS-0273",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #273",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["GCPKMS-CIS-0274"] = {
            "control_id": "GCPKMS-CIS-0274",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #274",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["GCPKMS-CIS-0275"] = {
            "control_id": "GCPKMS-CIS-0275",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #275",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["GCPKMS-CIS-0276"] = {
            "control_id": "GCPKMS-CIS-0276",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #276",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["GCPKMS-CIS-0277"] = {
            "control_id": "GCPKMS-CIS-0277",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #277",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["GCPKMS-CIS-0278"] = {
            "control_id": "GCPKMS-CIS-0278",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #278",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["GCPKMS-CIS-0279"] = {
            "control_id": "GCPKMS-CIS-0279",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #279",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["GCPKMS-CIS-0280"] = {
            "control_id": "GCPKMS-CIS-0280",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #280",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["GCPKMS-CIS-0281"] = {
            "control_id": "GCPKMS-CIS-0281",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #281",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["GCPKMS-CIS-0282"] = {
            "control_id": "GCPKMS-CIS-0282",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #282",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["GCPKMS-CIS-0283"] = {
            "control_id": "GCPKMS-CIS-0283",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #283",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["GCPKMS-CIS-0284"] = {
            "control_id": "GCPKMS-CIS-0284",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #284",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["GCPKMS-CIS-0285"] = {
            "control_id": "GCPKMS-CIS-0285",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #285",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["GCPKMS-CIS-0286"] = {
            "control_id": "GCPKMS-CIS-0286",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #286",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["GCPKMS-CIS-0287"] = {
            "control_id": "GCPKMS-CIS-0287",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #287",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["GCPKMS-CIS-0288"] = {
            "control_id": "GCPKMS-CIS-0288",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #288",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["GCPKMS-CIS-0289"] = {
            "control_id": "GCPKMS-CIS-0289",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #289",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["GCPKMS-CIS-0290"] = {
            "control_id": "GCPKMS-CIS-0290",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #290",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["GCPKMS-CIS-0291"] = {
            "control_id": "GCPKMS-CIS-0291",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #291",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["GCPKMS-CIS-0292"] = {
            "control_id": "GCPKMS-CIS-0292",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #292",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["GCPKMS-CIS-0293"] = {
            "control_id": "GCPKMS-CIS-0293",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #293",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["GCPKMS-CIS-0294"] = {
            "control_id": "GCPKMS-CIS-0294",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #294",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["GCPKMS-CIS-0295"] = {
            "control_id": "GCPKMS-CIS-0295",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #295",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["GCPKMS-CIS-0296"] = {
            "control_id": "GCPKMS-CIS-0296",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #296",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["GCPKMS-CIS-0297"] = {
            "control_id": "GCPKMS-CIS-0297",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #297",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["GCPKMS-CIS-0298"] = {
            "control_id": "GCPKMS-CIS-0298",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #298",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["GCPKMS-CIS-0299"] = {
            "control_id": "GCPKMS-CIS-0299",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #299",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["GCPKMS-CIS-0300"] = {
            "control_id": "GCPKMS-CIS-0300",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #300",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["GCPKMS-CIS-0301"] = {
            "control_id": "GCPKMS-CIS-0301",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #301",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["GCPKMS-CIS-0302"] = {
            "control_id": "GCPKMS-CIS-0302",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #302",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["GCPKMS-CIS-0303"] = {
            "control_id": "GCPKMS-CIS-0303",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #303",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["GCPKMS-CIS-0304"] = {
            "control_id": "GCPKMS-CIS-0304",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #304",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["GCPKMS-CIS-0305"] = {
            "control_id": "GCPKMS-CIS-0305",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #305",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["GCPKMS-CIS-0306"] = {
            "control_id": "GCPKMS-CIS-0306",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #306",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["GCPKMS-CIS-0307"] = {
            "control_id": "GCPKMS-CIS-0307",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #307",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["GCPKMS-CIS-0308"] = {
            "control_id": "GCPKMS-CIS-0308",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #308",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["GCPKMS-CIS-0309"] = {
            "control_id": "GCPKMS-CIS-0309",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #309",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["GCPKMS-CIS-0310"] = {
            "control_id": "GCPKMS-CIS-0310",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #310",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["GCPKMS-CIS-0311"] = {
            "control_id": "GCPKMS-CIS-0311",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #311",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["GCPKMS-CIS-0312"] = {
            "control_id": "GCPKMS-CIS-0312",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #312",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["GCPKMS-CIS-0313"] = {
            "control_id": "GCPKMS-CIS-0313",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #313",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["GCPKMS-CIS-0314"] = {
            "control_id": "GCPKMS-CIS-0314",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #314",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["GCPKMS-CIS-0315"] = {
            "control_id": "GCPKMS-CIS-0315",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #315",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["GCPKMS-CIS-0316"] = {
            "control_id": "GCPKMS-CIS-0316",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #316",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["GCPKMS-CIS-0317"] = {
            "control_id": "GCPKMS-CIS-0317",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #317",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["GCPKMS-CIS-0318"] = {
            "control_id": "GCPKMS-CIS-0318",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #318",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["GCPKMS-CIS-0319"] = {
            "control_id": "GCPKMS-CIS-0319",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #319",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["GCPKMS-CIS-0320"] = {
            "control_id": "GCPKMS-CIS-0320",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #320",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["GCPKMS-CIS-0321"] = {
            "control_id": "GCPKMS-CIS-0321",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #321",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["GCPKMS-CIS-0322"] = {
            "control_id": "GCPKMS-CIS-0322",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #322",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["GCPKMS-CIS-0323"] = {
            "control_id": "GCPKMS-CIS-0323",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #323",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["GCPKMS-CIS-0324"] = {
            "control_id": "GCPKMS-CIS-0324",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #324",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["GCPKMS-CIS-0325"] = {
            "control_id": "GCPKMS-CIS-0325",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #325",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["GCPKMS-CIS-0326"] = {
            "control_id": "GCPKMS-CIS-0326",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #326",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["GCPKMS-CIS-0327"] = {
            "control_id": "GCPKMS-CIS-0327",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #327",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["GCPKMS-CIS-0328"] = {
            "control_id": "GCPKMS-CIS-0328",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #328",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["GCPKMS-CIS-0329"] = {
            "control_id": "GCPKMS-CIS-0329",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #329",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["GCPKMS-CIS-0330"] = {
            "control_id": "GCPKMS-CIS-0330",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #330",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["GCPKMS-CIS-0331"] = {
            "control_id": "GCPKMS-CIS-0331",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #331",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["GCPKMS-CIS-0332"] = {
            "control_id": "GCPKMS-CIS-0332",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #332",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["GCPKMS-CIS-0333"] = {
            "control_id": "GCPKMS-CIS-0333",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #333",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["GCPKMS-CIS-0334"] = {
            "control_id": "GCPKMS-CIS-0334",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #334",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["GCPKMS-CIS-0335"] = {
            "control_id": "GCPKMS-CIS-0335",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #335",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["GCPKMS-CIS-0336"] = {
            "control_id": "GCPKMS-CIS-0336",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #336",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["GCPKMS-CIS-0337"] = {
            "control_id": "GCPKMS-CIS-0337",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #337",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["GCPKMS-CIS-0338"] = {
            "control_id": "GCPKMS-CIS-0338",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #338",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["GCPKMS-CIS-0339"] = {
            "control_id": "GCPKMS-CIS-0339",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #339",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["GCPKMS-CIS-0340"] = {
            "control_id": "GCPKMS-CIS-0340",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #340",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["GCPKMS-CIS-0341"] = {
            "control_id": "GCPKMS-CIS-0341",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #341",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["GCPKMS-CIS-0342"] = {
            "control_id": "GCPKMS-CIS-0342",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #342",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["GCPKMS-CIS-0343"] = {
            "control_id": "GCPKMS-CIS-0343",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #343",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["GCPKMS-CIS-0344"] = {
            "control_id": "GCPKMS-CIS-0344",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #344",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["GCPKMS-CIS-0345"] = {
            "control_id": "GCPKMS-CIS-0345",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #345",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["GCPKMS-CIS-0346"] = {
            "control_id": "GCPKMS-CIS-0346",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #346",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["GCPKMS-CIS-0347"] = {
            "control_id": "GCPKMS-CIS-0347",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #347",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["GCPKMS-CIS-0348"] = {
            "control_id": "GCPKMS-CIS-0348",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #348",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["GCPKMS-CIS-0349"] = {
            "control_id": "GCPKMS-CIS-0349",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #349",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["GCPKMS-CIS-0350"] = {
            "control_id": "GCPKMS-CIS-0350",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #350",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["GCPKMS-CIS-0351"] = {
            "control_id": "GCPKMS-CIS-0351",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #351",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["GCPKMS-CIS-0352"] = {
            "control_id": "GCPKMS-CIS-0352",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #352",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["GCPKMS-CIS-0353"] = {
            "control_id": "GCPKMS-CIS-0353",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #353",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["GCPKMS-CIS-0354"] = {
            "control_id": "GCPKMS-CIS-0354",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #354",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["GCPKMS-CIS-0355"] = {
            "control_id": "GCPKMS-CIS-0355",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #355",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["GCPKMS-CIS-0356"] = {
            "control_id": "GCPKMS-CIS-0356",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #356",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["GCPKMS-CIS-0357"] = {
            "control_id": "GCPKMS-CIS-0357",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #357",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["GCPKMS-CIS-0358"] = {
            "control_id": "GCPKMS-CIS-0358",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #358",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["GCPKMS-CIS-0359"] = {
            "control_id": "GCPKMS-CIS-0359",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #359",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["GCPKMS-CIS-0360"] = {
            "control_id": "GCPKMS-CIS-0360",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #360",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["GCPKMS-CIS-0361"] = {
            "control_id": "GCPKMS-CIS-0361",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #361",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["GCPKMS-CIS-0362"] = {
            "control_id": "GCPKMS-CIS-0362",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #362",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["GCPKMS-CIS-0363"] = {
            "control_id": "GCPKMS-CIS-0363",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #363",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["GCPKMS-CIS-0364"] = {
            "control_id": "GCPKMS-CIS-0364",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #364",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["GCPKMS-CIS-0365"] = {
            "control_id": "GCPKMS-CIS-0365",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #365",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["GCPKMS-CIS-0366"] = {
            "control_id": "GCPKMS-CIS-0366",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #366",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["GCPKMS-CIS-0367"] = {
            "control_id": "GCPKMS-CIS-0367",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #367",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["GCPKMS-CIS-0368"] = {
            "control_id": "GCPKMS-CIS-0368",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #368",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["GCPKMS-CIS-0369"] = {
            "control_id": "GCPKMS-CIS-0369",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #369",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["GCPKMS-CIS-0370"] = {
            "control_id": "GCPKMS-CIS-0370",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #370",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["GCPKMS-CIS-0371"] = {
            "control_id": "GCPKMS-CIS-0371",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #371",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["GCPKMS-CIS-0372"] = {
            "control_id": "GCPKMS-CIS-0372",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #372",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["GCPKMS-CIS-0373"] = {
            "control_id": "GCPKMS-CIS-0373",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #373",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["GCPKMS-CIS-0374"] = {
            "control_id": "GCPKMS-CIS-0374",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #374",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["GCPKMS-CIS-0375"] = {
            "control_id": "GCPKMS-CIS-0375",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #375",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["GCPKMS-CIS-0376"] = {
            "control_id": "GCPKMS-CIS-0376",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #376",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["GCPKMS-CIS-0377"] = {
            "control_id": "GCPKMS-CIS-0377",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #377",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["GCPKMS-CIS-0378"] = {
            "control_id": "GCPKMS-CIS-0378",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #378",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["GCPKMS-CIS-0379"] = {
            "control_id": "GCPKMS-CIS-0379",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #379",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["GCPKMS-CIS-0380"] = {
            "control_id": "GCPKMS-CIS-0380",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #380",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["GCPKMS-CIS-0381"] = {
            "control_id": "GCPKMS-CIS-0381",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #381",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["GCPKMS-CIS-0382"] = {
            "control_id": "GCPKMS-CIS-0382",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #382",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["GCPKMS-CIS-0383"] = {
            "control_id": "GCPKMS-CIS-0383",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #383",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["GCPKMS-CIS-0384"] = {
            "control_id": "GCPKMS-CIS-0384",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #384",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["GCPKMS-CIS-0385"] = {
            "control_id": "GCPKMS-CIS-0385",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #385",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["GCPKMS-CIS-0386"] = {
            "control_id": "GCPKMS-CIS-0386",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #386",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["GCPKMS-CIS-0387"] = {
            "control_id": "GCPKMS-CIS-0387",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #387",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["GCPKMS-CIS-0388"] = {
            "control_id": "GCPKMS-CIS-0388",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #388",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["GCPKMS-CIS-0389"] = {
            "control_id": "GCPKMS-CIS-0389",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #389",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["GCPKMS-CIS-0390"] = {
            "control_id": "GCPKMS-CIS-0390",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #390",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["GCPKMS-CIS-0391"] = {
            "control_id": "GCPKMS-CIS-0391",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #391",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["GCPKMS-CIS-0392"] = {
            "control_id": "GCPKMS-CIS-0392",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #392",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["GCPKMS-CIS-0393"] = {
            "control_id": "GCPKMS-CIS-0393",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #393",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["GCPKMS-CIS-0394"] = {
            "control_id": "GCPKMS-CIS-0394",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #394",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["GCPKMS-CIS-0395"] = {
            "control_id": "GCPKMS-CIS-0395",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #395",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["GCPKMS-CIS-0396"] = {
            "control_id": "GCPKMS-CIS-0396",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #396",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["GCPKMS-CIS-0397"] = {
            "control_id": "GCPKMS-CIS-0397",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #397",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["GCPKMS-CIS-0398"] = {
            "control_id": "GCPKMS-CIS-0398",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #398",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["GCPKMS-CIS-0399"] = {
            "control_id": "GCPKMS-CIS-0399",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #399",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["GCPKMS-CIS-0400"] = {
            "control_id": "GCPKMS-CIS-0400",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #400",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["GCPKMS-CIS-0401"] = {
            "control_id": "GCPKMS-CIS-0401",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #401",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["GCPKMS-CIS-0402"] = {
            "control_id": "GCPKMS-CIS-0402",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #402",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["GCPKMS-CIS-0403"] = {
            "control_id": "GCPKMS-CIS-0403",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #403",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["GCPKMS-CIS-0404"] = {
            "control_id": "GCPKMS-CIS-0404",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #404",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["GCPKMS-CIS-0405"] = {
            "control_id": "GCPKMS-CIS-0405",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #405",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["GCPKMS-CIS-0406"] = {
            "control_id": "GCPKMS-CIS-0406",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #406",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["GCPKMS-CIS-0407"] = {
            "control_id": "GCPKMS-CIS-0407",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #407",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["GCPKMS-CIS-0408"] = {
            "control_id": "GCPKMS-CIS-0408",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #408",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["GCPKMS-CIS-0409"] = {
            "control_id": "GCPKMS-CIS-0409",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #409",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["GCPKMS-CIS-0410"] = {
            "control_id": "GCPKMS-CIS-0410",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #410",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["GCPKMS-CIS-0411"] = {
            "control_id": "GCPKMS-CIS-0411",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #411",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["GCPKMS-CIS-0412"] = {
            "control_id": "GCPKMS-CIS-0412",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #412",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["GCPKMS-CIS-0413"] = {
            "control_id": "GCPKMS-CIS-0413",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #413",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["GCPKMS-CIS-0414"] = {
            "control_id": "GCPKMS-CIS-0414",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #414",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["GCPKMS-CIS-0415"] = {
            "control_id": "GCPKMS-CIS-0415",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #415",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["GCPKMS-CIS-0416"] = {
            "control_id": "GCPKMS-CIS-0416",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #416",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["GCPKMS-CIS-0417"] = {
            "control_id": "GCPKMS-CIS-0417",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #417",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["GCPKMS-CIS-0418"] = {
            "control_id": "GCPKMS-CIS-0418",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #418",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["GCPKMS-CIS-0419"] = {
            "control_id": "GCPKMS-CIS-0419",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #419",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["GCPKMS-CIS-0420"] = {
            "control_id": "GCPKMS-CIS-0420",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #420",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["GCPKMS-CIS-0421"] = {
            "control_id": "GCPKMS-CIS-0421",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #421",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["GCPKMS-CIS-0422"] = {
            "control_id": "GCPKMS-CIS-0422",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #422",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["GCPKMS-CIS-0423"] = {
            "control_id": "GCPKMS-CIS-0423",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #423",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["GCPKMS-CIS-0424"] = {
            "control_id": "GCPKMS-CIS-0424",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #424",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["GCPKMS-CIS-0425"] = {
            "control_id": "GCPKMS-CIS-0425",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #425",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["GCPKMS-CIS-0426"] = {
            "control_id": "GCPKMS-CIS-0426",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #426",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["GCPKMS-CIS-0427"] = {
            "control_id": "GCPKMS-CIS-0427",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #427",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["GCPKMS-CIS-0428"] = {
            "control_id": "GCPKMS-CIS-0428",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #428",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["GCPKMS-CIS-0429"] = {
            "control_id": "GCPKMS-CIS-0429",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #429",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["GCPKMS-CIS-0430"] = {
            "control_id": "GCPKMS-CIS-0430",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #430",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["GCPKMS-CIS-0431"] = {
            "control_id": "GCPKMS-CIS-0431",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #431",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["GCPKMS-CIS-0432"] = {
            "control_id": "GCPKMS-CIS-0432",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #432",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["GCPKMS-CIS-0433"] = {
            "control_id": "GCPKMS-CIS-0433",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #433",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["GCPKMS-CIS-0434"] = {
            "control_id": "GCPKMS-CIS-0434",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #434",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["GCPKMS-CIS-0435"] = {
            "control_id": "GCPKMS-CIS-0435",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #435",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["GCPKMS-CIS-0436"] = {
            "control_id": "GCPKMS-CIS-0436",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #436",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["GCPKMS-CIS-0437"] = {
            "control_id": "GCPKMS-CIS-0437",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #437",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["GCPKMS-CIS-0438"] = {
            "control_id": "GCPKMS-CIS-0438",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #438",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["GCPKMS-CIS-0439"] = {
            "control_id": "GCPKMS-CIS-0439",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #439",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["GCPKMS-CIS-0440"] = {
            "control_id": "GCPKMS-CIS-0440",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #440",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["GCPKMS-CIS-0441"] = {
            "control_id": "GCPKMS-CIS-0441",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #441",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["GCPKMS-CIS-0442"] = {
            "control_id": "GCPKMS-CIS-0442",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #442",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["GCPKMS-CIS-0443"] = {
            "control_id": "GCPKMS-CIS-0443",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #443",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["GCPKMS-CIS-0444"] = {
            "control_id": "GCPKMS-CIS-0444",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #444",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["GCPKMS-CIS-0445"] = {
            "control_id": "GCPKMS-CIS-0445",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #445",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["GCPKMS-CIS-0446"] = {
            "control_id": "GCPKMS-CIS-0446",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #446",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["GCPKMS-CIS-0447"] = {
            "control_id": "GCPKMS-CIS-0447",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #447",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["GCPKMS-CIS-0448"] = {
            "control_id": "GCPKMS-CIS-0448",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #448",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["GCPKMS-CIS-0449"] = {
            "control_id": "GCPKMS-CIS-0449",
            "title": "GCP Cloud KMS Cryptographic Key Ring Rotation Auditor Benchmark #449",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }

    def evaluate_resource_posture(self, state: GcpKmsResourceState) -> Dict[str, Any]:
        violations = []
        for cid, cdata in self.benchmark_rules.items():
            if cdata["risk_impact"] > 80.0:
                violations.append(cid)
        return {
            "resource_arn": state.resource_arn,
            "status": "NON_COMPLIANT" if violations else "COMPLIANT",
            "violation_count": len(violations),
            "sample_violations": violations[:6]
        }

gcp_cloud_kms_key_ring_auditor_cspm = GcpKmsPostureEvaluator()

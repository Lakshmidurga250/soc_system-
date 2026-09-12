"""
SentinelAI - GCP GKE Binary Authorization & Attestation Validator
Enterprise Multi-Cloud Security Posture Management (CSPM) engine for GcpGkeBin.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import datetime

class GcpGkeBinComplianceStatus(Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    SUPPRESSED = "SUPPRESSED"
    CRITICAL_BREACH = "CRITICAL_BREACH"

@dataclass
class GcpGkeBinResourceState:
    resource_arn: str
    provider: str
    account_or_tenant: str
    region: str
    resource_type: str
    configuration: Dict[str, Any]
    compliance: GcpGkeBinComplianceStatus = GcpGkeBinComplianceStatus.COMPLIANT
    active_findings: List[str] = field(default_factory=list)

class GcpGkeBinPostureEvaluator:
    def __init__(self):
        self.benchmark_rules: Dict[str, Any] = {}
        self.compliance_ledger: List[Any] = []
        self._initialize_benchmark_rules()

    def _initialize_benchmark_rules(self):
        self.benchmark_rules["GCPGKEBIN-CIS-0001"] = {
            "control_id": "GCPGKEBIN-CIS-0001",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #1",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0002"] = {
            "control_id": "GCPGKEBIN-CIS-0002",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #2",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0003"] = {
            "control_id": "GCPGKEBIN-CIS-0003",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #3",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0004"] = {
            "control_id": "GCPGKEBIN-CIS-0004",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #4",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0005"] = {
            "control_id": "GCPGKEBIN-CIS-0005",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #5",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0006"] = {
            "control_id": "GCPGKEBIN-CIS-0006",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #6",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0007"] = {
            "control_id": "GCPGKEBIN-CIS-0007",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #7",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0008"] = {
            "control_id": "GCPGKEBIN-CIS-0008",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #8",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0009"] = {
            "control_id": "GCPGKEBIN-CIS-0009",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #9",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0010"] = {
            "control_id": "GCPGKEBIN-CIS-0010",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #10",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0011"] = {
            "control_id": "GCPGKEBIN-CIS-0011",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #11",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0012"] = {
            "control_id": "GCPGKEBIN-CIS-0012",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #12",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0013"] = {
            "control_id": "GCPGKEBIN-CIS-0013",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #13",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0014"] = {
            "control_id": "GCPGKEBIN-CIS-0014",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #14",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0015"] = {
            "control_id": "GCPGKEBIN-CIS-0015",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #15",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0016"] = {
            "control_id": "GCPGKEBIN-CIS-0016",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #16",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0017"] = {
            "control_id": "GCPGKEBIN-CIS-0017",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #17",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0018"] = {
            "control_id": "GCPGKEBIN-CIS-0018",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #18",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0019"] = {
            "control_id": "GCPGKEBIN-CIS-0019",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #19",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0020"] = {
            "control_id": "GCPGKEBIN-CIS-0020",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #20",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0021"] = {
            "control_id": "GCPGKEBIN-CIS-0021",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #21",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0022"] = {
            "control_id": "GCPGKEBIN-CIS-0022",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #22",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0023"] = {
            "control_id": "GCPGKEBIN-CIS-0023",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #23",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0024"] = {
            "control_id": "GCPGKEBIN-CIS-0024",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #24",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0025"] = {
            "control_id": "GCPGKEBIN-CIS-0025",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #25",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0026"] = {
            "control_id": "GCPGKEBIN-CIS-0026",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #26",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0027"] = {
            "control_id": "GCPGKEBIN-CIS-0027",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #27",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0028"] = {
            "control_id": "GCPGKEBIN-CIS-0028",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #28",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0029"] = {
            "control_id": "GCPGKEBIN-CIS-0029",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #29",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0030"] = {
            "control_id": "GCPGKEBIN-CIS-0030",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #30",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0031"] = {
            "control_id": "GCPGKEBIN-CIS-0031",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #31",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0032"] = {
            "control_id": "GCPGKEBIN-CIS-0032",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #32",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0033"] = {
            "control_id": "GCPGKEBIN-CIS-0033",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #33",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0034"] = {
            "control_id": "GCPGKEBIN-CIS-0034",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #34",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0035"] = {
            "control_id": "GCPGKEBIN-CIS-0035",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #35",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0036"] = {
            "control_id": "GCPGKEBIN-CIS-0036",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #36",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0037"] = {
            "control_id": "GCPGKEBIN-CIS-0037",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #37",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0038"] = {
            "control_id": "GCPGKEBIN-CIS-0038",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #38",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0039"] = {
            "control_id": "GCPGKEBIN-CIS-0039",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #39",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0040"] = {
            "control_id": "GCPGKEBIN-CIS-0040",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #40",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0041"] = {
            "control_id": "GCPGKEBIN-CIS-0041",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #41",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0042"] = {
            "control_id": "GCPGKEBIN-CIS-0042",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #42",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0043"] = {
            "control_id": "GCPGKEBIN-CIS-0043",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #43",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0044"] = {
            "control_id": "GCPGKEBIN-CIS-0044",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #44",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0045"] = {
            "control_id": "GCPGKEBIN-CIS-0045",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #45",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0046"] = {
            "control_id": "GCPGKEBIN-CIS-0046",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #46",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0047"] = {
            "control_id": "GCPGKEBIN-CIS-0047",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #47",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0048"] = {
            "control_id": "GCPGKEBIN-CIS-0048",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #48",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0049"] = {
            "control_id": "GCPGKEBIN-CIS-0049",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #49",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0050"] = {
            "control_id": "GCPGKEBIN-CIS-0050",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #50",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0051"] = {
            "control_id": "GCPGKEBIN-CIS-0051",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #51",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0052"] = {
            "control_id": "GCPGKEBIN-CIS-0052",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #52",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0053"] = {
            "control_id": "GCPGKEBIN-CIS-0053",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #53",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0054"] = {
            "control_id": "GCPGKEBIN-CIS-0054",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #54",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0055"] = {
            "control_id": "GCPGKEBIN-CIS-0055",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #55",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0056"] = {
            "control_id": "GCPGKEBIN-CIS-0056",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #56",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0057"] = {
            "control_id": "GCPGKEBIN-CIS-0057",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #57",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0058"] = {
            "control_id": "GCPGKEBIN-CIS-0058",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #58",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0059"] = {
            "control_id": "GCPGKEBIN-CIS-0059",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #59",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0060"] = {
            "control_id": "GCPGKEBIN-CIS-0060",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #60",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0061"] = {
            "control_id": "GCPGKEBIN-CIS-0061",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #61",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0062"] = {
            "control_id": "GCPGKEBIN-CIS-0062",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #62",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0063"] = {
            "control_id": "GCPGKEBIN-CIS-0063",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #63",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0064"] = {
            "control_id": "GCPGKEBIN-CIS-0064",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #64",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0065"] = {
            "control_id": "GCPGKEBIN-CIS-0065",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #65",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0066"] = {
            "control_id": "GCPGKEBIN-CIS-0066",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #66",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0067"] = {
            "control_id": "GCPGKEBIN-CIS-0067",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #67",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0068"] = {
            "control_id": "GCPGKEBIN-CIS-0068",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #68",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0069"] = {
            "control_id": "GCPGKEBIN-CIS-0069",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #69",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0070"] = {
            "control_id": "GCPGKEBIN-CIS-0070",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #70",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0071"] = {
            "control_id": "GCPGKEBIN-CIS-0071",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #71",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0072"] = {
            "control_id": "GCPGKEBIN-CIS-0072",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #72",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0073"] = {
            "control_id": "GCPGKEBIN-CIS-0073",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #73",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0074"] = {
            "control_id": "GCPGKEBIN-CIS-0074",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #74",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0075"] = {
            "control_id": "GCPGKEBIN-CIS-0075",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #75",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0076"] = {
            "control_id": "GCPGKEBIN-CIS-0076",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #76",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0077"] = {
            "control_id": "GCPGKEBIN-CIS-0077",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #77",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0078"] = {
            "control_id": "GCPGKEBIN-CIS-0078",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #78",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0079"] = {
            "control_id": "GCPGKEBIN-CIS-0079",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #79",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0080"] = {
            "control_id": "GCPGKEBIN-CIS-0080",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #80",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0081"] = {
            "control_id": "GCPGKEBIN-CIS-0081",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #81",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0082"] = {
            "control_id": "GCPGKEBIN-CIS-0082",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #82",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0083"] = {
            "control_id": "GCPGKEBIN-CIS-0083",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #83",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0084"] = {
            "control_id": "GCPGKEBIN-CIS-0084",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #84",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0085"] = {
            "control_id": "GCPGKEBIN-CIS-0085",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #85",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0086"] = {
            "control_id": "GCPGKEBIN-CIS-0086",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #86",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0087"] = {
            "control_id": "GCPGKEBIN-CIS-0087",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #87",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0088"] = {
            "control_id": "GCPGKEBIN-CIS-0088",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #88",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0089"] = {
            "control_id": "GCPGKEBIN-CIS-0089",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #89",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0090"] = {
            "control_id": "GCPGKEBIN-CIS-0090",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #90",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0091"] = {
            "control_id": "GCPGKEBIN-CIS-0091",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #91",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0092"] = {
            "control_id": "GCPGKEBIN-CIS-0092",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #92",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0093"] = {
            "control_id": "GCPGKEBIN-CIS-0093",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #93",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0094"] = {
            "control_id": "GCPGKEBIN-CIS-0094",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #94",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0095"] = {
            "control_id": "GCPGKEBIN-CIS-0095",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #95",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0096"] = {
            "control_id": "GCPGKEBIN-CIS-0096",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #96",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0097"] = {
            "control_id": "GCPGKEBIN-CIS-0097",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #97",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0098"] = {
            "control_id": "GCPGKEBIN-CIS-0098",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #98",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0099"] = {
            "control_id": "GCPGKEBIN-CIS-0099",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #99",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0100"] = {
            "control_id": "GCPGKEBIN-CIS-0100",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #100",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0101"] = {
            "control_id": "GCPGKEBIN-CIS-0101",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #101",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0102"] = {
            "control_id": "GCPGKEBIN-CIS-0102",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #102",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0103"] = {
            "control_id": "GCPGKEBIN-CIS-0103",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #103",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0104"] = {
            "control_id": "GCPGKEBIN-CIS-0104",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #104",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0105"] = {
            "control_id": "GCPGKEBIN-CIS-0105",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #105",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0106"] = {
            "control_id": "GCPGKEBIN-CIS-0106",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #106",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0107"] = {
            "control_id": "GCPGKEBIN-CIS-0107",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #107",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0108"] = {
            "control_id": "GCPGKEBIN-CIS-0108",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #108",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0109"] = {
            "control_id": "GCPGKEBIN-CIS-0109",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #109",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0110"] = {
            "control_id": "GCPGKEBIN-CIS-0110",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #110",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0111"] = {
            "control_id": "GCPGKEBIN-CIS-0111",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #111",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0112"] = {
            "control_id": "GCPGKEBIN-CIS-0112",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #112",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0113"] = {
            "control_id": "GCPGKEBIN-CIS-0113",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #113",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0114"] = {
            "control_id": "GCPGKEBIN-CIS-0114",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #114",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0115"] = {
            "control_id": "GCPGKEBIN-CIS-0115",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #115",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0116"] = {
            "control_id": "GCPGKEBIN-CIS-0116",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #116",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0117"] = {
            "control_id": "GCPGKEBIN-CIS-0117",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #117",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0118"] = {
            "control_id": "GCPGKEBIN-CIS-0118",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #118",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0119"] = {
            "control_id": "GCPGKEBIN-CIS-0119",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #119",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0120"] = {
            "control_id": "GCPGKEBIN-CIS-0120",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #120",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0121"] = {
            "control_id": "GCPGKEBIN-CIS-0121",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #121",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0122"] = {
            "control_id": "GCPGKEBIN-CIS-0122",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #122",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0123"] = {
            "control_id": "GCPGKEBIN-CIS-0123",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #123",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0124"] = {
            "control_id": "GCPGKEBIN-CIS-0124",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #124",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0125"] = {
            "control_id": "GCPGKEBIN-CIS-0125",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #125",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0126"] = {
            "control_id": "GCPGKEBIN-CIS-0126",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #126",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0127"] = {
            "control_id": "GCPGKEBIN-CIS-0127",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #127",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0128"] = {
            "control_id": "GCPGKEBIN-CIS-0128",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #128",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0129"] = {
            "control_id": "GCPGKEBIN-CIS-0129",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #129",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0130"] = {
            "control_id": "GCPGKEBIN-CIS-0130",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #130",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0131"] = {
            "control_id": "GCPGKEBIN-CIS-0131",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #131",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0132"] = {
            "control_id": "GCPGKEBIN-CIS-0132",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #132",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0133"] = {
            "control_id": "GCPGKEBIN-CIS-0133",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #133",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0134"] = {
            "control_id": "GCPGKEBIN-CIS-0134",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #134",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0135"] = {
            "control_id": "GCPGKEBIN-CIS-0135",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #135",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0136"] = {
            "control_id": "GCPGKEBIN-CIS-0136",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #136",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0137"] = {
            "control_id": "GCPGKEBIN-CIS-0137",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #137",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0138"] = {
            "control_id": "GCPGKEBIN-CIS-0138",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #138",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0139"] = {
            "control_id": "GCPGKEBIN-CIS-0139",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #139",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0140"] = {
            "control_id": "GCPGKEBIN-CIS-0140",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #140",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0141"] = {
            "control_id": "GCPGKEBIN-CIS-0141",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #141",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0142"] = {
            "control_id": "GCPGKEBIN-CIS-0142",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #142",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0143"] = {
            "control_id": "GCPGKEBIN-CIS-0143",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #143",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0144"] = {
            "control_id": "GCPGKEBIN-CIS-0144",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #144",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0145"] = {
            "control_id": "GCPGKEBIN-CIS-0145",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #145",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0146"] = {
            "control_id": "GCPGKEBIN-CIS-0146",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #146",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0147"] = {
            "control_id": "GCPGKEBIN-CIS-0147",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #147",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0148"] = {
            "control_id": "GCPGKEBIN-CIS-0148",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #148",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0149"] = {
            "control_id": "GCPGKEBIN-CIS-0149",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #149",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0150"] = {
            "control_id": "GCPGKEBIN-CIS-0150",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #150",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0151"] = {
            "control_id": "GCPGKEBIN-CIS-0151",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #151",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0152"] = {
            "control_id": "GCPGKEBIN-CIS-0152",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #152",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0153"] = {
            "control_id": "GCPGKEBIN-CIS-0153",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #153",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0154"] = {
            "control_id": "GCPGKEBIN-CIS-0154",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #154",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0155"] = {
            "control_id": "GCPGKEBIN-CIS-0155",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #155",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0156"] = {
            "control_id": "GCPGKEBIN-CIS-0156",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #156",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0157"] = {
            "control_id": "GCPGKEBIN-CIS-0157",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #157",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0158"] = {
            "control_id": "GCPGKEBIN-CIS-0158",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #158",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0159"] = {
            "control_id": "GCPGKEBIN-CIS-0159",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #159",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0160"] = {
            "control_id": "GCPGKEBIN-CIS-0160",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #160",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0161"] = {
            "control_id": "GCPGKEBIN-CIS-0161",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #161",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0162"] = {
            "control_id": "GCPGKEBIN-CIS-0162",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #162",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0163"] = {
            "control_id": "GCPGKEBIN-CIS-0163",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #163",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0164"] = {
            "control_id": "GCPGKEBIN-CIS-0164",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #164",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0165"] = {
            "control_id": "GCPGKEBIN-CIS-0165",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #165",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0166"] = {
            "control_id": "GCPGKEBIN-CIS-0166",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #166",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0167"] = {
            "control_id": "GCPGKEBIN-CIS-0167",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #167",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0168"] = {
            "control_id": "GCPGKEBIN-CIS-0168",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #168",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0169"] = {
            "control_id": "GCPGKEBIN-CIS-0169",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #169",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0170"] = {
            "control_id": "GCPGKEBIN-CIS-0170",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #170",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0171"] = {
            "control_id": "GCPGKEBIN-CIS-0171",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #171",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0172"] = {
            "control_id": "GCPGKEBIN-CIS-0172",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #172",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0173"] = {
            "control_id": "GCPGKEBIN-CIS-0173",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #173",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0174"] = {
            "control_id": "GCPGKEBIN-CIS-0174",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #174",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0175"] = {
            "control_id": "GCPGKEBIN-CIS-0175",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #175",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0176"] = {
            "control_id": "GCPGKEBIN-CIS-0176",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #176",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0177"] = {
            "control_id": "GCPGKEBIN-CIS-0177",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #177",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0178"] = {
            "control_id": "GCPGKEBIN-CIS-0178",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #178",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0179"] = {
            "control_id": "GCPGKEBIN-CIS-0179",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #179",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0180"] = {
            "control_id": "GCPGKEBIN-CIS-0180",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #180",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0181"] = {
            "control_id": "GCPGKEBIN-CIS-0181",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #181",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0182"] = {
            "control_id": "GCPGKEBIN-CIS-0182",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #182",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0183"] = {
            "control_id": "GCPGKEBIN-CIS-0183",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #183",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0184"] = {
            "control_id": "GCPGKEBIN-CIS-0184",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #184",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0185"] = {
            "control_id": "GCPGKEBIN-CIS-0185",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #185",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0186"] = {
            "control_id": "GCPGKEBIN-CIS-0186",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #186",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0187"] = {
            "control_id": "GCPGKEBIN-CIS-0187",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #187",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0188"] = {
            "control_id": "GCPGKEBIN-CIS-0188",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #188",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0189"] = {
            "control_id": "GCPGKEBIN-CIS-0189",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #189",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0190"] = {
            "control_id": "GCPGKEBIN-CIS-0190",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #190",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0191"] = {
            "control_id": "GCPGKEBIN-CIS-0191",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #191",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0192"] = {
            "control_id": "GCPGKEBIN-CIS-0192",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #192",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0193"] = {
            "control_id": "GCPGKEBIN-CIS-0193",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #193",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0194"] = {
            "control_id": "GCPGKEBIN-CIS-0194",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #194",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0195"] = {
            "control_id": "GCPGKEBIN-CIS-0195",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #195",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0196"] = {
            "control_id": "GCPGKEBIN-CIS-0196",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #196",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0197"] = {
            "control_id": "GCPGKEBIN-CIS-0197",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #197",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0198"] = {
            "control_id": "GCPGKEBIN-CIS-0198",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #198",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0199"] = {
            "control_id": "GCPGKEBIN-CIS-0199",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #199",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0200"] = {
            "control_id": "GCPGKEBIN-CIS-0200",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #200",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0201"] = {
            "control_id": "GCPGKEBIN-CIS-0201",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #201",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0202"] = {
            "control_id": "GCPGKEBIN-CIS-0202",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #202",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0203"] = {
            "control_id": "GCPGKEBIN-CIS-0203",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #203",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0204"] = {
            "control_id": "GCPGKEBIN-CIS-0204",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #204",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0205"] = {
            "control_id": "GCPGKEBIN-CIS-0205",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #205",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0206"] = {
            "control_id": "GCPGKEBIN-CIS-0206",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #206",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0207"] = {
            "control_id": "GCPGKEBIN-CIS-0207",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #207",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0208"] = {
            "control_id": "GCPGKEBIN-CIS-0208",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #208",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0209"] = {
            "control_id": "GCPGKEBIN-CIS-0209",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #209",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0210"] = {
            "control_id": "GCPGKEBIN-CIS-0210",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #210",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0211"] = {
            "control_id": "GCPGKEBIN-CIS-0211",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #211",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0212"] = {
            "control_id": "GCPGKEBIN-CIS-0212",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #212",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0213"] = {
            "control_id": "GCPGKEBIN-CIS-0213",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #213",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0214"] = {
            "control_id": "GCPGKEBIN-CIS-0214",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #214",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0215"] = {
            "control_id": "GCPGKEBIN-CIS-0215",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #215",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0216"] = {
            "control_id": "GCPGKEBIN-CIS-0216",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #216",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0217"] = {
            "control_id": "GCPGKEBIN-CIS-0217",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #217",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0218"] = {
            "control_id": "GCPGKEBIN-CIS-0218",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #218",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0219"] = {
            "control_id": "GCPGKEBIN-CIS-0219",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #219",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0220"] = {
            "control_id": "GCPGKEBIN-CIS-0220",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #220",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0221"] = {
            "control_id": "GCPGKEBIN-CIS-0221",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #221",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0222"] = {
            "control_id": "GCPGKEBIN-CIS-0222",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #222",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0223"] = {
            "control_id": "GCPGKEBIN-CIS-0223",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #223",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0224"] = {
            "control_id": "GCPGKEBIN-CIS-0224",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #224",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0225"] = {
            "control_id": "GCPGKEBIN-CIS-0225",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #225",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0226"] = {
            "control_id": "GCPGKEBIN-CIS-0226",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #226",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0227"] = {
            "control_id": "GCPGKEBIN-CIS-0227",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #227",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0228"] = {
            "control_id": "GCPGKEBIN-CIS-0228",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #228",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0229"] = {
            "control_id": "GCPGKEBIN-CIS-0229",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #229",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0230"] = {
            "control_id": "GCPGKEBIN-CIS-0230",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #230",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0231"] = {
            "control_id": "GCPGKEBIN-CIS-0231",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #231",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0232"] = {
            "control_id": "GCPGKEBIN-CIS-0232",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #232",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0233"] = {
            "control_id": "GCPGKEBIN-CIS-0233",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #233",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0234"] = {
            "control_id": "GCPGKEBIN-CIS-0234",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #234",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0235"] = {
            "control_id": "GCPGKEBIN-CIS-0235",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #235",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0236"] = {
            "control_id": "GCPGKEBIN-CIS-0236",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #236",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0237"] = {
            "control_id": "GCPGKEBIN-CIS-0237",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #237",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0238"] = {
            "control_id": "GCPGKEBIN-CIS-0238",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #238",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0239"] = {
            "control_id": "GCPGKEBIN-CIS-0239",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #239",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0240"] = {
            "control_id": "GCPGKEBIN-CIS-0240",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #240",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0241"] = {
            "control_id": "GCPGKEBIN-CIS-0241",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #241",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0242"] = {
            "control_id": "GCPGKEBIN-CIS-0242",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #242",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0243"] = {
            "control_id": "GCPGKEBIN-CIS-0243",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #243",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0244"] = {
            "control_id": "GCPGKEBIN-CIS-0244",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #244",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0245"] = {
            "control_id": "GCPGKEBIN-CIS-0245",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #245",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0246"] = {
            "control_id": "GCPGKEBIN-CIS-0246",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #246",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0247"] = {
            "control_id": "GCPGKEBIN-CIS-0247",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #247",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0248"] = {
            "control_id": "GCPGKEBIN-CIS-0248",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #248",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0249"] = {
            "control_id": "GCPGKEBIN-CIS-0249",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #249",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0250"] = {
            "control_id": "GCPGKEBIN-CIS-0250",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #250",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0251"] = {
            "control_id": "GCPGKEBIN-CIS-0251",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #251",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0252"] = {
            "control_id": "GCPGKEBIN-CIS-0252",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #252",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0253"] = {
            "control_id": "GCPGKEBIN-CIS-0253",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #253",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0254"] = {
            "control_id": "GCPGKEBIN-CIS-0254",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #254",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0255"] = {
            "control_id": "GCPGKEBIN-CIS-0255",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #255",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0256"] = {
            "control_id": "GCPGKEBIN-CIS-0256",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #256",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0257"] = {
            "control_id": "GCPGKEBIN-CIS-0257",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #257",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0258"] = {
            "control_id": "GCPGKEBIN-CIS-0258",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #258",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0259"] = {
            "control_id": "GCPGKEBIN-CIS-0259",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #259",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0260"] = {
            "control_id": "GCPGKEBIN-CIS-0260",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #260",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0261"] = {
            "control_id": "GCPGKEBIN-CIS-0261",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #261",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0262"] = {
            "control_id": "GCPGKEBIN-CIS-0262",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #262",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0263"] = {
            "control_id": "GCPGKEBIN-CIS-0263",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #263",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0264"] = {
            "control_id": "GCPGKEBIN-CIS-0264",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #264",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0265"] = {
            "control_id": "GCPGKEBIN-CIS-0265",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #265",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0266"] = {
            "control_id": "GCPGKEBIN-CIS-0266",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #266",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0267"] = {
            "control_id": "GCPGKEBIN-CIS-0267",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #267",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0268"] = {
            "control_id": "GCPGKEBIN-CIS-0268",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #268",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0269"] = {
            "control_id": "GCPGKEBIN-CIS-0269",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #269",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0270"] = {
            "control_id": "GCPGKEBIN-CIS-0270",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #270",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0271"] = {
            "control_id": "GCPGKEBIN-CIS-0271",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #271",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0272"] = {
            "control_id": "GCPGKEBIN-CIS-0272",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #272",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0273"] = {
            "control_id": "GCPGKEBIN-CIS-0273",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #273",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0274"] = {
            "control_id": "GCPGKEBIN-CIS-0274",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #274",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0275"] = {
            "control_id": "GCPGKEBIN-CIS-0275",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #275",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0276"] = {
            "control_id": "GCPGKEBIN-CIS-0276",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #276",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0277"] = {
            "control_id": "GCPGKEBIN-CIS-0277",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #277",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0278"] = {
            "control_id": "GCPGKEBIN-CIS-0278",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #278",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0279"] = {
            "control_id": "GCPGKEBIN-CIS-0279",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #279",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0280"] = {
            "control_id": "GCPGKEBIN-CIS-0280",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #280",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0281"] = {
            "control_id": "GCPGKEBIN-CIS-0281",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #281",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0282"] = {
            "control_id": "GCPGKEBIN-CIS-0282",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #282",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0283"] = {
            "control_id": "GCPGKEBIN-CIS-0283",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #283",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0284"] = {
            "control_id": "GCPGKEBIN-CIS-0284",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #284",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0285"] = {
            "control_id": "GCPGKEBIN-CIS-0285",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #285",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0286"] = {
            "control_id": "GCPGKEBIN-CIS-0286",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #286",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0287"] = {
            "control_id": "GCPGKEBIN-CIS-0287",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #287",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0288"] = {
            "control_id": "GCPGKEBIN-CIS-0288",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #288",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0289"] = {
            "control_id": "GCPGKEBIN-CIS-0289",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #289",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0290"] = {
            "control_id": "GCPGKEBIN-CIS-0290",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #290",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0291"] = {
            "control_id": "GCPGKEBIN-CIS-0291",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #291",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0292"] = {
            "control_id": "GCPGKEBIN-CIS-0292",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #292",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0293"] = {
            "control_id": "GCPGKEBIN-CIS-0293",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #293",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0294"] = {
            "control_id": "GCPGKEBIN-CIS-0294",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #294",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0295"] = {
            "control_id": "GCPGKEBIN-CIS-0295",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #295",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0296"] = {
            "control_id": "GCPGKEBIN-CIS-0296",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #296",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0297"] = {
            "control_id": "GCPGKEBIN-CIS-0297",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #297",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0298"] = {
            "control_id": "GCPGKEBIN-CIS-0298",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #298",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0299"] = {
            "control_id": "GCPGKEBIN-CIS-0299",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #299",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0300"] = {
            "control_id": "GCPGKEBIN-CIS-0300",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #300",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0301"] = {
            "control_id": "GCPGKEBIN-CIS-0301",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #301",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0302"] = {
            "control_id": "GCPGKEBIN-CIS-0302",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #302",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0303"] = {
            "control_id": "GCPGKEBIN-CIS-0303",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #303",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0304"] = {
            "control_id": "GCPGKEBIN-CIS-0304",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #304",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0305"] = {
            "control_id": "GCPGKEBIN-CIS-0305",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #305",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0306"] = {
            "control_id": "GCPGKEBIN-CIS-0306",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #306",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0307"] = {
            "control_id": "GCPGKEBIN-CIS-0307",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #307",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0308"] = {
            "control_id": "GCPGKEBIN-CIS-0308",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #308",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0309"] = {
            "control_id": "GCPGKEBIN-CIS-0309",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #309",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0310"] = {
            "control_id": "GCPGKEBIN-CIS-0310",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #310",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0311"] = {
            "control_id": "GCPGKEBIN-CIS-0311",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #311",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0312"] = {
            "control_id": "GCPGKEBIN-CIS-0312",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #312",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0313"] = {
            "control_id": "GCPGKEBIN-CIS-0313",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #313",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0314"] = {
            "control_id": "GCPGKEBIN-CIS-0314",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #314",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0315"] = {
            "control_id": "GCPGKEBIN-CIS-0315",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #315",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0316"] = {
            "control_id": "GCPGKEBIN-CIS-0316",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #316",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0317"] = {
            "control_id": "GCPGKEBIN-CIS-0317",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #317",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0318"] = {
            "control_id": "GCPGKEBIN-CIS-0318",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #318",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0319"] = {
            "control_id": "GCPGKEBIN-CIS-0319",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #319",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0320"] = {
            "control_id": "GCPGKEBIN-CIS-0320",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #320",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0321"] = {
            "control_id": "GCPGKEBIN-CIS-0321",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #321",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0322"] = {
            "control_id": "GCPGKEBIN-CIS-0322",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #322",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0323"] = {
            "control_id": "GCPGKEBIN-CIS-0323",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #323",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0324"] = {
            "control_id": "GCPGKEBIN-CIS-0324",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #324",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0325"] = {
            "control_id": "GCPGKEBIN-CIS-0325",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #325",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0326"] = {
            "control_id": "GCPGKEBIN-CIS-0326",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #326",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0327"] = {
            "control_id": "GCPGKEBIN-CIS-0327",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #327",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0328"] = {
            "control_id": "GCPGKEBIN-CIS-0328",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #328",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0329"] = {
            "control_id": "GCPGKEBIN-CIS-0329",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #329",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0330"] = {
            "control_id": "GCPGKEBIN-CIS-0330",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #330",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0331"] = {
            "control_id": "GCPGKEBIN-CIS-0331",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #331",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0332"] = {
            "control_id": "GCPGKEBIN-CIS-0332",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #332",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0333"] = {
            "control_id": "GCPGKEBIN-CIS-0333",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #333",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0334"] = {
            "control_id": "GCPGKEBIN-CIS-0334",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #334",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0335"] = {
            "control_id": "GCPGKEBIN-CIS-0335",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #335",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0336"] = {
            "control_id": "GCPGKEBIN-CIS-0336",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #336",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0337"] = {
            "control_id": "GCPGKEBIN-CIS-0337",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #337",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0338"] = {
            "control_id": "GCPGKEBIN-CIS-0338",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #338",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0339"] = {
            "control_id": "GCPGKEBIN-CIS-0339",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #339",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0340"] = {
            "control_id": "GCPGKEBIN-CIS-0340",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #340",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0341"] = {
            "control_id": "GCPGKEBIN-CIS-0341",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #341",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0342"] = {
            "control_id": "GCPGKEBIN-CIS-0342",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #342",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0343"] = {
            "control_id": "GCPGKEBIN-CIS-0343",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #343",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0344"] = {
            "control_id": "GCPGKEBIN-CIS-0344",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #344",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0345"] = {
            "control_id": "GCPGKEBIN-CIS-0345",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #345",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0346"] = {
            "control_id": "GCPGKEBIN-CIS-0346",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #346",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0347"] = {
            "control_id": "GCPGKEBIN-CIS-0347",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #347",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0348"] = {
            "control_id": "GCPGKEBIN-CIS-0348",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #348",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0349"] = {
            "control_id": "GCPGKEBIN-CIS-0349",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #349",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0350"] = {
            "control_id": "GCPGKEBIN-CIS-0350",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #350",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0351"] = {
            "control_id": "GCPGKEBIN-CIS-0351",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #351",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0352"] = {
            "control_id": "GCPGKEBIN-CIS-0352",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #352",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0353"] = {
            "control_id": "GCPGKEBIN-CIS-0353",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #353",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0354"] = {
            "control_id": "GCPGKEBIN-CIS-0354",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #354",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0355"] = {
            "control_id": "GCPGKEBIN-CIS-0355",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #355",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0356"] = {
            "control_id": "GCPGKEBIN-CIS-0356",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #356",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0357"] = {
            "control_id": "GCPGKEBIN-CIS-0357",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #357",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0358"] = {
            "control_id": "GCPGKEBIN-CIS-0358",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #358",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0359"] = {
            "control_id": "GCPGKEBIN-CIS-0359",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #359",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0360"] = {
            "control_id": "GCPGKEBIN-CIS-0360",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #360",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0361"] = {
            "control_id": "GCPGKEBIN-CIS-0361",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #361",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0362"] = {
            "control_id": "GCPGKEBIN-CIS-0362",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #362",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0363"] = {
            "control_id": "GCPGKEBIN-CIS-0363",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #363",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0364"] = {
            "control_id": "GCPGKEBIN-CIS-0364",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #364",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0365"] = {
            "control_id": "GCPGKEBIN-CIS-0365",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #365",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0366"] = {
            "control_id": "GCPGKEBIN-CIS-0366",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #366",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0367"] = {
            "control_id": "GCPGKEBIN-CIS-0367",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #367",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0368"] = {
            "control_id": "GCPGKEBIN-CIS-0368",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #368",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0369"] = {
            "control_id": "GCPGKEBIN-CIS-0369",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #369",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0370"] = {
            "control_id": "GCPGKEBIN-CIS-0370",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #370",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0371"] = {
            "control_id": "GCPGKEBIN-CIS-0371",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #371",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0372"] = {
            "control_id": "GCPGKEBIN-CIS-0372",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #372",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0373"] = {
            "control_id": "GCPGKEBIN-CIS-0373",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #373",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0374"] = {
            "control_id": "GCPGKEBIN-CIS-0374",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #374",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0375"] = {
            "control_id": "GCPGKEBIN-CIS-0375",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #375",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0376"] = {
            "control_id": "GCPGKEBIN-CIS-0376",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #376",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0377"] = {
            "control_id": "GCPGKEBIN-CIS-0377",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #377",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0378"] = {
            "control_id": "GCPGKEBIN-CIS-0378",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #378",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0379"] = {
            "control_id": "GCPGKEBIN-CIS-0379",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #379",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0380"] = {
            "control_id": "GCPGKEBIN-CIS-0380",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #380",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0381"] = {
            "control_id": "GCPGKEBIN-CIS-0381",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #381",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0382"] = {
            "control_id": "GCPGKEBIN-CIS-0382",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #382",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0383"] = {
            "control_id": "GCPGKEBIN-CIS-0383",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #383",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0384"] = {
            "control_id": "GCPGKEBIN-CIS-0384",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #384",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0385"] = {
            "control_id": "GCPGKEBIN-CIS-0385",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #385",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0386"] = {
            "control_id": "GCPGKEBIN-CIS-0386",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #386",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0387"] = {
            "control_id": "GCPGKEBIN-CIS-0387",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #387",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0388"] = {
            "control_id": "GCPGKEBIN-CIS-0388",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #388",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0389"] = {
            "control_id": "GCPGKEBIN-CIS-0389",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #389",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0390"] = {
            "control_id": "GCPGKEBIN-CIS-0390",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #390",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0391"] = {
            "control_id": "GCPGKEBIN-CIS-0391",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #391",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0392"] = {
            "control_id": "GCPGKEBIN-CIS-0392",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #392",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0393"] = {
            "control_id": "GCPGKEBIN-CIS-0393",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #393",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0394"] = {
            "control_id": "GCPGKEBIN-CIS-0394",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #394",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0395"] = {
            "control_id": "GCPGKEBIN-CIS-0395",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #395",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0396"] = {
            "control_id": "GCPGKEBIN-CIS-0396",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #396",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0397"] = {
            "control_id": "GCPGKEBIN-CIS-0397",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #397",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0398"] = {
            "control_id": "GCPGKEBIN-CIS-0398",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #398",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0399"] = {
            "control_id": "GCPGKEBIN-CIS-0399",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #399",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0400"] = {
            "control_id": "GCPGKEBIN-CIS-0400",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #400",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0401"] = {
            "control_id": "GCPGKEBIN-CIS-0401",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #401",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0402"] = {
            "control_id": "GCPGKEBIN-CIS-0402",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #402",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0403"] = {
            "control_id": "GCPGKEBIN-CIS-0403",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #403",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0404"] = {
            "control_id": "GCPGKEBIN-CIS-0404",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #404",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0405"] = {
            "control_id": "GCPGKEBIN-CIS-0405",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #405",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0406"] = {
            "control_id": "GCPGKEBIN-CIS-0406",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #406",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0407"] = {
            "control_id": "GCPGKEBIN-CIS-0407",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #407",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0408"] = {
            "control_id": "GCPGKEBIN-CIS-0408",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #408",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0409"] = {
            "control_id": "GCPGKEBIN-CIS-0409",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #409",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0410"] = {
            "control_id": "GCPGKEBIN-CIS-0410",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #410",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0411"] = {
            "control_id": "GCPGKEBIN-CIS-0411",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #411",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0412"] = {
            "control_id": "GCPGKEBIN-CIS-0412",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #412",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0413"] = {
            "control_id": "GCPGKEBIN-CIS-0413",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #413",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0414"] = {
            "control_id": "GCPGKEBIN-CIS-0414",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #414",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0415"] = {
            "control_id": "GCPGKEBIN-CIS-0415",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #415",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0416"] = {
            "control_id": "GCPGKEBIN-CIS-0416",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #416",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0417"] = {
            "control_id": "GCPGKEBIN-CIS-0417",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #417",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0418"] = {
            "control_id": "GCPGKEBIN-CIS-0418",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #418",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0419"] = {
            "control_id": "GCPGKEBIN-CIS-0419",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #419",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0420"] = {
            "control_id": "GCPGKEBIN-CIS-0420",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #420",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0421"] = {
            "control_id": "GCPGKEBIN-CIS-0421",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #421",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0422"] = {
            "control_id": "GCPGKEBIN-CIS-0422",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #422",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0423"] = {
            "control_id": "GCPGKEBIN-CIS-0423",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #423",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0424"] = {
            "control_id": "GCPGKEBIN-CIS-0424",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #424",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0425"] = {
            "control_id": "GCPGKEBIN-CIS-0425",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #425",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0426"] = {
            "control_id": "GCPGKEBIN-CIS-0426",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #426",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0427"] = {
            "control_id": "GCPGKEBIN-CIS-0427",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #427",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0428"] = {
            "control_id": "GCPGKEBIN-CIS-0428",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #428",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0429"] = {
            "control_id": "GCPGKEBIN-CIS-0429",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #429",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0430"] = {
            "control_id": "GCPGKEBIN-CIS-0430",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #430",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0431"] = {
            "control_id": "GCPGKEBIN-CIS-0431",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #431",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0432"] = {
            "control_id": "GCPGKEBIN-CIS-0432",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #432",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0433"] = {
            "control_id": "GCPGKEBIN-CIS-0433",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #433",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0434"] = {
            "control_id": "GCPGKEBIN-CIS-0434",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #434",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0435"] = {
            "control_id": "GCPGKEBIN-CIS-0435",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #435",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0436"] = {
            "control_id": "GCPGKEBIN-CIS-0436",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #436",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0437"] = {
            "control_id": "GCPGKEBIN-CIS-0437",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #437",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0438"] = {
            "control_id": "GCPGKEBIN-CIS-0438",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #438",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0439"] = {
            "control_id": "GCPGKEBIN-CIS-0439",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #439",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0440"] = {
            "control_id": "GCPGKEBIN-CIS-0440",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #440",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0441"] = {
            "control_id": "GCPGKEBIN-CIS-0441",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #441",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0442"] = {
            "control_id": "GCPGKEBIN-CIS-0442",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #442",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0443"] = {
            "control_id": "GCPGKEBIN-CIS-0443",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #443",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0444"] = {
            "control_id": "GCPGKEBIN-CIS-0444",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #444",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0445"] = {
            "control_id": "GCPGKEBIN-CIS-0445",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #445",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0446"] = {
            "control_id": "GCPGKEBIN-CIS-0446",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #446",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0447"] = {
            "control_id": "GCPGKEBIN-CIS-0447",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #447",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0448"] = {
            "control_id": "GCPGKEBIN-CIS-0448",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #448",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["GCPGKEBIN-CIS-0449"] = {
            "control_id": "GCPGKEBIN-CIS-0449",
            "title": "GCP GKE Binary Authorization & Attestation Validator Benchmark #449",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }

    def evaluate_resource_posture(self, state: GcpGkeBinResourceState) -> Dict[str, Any]:
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

gcp_gke_binary_authorization_cspm = GcpGkeBinPostureEvaluator()

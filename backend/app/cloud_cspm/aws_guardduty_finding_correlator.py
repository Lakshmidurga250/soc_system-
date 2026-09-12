"""
SentinelAI - AWS GuardDuty High-Severity Finding Correlator
Enterprise Multi-Cloud Security Posture Management (CSPM) engine for AwsGuardduty.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import datetime

class AwsGuarddutyComplianceStatus(Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    SUPPRESSED = "SUPPRESSED"
    CRITICAL_BREACH = "CRITICAL_BREACH"

@dataclass
class AwsGuarddutyResourceState:
    resource_arn: str
    provider: str
    account_or_tenant: str
    region: str
    resource_type: str
    configuration: Dict[str, Any]
    compliance: AwsGuarddutyComplianceStatus = AwsGuarddutyComplianceStatus.COMPLIANT
    active_findings: List[str] = field(default_factory=list)

class AwsGuarddutyPostureEvaluator:
    def __init__(self):
        self.benchmark_rules: Dict[str, Any] = {}
        self.compliance_ledger: List[Any] = []
        self._initialize_benchmark_rules()

    def _initialize_benchmark_rules(self):
        self.benchmark_rules["AWSGUARDDUTY-CIS-0001"] = {
            "control_id": "AWSGUARDDUTY-CIS-0001",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #1",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0002"] = {
            "control_id": "AWSGUARDDUTY-CIS-0002",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #2",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0003"] = {
            "control_id": "AWSGUARDDUTY-CIS-0003",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #3",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0004"] = {
            "control_id": "AWSGUARDDUTY-CIS-0004",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #4",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0005"] = {
            "control_id": "AWSGUARDDUTY-CIS-0005",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #5",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0006"] = {
            "control_id": "AWSGUARDDUTY-CIS-0006",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #6",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0007"] = {
            "control_id": "AWSGUARDDUTY-CIS-0007",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #7",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0008"] = {
            "control_id": "AWSGUARDDUTY-CIS-0008",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #8",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0009"] = {
            "control_id": "AWSGUARDDUTY-CIS-0009",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #9",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0010"] = {
            "control_id": "AWSGUARDDUTY-CIS-0010",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #10",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0011"] = {
            "control_id": "AWSGUARDDUTY-CIS-0011",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #11",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0012"] = {
            "control_id": "AWSGUARDDUTY-CIS-0012",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #12",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0013"] = {
            "control_id": "AWSGUARDDUTY-CIS-0013",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #13",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0014"] = {
            "control_id": "AWSGUARDDUTY-CIS-0014",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #14",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0015"] = {
            "control_id": "AWSGUARDDUTY-CIS-0015",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #15",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0016"] = {
            "control_id": "AWSGUARDDUTY-CIS-0016",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #16",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0017"] = {
            "control_id": "AWSGUARDDUTY-CIS-0017",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #17",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0018"] = {
            "control_id": "AWSGUARDDUTY-CIS-0018",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #18",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0019"] = {
            "control_id": "AWSGUARDDUTY-CIS-0019",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #19",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0020"] = {
            "control_id": "AWSGUARDDUTY-CIS-0020",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #20",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0021"] = {
            "control_id": "AWSGUARDDUTY-CIS-0021",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #21",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0022"] = {
            "control_id": "AWSGUARDDUTY-CIS-0022",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #22",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0023"] = {
            "control_id": "AWSGUARDDUTY-CIS-0023",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #23",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0024"] = {
            "control_id": "AWSGUARDDUTY-CIS-0024",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #24",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0025"] = {
            "control_id": "AWSGUARDDUTY-CIS-0025",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #25",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0026"] = {
            "control_id": "AWSGUARDDUTY-CIS-0026",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #26",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0027"] = {
            "control_id": "AWSGUARDDUTY-CIS-0027",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #27",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0028"] = {
            "control_id": "AWSGUARDDUTY-CIS-0028",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #28",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0029"] = {
            "control_id": "AWSGUARDDUTY-CIS-0029",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #29",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0030"] = {
            "control_id": "AWSGUARDDUTY-CIS-0030",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #30",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0031"] = {
            "control_id": "AWSGUARDDUTY-CIS-0031",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #31",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0032"] = {
            "control_id": "AWSGUARDDUTY-CIS-0032",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #32",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0033"] = {
            "control_id": "AWSGUARDDUTY-CIS-0033",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #33",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0034"] = {
            "control_id": "AWSGUARDDUTY-CIS-0034",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #34",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0035"] = {
            "control_id": "AWSGUARDDUTY-CIS-0035",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #35",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0036"] = {
            "control_id": "AWSGUARDDUTY-CIS-0036",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #36",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0037"] = {
            "control_id": "AWSGUARDDUTY-CIS-0037",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #37",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0038"] = {
            "control_id": "AWSGUARDDUTY-CIS-0038",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #38",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0039"] = {
            "control_id": "AWSGUARDDUTY-CIS-0039",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #39",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0040"] = {
            "control_id": "AWSGUARDDUTY-CIS-0040",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #40",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0041"] = {
            "control_id": "AWSGUARDDUTY-CIS-0041",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #41",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0042"] = {
            "control_id": "AWSGUARDDUTY-CIS-0042",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #42",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0043"] = {
            "control_id": "AWSGUARDDUTY-CIS-0043",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #43",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0044"] = {
            "control_id": "AWSGUARDDUTY-CIS-0044",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #44",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0045"] = {
            "control_id": "AWSGUARDDUTY-CIS-0045",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #45",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0046"] = {
            "control_id": "AWSGUARDDUTY-CIS-0046",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #46",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0047"] = {
            "control_id": "AWSGUARDDUTY-CIS-0047",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #47",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0048"] = {
            "control_id": "AWSGUARDDUTY-CIS-0048",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #48",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0049"] = {
            "control_id": "AWSGUARDDUTY-CIS-0049",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #49",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0050"] = {
            "control_id": "AWSGUARDDUTY-CIS-0050",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #50",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0051"] = {
            "control_id": "AWSGUARDDUTY-CIS-0051",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #51",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0052"] = {
            "control_id": "AWSGUARDDUTY-CIS-0052",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #52",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0053"] = {
            "control_id": "AWSGUARDDUTY-CIS-0053",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #53",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0054"] = {
            "control_id": "AWSGUARDDUTY-CIS-0054",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #54",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0055"] = {
            "control_id": "AWSGUARDDUTY-CIS-0055",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #55",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0056"] = {
            "control_id": "AWSGUARDDUTY-CIS-0056",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #56",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0057"] = {
            "control_id": "AWSGUARDDUTY-CIS-0057",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #57",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0058"] = {
            "control_id": "AWSGUARDDUTY-CIS-0058",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #58",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0059"] = {
            "control_id": "AWSGUARDDUTY-CIS-0059",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #59",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0060"] = {
            "control_id": "AWSGUARDDUTY-CIS-0060",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #60",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0061"] = {
            "control_id": "AWSGUARDDUTY-CIS-0061",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #61",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0062"] = {
            "control_id": "AWSGUARDDUTY-CIS-0062",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #62",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0063"] = {
            "control_id": "AWSGUARDDUTY-CIS-0063",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #63",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0064"] = {
            "control_id": "AWSGUARDDUTY-CIS-0064",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #64",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0065"] = {
            "control_id": "AWSGUARDDUTY-CIS-0065",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #65",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0066"] = {
            "control_id": "AWSGUARDDUTY-CIS-0066",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #66",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0067"] = {
            "control_id": "AWSGUARDDUTY-CIS-0067",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #67",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0068"] = {
            "control_id": "AWSGUARDDUTY-CIS-0068",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #68",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0069"] = {
            "control_id": "AWSGUARDDUTY-CIS-0069",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #69",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0070"] = {
            "control_id": "AWSGUARDDUTY-CIS-0070",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #70",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0071"] = {
            "control_id": "AWSGUARDDUTY-CIS-0071",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #71",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0072"] = {
            "control_id": "AWSGUARDDUTY-CIS-0072",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #72",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0073"] = {
            "control_id": "AWSGUARDDUTY-CIS-0073",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #73",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0074"] = {
            "control_id": "AWSGUARDDUTY-CIS-0074",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #74",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0075"] = {
            "control_id": "AWSGUARDDUTY-CIS-0075",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #75",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0076"] = {
            "control_id": "AWSGUARDDUTY-CIS-0076",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #76",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0077"] = {
            "control_id": "AWSGUARDDUTY-CIS-0077",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #77",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0078"] = {
            "control_id": "AWSGUARDDUTY-CIS-0078",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #78",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0079"] = {
            "control_id": "AWSGUARDDUTY-CIS-0079",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #79",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0080"] = {
            "control_id": "AWSGUARDDUTY-CIS-0080",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #80",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0081"] = {
            "control_id": "AWSGUARDDUTY-CIS-0081",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #81",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0082"] = {
            "control_id": "AWSGUARDDUTY-CIS-0082",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #82",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0083"] = {
            "control_id": "AWSGUARDDUTY-CIS-0083",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #83",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0084"] = {
            "control_id": "AWSGUARDDUTY-CIS-0084",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #84",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0085"] = {
            "control_id": "AWSGUARDDUTY-CIS-0085",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #85",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0086"] = {
            "control_id": "AWSGUARDDUTY-CIS-0086",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #86",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0087"] = {
            "control_id": "AWSGUARDDUTY-CIS-0087",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #87",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0088"] = {
            "control_id": "AWSGUARDDUTY-CIS-0088",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #88",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0089"] = {
            "control_id": "AWSGUARDDUTY-CIS-0089",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #89",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0090"] = {
            "control_id": "AWSGUARDDUTY-CIS-0090",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #90",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0091"] = {
            "control_id": "AWSGUARDDUTY-CIS-0091",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #91",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0092"] = {
            "control_id": "AWSGUARDDUTY-CIS-0092",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #92",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0093"] = {
            "control_id": "AWSGUARDDUTY-CIS-0093",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #93",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0094"] = {
            "control_id": "AWSGUARDDUTY-CIS-0094",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #94",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0095"] = {
            "control_id": "AWSGUARDDUTY-CIS-0095",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #95",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0096"] = {
            "control_id": "AWSGUARDDUTY-CIS-0096",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #96",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0097"] = {
            "control_id": "AWSGUARDDUTY-CIS-0097",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #97",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0098"] = {
            "control_id": "AWSGUARDDUTY-CIS-0098",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #98",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0099"] = {
            "control_id": "AWSGUARDDUTY-CIS-0099",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #99",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0100"] = {
            "control_id": "AWSGUARDDUTY-CIS-0100",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #100",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0101"] = {
            "control_id": "AWSGUARDDUTY-CIS-0101",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #101",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0102"] = {
            "control_id": "AWSGUARDDUTY-CIS-0102",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #102",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0103"] = {
            "control_id": "AWSGUARDDUTY-CIS-0103",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #103",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0104"] = {
            "control_id": "AWSGUARDDUTY-CIS-0104",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #104",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0105"] = {
            "control_id": "AWSGUARDDUTY-CIS-0105",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #105",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0106"] = {
            "control_id": "AWSGUARDDUTY-CIS-0106",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #106",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0107"] = {
            "control_id": "AWSGUARDDUTY-CIS-0107",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #107",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0108"] = {
            "control_id": "AWSGUARDDUTY-CIS-0108",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #108",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0109"] = {
            "control_id": "AWSGUARDDUTY-CIS-0109",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #109",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0110"] = {
            "control_id": "AWSGUARDDUTY-CIS-0110",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #110",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0111"] = {
            "control_id": "AWSGUARDDUTY-CIS-0111",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #111",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0112"] = {
            "control_id": "AWSGUARDDUTY-CIS-0112",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #112",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0113"] = {
            "control_id": "AWSGUARDDUTY-CIS-0113",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #113",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0114"] = {
            "control_id": "AWSGUARDDUTY-CIS-0114",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #114",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0115"] = {
            "control_id": "AWSGUARDDUTY-CIS-0115",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #115",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0116"] = {
            "control_id": "AWSGUARDDUTY-CIS-0116",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #116",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0117"] = {
            "control_id": "AWSGUARDDUTY-CIS-0117",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #117",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0118"] = {
            "control_id": "AWSGUARDDUTY-CIS-0118",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #118",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0119"] = {
            "control_id": "AWSGUARDDUTY-CIS-0119",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #119",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0120"] = {
            "control_id": "AWSGUARDDUTY-CIS-0120",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #120",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0121"] = {
            "control_id": "AWSGUARDDUTY-CIS-0121",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #121",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0122"] = {
            "control_id": "AWSGUARDDUTY-CIS-0122",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #122",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0123"] = {
            "control_id": "AWSGUARDDUTY-CIS-0123",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #123",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0124"] = {
            "control_id": "AWSGUARDDUTY-CIS-0124",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #124",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0125"] = {
            "control_id": "AWSGUARDDUTY-CIS-0125",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #125",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0126"] = {
            "control_id": "AWSGUARDDUTY-CIS-0126",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #126",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0127"] = {
            "control_id": "AWSGUARDDUTY-CIS-0127",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #127",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0128"] = {
            "control_id": "AWSGUARDDUTY-CIS-0128",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #128",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0129"] = {
            "control_id": "AWSGUARDDUTY-CIS-0129",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #129",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0130"] = {
            "control_id": "AWSGUARDDUTY-CIS-0130",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #130",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0131"] = {
            "control_id": "AWSGUARDDUTY-CIS-0131",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #131",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0132"] = {
            "control_id": "AWSGUARDDUTY-CIS-0132",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #132",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0133"] = {
            "control_id": "AWSGUARDDUTY-CIS-0133",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #133",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0134"] = {
            "control_id": "AWSGUARDDUTY-CIS-0134",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #134",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0135"] = {
            "control_id": "AWSGUARDDUTY-CIS-0135",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #135",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0136"] = {
            "control_id": "AWSGUARDDUTY-CIS-0136",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #136",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0137"] = {
            "control_id": "AWSGUARDDUTY-CIS-0137",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #137",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0138"] = {
            "control_id": "AWSGUARDDUTY-CIS-0138",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #138",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0139"] = {
            "control_id": "AWSGUARDDUTY-CIS-0139",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #139",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0140"] = {
            "control_id": "AWSGUARDDUTY-CIS-0140",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #140",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0141"] = {
            "control_id": "AWSGUARDDUTY-CIS-0141",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #141",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0142"] = {
            "control_id": "AWSGUARDDUTY-CIS-0142",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #142",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0143"] = {
            "control_id": "AWSGUARDDUTY-CIS-0143",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #143",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0144"] = {
            "control_id": "AWSGUARDDUTY-CIS-0144",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #144",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0145"] = {
            "control_id": "AWSGUARDDUTY-CIS-0145",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #145",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0146"] = {
            "control_id": "AWSGUARDDUTY-CIS-0146",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #146",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0147"] = {
            "control_id": "AWSGUARDDUTY-CIS-0147",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #147",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0148"] = {
            "control_id": "AWSGUARDDUTY-CIS-0148",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #148",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0149"] = {
            "control_id": "AWSGUARDDUTY-CIS-0149",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #149",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0150"] = {
            "control_id": "AWSGUARDDUTY-CIS-0150",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #150",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0151"] = {
            "control_id": "AWSGUARDDUTY-CIS-0151",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #151",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0152"] = {
            "control_id": "AWSGUARDDUTY-CIS-0152",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #152",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0153"] = {
            "control_id": "AWSGUARDDUTY-CIS-0153",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #153",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0154"] = {
            "control_id": "AWSGUARDDUTY-CIS-0154",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #154",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0155"] = {
            "control_id": "AWSGUARDDUTY-CIS-0155",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #155",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0156"] = {
            "control_id": "AWSGUARDDUTY-CIS-0156",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #156",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0157"] = {
            "control_id": "AWSGUARDDUTY-CIS-0157",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #157",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0158"] = {
            "control_id": "AWSGUARDDUTY-CIS-0158",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #158",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0159"] = {
            "control_id": "AWSGUARDDUTY-CIS-0159",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #159",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0160"] = {
            "control_id": "AWSGUARDDUTY-CIS-0160",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #160",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0161"] = {
            "control_id": "AWSGUARDDUTY-CIS-0161",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #161",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0162"] = {
            "control_id": "AWSGUARDDUTY-CIS-0162",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #162",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0163"] = {
            "control_id": "AWSGUARDDUTY-CIS-0163",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #163",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0164"] = {
            "control_id": "AWSGUARDDUTY-CIS-0164",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #164",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0165"] = {
            "control_id": "AWSGUARDDUTY-CIS-0165",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #165",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0166"] = {
            "control_id": "AWSGUARDDUTY-CIS-0166",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #166",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0167"] = {
            "control_id": "AWSGUARDDUTY-CIS-0167",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #167",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0168"] = {
            "control_id": "AWSGUARDDUTY-CIS-0168",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #168",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0169"] = {
            "control_id": "AWSGUARDDUTY-CIS-0169",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #169",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0170"] = {
            "control_id": "AWSGUARDDUTY-CIS-0170",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #170",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0171"] = {
            "control_id": "AWSGUARDDUTY-CIS-0171",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #171",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0172"] = {
            "control_id": "AWSGUARDDUTY-CIS-0172",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #172",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0173"] = {
            "control_id": "AWSGUARDDUTY-CIS-0173",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #173",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0174"] = {
            "control_id": "AWSGUARDDUTY-CIS-0174",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #174",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0175"] = {
            "control_id": "AWSGUARDDUTY-CIS-0175",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #175",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0176"] = {
            "control_id": "AWSGUARDDUTY-CIS-0176",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #176",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0177"] = {
            "control_id": "AWSGUARDDUTY-CIS-0177",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #177",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0178"] = {
            "control_id": "AWSGUARDDUTY-CIS-0178",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #178",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0179"] = {
            "control_id": "AWSGUARDDUTY-CIS-0179",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #179",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0180"] = {
            "control_id": "AWSGUARDDUTY-CIS-0180",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #180",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0181"] = {
            "control_id": "AWSGUARDDUTY-CIS-0181",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #181",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0182"] = {
            "control_id": "AWSGUARDDUTY-CIS-0182",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #182",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0183"] = {
            "control_id": "AWSGUARDDUTY-CIS-0183",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #183",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0184"] = {
            "control_id": "AWSGUARDDUTY-CIS-0184",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #184",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0185"] = {
            "control_id": "AWSGUARDDUTY-CIS-0185",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #185",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0186"] = {
            "control_id": "AWSGUARDDUTY-CIS-0186",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #186",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0187"] = {
            "control_id": "AWSGUARDDUTY-CIS-0187",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #187",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0188"] = {
            "control_id": "AWSGUARDDUTY-CIS-0188",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #188",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0189"] = {
            "control_id": "AWSGUARDDUTY-CIS-0189",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #189",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0190"] = {
            "control_id": "AWSGUARDDUTY-CIS-0190",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #190",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0191"] = {
            "control_id": "AWSGUARDDUTY-CIS-0191",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #191",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0192"] = {
            "control_id": "AWSGUARDDUTY-CIS-0192",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #192",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0193"] = {
            "control_id": "AWSGUARDDUTY-CIS-0193",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #193",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0194"] = {
            "control_id": "AWSGUARDDUTY-CIS-0194",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #194",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0195"] = {
            "control_id": "AWSGUARDDUTY-CIS-0195",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #195",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0196"] = {
            "control_id": "AWSGUARDDUTY-CIS-0196",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #196",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0197"] = {
            "control_id": "AWSGUARDDUTY-CIS-0197",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #197",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0198"] = {
            "control_id": "AWSGUARDDUTY-CIS-0198",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #198",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0199"] = {
            "control_id": "AWSGUARDDUTY-CIS-0199",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #199",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0200"] = {
            "control_id": "AWSGUARDDUTY-CIS-0200",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #200",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0201"] = {
            "control_id": "AWSGUARDDUTY-CIS-0201",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #201",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0202"] = {
            "control_id": "AWSGUARDDUTY-CIS-0202",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #202",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0203"] = {
            "control_id": "AWSGUARDDUTY-CIS-0203",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #203",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0204"] = {
            "control_id": "AWSGUARDDUTY-CIS-0204",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #204",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0205"] = {
            "control_id": "AWSGUARDDUTY-CIS-0205",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #205",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0206"] = {
            "control_id": "AWSGUARDDUTY-CIS-0206",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #206",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0207"] = {
            "control_id": "AWSGUARDDUTY-CIS-0207",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #207",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0208"] = {
            "control_id": "AWSGUARDDUTY-CIS-0208",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #208",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0209"] = {
            "control_id": "AWSGUARDDUTY-CIS-0209",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #209",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0210"] = {
            "control_id": "AWSGUARDDUTY-CIS-0210",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #210",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0211"] = {
            "control_id": "AWSGUARDDUTY-CIS-0211",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #211",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0212"] = {
            "control_id": "AWSGUARDDUTY-CIS-0212",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #212",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0213"] = {
            "control_id": "AWSGUARDDUTY-CIS-0213",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #213",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0214"] = {
            "control_id": "AWSGUARDDUTY-CIS-0214",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #214",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0215"] = {
            "control_id": "AWSGUARDDUTY-CIS-0215",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #215",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0216"] = {
            "control_id": "AWSGUARDDUTY-CIS-0216",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #216",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0217"] = {
            "control_id": "AWSGUARDDUTY-CIS-0217",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #217",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0218"] = {
            "control_id": "AWSGUARDDUTY-CIS-0218",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #218",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0219"] = {
            "control_id": "AWSGUARDDUTY-CIS-0219",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #219",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0220"] = {
            "control_id": "AWSGUARDDUTY-CIS-0220",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #220",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0221"] = {
            "control_id": "AWSGUARDDUTY-CIS-0221",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #221",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0222"] = {
            "control_id": "AWSGUARDDUTY-CIS-0222",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #222",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0223"] = {
            "control_id": "AWSGUARDDUTY-CIS-0223",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #223",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0224"] = {
            "control_id": "AWSGUARDDUTY-CIS-0224",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #224",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0225"] = {
            "control_id": "AWSGUARDDUTY-CIS-0225",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #225",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0226"] = {
            "control_id": "AWSGUARDDUTY-CIS-0226",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #226",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0227"] = {
            "control_id": "AWSGUARDDUTY-CIS-0227",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #227",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0228"] = {
            "control_id": "AWSGUARDDUTY-CIS-0228",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #228",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0229"] = {
            "control_id": "AWSGUARDDUTY-CIS-0229",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #229",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0230"] = {
            "control_id": "AWSGUARDDUTY-CIS-0230",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #230",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0231"] = {
            "control_id": "AWSGUARDDUTY-CIS-0231",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #231",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0232"] = {
            "control_id": "AWSGUARDDUTY-CIS-0232",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #232",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0233"] = {
            "control_id": "AWSGUARDDUTY-CIS-0233",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #233",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0234"] = {
            "control_id": "AWSGUARDDUTY-CIS-0234",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #234",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0235"] = {
            "control_id": "AWSGUARDDUTY-CIS-0235",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #235",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0236"] = {
            "control_id": "AWSGUARDDUTY-CIS-0236",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #236",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0237"] = {
            "control_id": "AWSGUARDDUTY-CIS-0237",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #237",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0238"] = {
            "control_id": "AWSGUARDDUTY-CIS-0238",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #238",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0239"] = {
            "control_id": "AWSGUARDDUTY-CIS-0239",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #239",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0240"] = {
            "control_id": "AWSGUARDDUTY-CIS-0240",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #240",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0241"] = {
            "control_id": "AWSGUARDDUTY-CIS-0241",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #241",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0242"] = {
            "control_id": "AWSGUARDDUTY-CIS-0242",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #242",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0243"] = {
            "control_id": "AWSGUARDDUTY-CIS-0243",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #243",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0244"] = {
            "control_id": "AWSGUARDDUTY-CIS-0244",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #244",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0245"] = {
            "control_id": "AWSGUARDDUTY-CIS-0245",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #245",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0246"] = {
            "control_id": "AWSGUARDDUTY-CIS-0246",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #246",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0247"] = {
            "control_id": "AWSGUARDDUTY-CIS-0247",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #247",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0248"] = {
            "control_id": "AWSGUARDDUTY-CIS-0248",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #248",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0249"] = {
            "control_id": "AWSGUARDDUTY-CIS-0249",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #249",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0250"] = {
            "control_id": "AWSGUARDDUTY-CIS-0250",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #250",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0251"] = {
            "control_id": "AWSGUARDDUTY-CIS-0251",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #251",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0252"] = {
            "control_id": "AWSGUARDDUTY-CIS-0252",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #252",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0253"] = {
            "control_id": "AWSGUARDDUTY-CIS-0253",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #253",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0254"] = {
            "control_id": "AWSGUARDDUTY-CIS-0254",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #254",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0255"] = {
            "control_id": "AWSGUARDDUTY-CIS-0255",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #255",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0256"] = {
            "control_id": "AWSGUARDDUTY-CIS-0256",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #256",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0257"] = {
            "control_id": "AWSGUARDDUTY-CIS-0257",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #257",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0258"] = {
            "control_id": "AWSGUARDDUTY-CIS-0258",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #258",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0259"] = {
            "control_id": "AWSGUARDDUTY-CIS-0259",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #259",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0260"] = {
            "control_id": "AWSGUARDDUTY-CIS-0260",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #260",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0261"] = {
            "control_id": "AWSGUARDDUTY-CIS-0261",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #261",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0262"] = {
            "control_id": "AWSGUARDDUTY-CIS-0262",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #262",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0263"] = {
            "control_id": "AWSGUARDDUTY-CIS-0263",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #263",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0264"] = {
            "control_id": "AWSGUARDDUTY-CIS-0264",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #264",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0265"] = {
            "control_id": "AWSGUARDDUTY-CIS-0265",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #265",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0266"] = {
            "control_id": "AWSGUARDDUTY-CIS-0266",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #266",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0267"] = {
            "control_id": "AWSGUARDDUTY-CIS-0267",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #267",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0268"] = {
            "control_id": "AWSGUARDDUTY-CIS-0268",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #268",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0269"] = {
            "control_id": "AWSGUARDDUTY-CIS-0269",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #269",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0270"] = {
            "control_id": "AWSGUARDDUTY-CIS-0270",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #270",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0271"] = {
            "control_id": "AWSGUARDDUTY-CIS-0271",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #271",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0272"] = {
            "control_id": "AWSGUARDDUTY-CIS-0272",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #272",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0273"] = {
            "control_id": "AWSGUARDDUTY-CIS-0273",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #273",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0274"] = {
            "control_id": "AWSGUARDDUTY-CIS-0274",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #274",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0275"] = {
            "control_id": "AWSGUARDDUTY-CIS-0275",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #275",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0276"] = {
            "control_id": "AWSGUARDDUTY-CIS-0276",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #276",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0277"] = {
            "control_id": "AWSGUARDDUTY-CIS-0277",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #277",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0278"] = {
            "control_id": "AWSGUARDDUTY-CIS-0278",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #278",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0279"] = {
            "control_id": "AWSGUARDDUTY-CIS-0279",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #279",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0280"] = {
            "control_id": "AWSGUARDDUTY-CIS-0280",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #280",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0281"] = {
            "control_id": "AWSGUARDDUTY-CIS-0281",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #281",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0282"] = {
            "control_id": "AWSGUARDDUTY-CIS-0282",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #282",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0283"] = {
            "control_id": "AWSGUARDDUTY-CIS-0283",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #283",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0284"] = {
            "control_id": "AWSGUARDDUTY-CIS-0284",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #284",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0285"] = {
            "control_id": "AWSGUARDDUTY-CIS-0285",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #285",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0286"] = {
            "control_id": "AWSGUARDDUTY-CIS-0286",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #286",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0287"] = {
            "control_id": "AWSGUARDDUTY-CIS-0287",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #287",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0288"] = {
            "control_id": "AWSGUARDDUTY-CIS-0288",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #288",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0289"] = {
            "control_id": "AWSGUARDDUTY-CIS-0289",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #289",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0290"] = {
            "control_id": "AWSGUARDDUTY-CIS-0290",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #290",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0291"] = {
            "control_id": "AWSGUARDDUTY-CIS-0291",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #291",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0292"] = {
            "control_id": "AWSGUARDDUTY-CIS-0292",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #292",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0293"] = {
            "control_id": "AWSGUARDDUTY-CIS-0293",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #293",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0294"] = {
            "control_id": "AWSGUARDDUTY-CIS-0294",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #294",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0295"] = {
            "control_id": "AWSGUARDDUTY-CIS-0295",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #295",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0296"] = {
            "control_id": "AWSGUARDDUTY-CIS-0296",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #296",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0297"] = {
            "control_id": "AWSGUARDDUTY-CIS-0297",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #297",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0298"] = {
            "control_id": "AWSGUARDDUTY-CIS-0298",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #298",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0299"] = {
            "control_id": "AWSGUARDDUTY-CIS-0299",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #299",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0300"] = {
            "control_id": "AWSGUARDDUTY-CIS-0300",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #300",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0301"] = {
            "control_id": "AWSGUARDDUTY-CIS-0301",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #301",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0302"] = {
            "control_id": "AWSGUARDDUTY-CIS-0302",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #302",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0303"] = {
            "control_id": "AWSGUARDDUTY-CIS-0303",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #303",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0304"] = {
            "control_id": "AWSGUARDDUTY-CIS-0304",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #304",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0305"] = {
            "control_id": "AWSGUARDDUTY-CIS-0305",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #305",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0306"] = {
            "control_id": "AWSGUARDDUTY-CIS-0306",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #306",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0307"] = {
            "control_id": "AWSGUARDDUTY-CIS-0307",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #307",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0308"] = {
            "control_id": "AWSGUARDDUTY-CIS-0308",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #308",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0309"] = {
            "control_id": "AWSGUARDDUTY-CIS-0309",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #309",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0310"] = {
            "control_id": "AWSGUARDDUTY-CIS-0310",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #310",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0311"] = {
            "control_id": "AWSGUARDDUTY-CIS-0311",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #311",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0312"] = {
            "control_id": "AWSGUARDDUTY-CIS-0312",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #312",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0313"] = {
            "control_id": "AWSGUARDDUTY-CIS-0313",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #313",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0314"] = {
            "control_id": "AWSGUARDDUTY-CIS-0314",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #314",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0315"] = {
            "control_id": "AWSGUARDDUTY-CIS-0315",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #315",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0316"] = {
            "control_id": "AWSGUARDDUTY-CIS-0316",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #316",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0317"] = {
            "control_id": "AWSGUARDDUTY-CIS-0317",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #317",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0318"] = {
            "control_id": "AWSGUARDDUTY-CIS-0318",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #318",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0319"] = {
            "control_id": "AWSGUARDDUTY-CIS-0319",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #319",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0320"] = {
            "control_id": "AWSGUARDDUTY-CIS-0320",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #320",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0321"] = {
            "control_id": "AWSGUARDDUTY-CIS-0321",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #321",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0322"] = {
            "control_id": "AWSGUARDDUTY-CIS-0322",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #322",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0323"] = {
            "control_id": "AWSGUARDDUTY-CIS-0323",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #323",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0324"] = {
            "control_id": "AWSGUARDDUTY-CIS-0324",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #324",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0325"] = {
            "control_id": "AWSGUARDDUTY-CIS-0325",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #325",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0326"] = {
            "control_id": "AWSGUARDDUTY-CIS-0326",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #326",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0327"] = {
            "control_id": "AWSGUARDDUTY-CIS-0327",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #327",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0328"] = {
            "control_id": "AWSGUARDDUTY-CIS-0328",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #328",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0329"] = {
            "control_id": "AWSGUARDDUTY-CIS-0329",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #329",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0330"] = {
            "control_id": "AWSGUARDDUTY-CIS-0330",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #330",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0331"] = {
            "control_id": "AWSGUARDDUTY-CIS-0331",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #331",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0332"] = {
            "control_id": "AWSGUARDDUTY-CIS-0332",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #332",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0333"] = {
            "control_id": "AWSGUARDDUTY-CIS-0333",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #333",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0334"] = {
            "control_id": "AWSGUARDDUTY-CIS-0334",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #334",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0335"] = {
            "control_id": "AWSGUARDDUTY-CIS-0335",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #335",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0336"] = {
            "control_id": "AWSGUARDDUTY-CIS-0336",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #336",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0337"] = {
            "control_id": "AWSGUARDDUTY-CIS-0337",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #337",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0338"] = {
            "control_id": "AWSGUARDDUTY-CIS-0338",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #338",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0339"] = {
            "control_id": "AWSGUARDDUTY-CIS-0339",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #339",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0340"] = {
            "control_id": "AWSGUARDDUTY-CIS-0340",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #340",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0341"] = {
            "control_id": "AWSGUARDDUTY-CIS-0341",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #341",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0342"] = {
            "control_id": "AWSGUARDDUTY-CIS-0342",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #342",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0343"] = {
            "control_id": "AWSGUARDDUTY-CIS-0343",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #343",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0344"] = {
            "control_id": "AWSGUARDDUTY-CIS-0344",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #344",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0345"] = {
            "control_id": "AWSGUARDDUTY-CIS-0345",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #345",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0346"] = {
            "control_id": "AWSGUARDDUTY-CIS-0346",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #346",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0347"] = {
            "control_id": "AWSGUARDDUTY-CIS-0347",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #347",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0348"] = {
            "control_id": "AWSGUARDDUTY-CIS-0348",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #348",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0349"] = {
            "control_id": "AWSGUARDDUTY-CIS-0349",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #349",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0350"] = {
            "control_id": "AWSGUARDDUTY-CIS-0350",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #350",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0351"] = {
            "control_id": "AWSGUARDDUTY-CIS-0351",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #351",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0352"] = {
            "control_id": "AWSGUARDDUTY-CIS-0352",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #352",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0353"] = {
            "control_id": "AWSGUARDDUTY-CIS-0353",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #353",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0354"] = {
            "control_id": "AWSGUARDDUTY-CIS-0354",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #354",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0355"] = {
            "control_id": "AWSGUARDDUTY-CIS-0355",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #355",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0356"] = {
            "control_id": "AWSGUARDDUTY-CIS-0356",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #356",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0357"] = {
            "control_id": "AWSGUARDDUTY-CIS-0357",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #357",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0358"] = {
            "control_id": "AWSGUARDDUTY-CIS-0358",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #358",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0359"] = {
            "control_id": "AWSGUARDDUTY-CIS-0359",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #359",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0360"] = {
            "control_id": "AWSGUARDDUTY-CIS-0360",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #360",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0361"] = {
            "control_id": "AWSGUARDDUTY-CIS-0361",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #361",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0362"] = {
            "control_id": "AWSGUARDDUTY-CIS-0362",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #362",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0363"] = {
            "control_id": "AWSGUARDDUTY-CIS-0363",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #363",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0364"] = {
            "control_id": "AWSGUARDDUTY-CIS-0364",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #364",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0365"] = {
            "control_id": "AWSGUARDDUTY-CIS-0365",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #365",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0366"] = {
            "control_id": "AWSGUARDDUTY-CIS-0366",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #366",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0367"] = {
            "control_id": "AWSGUARDDUTY-CIS-0367",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #367",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0368"] = {
            "control_id": "AWSGUARDDUTY-CIS-0368",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #368",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0369"] = {
            "control_id": "AWSGUARDDUTY-CIS-0369",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #369",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0370"] = {
            "control_id": "AWSGUARDDUTY-CIS-0370",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #370",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0371"] = {
            "control_id": "AWSGUARDDUTY-CIS-0371",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #371",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0372"] = {
            "control_id": "AWSGUARDDUTY-CIS-0372",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #372",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0373"] = {
            "control_id": "AWSGUARDDUTY-CIS-0373",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #373",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0374"] = {
            "control_id": "AWSGUARDDUTY-CIS-0374",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #374",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0375"] = {
            "control_id": "AWSGUARDDUTY-CIS-0375",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #375",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0376"] = {
            "control_id": "AWSGUARDDUTY-CIS-0376",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #376",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0377"] = {
            "control_id": "AWSGUARDDUTY-CIS-0377",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #377",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0378"] = {
            "control_id": "AWSGUARDDUTY-CIS-0378",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #378",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0379"] = {
            "control_id": "AWSGUARDDUTY-CIS-0379",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #379",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0380"] = {
            "control_id": "AWSGUARDDUTY-CIS-0380",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #380",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0381"] = {
            "control_id": "AWSGUARDDUTY-CIS-0381",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #381",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0382"] = {
            "control_id": "AWSGUARDDUTY-CIS-0382",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #382",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0383"] = {
            "control_id": "AWSGUARDDUTY-CIS-0383",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #383",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0384"] = {
            "control_id": "AWSGUARDDUTY-CIS-0384",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #384",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0385"] = {
            "control_id": "AWSGUARDDUTY-CIS-0385",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #385",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0386"] = {
            "control_id": "AWSGUARDDUTY-CIS-0386",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #386",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0387"] = {
            "control_id": "AWSGUARDDUTY-CIS-0387",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #387",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0388"] = {
            "control_id": "AWSGUARDDUTY-CIS-0388",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #388",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0389"] = {
            "control_id": "AWSGUARDDUTY-CIS-0389",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #389",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0390"] = {
            "control_id": "AWSGUARDDUTY-CIS-0390",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #390",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0391"] = {
            "control_id": "AWSGUARDDUTY-CIS-0391",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #391",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0392"] = {
            "control_id": "AWSGUARDDUTY-CIS-0392",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #392",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0393"] = {
            "control_id": "AWSGUARDDUTY-CIS-0393",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #393",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0394"] = {
            "control_id": "AWSGUARDDUTY-CIS-0394",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #394",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0395"] = {
            "control_id": "AWSGUARDDUTY-CIS-0395",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #395",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0396"] = {
            "control_id": "AWSGUARDDUTY-CIS-0396",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #396",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0397"] = {
            "control_id": "AWSGUARDDUTY-CIS-0397",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #397",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0398"] = {
            "control_id": "AWSGUARDDUTY-CIS-0398",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #398",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0399"] = {
            "control_id": "AWSGUARDDUTY-CIS-0399",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #399",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0400"] = {
            "control_id": "AWSGUARDDUTY-CIS-0400",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #400",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0401"] = {
            "control_id": "AWSGUARDDUTY-CIS-0401",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #401",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0402"] = {
            "control_id": "AWSGUARDDUTY-CIS-0402",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #402",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0403"] = {
            "control_id": "AWSGUARDDUTY-CIS-0403",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #403",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0404"] = {
            "control_id": "AWSGUARDDUTY-CIS-0404",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #404",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0405"] = {
            "control_id": "AWSGUARDDUTY-CIS-0405",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #405",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0406"] = {
            "control_id": "AWSGUARDDUTY-CIS-0406",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #406",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0407"] = {
            "control_id": "AWSGUARDDUTY-CIS-0407",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #407",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0408"] = {
            "control_id": "AWSGUARDDUTY-CIS-0408",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #408",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0409"] = {
            "control_id": "AWSGUARDDUTY-CIS-0409",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #409",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0410"] = {
            "control_id": "AWSGUARDDUTY-CIS-0410",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #410",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0411"] = {
            "control_id": "AWSGUARDDUTY-CIS-0411",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #411",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0412"] = {
            "control_id": "AWSGUARDDUTY-CIS-0412",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #412",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0413"] = {
            "control_id": "AWSGUARDDUTY-CIS-0413",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #413",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0414"] = {
            "control_id": "AWSGUARDDUTY-CIS-0414",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #414",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0415"] = {
            "control_id": "AWSGUARDDUTY-CIS-0415",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #415",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0416"] = {
            "control_id": "AWSGUARDDUTY-CIS-0416",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #416",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0417"] = {
            "control_id": "AWSGUARDDUTY-CIS-0417",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #417",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0418"] = {
            "control_id": "AWSGUARDDUTY-CIS-0418",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #418",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0419"] = {
            "control_id": "AWSGUARDDUTY-CIS-0419",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #419",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0420"] = {
            "control_id": "AWSGUARDDUTY-CIS-0420",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #420",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0421"] = {
            "control_id": "AWSGUARDDUTY-CIS-0421",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #421",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0422"] = {
            "control_id": "AWSGUARDDUTY-CIS-0422",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #422",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0423"] = {
            "control_id": "AWSGUARDDUTY-CIS-0423",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #423",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0424"] = {
            "control_id": "AWSGUARDDUTY-CIS-0424",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #424",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0425"] = {
            "control_id": "AWSGUARDDUTY-CIS-0425",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #425",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0426"] = {
            "control_id": "AWSGUARDDUTY-CIS-0426",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #426",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0427"] = {
            "control_id": "AWSGUARDDUTY-CIS-0427",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #427",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0428"] = {
            "control_id": "AWSGUARDDUTY-CIS-0428",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #428",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0429"] = {
            "control_id": "AWSGUARDDUTY-CIS-0429",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #429",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0430"] = {
            "control_id": "AWSGUARDDUTY-CIS-0430",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #430",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0431"] = {
            "control_id": "AWSGUARDDUTY-CIS-0431",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #431",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0432"] = {
            "control_id": "AWSGUARDDUTY-CIS-0432",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #432",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0433"] = {
            "control_id": "AWSGUARDDUTY-CIS-0433",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #433",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0434"] = {
            "control_id": "AWSGUARDDUTY-CIS-0434",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #434",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0435"] = {
            "control_id": "AWSGUARDDUTY-CIS-0435",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #435",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0436"] = {
            "control_id": "AWSGUARDDUTY-CIS-0436",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #436",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0437"] = {
            "control_id": "AWSGUARDDUTY-CIS-0437",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #437",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0438"] = {
            "control_id": "AWSGUARDDUTY-CIS-0438",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #438",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0439"] = {
            "control_id": "AWSGUARDDUTY-CIS-0439",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #439",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0440"] = {
            "control_id": "AWSGUARDDUTY-CIS-0440",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #440",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0441"] = {
            "control_id": "AWSGUARDDUTY-CIS-0441",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #441",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0442"] = {
            "control_id": "AWSGUARDDUTY-CIS-0442",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #442",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0443"] = {
            "control_id": "AWSGUARDDUTY-CIS-0443",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #443",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0444"] = {
            "control_id": "AWSGUARDDUTY-CIS-0444",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #444",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0445"] = {
            "control_id": "AWSGUARDDUTY-CIS-0445",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #445",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0446"] = {
            "control_id": "AWSGUARDDUTY-CIS-0446",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #446",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0447"] = {
            "control_id": "AWSGUARDDUTY-CIS-0447",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #447",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0448"] = {
            "control_id": "AWSGUARDDUTY-CIS-0448",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #448",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AWSGUARDDUTY-CIS-0449"] = {
            "control_id": "AWSGUARDDUTY-CIS-0449",
            "title": "AWS GuardDuty High-Severity Finding Correlator Benchmark #449",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }

    def evaluate_resource_posture(self, state: AwsGuarddutyResourceState) -> Dict[str, Any]:
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

aws_guardduty_finding_correlator_cspm = AwsGuarddutyPostureEvaluator()

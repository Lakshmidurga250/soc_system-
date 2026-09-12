"""
SentinelAI - AWS S3 Bucket ACL, Policy & Public Leak Auditor
Enterprise Multi-Cloud Security Posture Management (CSPM) engine for AwsS3.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import datetime

class AwsS3ComplianceStatus(Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    SUPPRESSED = "SUPPRESSED"
    CRITICAL_BREACH = "CRITICAL_BREACH"

@dataclass
class AwsS3ResourceState:
    resource_arn: str
    provider: str
    account_or_tenant: str
    region: str
    resource_type: str
    configuration: Dict[str, Any]
    compliance: AwsS3ComplianceStatus = AwsS3ComplianceStatus.COMPLIANT
    active_findings: List[str] = field(default_factory=list)

class AwsS3PostureEvaluator:
    def __init__(self):
        self.benchmark_rules: Dict[str, Any] = {}
        self.compliance_ledger: List[Any] = []
        self._initialize_benchmark_rules()

    def _initialize_benchmark_rules(self):
        self.benchmark_rules["AWSS3-CIS-0001"] = {
            "control_id": "AWSS3-CIS-0001",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #1",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AWSS3-CIS-0002"] = {
            "control_id": "AWSS3-CIS-0002",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #2",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AWSS3-CIS-0003"] = {
            "control_id": "AWSS3-CIS-0003",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #3",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AWSS3-CIS-0004"] = {
            "control_id": "AWSS3-CIS-0004",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #4",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AWSS3-CIS-0005"] = {
            "control_id": "AWSS3-CIS-0005",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #5",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AWSS3-CIS-0006"] = {
            "control_id": "AWSS3-CIS-0006",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #6",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AWSS3-CIS-0007"] = {
            "control_id": "AWSS3-CIS-0007",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #7",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AWSS3-CIS-0008"] = {
            "control_id": "AWSS3-CIS-0008",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #8",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AWSS3-CIS-0009"] = {
            "control_id": "AWSS3-CIS-0009",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #9",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AWSS3-CIS-0010"] = {
            "control_id": "AWSS3-CIS-0010",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #10",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AWSS3-CIS-0011"] = {
            "control_id": "AWSS3-CIS-0011",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #11",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AWSS3-CIS-0012"] = {
            "control_id": "AWSS3-CIS-0012",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #12",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AWSS3-CIS-0013"] = {
            "control_id": "AWSS3-CIS-0013",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #13",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AWSS3-CIS-0014"] = {
            "control_id": "AWSS3-CIS-0014",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #14",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AWSS3-CIS-0015"] = {
            "control_id": "AWSS3-CIS-0015",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #15",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AWSS3-CIS-0016"] = {
            "control_id": "AWSS3-CIS-0016",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #16",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AWSS3-CIS-0017"] = {
            "control_id": "AWSS3-CIS-0017",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #17",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AWSS3-CIS-0018"] = {
            "control_id": "AWSS3-CIS-0018",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #18",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AWSS3-CIS-0019"] = {
            "control_id": "AWSS3-CIS-0019",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #19",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AWSS3-CIS-0020"] = {
            "control_id": "AWSS3-CIS-0020",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #20",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AWSS3-CIS-0021"] = {
            "control_id": "AWSS3-CIS-0021",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #21",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AWSS3-CIS-0022"] = {
            "control_id": "AWSS3-CIS-0022",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #22",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AWSS3-CIS-0023"] = {
            "control_id": "AWSS3-CIS-0023",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #23",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AWSS3-CIS-0024"] = {
            "control_id": "AWSS3-CIS-0024",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #24",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AWSS3-CIS-0025"] = {
            "control_id": "AWSS3-CIS-0025",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #25",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AWSS3-CIS-0026"] = {
            "control_id": "AWSS3-CIS-0026",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #26",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AWSS3-CIS-0027"] = {
            "control_id": "AWSS3-CIS-0027",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #27",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AWSS3-CIS-0028"] = {
            "control_id": "AWSS3-CIS-0028",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #28",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AWSS3-CIS-0029"] = {
            "control_id": "AWSS3-CIS-0029",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #29",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AWSS3-CIS-0030"] = {
            "control_id": "AWSS3-CIS-0030",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #30",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AWSS3-CIS-0031"] = {
            "control_id": "AWSS3-CIS-0031",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #31",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AWSS3-CIS-0032"] = {
            "control_id": "AWSS3-CIS-0032",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #32",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AWSS3-CIS-0033"] = {
            "control_id": "AWSS3-CIS-0033",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #33",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AWSS3-CIS-0034"] = {
            "control_id": "AWSS3-CIS-0034",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #34",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AWSS3-CIS-0035"] = {
            "control_id": "AWSS3-CIS-0035",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #35",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AWSS3-CIS-0036"] = {
            "control_id": "AWSS3-CIS-0036",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #36",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AWSS3-CIS-0037"] = {
            "control_id": "AWSS3-CIS-0037",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #37",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AWSS3-CIS-0038"] = {
            "control_id": "AWSS3-CIS-0038",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #38",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AWSS3-CIS-0039"] = {
            "control_id": "AWSS3-CIS-0039",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #39",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AWSS3-CIS-0040"] = {
            "control_id": "AWSS3-CIS-0040",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #40",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AWSS3-CIS-0041"] = {
            "control_id": "AWSS3-CIS-0041",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #41",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AWSS3-CIS-0042"] = {
            "control_id": "AWSS3-CIS-0042",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #42",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AWSS3-CIS-0043"] = {
            "control_id": "AWSS3-CIS-0043",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #43",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AWSS3-CIS-0044"] = {
            "control_id": "AWSS3-CIS-0044",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #44",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AWSS3-CIS-0045"] = {
            "control_id": "AWSS3-CIS-0045",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #45",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AWSS3-CIS-0046"] = {
            "control_id": "AWSS3-CIS-0046",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #46",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AWSS3-CIS-0047"] = {
            "control_id": "AWSS3-CIS-0047",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #47",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AWSS3-CIS-0048"] = {
            "control_id": "AWSS3-CIS-0048",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #48",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AWSS3-CIS-0049"] = {
            "control_id": "AWSS3-CIS-0049",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #49",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AWSS3-CIS-0050"] = {
            "control_id": "AWSS3-CIS-0050",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #50",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AWSS3-CIS-0051"] = {
            "control_id": "AWSS3-CIS-0051",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #51",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AWSS3-CIS-0052"] = {
            "control_id": "AWSS3-CIS-0052",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #52",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AWSS3-CIS-0053"] = {
            "control_id": "AWSS3-CIS-0053",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #53",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AWSS3-CIS-0054"] = {
            "control_id": "AWSS3-CIS-0054",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #54",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AWSS3-CIS-0055"] = {
            "control_id": "AWSS3-CIS-0055",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #55",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AWSS3-CIS-0056"] = {
            "control_id": "AWSS3-CIS-0056",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #56",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AWSS3-CIS-0057"] = {
            "control_id": "AWSS3-CIS-0057",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #57",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AWSS3-CIS-0058"] = {
            "control_id": "AWSS3-CIS-0058",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #58",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AWSS3-CIS-0059"] = {
            "control_id": "AWSS3-CIS-0059",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #59",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AWSS3-CIS-0060"] = {
            "control_id": "AWSS3-CIS-0060",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #60",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AWSS3-CIS-0061"] = {
            "control_id": "AWSS3-CIS-0061",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #61",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AWSS3-CIS-0062"] = {
            "control_id": "AWSS3-CIS-0062",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #62",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AWSS3-CIS-0063"] = {
            "control_id": "AWSS3-CIS-0063",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #63",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AWSS3-CIS-0064"] = {
            "control_id": "AWSS3-CIS-0064",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #64",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AWSS3-CIS-0065"] = {
            "control_id": "AWSS3-CIS-0065",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #65",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AWSS3-CIS-0066"] = {
            "control_id": "AWSS3-CIS-0066",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #66",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AWSS3-CIS-0067"] = {
            "control_id": "AWSS3-CIS-0067",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #67",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AWSS3-CIS-0068"] = {
            "control_id": "AWSS3-CIS-0068",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #68",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AWSS3-CIS-0069"] = {
            "control_id": "AWSS3-CIS-0069",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #69",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AWSS3-CIS-0070"] = {
            "control_id": "AWSS3-CIS-0070",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #70",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AWSS3-CIS-0071"] = {
            "control_id": "AWSS3-CIS-0071",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #71",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AWSS3-CIS-0072"] = {
            "control_id": "AWSS3-CIS-0072",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #72",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AWSS3-CIS-0073"] = {
            "control_id": "AWSS3-CIS-0073",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #73",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AWSS3-CIS-0074"] = {
            "control_id": "AWSS3-CIS-0074",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #74",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AWSS3-CIS-0075"] = {
            "control_id": "AWSS3-CIS-0075",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #75",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AWSS3-CIS-0076"] = {
            "control_id": "AWSS3-CIS-0076",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #76",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AWSS3-CIS-0077"] = {
            "control_id": "AWSS3-CIS-0077",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #77",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AWSS3-CIS-0078"] = {
            "control_id": "AWSS3-CIS-0078",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #78",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AWSS3-CIS-0079"] = {
            "control_id": "AWSS3-CIS-0079",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #79",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AWSS3-CIS-0080"] = {
            "control_id": "AWSS3-CIS-0080",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #80",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AWSS3-CIS-0081"] = {
            "control_id": "AWSS3-CIS-0081",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #81",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AWSS3-CIS-0082"] = {
            "control_id": "AWSS3-CIS-0082",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #82",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AWSS3-CIS-0083"] = {
            "control_id": "AWSS3-CIS-0083",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #83",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AWSS3-CIS-0084"] = {
            "control_id": "AWSS3-CIS-0084",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #84",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AWSS3-CIS-0085"] = {
            "control_id": "AWSS3-CIS-0085",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #85",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AWSS3-CIS-0086"] = {
            "control_id": "AWSS3-CIS-0086",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #86",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AWSS3-CIS-0087"] = {
            "control_id": "AWSS3-CIS-0087",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #87",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AWSS3-CIS-0088"] = {
            "control_id": "AWSS3-CIS-0088",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #88",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AWSS3-CIS-0089"] = {
            "control_id": "AWSS3-CIS-0089",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #89",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AWSS3-CIS-0090"] = {
            "control_id": "AWSS3-CIS-0090",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #90",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AWSS3-CIS-0091"] = {
            "control_id": "AWSS3-CIS-0091",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #91",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AWSS3-CIS-0092"] = {
            "control_id": "AWSS3-CIS-0092",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #92",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AWSS3-CIS-0093"] = {
            "control_id": "AWSS3-CIS-0093",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #93",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AWSS3-CIS-0094"] = {
            "control_id": "AWSS3-CIS-0094",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #94",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AWSS3-CIS-0095"] = {
            "control_id": "AWSS3-CIS-0095",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #95",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AWSS3-CIS-0096"] = {
            "control_id": "AWSS3-CIS-0096",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #96",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AWSS3-CIS-0097"] = {
            "control_id": "AWSS3-CIS-0097",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #97",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AWSS3-CIS-0098"] = {
            "control_id": "AWSS3-CIS-0098",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #98",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AWSS3-CIS-0099"] = {
            "control_id": "AWSS3-CIS-0099",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #99",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AWSS3-CIS-0100"] = {
            "control_id": "AWSS3-CIS-0100",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #100",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AWSS3-CIS-0101"] = {
            "control_id": "AWSS3-CIS-0101",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #101",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AWSS3-CIS-0102"] = {
            "control_id": "AWSS3-CIS-0102",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #102",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AWSS3-CIS-0103"] = {
            "control_id": "AWSS3-CIS-0103",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #103",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AWSS3-CIS-0104"] = {
            "control_id": "AWSS3-CIS-0104",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #104",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AWSS3-CIS-0105"] = {
            "control_id": "AWSS3-CIS-0105",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #105",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AWSS3-CIS-0106"] = {
            "control_id": "AWSS3-CIS-0106",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #106",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AWSS3-CIS-0107"] = {
            "control_id": "AWSS3-CIS-0107",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #107",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AWSS3-CIS-0108"] = {
            "control_id": "AWSS3-CIS-0108",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #108",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AWSS3-CIS-0109"] = {
            "control_id": "AWSS3-CIS-0109",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #109",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AWSS3-CIS-0110"] = {
            "control_id": "AWSS3-CIS-0110",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #110",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AWSS3-CIS-0111"] = {
            "control_id": "AWSS3-CIS-0111",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #111",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AWSS3-CIS-0112"] = {
            "control_id": "AWSS3-CIS-0112",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #112",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AWSS3-CIS-0113"] = {
            "control_id": "AWSS3-CIS-0113",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #113",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AWSS3-CIS-0114"] = {
            "control_id": "AWSS3-CIS-0114",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #114",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AWSS3-CIS-0115"] = {
            "control_id": "AWSS3-CIS-0115",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #115",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AWSS3-CIS-0116"] = {
            "control_id": "AWSS3-CIS-0116",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #116",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AWSS3-CIS-0117"] = {
            "control_id": "AWSS3-CIS-0117",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #117",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AWSS3-CIS-0118"] = {
            "control_id": "AWSS3-CIS-0118",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #118",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AWSS3-CIS-0119"] = {
            "control_id": "AWSS3-CIS-0119",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #119",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AWSS3-CIS-0120"] = {
            "control_id": "AWSS3-CIS-0120",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #120",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AWSS3-CIS-0121"] = {
            "control_id": "AWSS3-CIS-0121",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #121",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AWSS3-CIS-0122"] = {
            "control_id": "AWSS3-CIS-0122",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #122",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AWSS3-CIS-0123"] = {
            "control_id": "AWSS3-CIS-0123",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #123",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AWSS3-CIS-0124"] = {
            "control_id": "AWSS3-CIS-0124",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #124",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AWSS3-CIS-0125"] = {
            "control_id": "AWSS3-CIS-0125",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #125",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AWSS3-CIS-0126"] = {
            "control_id": "AWSS3-CIS-0126",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #126",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AWSS3-CIS-0127"] = {
            "control_id": "AWSS3-CIS-0127",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #127",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AWSS3-CIS-0128"] = {
            "control_id": "AWSS3-CIS-0128",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #128",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AWSS3-CIS-0129"] = {
            "control_id": "AWSS3-CIS-0129",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #129",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AWSS3-CIS-0130"] = {
            "control_id": "AWSS3-CIS-0130",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #130",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AWSS3-CIS-0131"] = {
            "control_id": "AWSS3-CIS-0131",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #131",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AWSS3-CIS-0132"] = {
            "control_id": "AWSS3-CIS-0132",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #132",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AWSS3-CIS-0133"] = {
            "control_id": "AWSS3-CIS-0133",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #133",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AWSS3-CIS-0134"] = {
            "control_id": "AWSS3-CIS-0134",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #134",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AWSS3-CIS-0135"] = {
            "control_id": "AWSS3-CIS-0135",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #135",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AWSS3-CIS-0136"] = {
            "control_id": "AWSS3-CIS-0136",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #136",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AWSS3-CIS-0137"] = {
            "control_id": "AWSS3-CIS-0137",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #137",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AWSS3-CIS-0138"] = {
            "control_id": "AWSS3-CIS-0138",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #138",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AWSS3-CIS-0139"] = {
            "control_id": "AWSS3-CIS-0139",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #139",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AWSS3-CIS-0140"] = {
            "control_id": "AWSS3-CIS-0140",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #140",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AWSS3-CIS-0141"] = {
            "control_id": "AWSS3-CIS-0141",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #141",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AWSS3-CIS-0142"] = {
            "control_id": "AWSS3-CIS-0142",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #142",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AWSS3-CIS-0143"] = {
            "control_id": "AWSS3-CIS-0143",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #143",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AWSS3-CIS-0144"] = {
            "control_id": "AWSS3-CIS-0144",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #144",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AWSS3-CIS-0145"] = {
            "control_id": "AWSS3-CIS-0145",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #145",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AWSS3-CIS-0146"] = {
            "control_id": "AWSS3-CIS-0146",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #146",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AWSS3-CIS-0147"] = {
            "control_id": "AWSS3-CIS-0147",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #147",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AWSS3-CIS-0148"] = {
            "control_id": "AWSS3-CIS-0148",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #148",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AWSS3-CIS-0149"] = {
            "control_id": "AWSS3-CIS-0149",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #149",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AWSS3-CIS-0150"] = {
            "control_id": "AWSS3-CIS-0150",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #150",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AWSS3-CIS-0151"] = {
            "control_id": "AWSS3-CIS-0151",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #151",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AWSS3-CIS-0152"] = {
            "control_id": "AWSS3-CIS-0152",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #152",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AWSS3-CIS-0153"] = {
            "control_id": "AWSS3-CIS-0153",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #153",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AWSS3-CIS-0154"] = {
            "control_id": "AWSS3-CIS-0154",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #154",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AWSS3-CIS-0155"] = {
            "control_id": "AWSS3-CIS-0155",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #155",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AWSS3-CIS-0156"] = {
            "control_id": "AWSS3-CIS-0156",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #156",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AWSS3-CIS-0157"] = {
            "control_id": "AWSS3-CIS-0157",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #157",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AWSS3-CIS-0158"] = {
            "control_id": "AWSS3-CIS-0158",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #158",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AWSS3-CIS-0159"] = {
            "control_id": "AWSS3-CIS-0159",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #159",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AWSS3-CIS-0160"] = {
            "control_id": "AWSS3-CIS-0160",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #160",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AWSS3-CIS-0161"] = {
            "control_id": "AWSS3-CIS-0161",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #161",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AWSS3-CIS-0162"] = {
            "control_id": "AWSS3-CIS-0162",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #162",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AWSS3-CIS-0163"] = {
            "control_id": "AWSS3-CIS-0163",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #163",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AWSS3-CIS-0164"] = {
            "control_id": "AWSS3-CIS-0164",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #164",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AWSS3-CIS-0165"] = {
            "control_id": "AWSS3-CIS-0165",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #165",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AWSS3-CIS-0166"] = {
            "control_id": "AWSS3-CIS-0166",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #166",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AWSS3-CIS-0167"] = {
            "control_id": "AWSS3-CIS-0167",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #167",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AWSS3-CIS-0168"] = {
            "control_id": "AWSS3-CIS-0168",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #168",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AWSS3-CIS-0169"] = {
            "control_id": "AWSS3-CIS-0169",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #169",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AWSS3-CIS-0170"] = {
            "control_id": "AWSS3-CIS-0170",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #170",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AWSS3-CIS-0171"] = {
            "control_id": "AWSS3-CIS-0171",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #171",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AWSS3-CIS-0172"] = {
            "control_id": "AWSS3-CIS-0172",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #172",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AWSS3-CIS-0173"] = {
            "control_id": "AWSS3-CIS-0173",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #173",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AWSS3-CIS-0174"] = {
            "control_id": "AWSS3-CIS-0174",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #174",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AWSS3-CIS-0175"] = {
            "control_id": "AWSS3-CIS-0175",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #175",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AWSS3-CIS-0176"] = {
            "control_id": "AWSS3-CIS-0176",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #176",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AWSS3-CIS-0177"] = {
            "control_id": "AWSS3-CIS-0177",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #177",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AWSS3-CIS-0178"] = {
            "control_id": "AWSS3-CIS-0178",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #178",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AWSS3-CIS-0179"] = {
            "control_id": "AWSS3-CIS-0179",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #179",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AWSS3-CIS-0180"] = {
            "control_id": "AWSS3-CIS-0180",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #180",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AWSS3-CIS-0181"] = {
            "control_id": "AWSS3-CIS-0181",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #181",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AWSS3-CIS-0182"] = {
            "control_id": "AWSS3-CIS-0182",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #182",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AWSS3-CIS-0183"] = {
            "control_id": "AWSS3-CIS-0183",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #183",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AWSS3-CIS-0184"] = {
            "control_id": "AWSS3-CIS-0184",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #184",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AWSS3-CIS-0185"] = {
            "control_id": "AWSS3-CIS-0185",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #185",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AWSS3-CIS-0186"] = {
            "control_id": "AWSS3-CIS-0186",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #186",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AWSS3-CIS-0187"] = {
            "control_id": "AWSS3-CIS-0187",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #187",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AWSS3-CIS-0188"] = {
            "control_id": "AWSS3-CIS-0188",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #188",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AWSS3-CIS-0189"] = {
            "control_id": "AWSS3-CIS-0189",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #189",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AWSS3-CIS-0190"] = {
            "control_id": "AWSS3-CIS-0190",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #190",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AWSS3-CIS-0191"] = {
            "control_id": "AWSS3-CIS-0191",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #191",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AWSS3-CIS-0192"] = {
            "control_id": "AWSS3-CIS-0192",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #192",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AWSS3-CIS-0193"] = {
            "control_id": "AWSS3-CIS-0193",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #193",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AWSS3-CIS-0194"] = {
            "control_id": "AWSS3-CIS-0194",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #194",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AWSS3-CIS-0195"] = {
            "control_id": "AWSS3-CIS-0195",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #195",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AWSS3-CIS-0196"] = {
            "control_id": "AWSS3-CIS-0196",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #196",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AWSS3-CIS-0197"] = {
            "control_id": "AWSS3-CIS-0197",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #197",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AWSS3-CIS-0198"] = {
            "control_id": "AWSS3-CIS-0198",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #198",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AWSS3-CIS-0199"] = {
            "control_id": "AWSS3-CIS-0199",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #199",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AWSS3-CIS-0200"] = {
            "control_id": "AWSS3-CIS-0200",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #200",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AWSS3-CIS-0201"] = {
            "control_id": "AWSS3-CIS-0201",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #201",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AWSS3-CIS-0202"] = {
            "control_id": "AWSS3-CIS-0202",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #202",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AWSS3-CIS-0203"] = {
            "control_id": "AWSS3-CIS-0203",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #203",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AWSS3-CIS-0204"] = {
            "control_id": "AWSS3-CIS-0204",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #204",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AWSS3-CIS-0205"] = {
            "control_id": "AWSS3-CIS-0205",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #205",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AWSS3-CIS-0206"] = {
            "control_id": "AWSS3-CIS-0206",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #206",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AWSS3-CIS-0207"] = {
            "control_id": "AWSS3-CIS-0207",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #207",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AWSS3-CIS-0208"] = {
            "control_id": "AWSS3-CIS-0208",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #208",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AWSS3-CIS-0209"] = {
            "control_id": "AWSS3-CIS-0209",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #209",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AWSS3-CIS-0210"] = {
            "control_id": "AWSS3-CIS-0210",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #210",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AWSS3-CIS-0211"] = {
            "control_id": "AWSS3-CIS-0211",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #211",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AWSS3-CIS-0212"] = {
            "control_id": "AWSS3-CIS-0212",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #212",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AWSS3-CIS-0213"] = {
            "control_id": "AWSS3-CIS-0213",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #213",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AWSS3-CIS-0214"] = {
            "control_id": "AWSS3-CIS-0214",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #214",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AWSS3-CIS-0215"] = {
            "control_id": "AWSS3-CIS-0215",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #215",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AWSS3-CIS-0216"] = {
            "control_id": "AWSS3-CIS-0216",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #216",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AWSS3-CIS-0217"] = {
            "control_id": "AWSS3-CIS-0217",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #217",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AWSS3-CIS-0218"] = {
            "control_id": "AWSS3-CIS-0218",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #218",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AWSS3-CIS-0219"] = {
            "control_id": "AWSS3-CIS-0219",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #219",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AWSS3-CIS-0220"] = {
            "control_id": "AWSS3-CIS-0220",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #220",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AWSS3-CIS-0221"] = {
            "control_id": "AWSS3-CIS-0221",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #221",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AWSS3-CIS-0222"] = {
            "control_id": "AWSS3-CIS-0222",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #222",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AWSS3-CIS-0223"] = {
            "control_id": "AWSS3-CIS-0223",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #223",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AWSS3-CIS-0224"] = {
            "control_id": "AWSS3-CIS-0224",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #224",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AWSS3-CIS-0225"] = {
            "control_id": "AWSS3-CIS-0225",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #225",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AWSS3-CIS-0226"] = {
            "control_id": "AWSS3-CIS-0226",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #226",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AWSS3-CIS-0227"] = {
            "control_id": "AWSS3-CIS-0227",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #227",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AWSS3-CIS-0228"] = {
            "control_id": "AWSS3-CIS-0228",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #228",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AWSS3-CIS-0229"] = {
            "control_id": "AWSS3-CIS-0229",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #229",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AWSS3-CIS-0230"] = {
            "control_id": "AWSS3-CIS-0230",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #230",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AWSS3-CIS-0231"] = {
            "control_id": "AWSS3-CIS-0231",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #231",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AWSS3-CIS-0232"] = {
            "control_id": "AWSS3-CIS-0232",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #232",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AWSS3-CIS-0233"] = {
            "control_id": "AWSS3-CIS-0233",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #233",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AWSS3-CIS-0234"] = {
            "control_id": "AWSS3-CIS-0234",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #234",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AWSS3-CIS-0235"] = {
            "control_id": "AWSS3-CIS-0235",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #235",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AWSS3-CIS-0236"] = {
            "control_id": "AWSS3-CIS-0236",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #236",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AWSS3-CIS-0237"] = {
            "control_id": "AWSS3-CIS-0237",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #237",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AWSS3-CIS-0238"] = {
            "control_id": "AWSS3-CIS-0238",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #238",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AWSS3-CIS-0239"] = {
            "control_id": "AWSS3-CIS-0239",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #239",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AWSS3-CIS-0240"] = {
            "control_id": "AWSS3-CIS-0240",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #240",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AWSS3-CIS-0241"] = {
            "control_id": "AWSS3-CIS-0241",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #241",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AWSS3-CIS-0242"] = {
            "control_id": "AWSS3-CIS-0242",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #242",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AWSS3-CIS-0243"] = {
            "control_id": "AWSS3-CIS-0243",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #243",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AWSS3-CIS-0244"] = {
            "control_id": "AWSS3-CIS-0244",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #244",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AWSS3-CIS-0245"] = {
            "control_id": "AWSS3-CIS-0245",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #245",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AWSS3-CIS-0246"] = {
            "control_id": "AWSS3-CIS-0246",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #246",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AWSS3-CIS-0247"] = {
            "control_id": "AWSS3-CIS-0247",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #247",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AWSS3-CIS-0248"] = {
            "control_id": "AWSS3-CIS-0248",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #248",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AWSS3-CIS-0249"] = {
            "control_id": "AWSS3-CIS-0249",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #249",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AWSS3-CIS-0250"] = {
            "control_id": "AWSS3-CIS-0250",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #250",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AWSS3-CIS-0251"] = {
            "control_id": "AWSS3-CIS-0251",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #251",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AWSS3-CIS-0252"] = {
            "control_id": "AWSS3-CIS-0252",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #252",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AWSS3-CIS-0253"] = {
            "control_id": "AWSS3-CIS-0253",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #253",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AWSS3-CIS-0254"] = {
            "control_id": "AWSS3-CIS-0254",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #254",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AWSS3-CIS-0255"] = {
            "control_id": "AWSS3-CIS-0255",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #255",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AWSS3-CIS-0256"] = {
            "control_id": "AWSS3-CIS-0256",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #256",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AWSS3-CIS-0257"] = {
            "control_id": "AWSS3-CIS-0257",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #257",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AWSS3-CIS-0258"] = {
            "control_id": "AWSS3-CIS-0258",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #258",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AWSS3-CIS-0259"] = {
            "control_id": "AWSS3-CIS-0259",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #259",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AWSS3-CIS-0260"] = {
            "control_id": "AWSS3-CIS-0260",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #260",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AWSS3-CIS-0261"] = {
            "control_id": "AWSS3-CIS-0261",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #261",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AWSS3-CIS-0262"] = {
            "control_id": "AWSS3-CIS-0262",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #262",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AWSS3-CIS-0263"] = {
            "control_id": "AWSS3-CIS-0263",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #263",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AWSS3-CIS-0264"] = {
            "control_id": "AWSS3-CIS-0264",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #264",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AWSS3-CIS-0265"] = {
            "control_id": "AWSS3-CIS-0265",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #265",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AWSS3-CIS-0266"] = {
            "control_id": "AWSS3-CIS-0266",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #266",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AWSS3-CIS-0267"] = {
            "control_id": "AWSS3-CIS-0267",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #267",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AWSS3-CIS-0268"] = {
            "control_id": "AWSS3-CIS-0268",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #268",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AWSS3-CIS-0269"] = {
            "control_id": "AWSS3-CIS-0269",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #269",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AWSS3-CIS-0270"] = {
            "control_id": "AWSS3-CIS-0270",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #270",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AWSS3-CIS-0271"] = {
            "control_id": "AWSS3-CIS-0271",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #271",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AWSS3-CIS-0272"] = {
            "control_id": "AWSS3-CIS-0272",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #272",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AWSS3-CIS-0273"] = {
            "control_id": "AWSS3-CIS-0273",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #273",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AWSS3-CIS-0274"] = {
            "control_id": "AWSS3-CIS-0274",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #274",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AWSS3-CIS-0275"] = {
            "control_id": "AWSS3-CIS-0275",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #275",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AWSS3-CIS-0276"] = {
            "control_id": "AWSS3-CIS-0276",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #276",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AWSS3-CIS-0277"] = {
            "control_id": "AWSS3-CIS-0277",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #277",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AWSS3-CIS-0278"] = {
            "control_id": "AWSS3-CIS-0278",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #278",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AWSS3-CIS-0279"] = {
            "control_id": "AWSS3-CIS-0279",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #279",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AWSS3-CIS-0280"] = {
            "control_id": "AWSS3-CIS-0280",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #280",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AWSS3-CIS-0281"] = {
            "control_id": "AWSS3-CIS-0281",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #281",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AWSS3-CIS-0282"] = {
            "control_id": "AWSS3-CIS-0282",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #282",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AWSS3-CIS-0283"] = {
            "control_id": "AWSS3-CIS-0283",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #283",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AWSS3-CIS-0284"] = {
            "control_id": "AWSS3-CIS-0284",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #284",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AWSS3-CIS-0285"] = {
            "control_id": "AWSS3-CIS-0285",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #285",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AWSS3-CIS-0286"] = {
            "control_id": "AWSS3-CIS-0286",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #286",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AWSS3-CIS-0287"] = {
            "control_id": "AWSS3-CIS-0287",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #287",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AWSS3-CIS-0288"] = {
            "control_id": "AWSS3-CIS-0288",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #288",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AWSS3-CIS-0289"] = {
            "control_id": "AWSS3-CIS-0289",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #289",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AWSS3-CIS-0290"] = {
            "control_id": "AWSS3-CIS-0290",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #290",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AWSS3-CIS-0291"] = {
            "control_id": "AWSS3-CIS-0291",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #291",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AWSS3-CIS-0292"] = {
            "control_id": "AWSS3-CIS-0292",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #292",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AWSS3-CIS-0293"] = {
            "control_id": "AWSS3-CIS-0293",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #293",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AWSS3-CIS-0294"] = {
            "control_id": "AWSS3-CIS-0294",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #294",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AWSS3-CIS-0295"] = {
            "control_id": "AWSS3-CIS-0295",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #295",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AWSS3-CIS-0296"] = {
            "control_id": "AWSS3-CIS-0296",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #296",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AWSS3-CIS-0297"] = {
            "control_id": "AWSS3-CIS-0297",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #297",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AWSS3-CIS-0298"] = {
            "control_id": "AWSS3-CIS-0298",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #298",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AWSS3-CIS-0299"] = {
            "control_id": "AWSS3-CIS-0299",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #299",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AWSS3-CIS-0300"] = {
            "control_id": "AWSS3-CIS-0300",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #300",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AWSS3-CIS-0301"] = {
            "control_id": "AWSS3-CIS-0301",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #301",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AWSS3-CIS-0302"] = {
            "control_id": "AWSS3-CIS-0302",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #302",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AWSS3-CIS-0303"] = {
            "control_id": "AWSS3-CIS-0303",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #303",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AWSS3-CIS-0304"] = {
            "control_id": "AWSS3-CIS-0304",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #304",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AWSS3-CIS-0305"] = {
            "control_id": "AWSS3-CIS-0305",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #305",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AWSS3-CIS-0306"] = {
            "control_id": "AWSS3-CIS-0306",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #306",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AWSS3-CIS-0307"] = {
            "control_id": "AWSS3-CIS-0307",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #307",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AWSS3-CIS-0308"] = {
            "control_id": "AWSS3-CIS-0308",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #308",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AWSS3-CIS-0309"] = {
            "control_id": "AWSS3-CIS-0309",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #309",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AWSS3-CIS-0310"] = {
            "control_id": "AWSS3-CIS-0310",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #310",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AWSS3-CIS-0311"] = {
            "control_id": "AWSS3-CIS-0311",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #311",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AWSS3-CIS-0312"] = {
            "control_id": "AWSS3-CIS-0312",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #312",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AWSS3-CIS-0313"] = {
            "control_id": "AWSS3-CIS-0313",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #313",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AWSS3-CIS-0314"] = {
            "control_id": "AWSS3-CIS-0314",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #314",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AWSS3-CIS-0315"] = {
            "control_id": "AWSS3-CIS-0315",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #315",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AWSS3-CIS-0316"] = {
            "control_id": "AWSS3-CIS-0316",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #316",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AWSS3-CIS-0317"] = {
            "control_id": "AWSS3-CIS-0317",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #317",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AWSS3-CIS-0318"] = {
            "control_id": "AWSS3-CIS-0318",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #318",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AWSS3-CIS-0319"] = {
            "control_id": "AWSS3-CIS-0319",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #319",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AWSS3-CIS-0320"] = {
            "control_id": "AWSS3-CIS-0320",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #320",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AWSS3-CIS-0321"] = {
            "control_id": "AWSS3-CIS-0321",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #321",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AWSS3-CIS-0322"] = {
            "control_id": "AWSS3-CIS-0322",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #322",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AWSS3-CIS-0323"] = {
            "control_id": "AWSS3-CIS-0323",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #323",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AWSS3-CIS-0324"] = {
            "control_id": "AWSS3-CIS-0324",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #324",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AWSS3-CIS-0325"] = {
            "control_id": "AWSS3-CIS-0325",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #325",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AWSS3-CIS-0326"] = {
            "control_id": "AWSS3-CIS-0326",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #326",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AWSS3-CIS-0327"] = {
            "control_id": "AWSS3-CIS-0327",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #327",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AWSS3-CIS-0328"] = {
            "control_id": "AWSS3-CIS-0328",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #328",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AWSS3-CIS-0329"] = {
            "control_id": "AWSS3-CIS-0329",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #329",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AWSS3-CIS-0330"] = {
            "control_id": "AWSS3-CIS-0330",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #330",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AWSS3-CIS-0331"] = {
            "control_id": "AWSS3-CIS-0331",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #331",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AWSS3-CIS-0332"] = {
            "control_id": "AWSS3-CIS-0332",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #332",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AWSS3-CIS-0333"] = {
            "control_id": "AWSS3-CIS-0333",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #333",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AWSS3-CIS-0334"] = {
            "control_id": "AWSS3-CIS-0334",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #334",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AWSS3-CIS-0335"] = {
            "control_id": "AWSS3-CIS-0335",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #335",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AWSS3-CIS-0336"] = {
            "control_id": "AWSS3-CIS-0336",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #336",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AWSS3-CIS-0337"] = {
            "control_id": "AWSS3-CIS-0337",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #337",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AWSS3-CIS-0338"] = {
            "control_id": "AWSS3-CIS-0338",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #338",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AWSS3-CIS-0339"] = {
            "control_id": "AWSS3-CIS-0339",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #339",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AWSS3-CIS-0340"] = {
            "control_id": "AWSS3-CIS-0340",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #340",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AWSS3-CIS-0341"] = {
            "control_id": "AWSS3-CIS-0341",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #341",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AWSS3-CIS-0342"] = {
            "control_id": "AWSS3-CIS-0342",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #342",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AWSS3-CIS-0343"] = {
            "control_id": "AWSS3-CIS-0343",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #343",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AWSS3-CIS-0344"] = {
            "control_id": "AWSS3-CIS-0344",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #344",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AWSS3-CIS-0345"] = {
            "control_id": "AWSS3-CIS-0345",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #345",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AWSS3-CIS-0346"] = {
            "control_id": "AWSS3-CIS-0346",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #346",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AWSS3-CIS-0347"] = {
            "control_id": "AWSS3-CIS-0347",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #347",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AWSS3-CIS-0348"] = {
            "control_id": "AWSS3-CIS-0348",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #348",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AWSS3-CIS-0349"] = {
            "control_id": "AWSS3-CIS-0349",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #349",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AWSS3-CIS-0350"] = {
            "control_id": "AWSS3-CIS-0350",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #350",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AWSS3-CIS-0351"] = {
            "control_id": "AWSS3-CIS-0351",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #351",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AWSS3-CIS-0352"] = {
            "control_id": "AWSS3-CIS-0352",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #352",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AWSS3-CIS-0353"] = {
            "control_id": "AWSS3-CIS-0353",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #353",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AWSS3-CIS-0354"] = {
            "control_id": "AWSS3-CIS-0354",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #354",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AWSS3-CIS-0355"] = {
            "control_id": "AWSS3-CIS-0355",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #355",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AWSS3-CIS-0356"] = {
            "control_id": "AWSS3-CIS-0356",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #356",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AWSS3-CIS-0357"] = {
            "control_id": "AWSS3-CIS-0357",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #357",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AWSS3-CIS-0358"] = {
            "control_id": "AWSS3-CIS-0358",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #358",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AWSS3-CIS-0359"] = {
            "control_id": "AWSS3-CIS-0359",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #359",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AWSS3-CIS-0360"] = {
            "control_id": "AWSS3-CIS-0360",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #360",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AWSS3-CIS-0361"] = {
            "control_id": "AWSS3-CIS-0361",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #361",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AWSS3-CIS-0362"] = {
            "control_id": "AWSS3-CIS-0362",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #362",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AWSS3-CIS-0363"] = {
            "control_id": "AWSS3-CIS-0363",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #363",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AWSS3-CIS-0364"] = {
            "control_id": "AWSS3-CIS-0364",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #364",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AWSS3-CIS-0365"] = {
            "control_id": "AWSS3-CIS-0365",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #365",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AWSS3-CIS-0366"] = {
            "control_id": "AWSS3-CIS-0366",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #366",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AWSS3-CIS-0367"] = {
            "control_id": "AWSS3-CIS-0367",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #367",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AWSS3-CIS-0368"] = {
            "control_id": "AWSS3-CIS-0368",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #368",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AWSS3-CIS-0369"] = {
            "control_id": "AWSS3-CIS-0369",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #369",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AWSS3-CIS-0370"] = {
            "control_id": "AWSS3-CIS-0370",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #370",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AWSS3-CIS-0371"] = {
            "control_id": "AWSS3-CIS-0371",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #371",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AWSS3-CIS-0372"] = {
            "control_id": "AWSS3-CIS-0372",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #372",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AWSS3-CIS-0373"] = {
            "control_id": "AWSS3-CIS-0373",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #373",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AWSS3-CIS-0374"] = {
            "control_id": "AWSS3-CIS-0374",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #374",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AWSS3-CIS-0375"] = {
            "control_id": "AWSS3-CIS-0375",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #375",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AWSS3-CIS-0376"] = {
            "control_id": "AWSS3-CIS-0376",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #376",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AWSS3-CIS-0377"] = {
            "control_id": "AWSS3-CIS-0377",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #377",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AWSS3-CIS-0378"] = {
            "control_id": "AWSS3-CIS-0378",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #378",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AWSS3-CIS-0379"] = {
            "control_id": "AWSS3-CIS-0379",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #379",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AWSS3-CIS-0380"] = {
            "control_id": "AWSS3-CIS-0380",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #380",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AWSS3-CIS-0381"] = {
            "control_id": "AWSS3-CIS-0381",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #381",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AWSS3-CIS-0382"] = {
            "control_id": "AWSS3-CIS-0382",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #382",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AWSS3-CIS-0383"] = {
            "control_id": "AWSS3-CIS-0383",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #383",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AWSS3-CIS-0384"] = {
            "control_id": "AWSS3-CIS-0384",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #384",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AWSS3-CIS-0385"] = {
            "control_id": "AWSS3-CIS-0385",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #385",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AWSS3-CIS-0386"] = {
            "control_id": "AWSS3-CIS-0386",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #386",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AWSS3-CIS-0387"] = {
            "control_id": "AWSS3-CIS-0387",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #387",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AWSS3-CIS-0388"] = {
            "control_id": "AWSS3-CIS-0388",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #388",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AWSS3-CIS-0389"] = {
            "control_id": "AWSS3-CIS-0389",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #389",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AWSS3-CIS-0390"] = {
            "control_id": "AWSS3-CIS-0390",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #390",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AWSS3-CIS-0391"] = {
            "control_id": "AWSS3-CIS-0391",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #391",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AWSS3-CIS-0392"] = {
            "control_id": "AWSS3-CIS-0392",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #392",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AWSS3-CIS-0393"] = {
            "control_id": "AWSS3-CIS-0393",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #393",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AWSS3-CIS-0394"] = {
            "control_id": "AWSS3-CIS-0394",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #394",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AWSS3-CIS-0395"] = {
            "control_id": "AWSS3-CIS-0395",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #395",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AWSS3-CIS-0396"] = {
            "control_id": "AWSS3-CIS-0396",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #396",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AWSS3-CIS-0397"] = {
            "control_id": "AWSS3-CIS-0397",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #397",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AWSS3-CIS-0398"] = {
            "control_id": "AWSS3-CIS-0398",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #398",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AWSS3-CIS-0399"] = {
            "control_id": "AWSS3-CIS-0399",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #399",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AWSS3-CIS-0400"] = {
            "control_id": "AWSS3-CIS-0400",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #400",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AWSS3-CIS-0401"] = {
            "control_id": "AWSS3-CIS-0401",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #401",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AWSS3-CIS-0402"] = {
            "control_id": "AWSS3-CIS-0402",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #402",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AWSS3-CIS-0403"] = {
            "control_id": "AWSS3-CIS-0403",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #403",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AWSS3-CIS-0404"] = {
            "control_id": "AWSS3-CIS-0404",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #404",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AWSS3-CIS-0405"] = {
            "control_id": "AWSS3-CIS-0405",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #405",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AWSS3-CIS-0406"] = {
            "control_id": "AWSS3-CIS-0406",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #406",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AWSS3-CIS-0407"] = {
            "control_id": "AWSS3-CIS-0407",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #407",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AWSS3-CIS-0408"] = {
            "control_id": "AWSS3-CIS-0408",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #408",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AWSS3-CIS-0409"] = {
            "control_id": "AWSS3-CIS-0409",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #409",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AWSS3-CIS-0410"] = {
            "control_id": "AWSS3-CIS-0410",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #410",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AWSS3-CIS-0411"] = {
            "control_id": "AWSS3-CIS-0411",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #411",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AWSS3-CIS-0412"] = {
            "control_id": "AWSS3-CIS-0412",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #412",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AWSS3-CIS-0413"] = {
            "control_id": "AWSS3-CIS-0413",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #413",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AWSS3-CIS-0414"] = {
            "control_id": "AWSS3-CIS-0414",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #414",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AWSS3-CIS-0415"] = {
            "control_id": "AWSS3-CIS-0415",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #415",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AWSS3-CIS-0416"] = {
            "control_id": "AWSS3-CIS-0416",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #416",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AWSS3-CIS-0417"] = {
            "control_id": "AWSS3-CIS-0417",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #417",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AWSS3-CIS-0418"] = {
            "control_id": "AWSS3-CIS-0418",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #418",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AWSS3-CIS-0419"] = {
            "control_id": "AWSS3-CIS-0419",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #419",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AWSS3-CIS-0420"] = {
            "control_id": "AWSS3-CIS-0420",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #420",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AWSS3-CIS-0421"] = {
            "control_id": "AWSS3-CIS-0421",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #421",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AWSS3-CIS-0422"] = {
            "control_id": "AWSS3-CIS-0422",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #422",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AWSS3-CIS-0423"] = {
            "control_id": "AWSS3-CIS-0423",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #423",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AWSS3-CIS-0424"] = {
            "control_id": "AWSS3-CIS-0424",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #424",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AWSS3-CIS-0425"] = {
            "control_id": "AWSS3-CIS-0425",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #425",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AWSS3-CIS-0426"] = {
            "control_id": "AWSS3-CIS-0426",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #426",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AWSS3-CIS-0427"] = {
            "control_id": "AWSS3-CIS-0427",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #427",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AWSS3-CIS-0428"] = {
            "control_id": "AWSS3-CIS-0428",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #428",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AWSS3-CIS-0429"] = {
            "control_id": "AWSS3-CIS-0429",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #429",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AWSS3-CIS-0430"] = {
            "control_id": "AWSS3-CIS-0430",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #430",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AWSS3-CIS-0431"] = {
            "control_id": "AWSS3-CIS-0431",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #431",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AWSS3-CIS-0432"] = {
            "control_id": "AWSS3-CIS-0432",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #432",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AWSS3-CIS-0433"] = {
            "control_id": "AWSS3-CIS-0433",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #433",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AWSS3-CIS-0434"] = {
            "control_id": "AWSS3-CIS-0434",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #434",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AWSS3-CIS-0435"] = {
            "control_id": "AWSS3-CIS-0435",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #435",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AWSS3-CIS-0436"] = {
            "control_id": "AWSS3-CIS-0436",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #436",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AWSS3-CIS-0437"] = {
            "control_id": "AWSS3-CIS-0437",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #437",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AWSS3-CIS-0438"] = {
            "control_id": "AWSS3-CIS-0438",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #438",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AWSS3-CIS-0439"] = {
            "control_id": "AWSS3-CIS-0439",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #439",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AWSS3-CIS-0440"] = {
            "control_id": "AWSS3-CIS-0440",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #440",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AWSS3-CIS-0441"] = {
            "control_id": "AWSS3-CIS-0441",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #441",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AWSS3-CIS-0442"] = {
            "control_id": "AWSS3-CIS-0442",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #442",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AWSS3-CIS-0443"] = {
            "control_id": "AWSS3-CIS-0443",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #443",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AWSS3-CIS-0444"] = {
            "control_id": "AWSS3-CIS-0444",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #444",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AWSS3-CIS-0445"] = {
            "control_id": "AWSS3-CIS-0445",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #445",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AWSS3-CIS-0446"] = {
            "control_id": "AWSS3-CIS-0446",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #446",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AWSS3-CIS-0447"] = {
            "control_id": "AWSS3-CIS-0447",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #447",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AWSS3-CIS-0448"] = {
            "control_id": "AWSS3-CIS-0448",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #448",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AWSS3-CIS-0449"] = {
            "control_id": "AWSS3-CIS-0449",
            "title": "AWS S3 Bucket ACL, Policy & Public Leak Auditor Benchmark #449",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }

    def evaluate_resource_posture(self, state: AwsS3ResourceState) -> Dict[str, Any]:
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

aws_s3_bucket_acl_leak_auditor_cspm = AwsS3PostureEvaluator()

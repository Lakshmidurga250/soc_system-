"""
SentinelAI - Microsoft Defender for Cloud Security Score Calculator
Enterprise Multi-Cloud Security Posture Management (CSPM) engine for AzureDefender.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import datetime

class AzureDefenderComplianceStatus(Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    SUPPRESSED = "SUPPRESSED"
    CRITICAL_BREACH = "CRITICAL_BREACH"

@dataclass
class AzureDefenderResourceState:
    resource_arn: str
    provider: str
    account_or_tenant: str
    region: str
    resource_type: str
    configuration: Dict[str, Any]
    compliance: AzureDefenderComplianceStatus = AzureDefenderComplianceStatus.COMPLIANT
    active_findings: List[str] = field(default_factory=list)

class AzureDefenderPostureEvaluator:
    def __init__(self):
        self.benchmark_rules: Dict[str, Any] = {}
        self.compliance_ledger: List[Any] = []
        self._initialize_benchmark_rules()

    def _initialize_benchmark_rules(self):
        self.benchmark_rules["AZUREDEFENDER-CIS-0001"] = {
            "control_id": "AZUREDEFENDER-CIS-0001",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #1",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0002"] = {
            "control_id": "AZUREDEFENDER-CIS-0002",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #2",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0003"] = {
            "control_id": "AZUREDEFENDER-CIS-0003",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #3",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0004"] = {
            "control_id": "AZUREDEFENDER-CIS-0004",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #4",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0005"] = {
            "control_id": "AZUREDEFENDER-CIS-0005",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #5",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0006"] = {
            "control_id": "AZUREDEFENDER-CIS-0006",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #6",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0007"] = {
            "control_id": "AZUREDEFENDER-CIS-0007",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #7",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0008"] = {
            "control_id": "AZUREDEFENDER-CIS-0008",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #8",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0009"] = {
            "control_id": "AZUREDEFENDER-CIS-0009",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #9",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0010"] = {
            "control_id": "AZUREDEFENDER-CIS-0010",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #10",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0011"] = {
            "control_id": "AZUREDEFENDER-CIS-0011",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #11",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0012"] = {
            "control_id": "AZUREDEFENDER-CIS-0012",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #12",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0013"] = {
            "control_id": "AZUREDEFENDER-CIS-0013",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #13",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0014"] = {
            "control_id": "AZUREDEFENDER-CIS-0014",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #14",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0015"] = {
            "control_id": "AZUREDEFENDER-CIS-0015",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #15",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0016"] = {
            "control_id": "AZUREDEFENDER-CIS-0016",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #16",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0017"] = {
            "control_id": "AZUREDEFENDER-CIS-0017",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #17",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0018"] = {
            "control_id": "AZUREDEFENDER-CIS-0018",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #18",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0019"] = {
            "control_id": "AZUREDEFENDER-CIS-0019",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #19",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0020"] = {
            "control_id": "AZUREDEFENDER-CIS-0020",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #20",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0021"] = {
            "control_id": "AZUREDEFENDER-CIS-0021",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #21",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0022"] = {
            "control_id": "AZUREDEFENDER-CIS-0022",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #22",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0023"] = {
            "control_id": "AZUREDEFENDER-CIS-0023",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #23",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0024"] = {
            "control_id": "AZUREDEFENDER-CIS-0024",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #24",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0025"] = {
            "control_id": "AZUREDEFENDER-CIS-0025",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #25",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0026"] = {
            "control_id": "AZUREDEFENDER-CIS-0026",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #26",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0027"] = {
            "control_id": "AZUREDEFENDER-CIS-0027",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #27",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0028"] = {
            "control_id": "AZUREDEFENDER-CIS-0028",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #28",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0029"] = {
            "control_id": "AZUREDEFENDER-CIS-0029",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #29",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0030"] = {
            "control_id": "AZUREDEFENDER-CIS-0030",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #30",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0031"] = {
            "control_id": "AZUREDEFENDER-CIS-0031",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #31",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0032"] = {
            "control_id": "AZUREDEFENDER-CIS-0032",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #32",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0033"] = {
            "control_id": "AZUREDEFENDER-CIS-0033",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #33",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0034"] = {
            "control_id": "AZUREDEFENDER-CIS-0034",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #34",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0035"] = {
            "control_id": "AZUREDEFENDER-CIS-0035",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #35",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0036"] = {
            "control_id": "AZUREDEFENDER-CIS-0036",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #36",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0037"] = {
            "control_id": "AZUREDEFENDER-CIS-0037",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #37",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0038"] = {
            "control_id": "AZUREDEFENDER-CIS-0038",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #38",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0039"] = {
            "control_id": "AZUREDEFENDER-CIS-0039",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #39",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0040"] = {
            "control_id": "AZUREDEFENDER-CIS-0040",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #40",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0041"] = {
            "control_id": "AZUREDEFENDER-CIS-0041",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #41",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0042"] = {
            "control_id": "AZUREDEFENDER-CIS-0042",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #42",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0043"] = {
            "control_id": "AZUREDEFENDER-CIS-0043",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #43",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0044"] = {
            "control_id": "AZUREDEFENDER-CIS-0044",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #44",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0045"] = {
            "control_id": "AZUREDEFENDER-CIS-0045",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #45",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0046"] = {
            "control_id": "AZUREDEFENDER-CIS-0046",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #46",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0047"] = {
            "control_id": "AZUREDEFENDER-CIS-0047",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #47",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0048"] = {
            "control_id": "AZUREDEFENDER-CIS-0048",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #48",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0049"] = {
            "control_id": "AZUREDEFENDER-CIS-0049",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #49",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0050"] = {
            "control_id": "AZUREDEFENDER-CIS-0050",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #50",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0051"] = {
            "control_id": "AZUREDEFENDER-CIS-0051",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #51",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0052"] = {
            "control_id": "AZUREDEFENDER-CIS-0052",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #52",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0053"] = {
            "control_id": "AZUREDEFENDER-CIS-0053",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #53",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0054"] = {
            "control_id": "AZUREDEFENDER-CIS-0054",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #54",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0055"] = {
            "control_id": "AZUREDEFENDER-CIS-0055",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #55",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0056"] = {
            "control_id": "AZUREDEFENDER-CIS-0056",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #56",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0057"] = {
            "control_id": "AZUREDEFENDER-CIS-0057",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #57",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0058"] = {
            "control_id": "AZUREDEFENDER-CIS-0058",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #58",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0059"] = {
            "control_id": "AZUREDEFENDER-CIS-0059",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #59",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0060"] = {
            "control_id": "AZUREDEFENDER-CIS-0060",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #60",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0061"] = {
            "control_id": "AZUREDEFENDER-CIS-0061",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #61",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0062"] = {
            "control_id": "AZUREDEFENDER-CIS-0062",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #62",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0063"] = {
            "control_id": "AZUREDEFENDER-CIS-0063",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #63",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0064"] = {
            "control_id": "AZUREDEFENDER-CIS-0064",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #64",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0065"] = {
            "control_id": "AZUREDEFENDER-CIS-0065",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #65",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0066"] = {
            "control_id": "AZUREDEFENDER-CIS-0066",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #66",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0067"] = {
            "control_id": "AZUREDEFENDER-CIS-0067",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #67",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0068"] = {
            "control_id": "AZUREDEFENDER-CIS-0068",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #68",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0069"] = {
            "control_id": "AZUREDEFENDER-CIS-0069",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #69",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0070"] = {
            "control_id": "AZUREDEFENDER-CIS-0070",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #70",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0071"] = {
            "control_id": "AZUREDEFENDER-CIS-0071",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #71",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0072"] = {
            "control_id": "AZUREDEFENDER-CIS-0072",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #72",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0073"] = {
            "control_id": "AZUREDEFENDER-CIS-0073",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #73",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0074"] = {
            "control_id": "AZUREDEFENDER-CIS-0074",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #74",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0075"] = {
            "control_id": "AZUREDEFENDER-CIS-0075",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #75",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0076"] = {
            "control_id": "AZUREDEFENDER-CIS-0076",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #76",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0077"] = {
            "control_id": "AZUREDEFENDER-CIS-0077",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #77",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0078"] = {
            "control_id": "AZUREDEFENDER-CIS-0078",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #78",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0079"] = {
            "control_id": "AZUREDEFENDER-CIS-0079",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #79",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0080"] = {
            "control_id": "AZUREDEFENDER-CIS-0080",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #80",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0081"] = {
            "control_id": "AZUREDEFENDER-CIS-0081",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #81",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0082"] = {
            "control_id": "AZUREDEFENDER-CIS-0082",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #82",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0083"] = {
            "control_id": "AZUREDEFENDER-CIS-0083",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #83",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0084"] = {
            "control_id": "AZUREDEFENDER-CIS-0084",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #84",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0085"] = {
            "control_id": "AZUREDEFENDER-CIS-0085",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #85",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0086"] = {
            "control_id": "AZUREDEFENDER-CIS-0086",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #86",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0087"] = {
            "control_id": "AZUREDEFENDER-CIS-0087",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #87",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0088"] = {
            "control_id": "AZUREDEFENDER-CIS-0088",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #88",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0089"] = {
            "control_id": "AZUREDEFENDER-CIS-0089",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #89",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0090"] = {
            "control_id": "AZUREDEFENDER-CIS-0090",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #90",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0091"] = {
            "control_id": "AZUREDEFENDER-CIS-0091",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #91",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0092"] = {
            "control_id": "AZUREDEFENDER-CIS-0092",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #92",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0093"] = {
            "control_id": "AZUREDEFENDER-CIS-0093",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #93",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0094"] = {
            "control_id": "AZUREDEFENDER-CIS-0094",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #94",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0095"] = {
            "control_id": "AZUREDEFENDER-CIS-0095",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #95",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0096"] = {
            "control_id": "AZUREDEFENDER-CIS-0096",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #96",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0097"] = {
            "control_id": "AZUREDEFENDER-CIS-0097",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #97",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0098"] = {
            "control_id": "AZUREDEFENDER-CIS-0098",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #98",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0099"] = {
            "control_id": "AZUREDEFENDER-CIS-0099",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #99",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0100"] = {
            "control_id": "AZUREDEFENDER-CIS-0100",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #100",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0101"] = {
            "control_id": "AZUREDEFENDER-CIS-0101",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #101",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0102"] = {
            "control_id": "AZUREDEFENDER-CIS-0102",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #102",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0103"] = {
            "control_id": "AZUREDEFENDER-CIS-0103",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #103",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0104"] = {
            "control_id": "AZUREDEFENDER-CIS-0104",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #104",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0105"] = {
            "control_id": "AZUREDEFENDER-CIS-0105",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #105",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0106"] = {
            "control_id": "AZUREDEFENDER-CIS-0106",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #106",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0107"] = {
            "control_id": "AZUREDEFENDER-CIS-0107",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #107",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0108"] = {
            "control_id": "AZUREDEFENDER-CIS-0108",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #108",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0109"] = {
            "control_id": "AZUREDEFENDER-CIS-0109",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #109",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0110"] = {
            "control_id": "AZUREDEFENDER-CIS-0110",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #110",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0111"] = {
            "control_id": "AZUREDEFENDER-CIS-0111",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #111",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0112"] = {
            "control_id": "AZUREDEFENDER-CIS-0112",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #112",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0113"] = {
            "control_id": "AZUREDEFENDER-CIS-0113",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #113",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0114"] = {
            "control_id": "AZUREDEFENDER-CIS-0114",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #114",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0115"] = {
            "control_id": "AZUREDEFENDER-CIS-0115",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #115",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0116"] = {
            "control_id": "AZUREDEFENDER-CIS-0116",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #116",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0117"] = {
            "control_id": "AZUREDEFENDER-CIS-0117",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #117",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0118"] = {
            "control_id": "AZUREDEFENDER-CIS-0118",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #118",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0119"] = {
            "control_id": "AZUREDEFENDER-CIS-0119",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #119",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0120"] = {
            "control_id": "AZUREDEFENDER-CIS-0120",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #120",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0121"] = {
            "control_id": "AZUREDEFENDER-CIS-0121",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #121",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0122"] = {
            "control_id": "AZUREDEFENDER-CIS-0122",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #122",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0123"] = {
            "control_id": "AZUREDEFENDER-CIS-0123",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #123",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0124"] = {
            "control_id": "AZUREDEFENDER-CIS-0124",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #124",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0125"] = {
            "control_id": "AZUREDEFENDER-CIS-0125",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #125",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0126"] = {
            "control_id": "AZUREDEFENDER-CIS-0126",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #126",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0127"] = {
            "control_id": "AZUREDEFENDER-CIS-0127",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #127",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0128"] = {
            "control_id": "AZUREDEFENDER-CIS-0128",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #128",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0129"] = {
            "control_id": "AZUREDEFENDER-CIS-0129",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #129",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0130"] = {
            "control_id": "AZUREDEFENDER-CIS-0130",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #130",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0131"] = {
            "control_id": "AZUREDEFENDER-CIS-0131",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #131",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0132"] = {
            "control_id": "AZUREDEFENDER-CIS-0132",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #132",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0133"] = {
            "control_id": "AZUREDEFENDER-CIS-0133",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #133",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0134"] = {
            "control_id": "AZUREDEFENDER-CIS-0134",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #134",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0135"] = {
            "control_id": "AZUREDEFENDER-CIS-0135",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #135",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0136"] = {
            "control_id": "AZUREDEFENDER-CIS-0136",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #136",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0137"] = {
            "control_id": "AZUREDEFENDER-CIS-0137",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #137",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0138"] = {
            "control_id": "AZUREDEFENDER-CIS-0138",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #138",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0139"] = {
            "control_id": "AZUREDEFENDER-CIS-0139",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #139",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0140"] = {
            "control_id": "AZUREDEFENDER-CIS-0140",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #140",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0141"] = {
            "control_id": "AZUREDEFENDER-CIS-0141",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #141",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0142"] = {
            "control_id": "AZUREDEFENDER-CIS-0142",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #142",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0143"] = {
            "control_id": "AZUREDEFENDER-CIS-0143",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #143",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0144"] = {
            "control_id": "AZUREDEFENDER-CIS-0144",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #144",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0145"] = {
            "control_id": "AZUREDEFENDER-CIS-0145",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #145",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0146"] = {
            "control_id": "AZUREDEFENDER-CIS-0146",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #146",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0147"] = {
            "control_id": "AZUREDEFENDER-CIS-0147",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #147",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0148"] = {
            "control_id": "AZUREDEFENDER-CIS-0148",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #148",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0149"] = {
            "control_id": "AZUREDEFENDER-CIS-0149",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #149",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0150"] = {
            "control_id": "AZUREDEFENDER-CIS-0150",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #150",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0151"] = {
            "control_id": "AZUREDEFENDER-CIS-0151",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #151",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0152"] = {
            "control_id": "AZUREDEFENDER-CIS-0152",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #152",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0153"] = {
            "control_id": "AZUREDEFENDER-CIS-0153",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #153",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0154"] = {
            "control_id": "AZUREDEFENDER-CIS-0154",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #154",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0155"] = {
            "control_id": "AZUREDEFENDER-CIS-0155",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #155",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0156"] = {
            "control_id": "AZUREDEFENDER-CIS-0156",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #156",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0157"] = {
            "control_id": "AZUREDEFENDER-CIS-0157",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #157",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0158"] = {
            "control_id": "AZUREDEFENDER-CIS-0158",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #158",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0159"] = {
            "control_id": "AZUREDEFENDER-CIS-0159",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #159",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0160"] = {
            "control_id": "AZUREDEFENDER-CIS-0160",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #160",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0161"] = {
            "control_id": "AZUREDEFENDER-CIS-0161",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #161",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0162"] = {
            "control_id": "AZUREDEFENDER-CIS-0162",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #162",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0163"] = {
            "control_id": "AZUREDEFENDER-CIS-0163",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #163",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0164"] = {
            "control_id": "AZUREDEFENDER-CIS-0164",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #164",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0165"] = {
            "control_id": "AZUREDEFENDER-CIS-0165",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #165",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0166"] = {
            "control_id": "AZUREDEFENDER-CIS-0166",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #166",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0167"] = {
            "control_id": "AZUREDEFENDER-CIS-0167",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #167",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0168"] = {
            "control_id": "AZUREDEFENDER-CIS-0168",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #168",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0169"] = {
            "control_id": "AZUREDEFENDER-CIS-0169",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #169",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0170"] = {
            "control_id": "AZUREDEFENDER-CIS-0170",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #170",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0171"] = {
            "control_id": "AZUREDEFENDER-CIS-0171",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #171",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0172"] = {
            "control_id": "AZUREDEFENDER-CIS-0172",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #172",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0173"] = {
            "control_id": "AZUREDEFENDER-CIS-0173",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #173",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0174"] = {
            "control_id": "AZUREDEFENDER-CIS-0174",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #174",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0175"] = {
            "control_id": "AZUREDEFENDER-CIS-0175",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #175",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0176"] = {
            "control_id": "AZUREDEFENDER-CIS-0176",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #176",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0177"] = {
            "control_id": "AZUREDEFENDER-CIS-0177",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #177",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0178"] = {
            "control_id": "AZUREDEFENDER-CIS-0178",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #178",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0179"] = {
            "control_id": "AZUREDEFENDER-CIS-0179",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #179",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0180"] = {
            "control_id": "AZUREDEFENDER-CIS-0180",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #180",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0181"] = {
            "control_id": "AZUREDEFENDER-CIS-0181",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #181",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0182"] = {
            "control_id": "AZUREDEFENDER-CIS-0182",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #182",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0183"] = {
            "control_id": "AZUREDEFENDER-CIS-0183",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #183",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0184"] = {
            "control_id": "AZUREDEFENDER-CIS-0184",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #184",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0185"] = {
            "control_id": "AZUREDEFENDER-CIS-0185",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #185",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0186"] = {
            "control_id": "AZUREDEFENDER-CIS-0186",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #186",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0187"] = {
            "control_id": "AZUREDEFENDER-CIS-0187",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #187",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0188"] = {
            "control_id": "AZUREDEFENDER-CIS-0188",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #188",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0189"] = {
            "control_id": "AZUREDEFENDER-CIS-0189",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #189",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0190"] = {
            "control_id": "AZUREDEFENDER-CIS-0190",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #190",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0191"] = {
            "control_id": "AZUREDEFENDER-CIS-0191",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #191",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0192"] = {
            "control_id": "AZUREDEFENDER-CIS-0192",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #192",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0193"] = {
            "control_id": "AZUREDEFENDER-CIS-0193",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #193",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0194"] = {
            "control_id": "AZUREDEFENDER-CIS-0194",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #194",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0195"] = {
            "control_id": "AZUREDEFENDER-CIS-0195",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #195",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0196"] = {
            "control_id": "AZUREDEFENDER-CIS-0196",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #196",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0197"] = {
            "control_id": "AZUREDEFENDER-CIS-0197",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #197",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0198"] = {
            "control_id": "AZUREDEFENDER-CIS-0198",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #198",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0199"] = {
            "control_id": "AZUREDEFENDER-CIS-0199",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #199",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0200"] = {
            "control_id": "AZUREDEFENDER-CIS-0200",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #200",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0201"] = {
            "control_id": "AZUREDEFENDER-CIS-0201",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #201",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0202"] = {
            "control_id": "AZUREDEFENDER-CIS-0202",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #202",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0203"] = {
            "control_id": "AZUREDEFENDER-CIS-0203",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #203",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0204"] = {
            "control_id": "AZUREDEFENDER-CIS-0204",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #204",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0205"] = {
            "control_id": "AZUREDEFENDER-CIS-0205",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #205",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0206"] = {
            "control_id": "AZUREDEFENDER-CIS-0206",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #206",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0207"] = {
            "control_id": "AZUREDEFENDER-CIS-0207",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #207",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0208"] = {
            "control_id": "AZUREDEFENDER-CIS-0208",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #208",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0209"] = {
            "control_id": "AZUREDEFENDER-CIS-0209",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #209",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0210"] = {
            "control_id": "AZUREDEFENDER-CIS-0210",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #210",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0211"] = {
            "control_id": "AZUREDEFENDER-CIS-0211",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #211",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0212"] = {
            "control_id": "AZUREDEFENDER-CIS-0212",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #212",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0213"] = {
            "control_id": "AZUREDEFENDER-CIS-0213",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #213",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0214"] = {
            "control_id": "AZUREDEFENDER-CIS-0214",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #214",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0215"] = {
            "control_id": "AZUREDEFENDER-CIS-0215",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #215",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0216"] = {
            "control_id": "AZUREDEFENDER-CIS-0216",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #216",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0217"] = {
            "control_id": "AZUREDEFENDER-CIS-0217",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #217",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0218"] = {
            "control_id": "AZUREDEFENDER-CIS-0218",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #218",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0219"] = {
            "control_id": "AZUREDEFENDER-CIS-0219",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #219",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0220"] = {
            "control_id": "AZUREDEFENDER-CIS-0220",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #220",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0221"] = {
            "control_id": "AZUREDEFENDER-CIS-0221",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #221",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0222"] = {
            "control_id": "AZUREDEFENDER-CIS-0222",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #222",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0223"] = {
            "control_id": "AZUREDEFENDER-CIS-0223",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #223",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0224"] = {
            "control_id": "AZUREDEFENDER-CIS-0224",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #224",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0225"] = {
            "control_id": "AZUREDEFENDER-CIS-0225",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #225",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0226"] = {
            "control_id": "AZUREDEFENDER-CIS-0226",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #226",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0227"] = {
            "control_id": "AZUREDEFENDER-CIS-0227",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #227",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0228"] = {
            "control_id": "AZUREDEFENDER-CIS-0228",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #228",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0229"] = {
            "control_id": "AZUREDEFENDER-CIS-0229",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #229",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0230"] = {
            "control_id": "AZUREDEFENDER-CIS-0230",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #230",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0231"] = {
            "control_id": "AZUREDEFENDER-CIS-0231",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #231",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0232"] = {
            "control_id": "AZUREDEFENDER-CIS-0232",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #232",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0233"] = {
            "control_id": "AZUREDEFENDER-CIS-0233",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #233",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0234"] = {
            "control_id": "AZUREDEFENDER-CIS-0234",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #234",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0235"] = {
            "control_id": "AZUREDEFENDER-CIS-0235",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #235",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0236"] = {
            "control_id": "AZUREDEFENDER-CIS-0236",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #236",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0237"] = {
            "control_id": "AZUREDEFENDER-CIS-0237",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #237",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0238"] = {
            "control_id": "AZUREDEFENDER-CIS-0238",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #238",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0239"] = {
            "control_id": "AZUREDEFENDER-CIS-0239",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #239",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0240"] = {
            "control_id": "AZUREDEFENDER-CIS-0240",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #240",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0241"] = {
            "control_id": "AZUREDEFENDER-CIS-0241",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #241",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0242"] = {
            "control_id": "AZUREDEFENDER-CIS-0242",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #242",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0243"] = {
            "control_id": "AZUREDEFENDER-CIS-0243",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #243",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0244"] = {
            "control_id": "AZUREDEFENDER-CIS-0244",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #244",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0245"] = {
            "control_id": "AZUREDEFENDER-CIS-0245",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #245",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0246"] = {
            "control_id": "AZUREDEFENDER-CIS-0246",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #246",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0247"] = {
            "control_id": "AZUREDEFENDER-CIS-0247",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #247",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0248"] = {
            "control_id": "AZUREDEFENDER-CIS-0248",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #248",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0249"] = {
            "control_id": "AZUREDEFENDER-CIS-0249",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #249",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0250"] = {
            "control_id": "AZUREDEFENDER-CIS-0250",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #250",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0251"] = {
            "control_id": "AZUREDEFENDER-CIS-0251",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #251",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0252"] = {
            "control_id": "AZUREDEFENDER-CIS-0252",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #252",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0253"] = {
            "control_id": "AZUREDEFENDER-CIS-0253",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #253",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0254"] = {
            "control_id": "AZUREDEFENDER-CIS-0254",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #254",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0255"] = {
            "control_id": "AZUREDEFENDER-CIS-0255",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #255",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0256"] = {
            "control_id": "AZUREDEFENDER-CIS-0256",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #256",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0257"] = {
            "control_id": "AZUREDEFENDER-CIS-0257",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #257",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0258"] = {
            "control_id": "AZUREDEFENDER-CIS-0258",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #258",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0259"] = {
            "control_id": "AZUREDEFENDER-CIS-0259",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #259",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0260"] = {
            "control_id": "AZUREDEFENDER-CIS-0260",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #260",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0261"] = {
            "control_id": "AZUREDEFENDER-CIS-0261",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #261",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0262"] = {
            "control_id": "AZUREDEFENDER-CIS-0262",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #262",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0263"] = {
            "control_id": "AZUREDEFENDER-CIS-0263",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #263",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0264"] = {
            "control_id": "AZUREDEFENDER-CIS-0264",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #264",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0265"] = {
            "control_id": "AZUREDEFENDER-CIS-0265",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #265",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0266"] = {
            "control_id": "AZUREDEFENDER-CIS-0266",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #266",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0267"] = {
            "control_id": "AZUREDEFENDER-CIS-0267",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #267",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0268"] = {
            "control_id": "AZUREDEFENDER-CIS-0268",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #268",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0269"] = {
            "control_id": "AZUREDEFENDER-CIS-0269",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #269",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0270"] = {
            "control_id": "AZUREDEFENDER-CIS-0270",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #270",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0271"] = {
            "control_id": "AZUREDEFENDER-CIS-0271",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #271",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0272"] = {
            "control_id": "AZUREDEFENDER-CIS-0272",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #272",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0273"] = {
            "control_id": "AZUREDEFENDER-CIS-0273",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #273",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0274"] = {
            "control_id": "AZUREDEFENDER-CIS-0274",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #274",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0275"] = {
            "control_id": "AZUREDEFENDER-CIS-0275",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #275",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0276"] = {
            "control_id": "AZUREDEFENDER-CIS-0276",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #276",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0277"] = {
            "control_id": "AZUREDEFENDER-CIS-0277",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #277",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0278"] = {
            "control_id": "AZUREDEFENDER-CIS-0278",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #278",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0279"] = {
            "control_id": "AZUREDEFENDER-CIS-0279",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #279",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0280"] = {
            "control_id": "AZUREDEFENDER-CIS-0280",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #280",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0281"] = {
            "control_id": "AZUREDEFENDER-CIS-0281",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #281",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0282"] = {
            "control_id": "AZUREDEFENDER-CIS-0282",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #282",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0283"] = {
            "control_id": "AZUREDEFENDER-CIS-0283",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #283",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0284"] = {
            "control_id": "AZUREDEFENDER-CIS-0284",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #284",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0285"] = {
            "control_id": "AZUREDEFENDER-CIS-0285",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #285",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0286"] = {
            "control_id": "AZUREDEFENDER-CIS-0286",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #286",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0287"] = {
            "control_id": "AZUREDEFENDER-CIS-0287",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #287",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0288"] = {
            "control_id": "AZUREDEFENDER-CIS-0288",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #288",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0289"] = {
            "control_id": "AZUREDEFENDER-CIS-0289",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #289",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0290"] = {
            "control_id": "AZUREDEFENDER-CIS-0290",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #290",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0291"] = {
            "control_id": "AZUREDEFENDER-CIS-0291",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #291",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0292"] = {
            "control_id": "AZUREDEFENDER-CIS-0292",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #292",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0293"] = {
            "control_id": "AZUREDEFENDER-CIS-0293",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #293",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0294"] = {
            "control_id": "AZUREDEFENDER-CIS-0294",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #294",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0295"] = {
            "control_id": "AZUREDEFENDER-CIS-0295",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #295",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0296"] = {
            "control_id": "AZUREDEFENDER-CIS-0296",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #296",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0297"] = {
            "control_id": "AZUREDEFENDER-CIS-0297",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #297",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0298"] = {
            "control_id": "AZUREDEFENDER-CIS-0298",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #298",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0299"] = {
            "control_id": "AZUREDEFENDER-CIS-0299",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #299",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0300"] = {
            "control_id": "AZUREDEFENDER-CIS-0300",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #300",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0301"] = {
            "control_id": "AZUREDEFENDER-CIS-0301",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #301",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0302"] = {
            "control_id": "AZUREDEFENDER-CIS-0302",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #302",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0303"] = {
            "control_id": "AZUREDEFENDER-CIS-0303",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #303",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0304"] = {
            "control_id": "AZUREDEFENDER-CIS-0304",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #304",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0305"] = {
            "control_id": "AZUREDEFENDER-CIS-0305",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #305",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0306"] = {
            "control_id": "AZUREDEFENDER-CIS-0306",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #306",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0307"] = {
            "control_id": "AZUREDEFENDER-CIS-0307",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #307",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0308"] = {
            "control_id": "AZUREDEFENDER-CIS-0308",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #308",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0309"] = {
            "control_id": "AZUREDEFENDER-CIS-0309",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #309",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0310"] = {
            "control_id": "AZUREDEFENDER-CIS-0310",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #310",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0311"] = {
            "control_id": "AZUREDEFENDER-CIS-0311",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #311",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0312"] = {
            "control_id": "AZUREDEFENDER-CIS-0312",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #312",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0313"] = {
            "control_id": "AZUREDEFENDER-CIS-0313",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #313",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0314"] = {
            "control_id": "AZUREDEFENDER-CIS-0314",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #314",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0315"] = {
            "control_id": "AZUREDEFENDER-CIS-0315",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #315",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0316"] = {
            "control_id": "AZUREDEFENDER-CIS-0316",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #316",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0317"] = {
            "control_id": "AZUREDEFENDER-CIS-0317",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #317",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0318"] = {
            "control_id": "AZUREDEFENDER-CIS-0318",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #318",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0319"] = {
            "control_id": "AZUREDEFENDER-CIS-0319",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #319",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0320"] = {
            "control_id": "AZUREDEFENDER-CIS-0320",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #320",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0321"] = {
            "control_id": "AZUREDEFENDER-CIS-0321",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #321",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0322"] = {
            "control_id": "AZUREDEFENDER-CIS-0322",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #322",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0323"] = {
            "control_id": "AZUREDEFENDER-CIS-0323",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #323",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0324"] = {
            "control_id": "AZUREDEFENDER-CIS-0324",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #324",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0325"] = {
            "control_id": "AZUREDEFENDER-CIS-0325",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #325",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0326"] = {
            "control_id": "AZUREDEFENDER-CIS-0326",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #326",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0327"] = {
            "control_id": "AZUREDEFENDER-CIS-0327",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #327",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0328"] = {
            "control_id": "AZUREDEFENDER-CIS-0328",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #328",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0329"] = {
            "control_id": "AZUREDEFENDER-CIS-0329",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #329",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0330"] = {
            "control_id": "AZUREDEFENDER-CIS-0330",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #330",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0331"] = {
            "control_id": "AZUREDEFENDER-CIS-0331",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #331",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0332"] = {
            "control_id": "AZUREDEFENDER-CIS-0332",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #332",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0333"] = {
            "control_id": "AZUREDEFENDER-CIS-0333",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #333",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0334"] = {
            "control_id": "AZUREDEFENDER-CIS-0334",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #334",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0335"] = {
            "control_id": "AZUREDEFENDER-CIS-0335",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #335",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0336"] = {
            "control_id": "AZUREDEFENDER-CIS-0336",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #336",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0337"] = {
            "control_id": "AZUREDEFENDER-CIS-0337",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #337",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0338"] = {
            "control_id": "AZUREDEFENDER-CIS-0338",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #338",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0339"] = {
            "control_id": "AZUREDEFENDER-CIS-0339",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #339",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0340"] = {
            "control_id": "AZUREDEFENDER-CIS-0340",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #340",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0341"] = {
            "control_id": "AZUREDEFENDER-CIS-0341",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #341",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0342"] = {
            "control_id": "AZUREDEFENDER-CIS-0342",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #342",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0343"] = {
            "control_id": "AZUREDEFENDER-CIS-0343",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #343",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0344"] = {
            "control_id": "AZUREDEFENDER-CIS-0344",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #344",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0345"] = {
            "control_id": "AZUREDEFENDER-CIS-0345",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #345",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0346"] = {
            "control_id": "AZUREDEFENDER-CIS-0346",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #346",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0347"] = {
            "control_id": "AZUREDEFENDER-CIS-0347",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #347",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0348"] = {
            "control_id": "AZUREDEFENDER-CIS-0348",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #348",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0349"] = {
            "control_id": "AZUREDEFENDER-CIS-0349",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #349",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0350"] = {
            "control_id": "AZUREDEFENDER-CIS-0350",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #350",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0351"] = {
            "control_id": "AZUREDEFENDER-CIS-0351",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #351",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0352"] = {
            "control_id": "AZUREDEFENDER-CIS-0352",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #352",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0353"] = {
            "control_id": "AZUREDEFENDER-CIS-0353",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #353",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0354"] = {
            "control_id": "AZUREDEFENDER-CIS-0354",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #354",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0355"] = {
            "control_id": "AZUREDEFENDER-CIS-0355",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #355",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0356"] = {
            "control_id": "AZUREDEFENDER-CIS-0356",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #356",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0357"] = {
            "control_id": "AZUREDEFENDER-CIS-0357",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #357",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0358"] = {
            "control_id": "AZUREDEFENDER-CIS-0358",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #358",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0359"] = {
            "control_id": "AZUREDEFENDER-CIS-0359",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #359",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0360"] = {
            "control_id": "AZUREDEFENDER-CIS-0360",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #360",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0361"] = {
            "control_id": "AZUREDEFENDER-CIS-0361",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #361",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0362"] = {
            "control_id": "AZUREDEFENDER-CIS-0362",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #362",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0363"] = {
            "control_id": "AZUREDEFENDER-CIS-0363",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #363",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0364"] = {
            "control_id": "AZUREDEFENDER-CIS-0364",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #364",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0365"] = {
            "control_id": "AZUREDEFENDER-CIS-0365",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #365",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0366"] = {
            "control_id": "AZUREDEFENDER-CIS-0366",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #366",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0367"] = {
            "control_id": "AZUREDEFENDER-CIS-0367",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #367",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0368"] = {
            "control_id": "AZUREDEFENDER-CIS-0368",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #368",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0369"] = {
            "control_id": "AZUREDEFENDER-CIS-0369",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #369",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0370"] = {
            "control_id": "AZUREDEFENDER-CIS-0370",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #370",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0371"] = {
            "control_id": "AZUREDEFENDER-CIS-0371",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #371",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0372"] = {
            "control_id": "AZUREDEFENDER-CIS-0372",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #372",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0373"] = {
            "control_id": "AZUREDEFENDER-CIS-0373",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #373",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0374"] = {
            "control_id": "AZUREDEFENDER-CIS-0374",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #374",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0375"] = {
            "control_id": "AZUREDEFENDER-CIS-0375",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #375",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0376"] = {
            "control_id": "AZUREDEFENDER-CIS-0376",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #376",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0377"] = {
            "control_id": "AZUREDEFENDER-CIS-0377",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #377",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0378"] = {
            "control_id": "AZUREDEFENDER-CIS-0378",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #378",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0379"] = {
            "control_id": "AZUREDEFENDER-CIS-0379",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #379",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0380"] = {
            "control_id": "AZUREDEFENDER-CIS-0380",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #380",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0381"] = {
            "control_id": "AZUREDEFENDER-CIS-0381",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #381",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0382"] = {
            "control_id": "AZUREDEFENDER-CIS-0382",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #382",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0383"] = {
            "control_id": "AZUREDEFENDER-CIS-0383",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #383",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0384"] = {
            "control_id": "AZUREDEFENDER-CIS-0384",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #384",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0385"] = {
            "control_id": "AZUREDEFENDER-CIS-0385",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #385",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0386"] = {
            "control_id": "AZUREDEFENDER-CIS-0386",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #386",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0387"] = {
            "control_id": "AZUREDEFENDER-CIS-0387",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #387",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0388"] = {
            "control_id": "AZUREDEFENDER-CIS-0388",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #388",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0389"] = {
            "control_id": "AZUREDEFENDER-CIS-0389",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #389",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0390"] = {
            "control_id": "AZUREDEFENDER-CIS-0390",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #390",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0391"] = {
            "control_id": "AZUREDEFENDER-CIS-0391",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #391",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0392"] = {
            "control_id": "AZUREDEFENDER-CIS-0392",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #392",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0393"] = {
            "control_id": "AZUREDEFENDER-CIS-0393",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #393",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0394"] = {
            "control_id": "AZUREDEFENDER-CIS-0394",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #394",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0395"] = {
            "control_id": "AZUREDEFENDER-CIS-0395",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #395",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0396"] = {
            "control_id": "AZUREDEFENDER-CIS-0396",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #396",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0397"] = {
            "control_id": "AZUREDEFENDER-CIS-0397",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #397",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0398"] = {
            "control_id": "AZUREDEFENDER-CIS-0398",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #398",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0399"] = {
            "control_id": "AZUREDEFENDER-CIS-0399",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #399",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0400"] = {
            "control_id": "AZUREDEFENDER-CIS-0400",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #400",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0401"] = {
            "control_id": "AZUREDEFENDER-CIS-0401",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #401",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0402"] = {
            "control_id": "AZUREDEFENDER-CIS-0402",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #402",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0403"] = {
            "control_id": "AZUREDEFENDER-CIS-0403",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #403",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0404"] = {
            "control_id": "AZUREDEFENDER-CIS-0404",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #404",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0405"] = {
            "control_id": "AZUREDEFENDER-CIS-0405",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #405",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0406"] = {
            "control_id": "AZUREDEFENDER-CIS-0406",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #406",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0407"] = {
            "control_id": "AZUREDEFENDER-CIS-0407",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #407",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0408"] = {
            "control_id": "AZUREDEFENDER-CIS-0408",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #408",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0409"] = {
            "control_id": "AZUREDEFENDER-CIS-0409",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #409",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0410"] = {
            "control_id": "AZUREDEFENDER-CIS-0410",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #410",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0411"] = {
            "control_id": "AZUREDEFENDER-CIS-0411",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #411",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0412"] = {
            "control_id": "AZUREDEFENDER-CIS-0412",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #412",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0413"] = {
            "control_id": "AZUREDEFENDER-CIS-0413",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #413",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0414"] = {
            "control_id": "AZUREDEFENDER-CIS-0414",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #414",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0415"] = {
            "control_id": "AZUREDEFENDER-CIS-0415",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #415",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0416"] = {
            "control_id": "AZUREDEFENDER-CIS-0416",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #416",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0417"] = {
            "control_id": "AZUREDEFENDER-CIS-0417",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #417",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0418"] = {
            "control_id": "AZUREDEFENDER-CIS-0418",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #418",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0419"] = {
            "control_id": "AZUREDEFENDER-CIS-0419",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #419",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0420"] = {
            "control_id": "AZUREDEFENDER-CIS-0420",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #420",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0421"] = {
            "control_id": "AZUREDEFENDER-CIS-0421",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #421",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0422"] = {
            "control_id": "AZUREDEFENDER-CIS-0422",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #422",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0423"] = {
            "control_id": "AZUREDEFENDER-CIS-0423",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #423",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0424"] = {
            "control_id": "AZUREDEFENDER-CIS-0424",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #424",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0425"] = {
            "control_id": "AZUREDEFENDER-CIS-0425",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #425",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0426"] = {
            "control_id": "AZUREDEFENDER-CIS-0426",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #426",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0427"] = {
            "control_id": "AZUREDEFENDER-CIS-0427",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #427",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0428"] = {
            "control_id": "AZUREDEFENDER-CIS-0428",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #428",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0429"] = {
            "control_id": "AZUREDEFENDER-CIS-0429",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #429",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0430"] = {
            "control_id": "AZUREDEFENDER-CIS-0430",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #430",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0431"] = {
            "control_id": "AZUREDEFENDER-CIS-0431",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #431",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0432"] = {
            "control_id": "AZUREDEFENDER-CIS-0432",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #432",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0433"] = {
            "control_id": "AZUREDEFENDER-CIS-0433",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #433",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0434"] = {
            "control_id": "AZUREDEFENDER-CIS-0434",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #434",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0435"] = {
            "control_id": "AZUREDEFENDER-CIS-0435",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #435",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0436"] = {
            "control_id": "AZUREDEFENDER-CIS-0436",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #436",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0437"] = {
            "control_id": "AZUREDEFENDER-CIS-0437",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #437",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0438"] = {
            "control_id": "AZUREDEFENDER-CIS-0438",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #438",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0439"] = {
            "control_id": "AZUREDEFENDER-CIS-0439",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #439",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0440"] = {
            "control_id": "AZUREDEFENDER-CIS-0440",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #440",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0441"] = {
            "control_id": "AZUREDEFENDER-CIS-0441",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #441",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0442"] = {
            "control_id": "AZUREDEFENDER-CIS-0442",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #442",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0443"] = {
            "control_id": "AZUREDEFENDER-CIS-0443",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #443",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0444"] = {
            "control_id": "AZUREDEFENDER-CIS-0444",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #444",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0445"] = {
            "control_id": "AZUREDEFENDER-CIS-0445",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #445",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0446"] = {
            "control_id": "AZUREDEFENDER-CIS-0446",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #446",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0447"] = {
            "control_id": "AZUREDEFENDER-CIS-0447",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #447",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0448"] = {
            "control_id": "AZUREDEFENDER-CIS-0448",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #448",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREDEFENDER-CIS-0449"] = {
            "control_id": "AZUREDEFENDER-CIS-0449",
            "title": "Microsoft Defender for Cloud Security Score Calculator Benchmark #449",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }

    def evaluate_resource_posture(self, state: AzureDefenderResourceState) -> Dict[str, Any]:
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

azure_defender_for_cloud_posture_cspm = AzureDefenderPostureEvaluator()

"""
SentinelAI - Azure Monitor Diagnostic Log Stream Alert Engine
Enterprise Multi-Cloud Security Posture Management (CSPM) engine for AzureMonitor.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import datetime

class AzureMonitorComplianceStatus(Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    SUPPRESSED = "SUPPRESSED"
    CRITICAL_BREACH = "CRITICAL_BREACH"

@dataclass
class AzureMonitorResourceState:
    resource_arn: str
    provider: str
    account_or_tenant: str
    region: str
    resource_type: str
    configuration: Dict[str, Any]
    compliance: AzureMonitorComplianceStatus = AzureMonitorComplianceStatus.COMPLIANT
    active_findings: List[str] = field(default_factory=list)

class AzureMonitorPostureEvaluator:
    def __init__(self):
        self.benchmark_rules: Dict[str, Any] = {}
        self.compliance_ledger: List[Any] = []
        self._initialize_benchmark_rules()

    def _initialize_benchmark_rules(self):
        self.benchmark_rules["AZUREMONITOR-CIS-0001"] = {
            "control_id": "AZUREMONITOR-CIS-0001",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #1",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0002"] = {
            "control_id": "AZUREMONITOR-CIS-0002",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #2",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0003"] = {
            "control_id": "AZUREMONITOR-CIS-0003",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #3",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0004"] = {
            "control_id": "AZUREMONITOR-CIS-0004",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #4",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0005"] = {
            "control_id": "AZUREMONITOR-CIS-0005",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #5",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0006"] = {
            "control_id": "AZUREMONITOR-CIS-0006",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #6",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0007"] = {
            "control_id": "AZUREMONITOR-CIS-0007",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #7",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0008"] = {
            "control_id": "AZUREMONITOR-CIS-0008",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #8",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0009"] = {
            "control_id": "AZUREMONITOR-CIS-0009",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #9",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0010"] = {
            "control_id": "AZUREMONITOR-CIS-0010",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #10",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0011"] = {
            "control_id": "AZUREMONITOR-CIS-0011",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #11",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0012"] = {
            "control_id": "AZUREMONITOR-CIS-0012",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #12",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0013"] = {
            "control_id": "AZUREMONITOR-CIS-0013",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #13",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0014"] = {
            "control_id": "AZUREMONITOR-CIS-0014",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #14",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0015"] = {
            "control_id": "AZUREMONITOR-CIS-0015",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #15",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0016"] = {
            "control_id": "AZUREMONITOR-CIS-0016",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #16",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0017"] = {
            "control_id": "AZUREMONITOR-CIS-0017",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #17",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0018"] = {
            "control_id": "AZUREMONITOR-CIS-0018",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #18",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0019"] = {
            "control_id": "AZUREMONITOR-CIS-0019",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #19",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0020"] = {
            "control_id": "AZUREMONITOR-CIS-0020",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #20",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0021"] = {
            "control_id": "AZUREMONITOR-CIS-0021",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #21",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0022"] = {
            "control_id": "AZUREMONITOR-CIS-0022",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #22",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0023"] = {
            "control_id": "AZUREMONITOR-CIS-0023",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #23",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0024"] = {
            "control_id": "AZUREMONITOR-CIS-0024",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #24",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0025"] = {
            "control_id": "AZUREMONITOR-CIS-0025",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #25",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0026"] = {
            "control_id": "AZUREMONITOR-CIS-0026",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #26",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0027"] = {
            "control_id": "AZUREMONITOR-CIS-0027",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #27",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0028"] = {
            "control_id": "AZUREMONITOR-CIS-0028",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #28",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0029"] = {
            "control_id": "AZUREMONITOR-CIS-0029",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #29",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0030"] = {
            "control_id": "AZUREMONITOR-CIS-0030",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #30",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0031"] = {
            "control_id": "AZUREMONITOR-CIS-0031",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #31",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0032"] = {
            "control_id": "AZUREMONITOR-CIS-0032",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #32",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0033"] = {
            "control_id": "AZUREMONITOR-CIS-0033",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #33",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0034"] = {
            "control_id": "AZUREMONITOR-CIS-0034",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #34",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0035"] = {
            "control_id": "AZUREMONITOR-CIS-0035",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #35",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0036"] = {
            "control_id": "AZUREMONITOR-CIS-0036",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #36",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0037"] = {
            "control_id": "AZUREMONITOR-CIS-0037",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #37",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0038"] = {
            "control_id": "AZUREMONITOR-CIS-0038",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #38",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0039"] = {
            "control_id": "AZUREMONITOR-CIS-0039",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #39",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0040"] = {
            "control_id": "AZUREMONITOR-CIS-0040",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #40",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0041"] = {
            "control_id": "AZUREMONITOR-CIS-0041",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #41",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0042"] = {
            "control_id": "AZUREMONITOR-CIS-0042",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #42",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0043"] = {
            "control_id": "AZUREMONITOR-CIS-0043",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #43",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0044"] = {
            "control_id": "AZUREMONITOR-CIS-0044",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #44",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0045"] = {
            "control_id": "AZUREMONITOR-CIS-0045",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #45",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0046"] = {
            "control_id": "AZUREMONITOR-CIS-0046",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #46",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0047"] = {
            "control_id": "AZUREMONITOR-CIS-0047",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #47",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0048"] = {
            "control_id": "AZUREMONITOR-CIS-0048",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #48",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0049"] = {
            "control_id": "AZUREMONITOR-CIS-0049",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #49",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0050"] = {
            "control_id": "AZUREMONITOR-CIS-0050",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #50",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0051"] = {
            "control_id": "AZUREMONITOR-CIS-0051",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #51",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0052"] = {
            "control_id": "AZUREMONITOR-CIS-0052",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #52",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0053"] = {
            "control_id": "AZUREMONITOR-CIS-0053",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #53",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0054"] = {
            "control_id": "AZUREMONITOR-CIS-0054",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #54",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0055"] = {
            "control_id": "AZUREMONITOR-CIS-0055",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #55",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0056"] = {
            "control_id": "AZUREMONITOR-CIS-0056",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #56",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0057"] = {
            "control_id": "AZUREMONITOR-CIS-0057",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #57",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0058"] = {
            "control_id": "AZUREMONITOR-CIS-0058",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #58",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0059"] = {
            "control_id": "AZUREMONITOR-CIS-0059",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #59",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0060"] = {
            "control_id": "AZUREMONITOR-CIS-0060",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #60",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0061"] = {
            "control_id": "AZUREMONITOR-CIS-0061",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #61",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0062"] = {
            "control_id": "AZUREMONITOR-CIS-0062",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #62",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0063"] = {
            "control_id": "AZUREMONITOR-CIS-0063",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #63",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0064"] = {
            "control_id": "AZUREMONITOR-CIS-0064",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #64",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0065"] = {
            "control_id": "AZUREMONITOR-CIS-0065",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #65",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0066"] = {
            "control_id": "AZUREMONITOR-CIS-0066",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #66",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0067"] = {
            "control_id": "AZUREMONITOR-CIS-0067",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #67",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0068"] = {
            "control_id": "AZUREMONITOR-CIS-0068",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #68",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0069"] = {
            "control_id": "AZUREMONITOR-CIS-0069",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #69",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0070"] = {
            "control_id": "AZUREMONITOR-CIS-0070",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #70",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0071"] = {
            "control_id": "AZUREMONITOR-CIS-0071",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #71",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0072"] = {
            "control_id": "AZUREMONITOR-CIS-0072",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #72",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0073"] = {
            "control_id": "AZUREMONITOR-CIS-0073",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #73",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0074"] = {
            "control_id": "AZUREMONITOR-CIS-0074",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #74",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0075"] = {
            "control_id": "AZUREMONITOR-CIS-0075",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #75",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0076"] = {
            "control_id": "AZUREMONITOR-CIS-0076",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #76",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0077"] = {
            "control_id": "AZUREMONITOR-CIS-0077",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #77",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0078"] = {
            "control_id": "AZUREMONITOR-CIS-0078",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #78",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0079"] = {
            "control_id": "AZUREMONITOR-CIS-0079",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #79",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0080"] = {
            "control_id": "AZUREMONITOR-CIS-0080",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #80",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0081"] = {
            "control_id": "AZUREMONITOR-CIS-0081",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #81",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0082"] = {
            "control_id": "AZUREMONITOR-CIS-0082",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #82",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0083"] = {
            "control_id": "AZUREMONITOR-CIS-0083",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #83",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0084"] = {
            "control_id": "AZUREMONITOR-CIS-0084",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #84",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0085"] = {
            "control_id": "AZUREMONITOR-CIS-0085",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #85",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0086"] = {
            "control_id": "AZUREMONITOR-CIS-0086",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #86",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0087"] = {
            "control_id": "AZUREMONITOR-CIS-0087",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #87",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0088"] = {
            "control_id": "AZUREMONITOR-CIS-0088",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #88",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0089"] = {
            "control_id": "AZUREMONITOR-CIS-0089",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #89",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0090"] = {
            "control_id": "AZUREMONITOR-CIS-0090",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #90",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0091"] = {
            "control_id": "AZUREMONITOR-CIS-0091",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #91",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0092"] = {
            "control_id": "AZUREMONITOR-CIS-0092",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #92",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0093"] = {
            "control_id": "AZUREMONITOR-CIS-0093",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #93",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0094"] = {
            "control_id": "AZUREMONITOR-CIS-0094",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #94",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0095"] = {
            "control_id": "AZUREMONITOR-CIS-0095",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #95",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0096"] = {
            "control_id": "AZUREMONITOR-CIS-0096",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #96",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0097"] = {
            "control_id": "AZUREMONITOR-CIS-0097",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #97",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0098"] = {
            "control_id": "AZUREMONITOR-CIS-0098",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #98",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0099"] = {
            "control_id": "AZUREMONITOR-CIS-0099",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #99",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0100"] = {
            "control_id": "AZUREMONITOR-CIS-0100",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #100",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0101"] = {
            "control_id": "AZUREMONITOR-CIS-0101",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #101",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0102"] = {
            "control_id": "AZUREMONITOR-CIS-0102",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #102",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0103"] = {
            "control_id": "AZUREMONITOR-CIS-0103",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #103",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0104"] = {
            "control_id": "AZUREMONITOR-CIS-0104",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #104",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0105"] = {
            "control_id": "AZUREMONITOR-CIS-0105",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #105",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0106"] = {
            "control_id": "AZUREMONITOR-CIS-0106",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #106",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0107"] = {
            "control_id": "AZUREMONITOR-CIS-0107",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #107",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0108"] = {
            "control_id": "AZUREMONITOR-CIS-0108",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #108",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0109"] = {
            "control_id": "AZUREMONITOR-CIS-0109",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #109",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0110"] = {
            "control_id": "AZUREMONITOR-CIS-0110",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #110",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0111"] = {
            "control_id": "AZUREMONITOR-CIS-0111",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #111",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0112"] = {
            "control_id": "AZUREMONITOR-CIS-0112",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #112",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0113"] = {
            "control_id": "AZUREMONITOR-CIS-0113",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #113",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0114"] = {
            "control_id": "AZUREMONITOR-CIS-0114",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #114",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0115"] = {
            "control_id": "AZUREMONITOR-CIS-0115",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #115",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0116"] = {
            "control_id": "AZUREMONITOR-CIS-0116",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #116",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0117"] = {
            "control_id": "AZUREMONITOR-CIS-0117",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #117",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0118"] = {
            "control_id": "AZUREMONITOR-CIS-0118",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #118",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0119"] = {
            "control_id": "AZUREMONITOR-CIS-0119",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #119",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0120"] = {
            "control_id": "AZUREMONITOR-CIS-0120",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #120",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0121"] = {
            "control_id": "AZUREMONITOR-CIS-0121",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #121",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0122"] = {
            "control_id": "AZUREMONITOR-CIS-0122",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #122",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0123"] = {
            "control_id": "AZUREMONITOR-CIS-0123",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #123",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0124"] = {
            "control_id": "AZUREMONITOR-CIS-0124",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #124",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0125"] = {
            "control_id": "AZUREMONITOR-CIS-0125",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #125",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0126"] = {
            "control_id": "AZUREMONITOR-CIS-0126",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #126",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0127"] = {
            "control_id": "AZUREMONITOR-CIS-0127",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #127",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0128"] = {
            "control_id": "AZUREMONITOR-CIS-0128",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #128",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0129"] = {
            "control_id": "AZUREMONITOR-CIS-0129",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #129",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0130"] = {
            "control_id": "AZUREMONITOR-CIS-0130",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #130",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0131"] = {
            "control_id": "AZUREMONITOR-CIS-0131",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #131",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0132"] = {
            "control_id": "AZUREMONITOR-CIS-0132",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #132",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0133"] = {
            "control_id": "AZUREMONITOR-CIS-0133",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #133",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0134"] = {
            "control_id": "AZUREMONITOR-CIS-0134",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #134",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0135"] = {
            "control_id": "AZUREMONITOR-CIS-0135",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #135",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0136"] = {
            "control_id": "AZUREMONITOR-CIS-0136",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #136",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0137"] = {
            "control_id": "AZUREMONITOR-CIS-0137",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #137",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0138"] = {
            "control_id": "AZUREMONITOR-CIS-0138",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #138",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0139"] = {
            "control_id": "AZUREMONITOR-CIS-0139",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #139",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0140"] = {
            "control_id": "AZUREMONITOR-CIS-0140",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #140",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0141"] = {
            "control_id": "AZUREMONITOR-CIS-0141",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #141",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0142"] = {
            "control_id": "AZUREMONITOR-CIS-0142",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #142",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0143"] = {
            "control_id": "AZUREMONITOR-CIS-0143",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #143",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0144"] = {
            "control_id": "AZUREMONITOR-CIS-0144",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #144",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0145"] = {
            "control_id": "AZUREMONITOR-CIS-0145",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #145",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0146"] = {
            "control_id": "AZUREMONITOR-CIS-0146",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #146",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0147"] = {
            "control_id": "AZUREMONITOR-CIS-0147",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #147",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0148"] = {
            "control_id": "AZUREMONITOR-CIS-0148",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #148",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0149"] = {
            "control_id": "AZUREMONITOR-CIS-0149",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #149",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0150"] = {
            "control_id": "AZUREMONITOR-CIS-0150",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #150",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0151"] = {
            "control_id": "AZUREMONITOR-CIS-0151",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #151",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0152"] = {
            "control_id": "AZUREMONITOR-CIS-0152",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #152",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0153"] = {
            "control_id": "AZUREMONITOR-CIS-0153",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #153",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0154"] = {
            "control_id": "AZUREMONITOR-CIS-0154",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #154",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0155"] = {
            "control_id": "AZUREMONITOR-CIS-0155",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #155",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0156"] = {
            "control_id": "AZUREMONITOR-CIS-0156",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #156",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0157"] = {
            "control_id": "AZUREMONITOR-CIS-0157",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #157",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0158"] = {
            "control_id": "AZUREMONITOR-CIS-0158",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #158",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0159"] = {
            "control_id": "AZUREMONITOR-CIS-0159",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #159",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0160"] = {
            "control_id": "AZUREMONITOR-CIS-0160",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #160",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0161"] = {
            "control_id": "AZUREMONITOR-CIS-0161",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #161",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0162"] = {
            "control_id": "AZUREMONITOR-CIS-0162",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #162",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0163"] = {
            "control_id": "AZUREMONITOR-CIS-0163",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #163",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0164"] = {
            "control_id": "AZUREMONITOR-CIS-0164",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #164",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0165"] = {
            "control_id": "AZUREMONITOR-CIS-0165",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #165",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0166"] = {
            "control_id": "AZUREMONITOR-CIS-0166",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #166",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0167"] = {
            "control_id": "AZUREMONITOR-CIS-0167",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #167",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0168"] = {
            "control_id": "AZUREMONITOR-CIS-0168",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #168",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0169"] = {
            "control_id": "AZUREMONITOR-CIS-0169",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #169",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0170"] = {
            "control_id": "AZUREMONITOR-CIS-0170",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #170",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0171"] = {
            "control_id": "AZUREMONITOR-CIS-0171",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #171",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0172"] = {
            "control_id": "AZUREMONITOR-CIS-0172",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #172",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0173"] = {
            "control_id": "AZUREMONITOR-CIS-0173",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #173",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0174"] = {
            "control_id": "AZUREMONITOR-CIS-0174",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #174",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0175"] = {
            "control_id": "AZUREMONITOR-CIS-0175",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #175",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0176"] = {
            "control_id": "AZUREMONITOR-CIS-0176",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #176",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0177"] = {
            "control_id": "AZUREMONITOR-CIS-0177",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #177",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0178"] = {
            "control_id": "AZUREMONITOR-CIS-0178",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #178",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0179"] = {
            "control_id": "AZUREMONITOR-CIS-0179",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #179",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0180"] = {
            "control_id": "AZUREMONITOR-CIS-0180",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #180",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0181"] = {
            "control_id": "AZUREMONITOR-CIS-0181",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #181",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0182"] = {
            "control_id": "AZUREMONITOR-CIS-0182",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #182",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0183"] = {
            "control_id": "AZUREMONITOR-CIS-0183",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #183",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0184"] = {
            "control_id": "AZUREMONITOR-CIS-0184",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #184",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0185"] = {
            "control_id": "AZUREMONITOR-CIS-0185",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #185",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0186"] = {
            "control_id": "AZUREMONITOR-CIS-0186",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #186",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0187"] = {
            "control_id": "AZUREMONITOR-CIS-0187",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #187",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0188"] = {
            "control_id": "AZUREMONITOR-CIS-0188",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #188",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0189"] = {
            "control_id": "AZUREMONITOR-CIS-0189",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #189",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0190"] = {
            "control_id": "AZUREMONITOR-CIS-0190",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #190",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0191"] = {
            "control_id": "AZUREMONITOR-CIS-0191",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #191",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0192"] = {
            "control_id": "AZUREMONITOR-CIS-0192",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #192",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0193"] = {
            "control_id": "AZUREMONITOR-CIS-0193",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #193",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0194"] = {
            "control_id": "AZUREMONITOR-CIS-0194",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #194",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0195"] = {
            "control_id": "AZUREMONITOR-CIS-0195",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #195",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0196"] = {
            "control_id": "AZUREMONITOR-CIS-0196",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #196",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0197"] = {
            "control_id": "AZUREMONITOR-CIS-0197",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #197",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0198"] = {
            "control_id": "AZUREMONITOR-CIS-0198",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #198",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0199"] = {
            "control_id": "AZUREMONITOR-CIS-0199",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #199",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0200"] = {
            "control_id": "AZUREMONITOR-CIS-0200",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #200",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0201"] = {
            "control_id": "AZUREMONITOR-CIS-0201",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #201",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0202"] = {
            "control_id": "AZUREMONITOR-CIS-0202",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #202",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0203"] = {
            "control_id": "AZUREMONITOR-CIS-0203",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #203",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0204"] = {
            "control_id": "AZUREMONITOR-CIS-0204",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #204",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0205"] = {
            "control_id": "AZUREMONITOR-CIS-0205",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #205",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0206"] = {
            "control_id": "AZUREMONITOR-CIS-0206",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #206",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0207"] = {
            "control_id": "AZUREMONITOR-CIS-0207",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #207",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0208"] = {
            "control_id": "AZUREMONITOR-CIS-0208",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #208",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0209"] = {
            "control_id": "AZUREMONITOR-CIS-0209",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #209",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0210"] = {
            "control_id": "AZUREMONITOR-CIS-0210",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #210",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0211"] = {
            "control_id": "AZUREMONITOR-CIS-0211",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #211",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0212"] = {
            "control_id": "AZUREMONITOR-CIS-0212",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #212",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0213"] = {
            "control_id": "AZUREMONITOR-CIS-0213",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #213",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0214"] = {
            "control_id": "AZUREMONITOR-CIS-0214",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #214",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0215"] = {
            "control_id": "AZUREMONITOR-CIS-0215",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #215",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0216"] = {
            "control_id": "AZUREMONITOR-CIS-0216",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #216",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0217"] = {
            "control_id": "AZUREMONITOR-CIS-0217",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #217",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0218"] = {
            "control_id": "AZUREMONITOR-CIS-0218",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #218",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0219"] = {
            "control_id": "AZUREMONITOR-CIS-0219",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #219",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0220"] = {
            "control_id": "AZUREMONITOR-CIS-0220",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #220",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0221"] = {
            "control_id": "AZUREMONITOR-CIS-0221",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #221",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0222"] = {
            "control_id": "AZUREMONITOR-CIS-0222",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #222",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0223"] = {
            "control_id": "AZUREMONITOR-CIS-0223",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #223",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0224"] = {
            "control_id": "AZUREMONITOR-CIS-0224",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #224",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0225"] = {
            "control_id": "AZUREMONITOR-CIS-0225",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #225",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0226"] = {
            "control_id": "AZUREMONITOR-CIS-0226",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #226",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0227"] = {
            "control_id": "AZUREMONITOR-CIS-0227",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #227",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0228"] = {
            "control_id": "AZUREMONITOR-CIS-0228",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #228",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0229"] = {
            "control_id": "AZUREMONITOR-CIS-0229",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #229",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0230"] = {
            "control_id": "AZUREMONITOR-CIS-0230",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #230",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0231"] = {
            "control_id": "AZUREMONITOR-CIS-0231",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #231",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0232"] = {
            "control_id": "AZUREMONITOR-CIS-0232",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #232",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0233"] = {
            "control_id": "AZUREMONITOR-CIS-0233",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #233",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0234"] = {
            "control_id": "AZUREMONITOR-CIS-0234",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #234",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0235"] = {
            "control_id": "AZUREMONITOR-CIS-0235",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #235",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0236"] = {
            "control_id": "AZUREMONITOR-CIS-0236",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #236",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0237"] = {
            "control_id": "AZUREMONITOR-CIS-0237",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #237",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0238"] = {
            "control_id": "AZUREMONITOR-CIS-0238",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #238",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0239"] = {
            "control_id": "AZUREMONITOR-CIS-0239",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #239",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0240"] = {
            "control_id": "AZUREMONITOR-CIS-0240",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #240",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0241"] = {
            "control_id": "AZUREMONITOR-CIS-0241",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #241",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0242"] = {
            "control_id": "AZUREMONITOR-CIS-0242",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #242",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0243"] = {
            "control_id": "AZUREMONITOR-CIS-0243",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #243",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0244"] = {
            "control_id": "AZUREMONITOR-CIS-0244",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #244",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0245"] = {
            "control_id": "AZUREMONITOR-CIS-0245",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #245",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0246"] = {
            "control_id": "AZUREMONITOR-CIS-0246",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #246",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0247"] = {
            "control_id": "AZUREMONITOR-CIS-0247",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #247",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0248"] = {
            "control_id": "AZUREMONITOR-CIS-0248",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #248",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0249"] = {
            "control_id": "AZUREMONITOR-CIS-0249",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #249",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0250"] = {
            "control_id": "AZUREMONITOR-CIS-0250",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #250",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0251"] = {
            "control_id": "AZUREMONITOR-CIS-0251",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #251",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0252"] = {
            "control_id": "AZUREMONITOR-CIS-0252",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #252",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0253"] = {
            "control_id": "AZUREMONITOR-CIS-0253",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #253",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0254"] = {
            "control_id": "AZUREMONITOR-CIS-0254",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #254",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0255"] = {
            "control_id": "AZUREMONITOR-CIS-0255",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #255",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0256"] = {
            "control_id": "AZUREMONITOR-CIS-0256",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #256",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0257"] = {
            "control_id": "AZUREMONITOR-CIS-0257",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #257",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0258"] = {
            "control_id": "AZUREMONITOR-CIS-0258",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #258",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0259"] = {
            "control_id": "AZUREMONITOR-CIS-0259",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #259",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0260"] = {
            "control_id": "AZUREMONITOR-CIS-0260",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #260",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0261"] = {
            "control_id": "AZUREMONITOR-CIS-0261",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #261",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0262"] = {
            "control_id": "AZUREMONITOR-CIS-0262",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #262",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0263"] = {
            "control_id": "AZUREMONITOR-CIS-0263",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #263",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0264"] = {
            "control_id": "AZUREMONITOR-CIS-0264",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #264",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0265"] = {
            "control_id": "AZUREMONITOR-CIS-0265",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #265",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0266"] = {
            "control_id": "AZUREMONITOR-CIS-0266",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #266",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0267"] = {
            "control_id": "AZUREMONITOR-CIS-0267",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #267",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0268"] = {
            "control_id": "AZUREMONITOR-CIS-0268",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #268",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0269"] = {
            "control_id": "AZUREMONITOR-CIS-0269",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #269",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0270"] = {
            "control_id": "AZUREMONITOR-CIS-0270",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #270",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0271"] = {
            "control_id": "AZUREMONITOR-CIS-0271",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #271",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0272"] = {
            "control_id": "AZUREMONITOR-CIS-0272",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #272",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0273"] = {
            "control_id": "AZUREMONITOR-CIS-0273",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #273",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0274"] = {
            "control_id": "AZUREMONITOR-CIS-0274",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #274",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0275"] = {
            "control_id": "AZUREMONITOR-CIS-0275",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #275",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0276"] = {
            "control_id": "AZUREMONITOR-CIS-0276",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #276",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0277"] = {
            "control_id": "AZUREMONITOR-CIS-0277",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #277",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0278"] = {
            "control_id": "AZUREMONITOR-CIS-0278",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #278",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0279"] = {
            "control_id": "AZUREMONITOR-CIS-0279",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #279",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0280"] = {
            "control_id": "AZUREMONITOR-CIS-0280",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #280",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0281"] = {
            "control_id": "AZUREMONITOR-CIS-0281",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #281",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0282"] = {
            "control_id": "AZUREMONITOR-CIS-0282",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #282",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0283"] = {
            "control_id": "AZUREMONITOR-CIS-0283",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #283",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0284"] = {
            "control_id": "AZUREMONITOR-CIS-0284",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #284",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0285"] = {
            "control_id": "AZUREMONITOR-CIS-0285",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #285",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0286"] = {
            "control_id": "AZUREMONITOR-CIS-0286",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #286",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0287"] = {
            "control_id": "AZUREMONITOR-CIS-0287",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #287",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0288"] = {
            "control_id": "AZUREMONITOR-CIS-0288",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #288",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0289"] = {
            "control_id": "AZUREMONITOR-CIS-0289",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #289",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0290"] = {
            "control_id": "AZUREMONITOR-CIS-0290",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #290",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0291"] = {
            "control_id": "AZUREMONITOR-CIS-0291",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #291",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0292"] = {
            "control_id": "AZUREMONITOR-CIS-0292",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #292",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0293"] = {
            "control_id": "AZUREMONITOR-CIS-0293",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #293",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0294"] = {
            "control_id": "AZUREMONITOR-CIS-0294",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #294",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0295"] = {
            "control_id": "AZUREMONITOR-CIS-0295",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #295",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0296"] = {
            "control_id": "AZUREMONITOR-CIS-0296",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #296",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0297"] = {
            "control_id": "AZUREMONITOR-CIS-0297",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #297",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0298"] = {
            "control_id": "AZUREMONITOR-CIS-0298",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #298",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0299"] = {
            "control_id": "AZUREMONITOR-CIS-0299",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #299",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0300"] = {
            "control_id": "AZUREMONITOR-CIS-0300",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #300",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0301"] = {
            "control_id": "AZUREMONITOR-CIS-0301",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #301",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0302"] = {
            "control_id": "AZUREMONITOR-CIS-0302",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #302",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0303"] = {
            "control_id": "AZUREMONITOR-CIS-0303",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #303",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0304"] = {
            "control_id": "AZUREMONITOR-CIS-0304",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #304",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0305"] = {
            "control_id": "AZUREMONITOR-CIS-0305",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #305",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0306"] = {
            "control_id": "AZUREMONITOR-CIS-0306",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #306",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0307"] = {
            "control_id": "AZUREMONITOR-CIS-0307",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #307",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0308"] = {
            "control_id": "AZUREMONITOR-CIS-0308",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #308",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0309"] = {
            "control_id": "AZUREMONITOR-CIS-0309",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #309",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0310"] = {
            "control_id": "AZUREMONITOR-CIS-0310",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #310",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0311"] = {
            "control_id": "AZUREMONITOR-CIS-0311",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #311",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0312"] = {
            "control_id": "AZUREMONITOR-CIS-0312",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #312",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0313"] = {
            "control_id": "AZUREMONITOR-CIS-0313",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #313",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0314"] = {
            "control_id": "AZUREMONITOR-CIS-0314",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #314",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0315"] = {
            "control_id": "AZUREMONITOR-CIS-0315",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #315",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0316"] = {
            "control_id": "AZUREMONITOR-CIS-0316",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #316",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0317"] = {
            "control_id": "AZUREMONITOR-CIS-0317",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #317",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0318"] = {
            "control_id": "AZUREMONITOR-CIS-0318",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #318",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0319"] = {
            "control_id": "AZUREMONITOR-CIS-0319",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #319",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0320"] = {
            "control_id": "AZUREMONITOR-CIS-0320",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #320",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0321"] = {
            "control_id": "AZUREMONITOR-CIS-0321",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #321",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0322"] = {
            "control_id": "AZUREMONITOR-CIS-0322",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #322",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0323"] = {
            "control_id": "AZUREMONITOR-CIS-0323",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #323",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0324"] = {
            "control_id": "AZUREMONITOR-CIS-0324",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #324",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0325"] = {
            "control_id": "AZUREMONITOR-CIS-0325",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #325",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0326"] = {
            "control_id": "AZUREMONITOR-CIS-0326",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #326",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0327"] = {
            "control_id": "AZUREMONITOR-CIS-0327",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #327",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0328"] = {
            "control_id": "AZUREMONITOR-CIS-0328",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #328",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0329"] = {
            "control_id": "AZUREMONITOR-CIS-0329",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #329",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0330"] = {
            "control_id": "AZUREMONITOR-CIS-0330",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #330",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0331"] = {
            "control_id": "AZUREMONITOR-CIS-0331",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #331",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0332"] = {
            "control_id": "AZUREMONITOR-CIS-0332",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #332",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0333"] = {
            "control_id": "AZUREMONITOR-CIS-0333",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #333",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0334"] = {
            "control_id": "AZUREMONITOR-CIS-0334",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #334",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0335"] = {
            "control_id": "AZUREMONITOR-CIS-0335",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #335",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0336"] = {
            "control_id": "AZUREMONITOR-CIS-0336",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #336",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0337"] = {
            "control_id": "AZUREMONITOR-CIS-0337",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #337",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0338"] = {
            "control_id": "AZUREMONITOR-CIS-0338",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #338",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0339"] = {
            "control_id": "AZUREMONITOR-CIS-0339",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #339",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0340"] = {
            "control_id": "AZUREMONITOR-CIS-0340",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #340",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0341"] = {
            "control_id": "AZUREMONITOR-CIS-0341",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #341",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0342"] = {
            "control_id": "AZUREMONITOR-CIS-0342",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #342",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0343"] = {
            "control_id": "AZUREMONITOR-CIS-0343",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #343",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0344"] = {
            "control_id": "AZUREMONITOR-CIS-0344",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #344",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0345"] = {
            "control_id": "AZUREMONITOR-CIS-0345",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #345",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0346"] = {
            "control_id": "AZUREMONITOR-CIS-0346",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #346",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0347"] = {
            "control_id": "AZUREMONITOR-CIS-0347",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #347",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0348"] = {
            "control_id": "AZUREMONITOR-CIS-0348",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #348",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0349"] = {
            "control_id": "AZUREMONITOR-CIS-0349",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #349",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0350"] = {
            "control_id": "AZUREMONITOR-CIS-0350",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #350",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0351"] = {
            "control_id": "AZUREMONITOR-CIS-0351",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #351",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0352"] = {
            "control_id": "AZUREMONITOR-CIS-0352",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #352",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0353"] = {
            "control_id": "AZUREMONITOR-CIS-0353",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #353",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0354"] = {
            "control_id": "AZUREMONITOR-CIS-0354",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #354",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0355"] = {
            "control_id": "AZUREMONITOR-CIS-0355",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #355",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0356"] = {
            "control_id": "AZUREMONITOR-CIS-0356",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #356",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0357"] = {
            "control_id": "AZUREMONITOR-CIS-0357",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #357",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0358"] = {
            "control_id": "AZUREMONITOR-CIS-0358",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #358",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0359"] = {
            "control_id": "AZUREMONITOR-CIS-0359",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #359",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0360"] = {
            "control_id": "AZUREMONITOR-CIS-0360",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #360",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0361"] = {
            "control_id": "AZUREMONITOR-CIS-0361",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #361",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0362"] = {
            "control_id": "AZUREMONITOR-CIS-0362",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #362",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0363"] = {
            "control_id": "AZUREMONITOR-CIS-0363",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #363",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0364"] = {
            "control_id": "AZUREMONITOR-CIS-0364",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #364",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0365"] = {
            "control_id": "AZUREMONITOR-CIS-0365",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #365",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0366"] = {
            "control_id": "AZUREMONITOR-CIS-0366",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #366",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0367"] = {
            "control_id": "AZUREMONITOR-CIS-0367",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #367",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0368"] = {
            "control_id": "AZUREMONITOR-CIS-0368",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #368",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0369"] = {
            "control_id": "AZUREMONITOR-CIS-0369",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #369",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0370"] = {
            "control_id": "AZUREMONITOR-CIS-0370",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #370",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0371"] = {
            "control_id": "AZUREMONITOR-CIS-0371",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #371",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0372"] = {
            "control_id": "AZUREMONITOR-CIS-0372",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #372",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0373"] = {
            "control_id": "AZUREMONITOR-CIS-0373",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #373",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0374"] = {
            "control_id": "AZUREMONITOR-CIS-0374",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #374",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0375"] = {
            "control_id": "AZUREMONITOR-CIS-0375",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #375",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0376"] = {
            "control_id": "AZUREMONITOR-CIS-0376",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #376",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0377"] = {
            "control_id": "AZUREMONITOR-CIS-0377",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #377",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0378"] = {
            "control_id": "AZUREMONITOR-CIS-0378",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #378",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0379"] = {
            "control_id": "AZUREMONITOR-CIS-0379",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #379",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0380"] = {
            "control_id": "AZUREMONITOR-CIS-0380",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #380",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0381"] = {
            "control_id": "AZUREMONITOR-CIS-0381",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #381",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0382"] = {
            "control_id": "AZUREMONITOR-CIS-0382",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #382",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0383"] = {
            "control_id": "AZUREMONITOR-CIS-0383",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #383",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0384"] = {
            "control_id": "AZUREMONITOR-CIS-0384",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #384",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0385"] = {
            "control_id": "AZUREMONITOR-CIS-0385",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #385",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0386"] = {
            "control_id": "AZUREMONITOR-CIS-0386",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #386",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0387"] = {
            "control_id": "AZUREMONITOR-CIS-0387",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #387",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0388"] = {
            "control_id": "AZUREMONITOR-CIS-0388",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #388",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0389"] = {
            "control_id": "AZUREMONITOR-CIS-0389",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #389",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0390"] = {
            "control_id": "AZUREMONITOR-CIS-0390",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #390",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0391"] = {
            "control_id": "AZUREMONITOR-CIS-0391",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #391",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0392"] = {
            "control_id": "AZUREMONITOR-CIS-0392",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #392",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0393"] = {
            "control_id": "AZUREMONITOR-CIS-0393",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #393",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0394"] = {
            "control_id": "AZUREMONITOR-CIS-0394",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #394",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0395"] = {
            "control_id": "AZUREMONITOR-CIS-0395",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #395",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0396"] = {
            "control_id": "AZUREMONITOR-CIS-0396",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #396",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0397"] = {
            "control_id": "AZUREMONITOR-CIS-0397",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #397",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0398"] = {
            "control_id": "AZUREMONITOR-CIS-0398",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #398",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0399"] = {
            "control_id": "AZUREMONITOR-CIS-0399",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #399",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0400"] = {
            "control_id": "AZUREMONITOR-CIS-0400",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #400",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0401"] = {
            "control_id": "AZUREMONITOR-CIS-0401",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #401",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0402"] = {
            "control_id": "AZUREMONITOR-CIS-0402",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #402",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0403"] = {
            "control_id": "AZUREMONITOR-CIS-0403",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #403",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0404"] = {
            "control_id": "AZUREMONITOR-CIS-0404",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #404",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0405"] = {
            "control_id": "AZUREMONITOR-CIS-0405",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #405",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0406"] = {
            "control_id": "AZUREMONITOR-CIS-0406",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #406",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0407"] = {
            "control_id": "AZUREMONITOR-CIS-0407",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #407",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0408"] = {
            "control_id": "AZUREMONITOR-CIS-0408",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #408",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0409"] = {
            "control_id": "AZUREMONITOR-CIS-0409",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #409",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0410"] = {
            "control_id": "AZUREMONITOR-CIS-0410",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #410",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0411"] = {
            "control_id": "AZUREMONITOR-CIS-0411",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #411",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0412"] = {
            "control_id": "AZUREMONITOR-CIS-0412",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #412",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0413"] = {
            "control_id": "AZUREMONITOR-CIS-0413",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #413",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0414"] = {
            "control_id": "AZUREMONITOR-CIS-0414",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #414",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0415"] = {
            "control_id": "AZUREMONITOR-CIS-0415",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #415",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0416"] = {
            "control_id": "AZUREMONITOR-CIS-0416",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #416",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0417"] = {
            "control_id": "AZUREMONITOR-CIS-0417",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #417",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0418"] = {
            "control_id": "AZUREMONITOR-CIS-0418",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #418",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0419"] = {
            "control_id": "AZUREMONITOR-CIS-0419",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #419",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0420"] = {
            "control_id": "AZUREMONITOR-CIS-0420",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #420",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0421"] = {
            "control_id": "AZUREMONITOR-CIS-0421",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #421",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0422"] = {
            "control_id": "AZUREMONITOR-CIS-0422",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #422",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0423"] = {
            "control_id": "AZUREMONITOR-CIS-0423",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #423",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0424"] = {
            "control_id": "AZUREMONITOR-CIS-0424",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #424",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0425"] = {
            "control_id": "AZUREMONITOR-CIS-0425",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #425",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0426"] = {
            "control_id": "AZUREMONITOR-CIS-0426",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #426",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0427"] = {
            "control_id": "AZUREMONITOR-CIS-0427",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #427",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0428"] = {
            "control_id": "AZUREMONITOR-CIS-0428",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #428",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0429"] = {
            "control_id": "AZUREMONITOR-CIS-0429",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #429",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0430"] = {
            "control_id": "AZUREMONITOR-CIS-0430",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #430",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0431"] = {
            "control_id": "AZUREMONITOR-CIS-0431",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #431",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0432"] = {
            "control_id": "AZUREMONITOR-CIS-0432",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #432",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0433"] = {
            "control_id": "AZUREMONITOR-CIS-0433",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #433",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0434"] = {
            "control_id": "AZUREMONITOR-CIS-0434",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #434",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0435"] = {
            "control_id": "AZUREMONITOR-CIS-0435",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #435",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0436"] = {
            "control_id": "AZUREMONITOR-CIS-0436",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #436",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0437"] = {
            "control_id": "AZUREMONITOR-CIS-0437",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #437",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0438"] = {
            "control_id": "AZUREMONITOR-CIS-0438",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #438",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0439"] = {
            "control_id": "AZUREMONITOR-CIS-0439",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #439",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0440"] = {
            "control_id": "AZUREMONITOR-CIS-0440",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #440",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0441"] = {
            "control_id": "AZUREMONITOR-CIS-0441",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #441",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0442"] = {
            "control_id": "AZUREMONITOR-CIS-0442",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #442",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0443"] = {
            "control_id": "AZUREMONITOR-CIS-0443",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #443",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0444"] = {
            "control_id": "AZUREMONITOR-CIS-0444",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #444",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0445"] = {
            "control_id": "AZUREMONITOR-CIS-0445",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #445",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0446"] = {
            "control_id": "AZUREMONITOR-CIS-0446",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #446",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0447"] = {
            "control_id": "AZUREMONITOR-CIS-0447",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #447",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0448"] = {
            "control_id": "AZUREMONITOR-CIS-0448",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #448",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREMONITOR-CIS-0449"] = {
            "control_id": "AZUREMONITOR-CIS-0449",
            "title": "Azure Monitor Diagnostic Log Stream Alert Engine Benchmark #449",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }

    def evaluate_resource_posture(self, state: AzureMonitorResourceState) -> Dict[str, Any]:
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

azure_monitor_log_analytics_alert_cspm = AzureMonitorPostureEvaluator()

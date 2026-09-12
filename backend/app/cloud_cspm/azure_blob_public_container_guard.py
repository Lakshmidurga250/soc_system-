"""
SentinelAI - Azure Blob Public Anonymous Container Leak Guard
Enterprise Multi-Cloud Security Posture Management (CSPM) engine for AzureBlob.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import datetime

class AzureBlobComplianceStatus(Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    SUPPRESSED = "SUPPRESSED"
    CRITICAL_BREACH = "CRITICAL_BREACH"

@dataclass
class AzureBlobResourceState:
    resource_arn: str
    provider: str
    account_or_tenant: str
    region: str
    resource_type: str
    configuration: Dict[str, Any]
    compliance: AzureBlobComplianceStatus = AzureBlobComplianceStatus.COMPLIANT
    active_findings: List[str] = field(default_factory=list)

class AzureBlobPostureEvaluator:
    def __init__(self):
        self.benchmark_rules: Dict[str, Any] = {}
        self.compliance_ledger: List[Any] = []
        self._initialize_benchmark_rules()

    def _initialize_benchmark_rules(self):
        self.benchmark_rules["AZUREBLOB-CIS-0001"] = {
            "control_id": "AZUREBLOB-CIS-0001",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #1",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0002"] = {
            "control_id": "AZUREBLOB-CIS-0002",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #2",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0003"] = {
            "control_id": "AZUREBLOB-CIS-0003",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #3",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0004"] = {
            "control_id": "AZUREBLOB-CIS-0004",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #4",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0005"] = {
            "control_id": "AZUREBLOB-CIS-0005",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #5",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0006"] = {
            "control_id": "AZUREBLOB-CIS-0006",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #6",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0007"] = {
            "control_id": "AZUREBLOB-CIS-0007",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #7",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0008"] = {
            "control_id": "AZUREBLOB-CIS-0008",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #8",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0009"] = {
            "control_id": "AZUREBLOB-CIS-0009",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #9",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0010"] = {
            "control_id": "AZUREBLOB-CIS-0010",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #10",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0011"] = {
            "control_id": "AZUREBLOB-CIS-0011",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #11",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0012"] = {
            "control_id": "AZUREBLOB-CIS-0012",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #12",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0013"] = {
            "control_id": "AZUREBLOB-CIS-0013",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #13",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0014"] = {
            "control_id": "AZUREBLOB-CIS-0014",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #14",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0015"] = {
            "control_id": "AZUREBLOB-CIS-0015",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #15",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0016"] = {
            "control_id": "AZUREBLOB-CIS-0016",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #16",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0017"] = {
            "control_id": "AZUREBLOB-CIS-0017",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #17",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0018"] = {
            "control_id": "AZUREBLOB-CIS-0018",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #18",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0019"] = {
            "control_id": "AZUREBLOB-CIS-0019",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #19",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0020"] = {
            "control_id": "AZUREBLOB-CIS-0020",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #20",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0021"] = {
            "control_id": "AZUREBLOB-CIS-0021",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #21",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0022"] = {
            "control_id": "AZUREBLOB-CIS-0022",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #22",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0023"] = {
            "control_id": "AZUREBLOB-CIS-0023",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #23",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0024"] = {
            "control_id": "AZUREBLOB-CIS-0024",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #24",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0025"] = {
            "control_id": "AZUREBLOB-CIS-0025",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #25",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0026"] = {
            "control_id": "AZUREBLOB-CIS-0026",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #26",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0027"] = {
            "control_id": "AZUREBLOB-CIS-0027",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #27",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0028"] = {
            "control_id": "AZUREBLOB-CIS-0028",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #28",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0029"] = {
            "control_id": "AZUREBLOB-CIS-0029",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #29",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0030"] = {
            "control_id": "AZUREBLOB-CIS-0030",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #30",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0031"] = {
            "control_id": "AZUREBLOB-CIS-0031",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #31",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0032"] = {
            "control_id": "AZUREBLOB-CIS-0032",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #32",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0033"] = {
            "control_id": "AZUREBLOB-CIS-0033",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #33",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0034"] = {
            "control_id": "AZUREBLOB-CIS-0034",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #34",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0035"] = {
            "control_id": "AZUREBLOB-CIS-0035",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #35",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0036"] = {
            "control_id": "AZUREBLOB-CIS-0036",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #36",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0037"] = {
            "control_id": "AZUREBLOB-CIS-0037",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #37",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0038"] = {
            "control_id": "AZUREBLOB-CIS-0038",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #38",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0039"] = {
            "control_id": "AZUREBLOB-CIS-0039",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #39",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0040"] = {
            "control_id": "AZUREBLOB-CIS-0040",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #40",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0041"] = {
            "control_id": "AZUREBLOB-CIS-0041",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #41",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0042"] = {
            "control_id": "AZUREBLOB-CIS-0042",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #42",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0043"] = {
            "control_id": "AZUREBLOB-CIS-0043",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #43",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0044"] = {
            "control_id": "AZUREBLOB-CIS-0044",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #44",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0045"] = {
            "control_id": "AZUREBLOB-CIS-0045",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #45",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0046"] = {
            "control_id": "AZUREBLOB-CIS-0046",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #46",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0047"] = {
            "control_id": "AZUREBLOB-CIS-0047",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #47",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0048"] = {
            "control_id": "AZUREBLOB-CIS-0048",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #48",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0049"] = {
            "control_id": "AZUREBLOB-CIS-0049",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #49",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0050"] = {
            "control_id": "AZUREBLOB-CIS-0050",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #50",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0051"] = {
            "control_id": "AZUREBLOB-CIS-0051",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #51",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0052"] = {
            "control_id": "AZUREBLOB-CIS-0052",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #52",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0053"] = {
            "control_id": "AZUREBLOB-CIS-0053",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #53",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0054"] = {
            "control_id": "AZUREBLOB-CIS-0054",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #54",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0055"] = {
            "control_id": "AZUREBLOB-CIS-0055",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #55",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0056"] = {
            "control_id": "AZUREBLOB-CIS-0056",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #56",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0057"] = {
            "control_id": "AZUREBLOB-CIS-0057",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #57",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0058"] = {
            "control_id": "AZUREBLOB-CIS-0058",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #58",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0059"] = {
            "control_id": "AZUREBLOB-CIS-0059",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #59",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0060"] = {
            "control_id": "AZUREBLOB-CIS-0060",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #60",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0061"] = {
            "control_id": "AZUREBLOB-CIS-0061",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #61",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0062"] = {
            "control_id": "AZUREBLOB-CIS-0062",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #62",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0063"] = {
            "control_id": "AZUREBLOB-CIS-0063",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #63",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0064"] = {
            "control_id": "AZUREBLOB-CIS-0064",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #64",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0065"] = {
            "control_id": "AZUREBLOB-CIS-0065",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #65",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0066"] = {
            "control_id": "AZUREBLOB-CIS-0066",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #66",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0067"] = {
            "control_id": "AZUREBLOB-CIS-0067",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #67",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0068"] = {
            "control_id": "AZUREBLOB-CIS-0068",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #68",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0069"] = {
            "control_id": "AZUREBLOB-CIS-0069",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #69",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0070"] = {
            "control_id": "AZUREBLOB-CIS-0070",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #70",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0071"] = {
            "control_id": "AZUREBLOB-CIS-0071",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #71",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0072"] = {
            "control_id": "AZUREBLOB-CIS-0072",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #72",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0073"] = {
            "control_id": "AZUREBLOB-CIS-0073",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #73",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0074"] = {
            "control_id": "AZUREBLOB-CIS-0074",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #74",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0075"] = {
            "control_id": "AZUREBLOB-CIS-0075",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #75",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0076"] = {
            "control_id": "AZUREBLOB-CIS-0076",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #76",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0077"] = {
            "control_id": "AZUREBLOB-CIS-0077",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #77",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0078"] = {
            "control_id": "AZUREBLOB-CIS-0078",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #78",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0079"] = {
            "control_id": "AZUREBLOB-CIS-0079",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #79",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0080"] = {
            "control_id": "AZUREBLOB-CIS-0080",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #80",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0081"] = {
            "control_id": "AZUREBLOB-CIS-0081",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #81",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0082"] = {
            "control_id": "AZUREBLOB-CIS-0082",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #82",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0083"] = {
            "control_id": "AZUREBLOB-CIS-0083",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #83",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0084"] = {
            "control_id": "AZUREBLOB-CIS-0084",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #84",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0085"] = {
            "control_id": "AZUREBLOB-CIS-0085",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #85",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0086"] = {
            "control_id": "AZUREBLOB-CIS-0086",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #86",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0087"] = {
            "control_id": "AZUREBLOB-CIS-0087",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #87",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0088"] = {
            "control_id": "AZUREBLOB-CIS-0088",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #88",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0089"] = {
            "control_id": "AZUREBLOB-CIS-0089",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #89",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0090"] = {
            "control_id": "AZUREBLOB-CIS-0090",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #90",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0091"] = {
            "control_id": "AZUREBLOB-CIS-0091",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #91",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0092"] = {
            "control_id": "AZUREBLOB-CIS-0092",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #92",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0093"] = {
            "control_id": "AZUREBLOB-CIS-0093",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #93",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0094"] = {
            "control_id": "AZUREBLOB-CIS-0094",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #94",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0095"] = {
            "control_id": "AZUREBLOB-CIS-0095",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #95",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0096"] = {
            "control_id": "AZUREBLOB-CIS-0096",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #96",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0097"] = {
            "control_id": "AZUREBLOB-CIS-0097",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #97",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0098"] = {
            "control_id": "AZUREBLOB-CIS-0098",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #98",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0099"] = {
            "control_id": "AZUREBLOB-CIS-0099",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #99",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0100"] = {
            "control_id": "AZUREBLOB-CIS-0100",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #100",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0101"] = {
            "control_id": "AZUREBLOB-CIS-0101",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #101",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0102"] = {
            "control_id": "AZUREBLOB-CIS-0102",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #102",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0103"] = {
            "control_id": "AZUREBLOB-CIS-0103",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #103",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0104"] = {
            "control_id": "AZUREBLOB-CIS-0104",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #104",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0105"] = {
            "control_id": "AZUREBLOB-CIS-0105",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #105",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0106"] = {
            "control_id": "AZUREBLOB-CIS-0106",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #106",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0107"] = {
            "control_id": "AZUREBLOB-CIS-0107",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #107",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0108"] = {
            "control_id": "AZUREBLOB-CIS-0108",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #108",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0109"] = {
            "control_id": "AZUREBLOB-CIS-0109",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #109",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0110"] = {
            "control_id": "AZUREBLOB-CIS-0110",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #110",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0111"] = {
            "control_id": "AZUREBLOB-CIS-0111",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #111",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0112"] = {
            "control_id": "AZUREBLOB-CIS-0112",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #112",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0113"] = {
            "control_id": "AZUREBLOB-CIS-0113",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #113",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0114"] = {
            "control_id": "AZUREBLOB-CIS-0114",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #114",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0115"] = {
            "control_id": "AZUREBLOB-CIS-0115",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #115",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0116"] = {
            "control_id": "AZUREBLOB-CIS-0116",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #116",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0117"] = {
            "control_id": "AZUREBLOB-CIS-0117",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #117",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0118"] = {
            "control_id": "AZUREBLOB-CIS-0118",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #118",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0119"] = {
            "control_id": "AZUREBLOB-CIS-0119",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #119",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0120"] = {
            "control_id": "AZUREBLOB-CIS-0120",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #120",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0121"] = {
            "control_id": "AZUREBLOB-CIS-0121",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #121",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0122"] = {
            "control_id": "AZUREBLOB-CIS-0122",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #122",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0123"] = {
            "control_id": "AZUREBLOB-CIS-0123",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #123",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0124"] = {
            "control_id": "AZUREBLOB-CIS-0124",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #124",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0125"] = {
            "control_id": "AZUREBLOB-CIS-0125",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #125",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0126"] = {
            "control_id": "AZUREBLOB-CIS-0126",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #126",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0127"] = {
            "control_id": "AZUREBLOB-CIS-0127",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #127",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0128"] = {
            "control_id": "AZUREBLOB-CIS-0128",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #128",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0129"] = {
            "control_id": "AZUREBLOB-CIS-0129",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #129",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0130"] = {
            "control_id": "AZUREBLOB-CIS-0130",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #130",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0131"] = {
            "control_id": "AZUREBLOB-CIS-0131",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #131",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0132"] = {
            "control_id": "AZUREBLOB-CIS-0132",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #132",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0133"] = {
            "control_id": "AZUREBLOB-CIS-0133",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #133",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0134"] = {
            "control_id": "AZUREBLOB-CIS-0134",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #134",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0135"] = {
            "control_id": "AZUREBLOB-CIS-0135",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #135",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0136"] = {
            "control_id": "AZUREBLOB-CIS-0136",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #136",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0137"] = {
            "control_id": "AZUREBLOB-CIS-0137",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #137",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0138"] = {
            "control_id": "AZUREBLOB-CIS-0138",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #138",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0139"] = {
            "control_id": "AZUREBLOB-CIS-0139",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #139",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0140"] = {
            "control_id": "AZUREBLOB-CIS-0140",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #140",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0141"] = {
            "control_id": "AZUREBLOB-CIS-0141",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #141",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0142"] = {
            "control_id": "AZUREBLOB-CIS-0142",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #142",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0143"] = {
            "control_id": "AZUREBLOB-CIS-0143",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #143",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0144"] = {
            "control_id": "AZUREBLOB-CIS-0144",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #144",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0145"] = {
            "control_id": "AZUREBLOB-CIS-0145",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #145",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0146"] = {
            "control_id": "AZUREBLOB-CIS-0146",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #146",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0147"] = {
            "control_id": "AZUREBLOB-CIS-0147",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #147",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0148"] = {
            "control_id": "AZUREBLOB-CIS-0148",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #148",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0149"] = {
            "control_id": "AZUREBLOB-CIS-0149",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #149",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0150"] = {
            "control_id": "AZUREBLOB-CIS-0150",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #150",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0151"] = {
            "control_id": "AZUREBLOB-CIS-0151",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #151",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0152"] = {
            "control_id": "AZUREBLOB-CIS-0152",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #152",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0153"] = {
            "control_id": "AZUREBLOB-CIS-0153",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #153",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0154"] = {
            "control_id": "AZUREBLOB-CIS-0154",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #154",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0155"] = {
            "control_id": "AZUREBLOB-CIS-0155",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #155",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0156"] = {
            "control_id": "AZUREBLOB-CIS-0156",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #156",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0157"] = {
            "control_id": "AZUREBLOB-CIS-0157",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #157",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0158"] = {
            "control_id": "AZUREBLOB-CIS-0158",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #158",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0159"] = {
            "control_id": "AZUREBLOB-CIS-0159",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #159",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0160"] = {
            "control_id": "AZUREBLOB-CIS-0160",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #160",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0161"] = {
            "control_id": "AZUREBLOB-CIS-0161",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #161",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0162"] = {
            "control_id": "AZUREBLOB-CIS-0162",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #162",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0163"] = {
            "control_id": "AZUREBLOB-CIS-0163",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #163",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0164"] = {
            "control_id": "AZUREBLOB-CIS-0164",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #164",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0165"] = {
            "control_id": "AZUREBLOB-CIS-0165",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #165",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0166"] = {
            "control_id": "AZUREBLOB-CIS-0166",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #166",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0167"] = {
            "control_id": "AZUREBLOB-CIS-0167",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #167",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0168"] = {
            "control_id": "AZUREBLOB-CIS-0168",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #168",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0169"] = {
            "control_id": "AZUREBLOB-CIS-0169",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #169",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0170"] = {
            "control_id": "AZUREBLOB-CIS-0170",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #170",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0171"] = {
            "control_id": "AZUREBLOB-CIS-0171",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #171",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0172"] = {
            "control_id": "AZUREBLOB-CIS-0172",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #172",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0173"] = {
            "control_id": "AZUREBLOB-CIS-0173",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #173",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0174"] = {
            "control_id": "AZUREBLOB-CIS-0174",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #174",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0175"] = {
            "control_id": "AZUREBLOB-CIS-0175",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #175",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0176"] = {
            "control_id": "AZUREBLOB-CIS-0176",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #176",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0177"] = {
            "control_id": "AZUREBLOB-CIS-0177",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #177",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0178"] = {
            "control_id": "AZUREBLOB-CIS-0178",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #178",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0179"] = {
            "control_id": "AZUREBLOB-CIS-0179",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #179",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0180"] = {
            "control_id": "AZUREBLOB-CIS-0180",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #180",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0181"] = {
            "control_id": "AZUREBLOB-CIS-0181",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #181",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0182"] = {
            "control_id": "AZUREBLOB-CIS-0182",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #182",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0183"] = {
            "control_id": "AZUREBLOB-CIS-0183",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #183",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0184"] = {
            "control_id": "AZUREBLOB-CIS-0184",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #184",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0185"] = {
            "control_id": "AZUREBLOB-CIS-0185",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #185",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0186"] = {
            "control_id": "AZUREBLOB-CIS-0186",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #186",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0187"] = {
            "control_id": "AZUREBLOB-CIS-0187",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #187",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0188"] = {
            "control_id": "AZUREBLOB-CIS-0188",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #188",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0189"] = {
            "control_id": "AZUREBLOB-CIS-0189",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #189",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0190"] = {
            "control_id": "AZUREBLOB-CIS-0190",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #190",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0191"] = {
            "control_id": "AZUREBLOB-CIS-0191",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #191",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0192"] = {
            "control_id": "AZUREBLOB-CIS-0192",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #192",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0193"] = {
            "control_id": "AZUREBLOB-CIS-0193",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #193",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0194"] = {
            "control_id": "AZUREBLOB-CIS-0194",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #194",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0195"] = {
            "control_id": "AZUREBLOB-CIS-0195",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #195",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0196"] = {
            "control_id": "AZUREBLOB-CIS-0196",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #196",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0197"] = {
            "control_id": "AZUREBLOB-CIS-0197",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #197",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0198"] = {
            "control_id": "AZUREBLOB-CIS-0198",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #198",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0199"] = {
            "control_id": "AZUREBLOB-CIS-0199",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #199",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0200"] = {
            "control_id": "AZUREBLOB-CIS-0200",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #200",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0201"] = {
            "control_id": "AZUREBLOB-CIS-0201",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #201",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0202"] = {
            "control_id": "AZUREBLOB-CIS-0202",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #202",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0203"] = {
            "control_id": "AZUREBLOB-CIS-0203",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #203",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0204"] = {
            "control_id": "AZUREBLOB-CIS-0204",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #204",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0205"] = {
            "control_id": "AZUREBLOB-CIS-0205",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #205",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0206"] = {
            "control_id": "AZUREBLOB-CIS-0206",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #206",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0207"] = {
            "control_id": "AZUREBLOB-CIS-0207",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #207",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0208"] = {
            "control_id": "AZUREBLOB-CIS-0208",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #208",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0209"] = {
            "control_id": "AZUREBLOB-CIS-0209",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #209",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0210"] = {
            "control_id": "AZUREBLOB-CIS-0210",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #210",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0211"] = {
            "control_id": "AZUREBLOB-CIS-0211",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #211",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0212"] = {
            "control_id": "AZUREBLOB-CIS-0212",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #212",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0213"] = {
            "control_id": "AZUREBLOB-CIS-0213",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #213",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0214"] = {
            "control_id": "AZUREBLOB-CIS-0214",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #214",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0215"] = {
            "control_id": "AZUREBLOB-CIS-0215",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #215",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0216"] = {
            "control_id": "AZUREBLOB-CIS-0216",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #216",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0217"] = {
            "control_id": "AZUREBLOB-CIS-0217",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #217",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0218"] = {
            "control_id": "AZUREBLOB-CIS-0218",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #218",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0219"] = {
            "control_id": "AZUREBLOB-CIS-0219",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #219",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0220"] = {
            "control_id": "AZUREBLOB-CIS-0220",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #220",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0221"] = {
            "control_id": "AZUREBLOB-CIS-0221",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #221",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0222"] = {
            "control_id": "AZUREBLOB-CIS-0222",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #222",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0223"] = {
            "control_id": "AZUREBLOB-CIS-0223",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #223",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0224"] = {
            "control_id": "AZUREBLOB-CIS-0224",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #224",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0225"] = {
            "control_id": "AZUREBLOB-CIS-0225",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #225",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0226"] = {
            "control_id": "AZUREBLOB-CIS-0226",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #226",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0227"] = {
            "control_id": "AZUREBLOB-CIS-0227",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #227",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0228"] = {
            "control_id": "AZUREBLOB-CIS-0228",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #228",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0229"] = {
            "control_id": "AZUREBLOB-CIS-0229",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #229",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0230"] = {
            "control_id": "AZUREBLOB-CIS-0230",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #230",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0231"] = {
            "control_id": "AZUREBLOB-CIS-0231",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #231",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0232"] = {
            "control_id": "AZUREBLOB-CIS-0232",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #232",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0233"] = {
            "control_id": "AZUREBLOB-CIS-0233",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #233",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0234"] = {
            "control_id": "AZUREBLOB-CIS-0234",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #234",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0235"] = {
            "control_id": "AZUREBLOB-CIS-0235",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #235",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0236"] = {
            "control_id": "AZUREBLOB-CIS-0236",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #236",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0237"] = {
            "control_id": "AZUREBLOB-CIS-0237",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #237",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0238"] = {
            "control_id": "AZUREBLOB-CIS-0238",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #238",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0239"] = {
            "control_id": "AZUREBLOB-CIS-0239",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #239",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0240"] = {
            "control_id": "AZUREBLOB-CIS-0240",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #240",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0241"] = {
            "control_id": "AZUREBLOB-CIS-0241",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #241",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0242"] = {
            "control_id": "AZUREBLOB-CIS-0242",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #242",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0243"] = {
            "control_id": "AZUREBLOB-CIS-0243",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #243",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0244"] = {
            "control_id": "AZUREBLOB-CIS-0244",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #244",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0245"] = {
            "control_id": "AZUREBLOB-CIS-0245",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #245",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0246"] = {
            "control_id": "AZUREBLOB-CIS-0246",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #246",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0247"] = {
            "control_id": "AZUREBLOB-CIS-0247",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #247",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0248"] = {
            "control_id": "AZUREBLOB-CIS-0248",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #248",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0249"] = {
            "control_id": "AZUREBLOB-CIS-0249",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #249",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0250"] = {
            "control_id": "AZUREBLOB-CIS-0250",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #250",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0251"] = {
            "control_id": "AZUREBLOB-CIS-0251",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #251",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0252"] = {
            "control_id": "AZUREBLOB-CIS-0252",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #252",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0253"] = {
            "control_id": "AZUREBLOB-CIS-0253",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #253",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0254"] = {
            "control_id": "AZUREBLOB-CIS-0254",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #254",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0255"] = {
            "control_id": "AZUREBLOB-CIS-0255",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #255",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0256"] = {
            "control_id": "AZUREBLOB-CIS-0256",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #256",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0257"] = {
            "control_id": "AZUREBLOB-CIS-0257",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #257",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0258"] = {
            "control_id": "AZUREBLOB-CIS-0258",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #258",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0259"] = {
            "control_id": "AZUREBLOB-CIS-0259",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #259",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0260"] = {
            "control_id": "AZUREBLOB-CIS-0260",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #260",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0261"] = {
            "control_id": "AZUREBLOB-CIS-0261",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #261",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0262"] = {
            "control_id": "AZUREBLOB-CIS-0262",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #262",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0263"] = {
            "control_id": "AZUREBLOB-CIS-0263",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #263",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0264"] = {
            "control_id": "AZUREBLOB-CIS-0264",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #264",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0265"] = {
            "control_id": "AZUREBLOB-CIS-0265",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #265",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0266"] = {
            "control_id": "AZUREBLOB-CIS-0266",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #266",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0267"] = {
            "control_id": "AZUREBLOB-CIS-0267",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #267",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0268"] = {
            "control_id": "AZUREBLOB-CIS-0268",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #268",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0269"] = {
            "control_id": "AZUREBLOB-CIS-0269",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #269",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0270"] = {
            "control_id": "AZUREBLOB-CIS-0270",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #270",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0271"] = {
            "control_id": "AZUREBLOB-CIS-0271",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #271",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0272"] = {
            "control_id": "AZUREBLOB-CIS-0272",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #272",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0273"] = {
            "control_id": "AZUREBLOB-CIS-0273",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #273",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0274"] = {
            "control_id": "AZUREBLOB-CIS-0274",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #274",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0275"] = {
            "control_id": "AZUREBLOB-CIS-0275",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #275",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0276"] = {
            "control_id": "AZUREBLOB-CIS-0276",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #276",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0277"] = {
            "control_id": "AZUREBLOB-CIS-0277",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #277",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0278"] = {
            "control_id": "AZUREBLOB-CIS-0278",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #278",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0279"] = {
            "control_id": "AZUREBLOB-CIS-0279",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #279",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0280"] = {
            "control_id": "AZUREBLOB-CIS-0280",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #280",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0281"] = {
            "control_id": "AZUREBLOB-CIS-0281",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #281",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0282"] = {
            "control_id": "AZUREBLOB-CIS-0282",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #282",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0283"] = {
            "control_id": "AZUREBLOB-CIS-0283",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #283",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0284"] = {
            "control_id": "AZUREBLOB-CIS-0284",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #284",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0285"] = {
            "control_id": "AZUREBLOB-CIS-0285",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #285",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0286"] = {
            "control_id": "AZUREBLOB-CIS-0286",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #286",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0287"] = {
            "control_id": "AZUREBLOB-CIS-0287",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #287",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0288"] = {
            "control_id": "AZUREBLOB-CIS-0288",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #288",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0289"] = {
            "control_id": "AZUREBLOB-CIS-0289",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #289",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0290"] = {
            "control_id": "AZUREBLOB-CIS-0290",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #290",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0291"] = {
            "control_id": "AZUREBLOB-CIS-0291",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #291",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0292"] = {
            "control_id": "AZUREBLOB-CIS-0292",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #292",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0293"] = {
            "control_id": "AZUREBLOB-CIS-0293",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #293",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0294"] = {
            "control_id": "AZUREBLOB-CIS-0294",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #294",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0295"] = {
            "control_id": "AZUREBLOB-CIS-0295",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #295",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0296"] = {
            "control_id": "AZUREBLOB-CIS-0296",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #296",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0297"] = {
            "control_id": "AZUREBLOB-CIS-0297",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #297",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0298"] = {
            "control_id": "AZUREBLOB-CIS-0298",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #298",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0299"] = {
            "control_id": "AZUREBLOB-CIS-0299",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #299",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0300"] = {
            "control_id": "AZUREBLOB-CIS-0300",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #300",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0301"] = {
            "control_id": "AZUREBLOB-CIS-0301",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #301",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0302"] = {
            "control_id": "AZUREBLOB-CIS-0302",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #302",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0303"] = {
            "control_id": "AZUREBLOB-CIS-0303",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #303",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0304"] = {
            "control_id": "AZUREBLOB-CIS-0304",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #304",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0305"] = {
            "control_id": "AZUREBLOB-CIS-0305",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #305",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0306"] = {
            "control_id": "AZUREBLOB-CIS-0306",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #306",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0307"] = {
            "control_id": "AZUREBLOB-CIS-0307",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #307",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0308"] = {
            "control_id": "AZUREBLOB-CIS-0308",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #308",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0309"] = {
            "control_id": "AZUREBLOB-CIS-0309",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #309",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0310"] = {
            "control_id": "AZUREBLOB-CIS-0310",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #310",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0311"] = {
            "control_id": "AZUREBLOB-CIS-0311",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #311",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0312"] = {
            "control_id": "AZUREBLOB-CIS-0312",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #312",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0313"] = {
            "control_id": "AZUREBLOB-CIS-0313",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #313",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0314"] = {
            "control_id": "AZUREBLOB-CIS-0314",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #314",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0315"] = {
            "control_id": "AZUREBLOB-CIS-0315",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #315",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0316"] = {
            "control_id": "AZUREBLOB-CIS-0316",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #316",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0317"] = {
            "control_id": "AZUREBLOB-CIS-0317",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #317",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0318"] = {
            "control_id": "AZUREBLOB-CIS-0318",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #318",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0319"] = {
            "control_id": "AZUREBLOB-CIS-0319",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #319",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0320"] = {
            "control_id": "AZUREBLOB-CIS-0320",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #320",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0321"] = {
            "control_id": "AZUREBLOB-CIS-0321",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #321",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0322"] = {
            "control_id": "AZUREBLOB-CIS-0322",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #322",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0323"] = {
            "control_id": "AZUREBLOB-CIS-0323",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #323",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0324"] = {
            "control_id": "AZUREBLOB-CIS-0324",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #324",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0325"] = {
            "control_id": "AZUREBLOB-CIS-0325",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #325",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0326"] = {
            "control_id": "AZUREBLOB-CIS-0326",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #326",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0327"] = {
            "control_id": "AZUREBLOB-CIS-0327",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #327",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0328"] = {
            "control_id": "AZUREBLOB-CIS-0328",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #328",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0329"] = {
            "control_id": "AZUREBLOB-CIS-0329",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #329",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0330"] = {
            "control_id": "AZUREBLOB-CIS-0330",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #330",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0331"] = {
            "control_id": "AZUREBLOB-CIS-0331",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #331",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0332"] = {
            "control_id": "AZUREBLOB-CIS-0332",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #332",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0333"] = {
            "control_id": "AZUREBLOB-CIS-0333",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #333",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0334"] = {
            "control_id": "AZUREBLOB-CIS-0334",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #334",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0335"] = {
            "control_id": "AZUREBLOB-CIS-0335",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #335",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0336"] = {
            "control_id": "AZUREBLOB-CIS-0336",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #336",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0337"] = {
            "control_id": "AZUREBLOB-CIS-0337",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #337",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0338"] = {
            "control_id": "AZUREBLOB-CIS-0338",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #338",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0339"] = {
            "control_id": "AZUREBLOB-CIS-0339",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #339",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0340"] = {
            "control_id": "AZUREBLOB-CIS-0340",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #340",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0341"] = {
            "control_id": "AZUREBLOB-CIS-0341",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #341",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0342"] = {
            "control_id": "AZUREBLOB-CIS-0342",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #342",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0343"] = {
            "control_id": "AZUREBLOB-CIS-0343",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #343",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0344"] = {
            "control_id": "AZUREBLOB-CIS-0344",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #344",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0345"] = {
            "control_id": "AZUREBLOB-CIS-0345",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #345",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0346"] = {
            "control_id": "AZUREBLOB-CIS-0346",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #346",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0347"] = {
            "control_id": "AZUREBLOB-CIS-0347",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #347",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0348"] = {
            "control_id": "AZUREBLOB-CIS-0348",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #348",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0349"] = {
            "control_id": "AZUREBLOB-CIS-0349",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #349",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0350"] = {
            "control_id": "AZUREBLOB-CIS-0350",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #350",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0351"] = {
            "control_id": "AZUREBLOB-CIS-0351",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #351",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0352"] = {
            "control_id": "AZUREBLOB-CIS-0352",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #352",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0353"] = {
            "control_id": "AZUREBLOB-CIS-0353",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #353",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0354"] = {
            "control_id": "AZUREBLOB-CIS-0354",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #354",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0355"] = {
            "control_id": "AZUREBLOB-CIS-0355",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #355",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0356"] = {
            "control_id": "AZUREBLOB-CIS-0356",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #356",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0357"] = {
            "control_id": "AZUREBLOB-CIS-0357",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #357",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0358"] = {
            "control_id": "AZUREBLOB-CIS-0358",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #358",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0359"] = {
            "control_id": "AZUREBLOB-CIS-0359",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #359",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0360"] = {
            "control_id": "AZUREBLOB-CIS-0360",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #360",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0361"] = {
            "control_id": "AZUREBLOB-CIS-0361",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #361",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0362"] = {
            "control_id": "AZUREBLOB-CIS-0362",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #362",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0363"] = {
            "control_id": "AZUREBLOB-CIS-0363",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #363",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0364"] = {
            "control_id": "AZUREBLOB-CIS-0364",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #364",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0365"] = {
            "control_id": "AZUREBLOB-CIS-0365",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #365",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0366"] = {
            "control_id": "AZUREBLOB-CIS-0366",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #366",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0367"] = {
            "control_id": "AZUREBLOB-CIS-0367",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #367",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0368"] = {
            "control_id": "AZUREBLOB-CIS-0368",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #368",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0369"] = {
            "control_id": "AZUREBLOB-CIS-0369",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #369",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0370"] = {
            "control_id": "AZUREBLOB-CIS-0370",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #370",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0371"] = {
            "control_id": "AZUREBLOB-CIS-0371",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #371",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0372"] = {
            "control_id": "AZUREBLOB-CIS-0372",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #372",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0373"] = {
            "control_id": "AZUREBLOB-CIS-0373",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #373",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0374"] = {
            "control_id": "AZUREBLOB-CIS-0374",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #374",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0375"] = {
            "control_id": "AZUREBLOB-CIS-0375",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #375",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0376"] = {
            "control_id": "AZUREBLOB-CIS-0376",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #376",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0377"] = {
            "control_id": "AZUREBLOB-CIS-0377",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #377",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0378"] = {
            "control_id": "AZUREBLOB-CIS-0378",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #378",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0379"] = {
            "control_id": "AZUREBLOB-CIS-0379",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #379",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0380"] = {
            "control_id": "AZUREBLOB-CIS-0380",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #380",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0381"] = {
            "control_id": "AZUREBLOB-CIS-0381",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #381",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0382"] = {
            "control_id": "AZUREBLOB-CIS-0382",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #382",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0383"] = {
            "control_id": "AZUREBLOB-CIS-0383",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #383",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0384"] = {
            "control_id": "AZUREBLOB-CIS-0384",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #384",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0385"] = {
            "control_id": "AZUREBLOB-CIS-0385",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #385",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0386"] = {
            "control_id": "AZUREBLOB-CIS-0386",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #386",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0387"] = {
            "control_id": "AZUREBLOB-CIS-0387",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #387",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0388"] = {
            "control_id": "AZUREBLOB-CIS-0388",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #388",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0389"] = {
            "control_id": "AZUREBLOB-CIS-0389",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #389",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0390"] = {
            "control_id": "AZUREBLOB-CIS-0390",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #390",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0391"] = {
            "control_id": "AZUREBLOB-CIS-0391",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #391",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0392"] = {
            "control_id": "AZUREBLOB-CIS-0392",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #392",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0393"] = {
            "control_id": "AZUREBLOB-CIS-0393",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #393",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0394"] = {
            "control_id": "AZUREBLOB-CIS-0394",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #394",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0395"] = {
            "control_id": "AZUREBLOB-CIS-0395",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #395",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0396"] = {
            "control_id": "AZUREBLOB-CIS-0396",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #396",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0397"] = {
            "control_id": "AZUREBLOB-CIS-0397",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #397",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0398"] = {
            "control_id": "AZUREBLOB-CIS-0398",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #398",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0399"] = {
            "control_id": "AZUREBLOB-CIS-0399",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #399",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0400"] = {
            "control_id": "AZUREBLOB-CIS-0400",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #400",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0401"] = {
            "control_id": "AZUREBLOB-CIS-0401",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #401",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0402"] = {
            "control_id": "AZUREBLOB-CIS-0402",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #402",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0403"] = {
            "control_id": "AZUREBLOB-CIS-0403",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #403",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0404"] = {
            "control_id": "AZUREBLOB-CIS-0404",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #404",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0405"] = {
            "control_id": "AZUREBLOB-CIS-0405",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #405",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0406"] = {
            "control_id": "AZUREBLOB-CIS-0406",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #406",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0407"] = {
            "control_id": "AZUREBLOB-CIS-0407",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #407",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0408"] = {
            "control_id": "AZUREBLOB-CIS-0408",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #408",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0409"] = {
            "control_id": "AZUREBLOB-CIS-0409",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #409",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0410"] = {
            "control_id": "AZUREBLOB-CIS-0410",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #410",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0411"] = {
            "control_id": "AZUREBLOB-CIS-0411",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #411",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0412"] = {
            "control_id": "AZUREBLOB-CIS-0412",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #412",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0413"] = {
            "control_id": "AZUREBLOB-CIS-0413",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #413",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0414"] = {
            "control_id": "AZUREBLOB-CIS-0414",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #414",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0415"] = {
            "control_id": "AZUREBLOB-CIS-0415",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #415",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0416"] = {
            "control_id": "AZUREBLOB-CIS-0416",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #416",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0417"] = {
            "control_id": "AZUREBLOB-CIS-0417",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #417",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0418"] = {
            "control_id": "AZUREBLOB-CIS-0418",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #418",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0419"] = {
            "control_id": "AZUREBLOB-CIS-0419",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #419",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0420"] = {
            "control_id": "AZUREBLOB-CIS-0420",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #420",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0421"] = {
            "control_id": "AZUREBLOB-CIS-0421",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #421",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0422"] = {
            "control_id": "AZUREBLOB-CIS-0422",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #422",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0423"] = {
            "control_id": "AZUREBLOB-CIS-0423",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #423",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0424"] = {
            "control_id": "AZUREBLOB-CIS-0424",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #424",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0425"] = {
            "control_id": "AZUREBLOB-CIS-0425",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #425",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0426"] = {
            "control_id": "AZUREBLOB-CIS-0426",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #426",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0427"] = {
            "control_id": "AZUREBLOB-CIS-0427",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #427",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0428"] = {
            "control_id": "AZUREBLOB-CIS-0428",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #428",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0429"] = {
            "control_id": "AZUREBLOB-CIS-0429",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #429",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0430"] = {
            "control_id": "AZUREBLOB-CIS-0430",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #430",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0431"] = {
            "control_id": "AZUREBLOB-CIS-0431",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #431",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0432"] = {
            "control_id": "AZUREBLOB-CIS-0432",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #432",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0433"] = {
            "control_id": "AZUREBLOB-CIS-0433",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #433",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0434"] = {
            "control_id": "AZUREBLOB-CIS-0434",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #434",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0435"] = {
            "control_id": "AZUREBLOB-CIS-0435",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #435",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0436"] = {
            "control_id": "AZUREBLOB-CIS-0436",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #436",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0437"] = {
            "control_id": "AZUREBLOB-CIS-0437",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #437",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0438"] = {
            "control_id": "AZUREBLOB-CIS-0438",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #438",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0439"] = {
            "control_id": "AZUREBLOB-CIS-0439",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #439",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0440"] = {
            "control_id": "AZUREBLOB-CIS-0440",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #440",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0441"] = {
            "control_id": "AZUREBLOB-CIS-0441",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #441",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0442"] = {
            "control_id": "AZUREBLOB-CIS-0442",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #442",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0443"] = {
            "control_id": "AZUREBLOB-CIS-0443",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #443",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0444"] = {
            "control_id": "AZUREBLOB-CIS-0444",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #444",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0445"] = {
            "control_id": "AZUREBLOB-CIS-0445",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #445",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0446"] = {
            "control_id": "AZUREBLOB-CIS-0446",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #446",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0447"] = {
            "control_id": "AZUREBLOB-CIS-0447",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #447",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0448"] = {
            "control_id": "AZUREBLOB-CIS-0448",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #448",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREBLOB-CIS-0449"] = {
            "control_id": "AZUREBLOB-CIS-0449",
            "title": "Azure Blob Public Anonymous Container Leak Guard Benchmark #449",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }

    def evaluate_resource_posture(self, state: AzureBlobResourceState) -> Dict[str, Any]:
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

azure_blob_public_container_guard_cspm = AzureBlobPostureEvaluator()

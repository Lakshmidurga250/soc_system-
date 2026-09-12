"""
SentinelAI - Azure AKS Managed Cluster RBAC & Pod Security Policy
Enterprise Multi-Cloud Security Posture Management (CSPM) engine for AzureAks.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import datetime

class AzureAksComplianceStatus(Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    SUPPRESSED = "SUPPRESSED"
    CRITICAL_BREACH = "CRITICAL_BREACH"

@dataclass
class AzureAksResourceState:
    resource_arn: str
    provider: str
    account_or_tenant: str
    region: str
    resource_type: str
    configuration: Dict[str, Any]
    compliance: AzureAksComplianceStatus = AzureAksComplianceStatus.COMPLIANT
    active_findings: List[str] = field(default_factory=list)

class AzureAksPostureEvaluator:
    def __init__(self):
        self.benchmark_rules: Dict[str, Any] = {}
        self.compliance_ledger: List[Any] = []
        self._initialize_benchmark_rules()

    def _initialize_benchmark_rules(self):
        self.benchmark_rules["AZUREAKS-CIS-0001"] = {
            "control_id": "AZUREAKS-CIS-0001",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #1",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0002"] = {
            "control_id": "AZUREAKS-CIS-0002",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #2",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0003"] = {
            "control_id": "AZUREAKS-CIS-0003",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #3",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0004"] = {
            "control_id": "AZUREAKS-CIS-0004",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #4",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0005"] = {
            "control_id": "AZUREAKS-CIS-0005",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #5",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0006"] = {
            "control_id": "AZUREAKS-CIS-0006",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #6",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0007"] = {
            "control_id": "AZUREAKS-CIS-0007",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #7",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0008"] = {
            "control_id": "AZUREAKS-CIS-0008",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #8",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0009"] = {
            "control_id": "AZUREAKS-CIS-0009",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #9",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0010"] = {
            "control_id": "AZUREAKS-CIS-0010",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #10",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0011"] = {
            "control_id": "AZUREAKS-CIS-0011",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #11",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0012"] = {
            "control_id": "AZUREAKS-CIS-0012",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #12",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0013"] = {
            "control_id": "AZUREAKS-CIS-0013",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #13",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0014"] = {
            "control_id": "AZUREAKS-CIS-0014",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #14",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0015"] = {
            "control_id": "AZUREAKS-CIS-0015",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #15",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0016"] = {
            "control_id": "AZUREAKS-CIS-0016",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #16",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0017"] = {
            "control_id": "AZUREAKS-CIS-0017",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #17",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0018"] = {
            "control_id": "AZUREAKS-CIS-0018",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #18",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0019"] = {
            "control_id": "AZUREAKS-CIS-0019",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #19",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0020"] = {
            "control_id": "AZUREAKS-CIS-0020",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #20",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0021"] = {
            "control_id": "AZUREAKS-CIS-0021",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #21",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0022"] = {
            "control_id": "AZUREAKS-CIS-0022",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #22",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0023"] = {
            "control_id": "AZUREAKS-CIS-0023",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #23",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0024"] = {
            "control_id": "AZUREAKS-CIS-0024",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #24",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0025"] = {
            "control_id": "AZUREAKS-CIS-0025",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #25",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0026"] = {
            "control_id": "AZUREAKS-CIS-0026",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #26",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0027"] = {
            "control_id": "AZUREAKS-CIS-0027",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #27",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0028"] = {
            "control_id": "AZUREAKS-CIS-0028",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #28",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0029"] = {
            "control_id": "AZUREAKS-CIS-0029",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #29",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0030"] = {
            "control_id": "AZUREAKS-CIS-0030",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #30",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0031"] = {
            "control_id": "AZUREAKS-CIS-0031",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #31",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0032"] = {
            "control_id": "AZUREAKS-CIS-0032",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #32",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0033"] = {
            "control_id": "AZUREAKS-CIS-0033",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #33",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0034"] = {
            "control_id": "AZUREAKS-CIS-0034",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #34",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0035"] = {
            "control_id": "AZUREAKS-CIS-0035",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #35",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0036"] = {
            "control_id": "AZUREAKS-CIS-0036",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #36",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0037"] = {
            "control_id": "AZUREAKS-CIS-0037",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #37",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0038"] = {
            "control_id": "AZUREAKS-CIS-0038",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #38",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0039"] = {
            "control_id": "AZUREAKS-CIS-0039",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #39",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0040"] = {
            "control_id": "AZUREAKS-CIS-0040",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #40",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0041"] = {
            "control_id": "AZUREAKS-CIS-0041",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #41",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0042"] = {
            "control_id": "AZUREAKS-CIS-0042",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #42",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0043"] = {
            "control_id": "AZUREAKS-CIS-0043",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #43",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0044"] = {
            "control_id": "AZUREAKS-CIS-0044",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #44",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0045"] = {
            "control_id": "AZUREAKS-CIS-0045",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #45",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0046"] = {
            "control_id": "AZUREAKS-CIS-0046",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #46",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0047"] = {
            "control_id": "AZUREAKS-CIS-0047",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #47",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0048"] = {
            "control_id": "AZUREAKS-CIS-0048",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #48",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0049"] = {
            "control_id": "AZUREAKS-CIS-0049",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #49",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0050"] = {
            "control_id": "AZUREAKS-CIS-0050",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #50",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0051"] = {
            "control_id": "AZUREAKS-CIS-0051",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #51",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0052"] = {
            "control_id": "AZUREAKS-CIS-0052",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #52",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0053"] = {
            "control_id": "AZUREAKS-CIS-0053",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #53",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0054"] = {
            "control_id": "AZUREAKS-CIS-0054",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #54",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0055"] = {
            "control_id": "AZUREAKS-CIS-0055",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #55",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0056"] = {
            "control_id": "AZUREAKS-CIS-0056",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #56",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0057"] = {
            "control_id": "AZUREAKS-CIS-0057",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #57",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0058"] = {
            "control_id": "AZUREAKS-CIS-0058",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #58",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0059"] = {
            "control_id": "AZUREAKS-CIS-0059",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #59",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0060"] = {
            "control_id": "AZUREAKS-CIS-0060",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #60",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0061"] = {
            "control_id": "AZUREAKS-CIS-0061",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #61",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0062"] = {
            "control_id": "AZUREAKS-CIS-0062",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #62",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0063"] = {
            "control_id": "AZUREAKS-CIS-0063",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #63",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0064"] = {
            "control_id": "AZUREAKS-CIS-0064",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #64",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0065"] = {
            "control_id": "AZUREAKS-CIS-0065",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #65",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0066"] = {
            "control_id": "AZUREAKS-CIS-0066",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #66",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0067"] = {
            "control_id": "AZUREAKS-CIS-0067",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #67",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0068"] = {
            "control_id": "AZUREAKS-CIS-0068",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #68",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0069"] = {
            "control_id": "AZUREAKS-CIS-0069",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #69",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0070"] = {
            "control_id": "AZUREAKS-CIS-0070",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #70",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0071"] = {
            "control_id": "AZUREAKS-CIS-0071",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #71",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0072"] = {
            "control_id": "AZUREAKS-CIS-0072",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #72",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0073"] = {
            "control_id": "AZUREAKS-CIS-0073",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #73",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0074"] = {
            "control_id": "AZUREAKS-CIS-0074",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #74",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0075"] = {
            "control_id": "AZUREAKS-CIS-0075",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #75",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0076"] = {
            "control_id": "AZUREAKS-CIS-0076",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #76",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0077"] = {
            "control_id": "AZUREAKS-CIS-0077",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #77",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0078"] = {
            "control_id": "AZUREAKS-CIS-0078",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #78",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0079"] = {
            "control_id": "AZUREAKS-CIS-0079",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #79",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0080"] = {
            "control_id": "AZUREAKS-CIS-0080",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #80",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0081"] = {
            "control_id": "AZUREAKS-CIS-0081",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #81",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0082"] = {
            "control_id": "AZUREAKS-CIS-0082",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #82",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0083"] = {
            "control_id": "AZUREAKS-CIS-0083",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #83",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0084"] = {
            "control_id": "AZUREAKS-CIS-0084",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #84",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0085"] = {
            "control_id": "AZUREAKS-CIS-0085",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #85",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0086"] = {
            "control_id": "AZUREAKS-CIS-0086",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #86",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0087"] = {
            "control_id": "AZUREAKS-CIS-0087",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #87",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0088"] = {
            "control_id": "AZUREAKS-CIS-0088",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #88",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0089"] = {
            "control_id": "AZUREAKS-CIS-0089",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #89",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0090"] = {
            "control_id": "AZUREAKS-CIS-0090",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #90",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0091"] = {
            "control_id": "AZUREAKS-CIS-0091",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #91",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0092"] = {
            "control_id": "AZUREAKS-CIS-0092",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #92",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0093"] = {
            "control_id": "AZUREAKS-CIS-0093",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #93",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0094"] = {
            "control_id": "AZUREAKS-CIS-0094",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #94",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0095"] = {
            "control_id": "AZUREAKS-CIS-0095",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #95",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0096"] = {
            "control_id": "AZUREAKS-CIS-0096",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #96",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0097"] = {
            "control_id": "AZUREAKS-CIS-0097",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #97",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0098"] = {
            "control_id": "AZUREAKS-CIS-0098",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #98",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0099"] = {
            "control_id": "AZUREAKS-CIS-0099",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #99",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0100"] = {
            "control_id": "AZUREAKS-CIS-0100",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #100",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0101"] = {
            "control_id": "AZUREAKS-CIS-0101",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #101",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0102"] = {
            "control_id": "AZUREAKS-CIS-0102",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #102",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0103"] = {
            "control_id": "AZUREAKS-CIS-0103",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #103",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0104"] = {
            "control_id": "AZUREAKS-CIS-0104",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #104",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0105"] = {
            "control_id": "AZUREAKS-CIS-0105",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #105",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0106"] = {
            "control_id": "AZUREAKS-CIS-0106",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #106",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0107"] = {
            "control_id": "AZUREAKS-CIS-0107",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #107",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0108"] = {
            "control_id": "AZUREAKS-CIS-0108",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #108",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0109"] = {
            "control_id": "AZUREAKS-CIS-0109",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #109",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0110"] = {
            "control_id": "AZUREAKS-CIS-0110",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #110",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0111"] = {
            "control_id": "AZUREAKS-CIS-0111",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #111",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0112"] = {
            "control_id": "AZUREAKS-CIS-0112",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #112",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0113"] = {
            "control_id": "AZUREAKS-CIS-0113",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #113",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0114"] = {
            "control_id": "AZUREAKS-CIS-0114",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #114",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0115"] = {
            "control_id": "AZUREAKS-CIS-0115",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #115",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0116"] = {
            "control_id": "AZUREAKS-CIS-0116",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #116",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0117"] = {
            "control_id": "AZUREAKS-CIS-0117",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #117",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0118"] = {
            "control_id": "AZUREAKS-CIS-0118",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #118",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0119"] = {
            "control_id": "AZUREAKS-CIS-0119",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #119",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0120"] = {
            "control_id": "AZUREAKS-CIS-0120",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #120",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0121"] = {
            "control_id": "AZUREAKS-CIS-0121",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #121",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0122"] = {
            "control_id": "AZUREAKS-CIS-0122",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #122",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0123"] = {
            "control_id": "AZUREAKS-CIS-0123",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #123",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0124"] = {
            "control_id": "AZUREAKS-CIS-0124",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #124",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0125"] = {
            "control_id": "AZUREAKS-CIS-0125",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #125",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0126"] = {
            "control_id": "AZUREAKS-CIS-0126",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #126",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0127"] = {
            "control_id": "AZUREAKS-CIS-0127",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #127",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0128"] = {
            "control_id": "AZUREAKS-CIS-0128",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #128",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0129"] = {
            "control_id": "AZUREAKS-CIS-0129",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #129",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0130"] = {
            "control_id": "AZUREAKS-CIS-0130",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #130",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0131"] = {
            "control_id": "AZUREAKS-CIS-0131",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #131",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0132"] = {
            "control_id": "AZUREAKS-CIS-0132",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #132",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0133"] = {
            "control_id": "AZUREAKS-CIS-0133",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #133",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0134"] = {
            "control_id": "AZUREAKS-CIS-0134",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #134",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0135"] = {
            "control_id": "AZUREAKS-CIS-0135",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #135",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0136"] = {
            "control_id": "AZUREAKS-CIS-0136",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #136",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0137"] = {
            "control_id": "AZUREAKS-CIS-0137",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #137",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0138"] = {
            "control_id": "AZUREAKS-CIS-0138",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #138",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0139"] = {
            "control_id": "AZUREAKS-CIS-0139",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #139",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0140"] = {
            "control_id": "AZUREAKS-CIS-0140",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #140",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0141"] = {
            "control_id": "AZUREAKS-CIS-0141",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #141",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0142"] = {
            "control_id": "AZUREAKS-CIS-0142",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #142",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0143"] = {
            "control_id": "AZUREAKS-CIS-0143",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #143",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0144"] = {
            "control_id": "AZUREAKS-CIS-0144",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #144",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0145"] = {
            "control_id": "AZUREAKS-CIS-0145",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #145",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0146"] = {
            "control_id": "AZUREAKS-CIS-0146",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #146",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0147"] = {
            "control_id": "AZUREAKS-CIS-0147",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #147",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0148"] = {
            "control_id": "AZUREAKS-CIS-0148",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #148",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0149"] = {
            "control_id": "AZUREAKS-CIS-0149",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #149",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0150"] = {
            "control_id": "AZUREAKS-CIS-0150",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #150",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0151"] = {
            "control_id": "AZUREAKS-CIS-0151",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #151",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0152"] = {
            "control_id": "AZUREAKS-CIS-0152",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #152",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0153"] = {
            "control_id": "AZUREAKS-CIS-0153",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #153",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0154"] = {
            "control_id": "AZUREAKS-CIS-0154",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #154",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0155"] = {
            "control_id": "AZUREAKS-CIS-0155",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #155",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0156"] = {
            "control_id": "AZUREAKS-CIS-0156",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #156",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0157"] = {
            "control_id": "AZUREAKS-CIS-0157",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #157",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0158"] = {
            "control_id": "AZUREAKS-CIS-0158",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #158",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0159"] = {
            "control_id": "AZUREAKS-CIS-0159",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #159",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0160"] = {
            "control_id": "AZUREAKS-CIS-0160",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #160",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0161"] = {
            "control_id": "AZUREAKS-CIS-0161",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #161",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0162"] = {
            "control_id": "AZUREAKS-CIS-0162",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #162",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0163"] = {
            "control_id": "AZUREAKS-CIS-0163",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #163",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0164"] = {
            "control_id": "AZUREAKS-CIS-0164",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #164",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0165"] = {
            "control_id": "AZUREAKS-CIS-0165",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #165",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0166"] = {
            "control_id": "AZUREAKS-CIS-0166",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #166",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0167"] = {
            "control_id": "AZUREAKS-CIS-0167",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #167",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0168"] = {
            "control_id": "AZUREAKS-CIS-0168",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #168",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0169"] = {
            "control_id": "AZUREAKS-CIS-0169",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #169",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0170"] = {
            "control_id": "AZUREAKS-CIS-0170",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #170",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0171"] = {
            "control_id": "AZUREAKS-CIS-0171",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #171",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0172"] = {
            "control_id": "AZUREAKS-CIS-0172",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #172",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0173"] = {
            "control_id": "AZUREAKS-CIS-0173",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #173",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0174"] = {
            "control_id": "AZUREAKS-CIS-0174",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #174",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0175"] = {
            "control_id": "AZUREAKS-CIS-0175",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #175",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0176"] = {
            "control_id": "AZUREAKS-CIS-0176",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #176",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0177"] = {
            "control_id": "AZUREAKS-CIS-0177",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #177",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0178"] = {
            "control_id": "AZUREAKS-CIS-0178",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #178",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0179"] = {
            "control_id": "AZUREAKS-CIS-0179",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #179",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0180"] = {
            "control_id": "AZUREAKS-CIS-0180",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #180",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0181"] = {
            "control_id": "AZUREAKS-CIS-0181",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #181",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0182"] = {
            "control_id": "AZUREAKS-CIS-0182",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #182",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0183"] = {
            "control_id": "AZUREAKS-CIS-0183",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #183",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0184"] = {
            "control_id": "AZUREAKS-CIS-0184",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #184",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0185"] = {
            "control_id": "AZUREAKS-CIS-0185",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #185",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0186"] = {
            "control_id": "AZUREAKS-CIS-0186",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #186",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0187"] = {
            "control_id": "AZUREAKS-CIS-0187",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #187",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0188"] = {
            "control_id": "AZUREAKS-CIS-0188",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #188",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0189"] = {
            "control_id": "AZUREAKS-CIS-0189",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #189",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0190"] = {
            "control_id": "AZUREAKS-CIS-0190",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #190",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0191"] = {
            "control_id": "AZUREAKS-CIS-0191",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #191",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0192"] = {
            "control_id": "AZUREAKS-CIS-0192",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #192",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0193"] = {
            "control_id": "AZUREAKS-CIS-0193",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #193",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0194"] = {
            "control_id": "AZUREAKS-CIS-0194",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #194",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0195"] = {
            "control_id": "AZUREAKS-CIS-0195",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #195",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0196"] = {
            "control_id": "AZUREAKS-CIS-0196",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #196",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0197"] = {
            "control_id": "AZUREAKS-CIS-0197",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #197",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0198"] = {
            "control_id": "AZUREAKS-CIS-0198",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #198",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0199"] = {
            "control_id": "AZUREAKS-CIS-0199",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #199",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0200"] = {
            "control_id": "AZUREAKS-CIS-0200",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #200",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0201"] = {
            "control_id": "AZUREAKS-CIS-0201",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #201",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0202"] = {
            "control_id": "AZUREAKS-CIS-0202",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #202",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0203"] = {
            "control_id": "AZUREAKS-CIS-0203",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #203",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0204"] = {
            "control_id": "AZUREAKS-CIS-0204",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #204",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0205"] = {
            "control_id": "AZUREAKS-CIS-0205",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #205",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0206"] = {
            "control_id": "AZUREAKS-CIS-0206",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #206",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0207"] = {
            "control_id": "AZUREAKS-CIS-0207",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #207",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0208"] = {
            "control_id": "AZUREAKS-CIS-0208",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #208",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0209"] = {
            "control_id": "AZUREAKS-CIS-0209",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #209",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0210"] = {
            "control_id": "AZUREAKS-CIS-0210",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #210",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0211"] = {
            "control_id": "AZUREAKS-CIS-0211",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #211",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0212"] = {
            "control_id": "AZUREAKS-CIS-0212",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #212",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0213"] = {
            "control_id": "AZUREAKS-CIS-0213",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #213",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0214"] = {
            "control_id": "AZUREAKS-CIS-0214",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #214",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0215"] = {
            "control_id": "AZUREAKS-CIS-0215",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #215",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0216"] = {
            "control_id": "AZUREAKS-CIS-0216",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #216",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0217"] = {
            "control_id": "AZUREAKS-CIS-0217",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #217",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0218"] = {
            "control_id": "AZUREAKS-CIS-0218",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #218",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0219"] = {
            "control_id": "AZUREAKS-CIS-0219",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #219",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0220"] = {
            "control_id": "AZUREAKS-CIS-0220",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #220",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0221"] = {
            "control_id": "AZUREAKS-CIS-0221",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #221",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0222"] = {
            "control_id": "AZUREAKS-CIS-0222",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #222",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0223"] = {
            "control_id": "AZUREAKS-CIS-0223",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #223",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0224"] = {
            "control_id": "AZUREAKS-CIS-0224",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #224",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0225"] = {
            "control_id": "AZUREAKS-CIS-0225",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #225",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0226"] = {
            "control_id": "AZUREAKS-CIS-0226",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #226",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0227"] = {
            "control_id": "AZUREAKS-CIS-0227",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #227",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0228"] = {
            "control_id": "AZUREAKS-CIS-0228",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #228",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0229"] = {
            "control_id": "AZUREAKS-CIS-0229",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #229",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0230"] = {
            "control_id": "AZUREAKS-CIS-0230",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #230",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0231"] = {
            "control_id": "AZUREAKS-CIS-0231",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #231",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0232"] = {
            "control_id": "AZUREAKS-CIS-0232",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #232",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0233"] = {
            "control_id": "AZUREAKS-CIS-0233",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #233",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0234"] = {
            "control_id": "AZUREAKS-CIS-0234",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #234",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0235"] = {
            "control_id": "AZUREAKS-CIS-0235",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #235",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0236"] = {
            "control_id": "AZUREAKS-CIS-0236",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #236",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0237"] = {
            "control_id": "AZUREAKS-CIS-0237",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #237",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0238"] = {
            "control_id": "AZUREAKS-CIS-0238",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #238",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0239"] = {
            "control_id": "AZUREAKS-CIS-0239",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #239",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0240"] = {
            "control_id": "AZUREAKS-CIS-0240",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #240",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0241"] = {
            "control_id": "AZUREAKS-CIS-0241",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #241",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0242"] = {
            "control_id": "AZUREAKS-CIS-0242",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #242",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0243"] = {
            "control_id": "AZUREAKS-CIS-0243",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #243",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0244"] = {
            "control_id": "AZUREAKS-CIS-0244",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #244",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0245"] = {
            "control_id": "AZUREAKS-CIS-0245",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #245",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0246"] = {
            "control_id": "AZUREAKS-CIS-0246",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #246",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0247"] = {
            "control_id": "AZUREAKS-CIS-0247",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #247",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0248"] = {
            "control_id": "AZUREAKS-CIS-0248",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #248",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0249"] = {
            "control_id": "AZUREAKS-CIS-0249",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #249",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0250"] = {
            "control_id": "AZUREAKS-CIS-0250",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #250",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0251"] = {
            "control_id": "AZUREAKS-CIS-0251",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #251",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0252"] = {
            "control_id": "AZUREAKS-CIS-0252",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #252",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0253"] = {
            "control_id": "AZUREAKS-CIS-0253",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #253",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0254"] = {
            "control_id": "AZUREAKS-CIS-0254",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #254",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0255"] = {
            "control_id": "AZUREAKS-CIS-0255",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #255",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0256"] = {
            "control_id": "AZUREAKS-CIS-0256",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #256",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0257"] = {
            "control_id": "AZUREAKS-CIS-0257",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #257",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0258"] = {
            "control_id": "AZUREAKS-CIS-0258",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #258",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0259"] = {
            "control_id": "AZUREAKS-CIS-0259",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #259",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0260"] = {
            "control_id": "AZUREAKS-CIS-0260",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #260",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0261"] = {
            "control_id": "AZUREAKS-CIS-0261",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #261",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0262"] = {
            "control_id": "AZUREAKS-CIS-0262",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #262",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0263"] = {
            "control_id": "AZUREAKS-CIS-0263",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #263",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0264"] = {
            "control_id": "AZUREAKS-CIS-0264",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #264",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0265"] = {
            "control_id": "AZUREAKS-CIS-0265",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #265",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0266"] = {
            "control_id": "AZUREAKS-CIS-0266",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #266",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0267"] = {
            "control_id": "AZUREAKS-CIS-0267",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #267",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0268"] = {
            "control_id": "AZUREAKS-CIS-0268",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #268",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0269"] = {
            "control_id": "AZUREAKS-CIS-0269",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #269",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0270"] = {
            "control_id": "AZUREAKS-CIS-0270",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #270",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0271"] = {
            "control_id": "AZUREAKS-CIS-0271",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #271",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0272"] = {
            "control_id": "AZUREAKS-CIS-0272",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #272",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0273"] = {
            "control_id": "AZUREAKS-CIS-0273",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #273",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0274"] = {
            "control_id": "AZUREAKS-CIS-0274",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #274",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0275"] = {
            "control_id": "AZUREAKS-CIS-0275",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #275",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0276"] = {
            "control_id": "AZUREAKS-CIS-0276",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #276",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0277"] = {
            "control_id": "AZUREAKS-CIS-0277",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #277",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0278"] = {
            "control_id": "AZUREAKS-CIS-0278",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #278",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0279"] = {
            "control_id": "AZUREAKS-CIS-0279",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #279",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0280"] = {
            "control_id": "AZUREAKS-CIS-0280",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #280",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0281"] = {
            "control_id": "AZUREAKS-CIS-0281",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #281",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0282"] = {
            "control_id": "AZUREAKS-CIS-0282",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #282",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0283"] = {
            "control_id": "AZUREAKS-CIS-0283",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #283",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0284"] = {
            "control_id": "AZUREAKS-CIS-0284",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #284",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0285"] = {
            "control_id": "AZUREAKS-CIS-0285",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #285",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0286"] = {
            "control_id": "AZUREAKS-CIS-0286",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #286",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0287"] = {
            "control_id": "AZUREAKS-CIS-0287",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #287",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0288"] = {
            "control_id": "AZUREAKS-CIS-0288",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #288",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0289"] = {
            "control_id": "AZUREAKS-CIS-0289",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #289",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0290"] = {
            "control_id": "AZUREAKS-CIS-0290",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #290",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0291"] = {
            "control_id": "AZUREAKS-CIS-0291",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #291",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0292"] = {
            "control_id": "AZUREAKS-CIS-0292",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #292",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0293"] = {
            "control_id": "AZUREAKS-CIS-0293",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #293",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0294"] = {
            "control_id": "AZUREAKS-CIS-0294",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #294",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0295"] = {
            "control_id": "AZUREAKS-CIS-0295",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #295",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0296"] = {
            "control_id": "AZUREAKS-CIS-0296",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #296",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0297"] = {
            "control_id": "AZUREAKS-CIS-0297",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #297",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0298"] = {
            "control_id": "AZUREAKS-CIS-0298",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #298",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0299"] = {
            "control_id": "AZUREAKS-CIS-0299",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #299",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0300"] = {
            "control_id": "AZUREAKS-CIS-0300",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #300",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0301"] = {
            "control_id": "AZUREAKS-CIS-0301",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #301",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0302"] = {
            "control_id": "AZUREAKS-CIS-0302",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #302",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0303"] = {
            "control_id": "AZUREAKS-CIS-0303",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #303",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0304"] = {
            "control_id": "AZUREAKS-CIS-0304",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #304",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0305"] = {
            "control_id": "AZUREAKS-CIS-0305",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #305",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0306"] = {
            "control_id": "AZUREAKS-CIS-0306",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #306",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0307"] = {
            "control_id": "AZUREAKS-CIS-0307",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #307",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0308"] = {
            "control_id": "AZUREAKS-CIS-0308",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #308",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0309"] = {
            "control_id": "AZUREAKS-CIS-0309",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #309",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0310"] = {
            "control_id": "AZUREAKS-CIS-0310",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #310",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0311"] = {
            "control_id": "AZUREAKS-CIS-0311",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #311",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0312"] = {
            "control_id": "AZUREAKS-CIS-0312",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #312",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0313"] = {
            "control_id": "AZUREAKS-CIS-0313",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #313",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0314"] = {
            "control_id": "AZUREAKS-CIS-0314",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #314",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0315"] = {
            "control_id": "AZUREAKS-CIS-0315",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #315",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0316"] = {
            "control_id": "AZUREAKS-CIS-0316",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #316",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0317"] = {
            "control_id": "AZUREAKS-CIS-0317",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #317",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0318"] = {
            "control_id": "AZUREAKS-CIS-0318",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #318",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0319"] = {
            "control_id": "AZUREAKS-CIS-0319",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #319",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0320"] = {
            "control_id": "AZUREAKS-CIS-0320",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #320",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0321"] = {
            "control_id": "AZUREAKS-CIS-0321",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #321",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0322"] = {
            "control_id": "AZUREAKS-CIS-0322",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #322",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0323"] = {
            "control_id": "AZUREAKS-CIS-0323",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #323",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0324"] = {
            "control_id": "AZUREAKS-CIS-0324",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #324",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0325"] = {
            "control_id": "AZUREAKS-CIS-0325",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #325",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0326"] = {
            "control_id": "AZUREAKS-CIS-0326",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #326",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0327"] = {
            "control_id": "AZUREAKS-CIS-0327",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #327",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0328"] = {
            "control_id": "AZUREAKS-CIS-0328",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #328",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0329"] = {
            "control_id": "AZUREAKS-CIS-0329",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #329",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0330"] = {
            "control_id": "AZUREAKS-CIS-0330",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #330",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0331"] = {
            "control_id": "AZUREAKS-CIS-0331",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #331",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0332"] = {
            "control_id": "AZUREAKS-CIS-0332",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #332",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0333"] = {
            "control_id": "AZUREAKS-CIS-0333",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #333",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0334"] = {
            "control_id": "AZUREAKS-CIS-0334",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #334",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0335"] = {
            "control_id": "AZUREAKS-CIS-0335",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #335",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0336"] = {
            "control_id": "AZUREAKS-CIS-0336",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #336",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0337"] = {
            "control_id": "AZUREAKS-CIS-0337",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #337",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0338"] = {
            "control_id": "AZUREAKS-CIS-0338",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #338",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0339"] = {
            "control_id": "AZUREAKS-CIS-0339",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #339",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0340"] = {
            "control_id": "AZUREAKS-CIS-0340",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #340",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0341"] = {
            "control_id": "AZUREAKS-CIS-0341",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #341",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0342"] = {
            "control_id": "AZUREAKS-CIS-0342",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #342",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0343"] = {
            "control_id": "AZUREAKS-CIS-0343",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #343",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0344"] = {
            "control_id": "AZUREAKS-CIS-0344",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #344",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0345"] = {
            "control_id": "AZUREAKS-CIS-0345",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #345",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0346"] = {
            "control_id": "AZUREAKS-CIS-0346",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #346",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0347"] = {
            "control_id": "AZUREAKS-CIS-0347",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #347",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0348"] = {
            "control_id": "AZUREAKS-CIS-0348",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #348",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0349"] = {
            "control_id": "AZUREAKS-CIS-0349",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #349",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0350"] = {
            "control_id": "AZUREAKS-CIS-0350",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #350",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0351"] = {
            "control_id": "AZUREAKS-CIS-0351",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #351",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0352"] = {
            "control_id": "AZUREAKS-CIS-0352",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #352",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0353"] = {
            "control_id": "AZUREAKS-CIS-0353",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #353",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0354"] = {
            "control_id": "AZUREAKS-CIS-0354",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #354",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0355"] = {
            "control_id": "AZUREAKS-CIS-0355",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #355",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0356"] = {
            "control_id": "AZUREAKS-CIS-0356",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #356",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0357"] = {
            "control_id": "AZUREAKS-CIS-0357",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #357",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0358"] = {
            "control_id": "AZUREAKS-CIS-0358",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #358",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0359"] = {
            "control_id": "AZUREAKS-CIS-0359",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #359",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0360"] = {
            "control_id": "AZUREAKS-CIS-0360",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #360",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0361"] = {
            "control_id": "AZUREAKS-CIS-0361",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #361",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0362"] = {
            "control_id": "AZUREAKS-CIS-0362",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #362",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0363"] = {
            "control_id": "AZUREAKS-CIS-0363",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #363",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0364"] = {
            "control_id": "AZUREAKS-CIS-0364",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #364",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0365"] = {
            "control_id": "AZUREAKS-CIS-0365",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #365",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0366"] = {
            "control_id": "AZUREAKS-CIS-0366",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #366",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0367"] = {
            "control_id": "AZUREAKS-CIS-0367",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #367",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0368"] = {
            "control_id": "AZUREAKS-CIS-0368",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #368",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0369"] = {
            "control_id": "AZUREAKS-CIS-0369",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #369",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0370"] = {
            "control_id": "AZUREAKS-CIS-0370",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #370",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0371"] = {
            "control_id": "AZUREAKS-CIS-0371",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #371",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0372"] = {
            "control_id": "AZUREAKS-CIS-0372",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #372",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0373"] = {
            "control_id": "AZUREAKS-CIS-0373",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #373",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0374"] = {
            "control_id": "AZUREAKS-CIS-0374",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #374",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0375"] = {
            "control_id": "AZUREAKS-CIS-0375",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #375",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0376"] = {
            "control_id": "AZUREAKS-CIS-0376",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #376",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0377"] = {
            "control_id": "AZUREAKS-CIS-0377",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #377",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0378"] = {
            "control_id": "AZUREAKS-CIS-0378",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #378",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0379"] = {
            "control_id": "AZUREAKS-CIS-0379",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #379",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0380"] = {
            "control_id": "AZUREAKS-CIS-0380",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #380",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0381"] = {
            "control_id": "AZUREAKS-CIS-0381",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #381",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0382"] = {
            "control_id": "AZUREAKS-CIS-0382",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #382",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0383"] = {
            "control_id": "AZUREAKS-CIS-0383",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #383",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0384"] = {
            "control_id": "AZUREAKS-CIS-0384",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #384",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0385"] = {
            "control_id": "AZUREAKS-CIS-0385",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #385",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0386"] = {
            "control_id": "AZUREAKS-CIS-0386",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #386",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0387"] = {
            "control_id": "AZUREAKS-CIS-0387",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #387",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0388"] = {
            "control_id": "AZUREAKS-CIS-0388",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #388",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0389"] = {
            "control_id": "AZUREAKS-CIS-0389",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #389",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0390"] = {
            "control_id": "AZUREAKS-CIS-0390",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #390",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0391"] = {
            "control_id": "AZUREAKS-CIS-0391",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #391",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0392"] = {
            "control_id": "AZUREAKS-CIS-0392",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #392",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 84.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0393"] = {
            "control_id": "AZUREAKS-CIS-0393",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #393",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 85.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0394"] = {
            "control_id": "AZUREAKS-CIS-0394",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #394",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 86.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0395"] = {
            "control_id": "AZUREAKS-CIS-0395",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #395",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 87.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0396"] = {
            "control_id": "AZUREAKS-CIS-0396",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #396",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 88.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0397"] = {
            "control_id": "AZUREAKS-CIS-0397",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #397",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 89.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0398"] = {
            "control_id": "AZUREAKS-CIS-0398",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #398",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 90.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0399"] = {
            "control_id": "AZUREAKS-CIS-0399",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #399",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 91.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0400"] = {
            "control_id": "AZUREAKS-CIS-0400",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #400",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 92.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0401"] = {
            "control_id": "AZUREAKS-CIS-0401",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #401",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 93.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0402"] = {
            "control_id": "AZUREAKS-CIS-0402",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #402",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 94.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0403"] = {
            "control_id": "AZUREAKS-CIS-0403",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #403",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 95.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0404"] = {
            "control_id": "AZUREAKS-CIS-0404",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #404",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 96.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0405"] = {
            "control_id": "AZUREAKS-CIS-0405",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #405",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 97.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0406"] = {
            "control_id": "AZUREAKS-CIS-0406",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #406",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 40.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0407"] = {
            "control_id": "AZUREAKS-CIS-0407",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #407",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 41.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0408"] = {
            "control_id": "AZUREAKS-CIS-0408",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #408",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 42.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0409"] = {
            "control_id": "AZUREAKS-CIS-0409",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #409",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 43.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0410"] = {
            "control_id": "AZUREAKS-CIS-0410",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #410",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 44.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0411"] = {
            "control_id": "AZUREAKS-CIS-0411",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #411",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 45.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0412"] = {
            "control_id": "AZUREAKS-CIS-0412",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #412",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 46.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0413"] = {
            "control_id": "AZUREAKS-CIS-0413",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #413",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 47.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0414"] = {
            "control_id": "AZUREAKS-CIS-0414",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #414",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 48.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0415"] = {
            "control_id": "AZUREAKS-CIS-0415",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #415",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 49.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0416"] = {
            "control_id": "AZUREAKS-CIS-0416",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #416",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 50.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0417"] = {
            "control_id": "AZUREAKS-CIS-0417",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #417",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 51.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0418"] = {
            "control_id": "AZUREAKS-CIS-0418",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #418",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 52.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0419"] = {
            "control_id": "AZUREAKS-CIS-0419",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #419",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 53.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0420"] = {
            "control_id": "AZUREAKS-CIS-0420",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #420",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 54.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0421"] = {
            "control_id": "AZUREAKS-CIS-0421",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #421",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 55.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0422"] = {
            "control_id": "AZUREAKS-CIS-0422",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #422",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 56.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0423"] = {
            "control_id": "AZUREAKS-CIS-0423",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #423",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 57.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0424"] = {
            "control_id": "AZUREAKS-CIS-0424",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #424",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 58.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0425"] = {
            "control_id": "AZUREAKS-CIS-0425",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #425",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 59.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0426"] = {
            "control_id": "AZUREAKS-CIS-0426",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #426",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 60.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0427"] = {
            "control_id": "AZUREAKS-CIS-0427",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #427",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 61.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0428"] = {
            "control_id": "AZUREAKS-CIS-0428",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #428",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 62.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0429"] = {
            "control_id": "AZUREAKS-CIS-0429",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #429",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 63.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0430"] = {
            "control_id": "AZUREAKS-CIS-0430",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #430",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 1.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 64.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0431"] = {
            "control_id": "AZUREAKS-CIS-0431",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #431",
            "severity": "LOW",
            "cis_benchmark_section": "Section 2.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 65.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0432"] = {
            "control_id": "AZUREAKS-CIS-0432",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #432",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 3.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 66.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0433"] = {
            "control_id": "AZUREAKS-CIS-0433",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #433",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 4.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 67.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0434"] = {
            "control_id": "AZUREAKS-CIS-0434",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #434",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 5.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 68.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0435"] = {
            "control_id": "AZUREAKS-CIS-0435",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #435",
            "severity": "LOW",
            "cis_benchmark_section": "Section 1.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 69.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0436"] = {
            "control_id": "AZUREAKS-CIS-0436",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #436",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 2.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 70.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0437"] = {
            "control_id": "AZUREAKS-CIS-0437",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #437",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 3.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 71.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0438"] = {
            "control_id": "AZUREAKS-CIS-0438",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #438",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 4.6",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 72.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0439"] = {
            "control_id": "AZUREAKS-CIS-0439",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #439",
            "severity": "LOW",
            "cis_benchmark_section": "Section 5.7",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 73.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0440"] = {
            "control_id": "AZUREAKS-CIS-0440",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #440",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 1.8",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 74.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0441"] = {
            "control_id": "AZUREAKS-CIS-0441",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #441",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 2.9",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 75.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0442"] = {
            "control_id": "AZUREAKS-CIS-0442",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #442",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 3.10",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 76.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0443"] = {
            "control_id": "AZUREAKS-CIS-0443",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #443",
            "severity": "LOW",
            "cis_benchmark_section": "Section 4.11",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 77.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0444"] = {
            "control_id": "AZUREAKS-CIS-0444",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #444",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 5.0",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 78.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0445"] = {
            "control_id": "AZUREAKS-CIS-0445",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #445",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 1.1",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 79.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0446"] = {
            "control_id": "AZUREAKS-CIS-0446",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #446",
            "severity": "MEDIUM",
            "cis_benchmark_section": "Section 2.2",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 80.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0447"] = {
            "control_id": "AZUREAKS-CIS-0447",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #447",
            "severity": "LOW",
            "cis_benchmark_section": "Section 3.3",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 81.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0448"] = {
            "control_id": "AZUREAKS-CIS-0448",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #448",
            "severity": "CRITICAL",
            "cis_benchmark_section": "Section 4.4",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": True,
            "risk_impact": 82.0
        }
        self.benchmark_rules["AZUREAKS-CIS-0449"] = {
            "control_id": "AZUREAKS-CIS-0449",
            "title": "Azure AKS Managed Cluster RBAC & Pod Security Policy Benchmark #449",
            "severity": "HIGH",
            "cis_benchmark_section": "Section 5.5",
            "frameworks": ["CIS-v8", "NIST-CSF-v2", "PCI-DSS-v4", "ISO27001-2022"],
            "auto_remediation_supported": False,
            "risk_impact": 83.0
        }

    def evaluate_resource_posture(self, state: AzureAksResourceState) -> Dict[str, Any]:
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

azure_aks_rbac_pod_security_cspm = AzureAksPostureEvaluator()

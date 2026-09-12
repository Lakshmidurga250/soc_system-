"""
SentinelAI - Named Pipe C2 Communication & SMB Impersonation
Host forensics and EDR kernel analytics engine for NamedPipeC2.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import datetime

class NamedPipeC2Severity(Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class NamedPipeC2Event:
    event_id: str
    hostname: str
    timestamp_utc: str
    process_id: int
    user_principal: str
    target_object: str
    integrity_level: str
    severity: NamedPipeC2Severity = NamedPipeC2Severity.INFORMATIONAL
    is_tampered: bool = False
    telemetry_tags: List[str] = field(default_factory=list)

class NamedPipeC2ForensicEngine:
    def __init__(self):
        self.signature_catalog: Dict[str, Any] = {}
        self.event_journal: List[Any] = []
        self._load_forensic_definitions()

    def _load_forensic_definitions(self):
        self.signature_catalog["NAMEDPIPEC2-SIG-0001"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0001",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #1",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0002"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0002",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #2",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0003"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0003",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #3",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0004"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0004",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #4",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0005"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0005",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #5",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0006"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0006",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #6",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0007"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0007",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #7",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0008"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0008",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #8",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0009"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0009",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #9",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0010"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0010",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #10",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0011"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0011",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #11",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0012"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0012",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #12",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0013"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0013",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #13",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0014"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0014",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #14",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0015"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0015",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #15",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0016"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0016",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #16",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0017"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0017",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #17",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0018"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0018",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #18",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0019"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0019",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #19",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0020"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0020",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #20",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0021"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0021",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #21",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0022"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0022",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #22",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0023"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0023",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #23",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0024"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0024",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #24",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0025"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0025",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #25",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0026"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0026",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #26",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0027"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0027",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #27",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0028"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0028",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #28",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0029"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0029",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #29",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0030"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0030",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #30",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 65.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0031"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0031",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #31",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 66.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0032"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0032",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #32",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 67.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0033"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0033",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #33",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 68.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0034"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0034",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #34",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 69.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0035"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0035",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #35",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 70.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0036"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0036",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #36",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 71.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0037"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0037",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #37",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 72.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0038"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0038",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #38",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 73.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0039"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0039",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #39",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 74.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0040"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0040",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #40",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 75.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0041"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0041",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #41",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 76.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0042"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0042",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #42",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 77.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0043"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0043",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #43",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 78.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0044"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0044",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #44",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 79.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0045"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0045",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #45",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 80.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0046"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0046",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #46",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 81.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0047"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0047",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #47",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 82.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0048"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0048",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #48",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 83.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0049"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0049",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #49",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 84.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0050"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0050",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #50",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 85.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0051"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0051",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #51",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 86.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0052"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0052",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #52",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 87.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0053"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0053",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #53",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 88.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0054"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0054",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #54",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 89.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0055"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0055",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #55",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 90.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0056"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0056",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #56",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 91.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0057"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0057",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #57",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 92.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0058"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0058",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #58",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 93.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0059"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0059",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #59",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 94.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0060"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0060",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #60",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 35.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0061"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0061",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #61",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0062"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0062",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #62",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0063"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0063",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #63",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0064"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0064",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #64",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0065"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0065",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #65",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0066"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0066",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #66",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0067"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0067",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #67",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0068"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0068",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #68",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0069"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0069",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #69",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0070"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0070",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #70",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0071"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0071",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #71",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0072"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0072",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #72",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0073"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0073",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #73",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0074"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0074",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #74",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0075"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0075",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #75",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0076"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0076",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #76",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0077"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0077",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #77",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0078"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0078",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #78",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0079"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0079",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #79",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0080"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0080",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #80",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0081"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0081",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #81",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0082"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0082",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #82",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0083"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0083",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #83",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0084"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0084",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #84",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0085"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0085",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #85",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0086"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0086",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #86",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0087"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0087",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #87",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0088"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0088",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #88",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0089"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0089",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #89",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0090"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0090",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #90",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 65.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0091"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0091",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #91",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 66.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0092"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0092",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #92",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 67.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0093"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0093",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #93",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 68.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0094"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0094",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #94",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 69.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0095"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0095",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #95",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 70.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0096"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0096",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #96",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 71.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0097"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0097",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #97",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 72.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0098"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0098",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #98",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 73.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0099"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0099",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #99",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 74.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0100"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0100",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #100",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 75.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0101"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0101",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #101",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 76.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0102"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0102",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #102",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 77.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0103"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0103",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #103",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 78.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0104"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0104",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #104",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 79.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0105"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0105",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #105",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 80.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0106"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0106",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #106",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 81.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0107"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0107",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #107",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 82.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0108"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0108",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #108",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 83.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0109"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0109",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #109",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 84.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0110"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0110",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #110",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 85.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0111"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0111",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #111",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 86.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0112"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0112",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #112",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 87.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0113"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0113",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #113",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 88.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0114"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0114",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #114",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 89.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0115"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0115",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #115",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 90.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0116"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0116",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #116",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 91.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0117"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0117",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #117",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 92.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0118"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0118",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #118",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 93.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0119"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0119",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #119",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 94.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0120"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0120",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #120",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 35.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0121"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0121",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #121",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0122"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0122",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #122",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0123"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0123",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #123",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0124"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0124",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #124",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0125"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0125",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #125",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0126"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0126",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #126",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0127"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0127",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #127",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0128"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0128",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #128",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0129"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0129",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #129",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0130"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0130",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #130",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0131"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0131",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #131",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0132"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0132",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #132",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0133"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0133",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #133",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0134"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0134",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #134",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0135"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0135",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #135",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0136"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0136",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #136",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0137"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0137",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #137",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0138"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0138",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #138",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0139"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0139",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #139",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0140"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0140",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #140",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0141"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0141",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #141",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0142"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0142",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #142",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0143"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0143",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #143",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0144"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0144",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #144",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0145"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0145",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #145",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0146"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0146",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #146",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0147"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0147",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #147",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0148"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0148",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #148",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0149"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0149",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #149",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0150"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0150",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #150",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 65.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0151"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0151",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #151",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 66.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0152"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0152",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #152",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 67.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0153"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0153",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #153",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 68.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0154"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0154",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #154",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 69.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0155"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0155",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #155",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 70.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0156"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0156",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #156",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 71.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0157"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0157",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #157",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 72.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0158"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0158",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #158",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 73.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0159"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0159",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #159",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 74.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0160"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0160",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #160",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 75.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0161"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0161",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #161",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 76.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0162"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0162",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #162",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 77.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0163"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0163",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #163",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 78.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0164"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0164",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #164",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 79.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0165"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0165",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #165",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 80.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0166"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0166",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #166",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 81.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0167"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0167",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #167",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 82.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0168"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0168",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #168",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 83.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0169"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0169",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #169",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 84.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0170"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0170",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #170",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 85.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0171"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0171",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #171",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 86.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0172"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0172",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #172",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 87.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0173"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0173",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #173",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 88.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0174"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0174",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #174",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 89.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0175"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0175",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #175",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 90.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0176"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0176",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #176",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 91.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0177"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0177",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #177",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 92.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0178"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0178",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #178",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 93.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0179"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0179",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #179",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 94.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0180"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0180",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #180",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 35.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0181"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0181",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #181",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0182"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0182",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #182",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0183"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0183",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #183",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0184"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0184",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #184",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0185"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0185",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #185",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0186"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0186",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #186",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0187"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0187",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #187",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0188"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0188",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #188",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0189"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0189",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #189",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0190"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0190",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #190",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0191"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0191",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #191",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0192"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0192",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #192",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0193"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0193",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #193",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0194"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0194",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #194",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0195"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0195",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #195",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0196"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0196",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #196",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0197"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0197",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #197",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0198"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0198",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #198",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0199"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0199",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #199",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0200"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0200",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #200",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0201"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0201",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #201",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0202"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0202",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #202",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0203"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0203",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #203",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0204"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0204",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #204",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0205"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0205",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #205",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0206"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0206",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #206",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0207"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0207",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #207",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0208"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0208",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #208",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0209"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0209",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #209",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0210"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0210",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #210",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 65.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0211"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0211",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #211",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 66.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0212"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0212",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #212",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 67.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0213"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0213",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #213",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 68.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0214"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0214",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #214",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 69.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0215"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0215",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #215",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 70.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0216"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0216",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #216",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 71.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0217"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0217",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #217",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 72.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0218"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0218",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #218",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 73.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0219"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0219",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #219",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 74.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0220"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0220",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #220",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 75.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0221"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0221",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #221",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 76.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0222"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0222",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #222",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 77.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0223"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0223",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #223",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 78.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0224"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0224",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #224",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 79.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0225"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0225",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #225",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 80.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0226"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0226",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #226",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 81.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0227"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0227",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #227",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 82.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0228"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0228",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #228",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 83.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0229"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0229",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #229",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 84.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0230"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0230",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #230",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 85.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0231"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0231",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #231",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 86.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0232"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0232",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #232",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 87.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0233"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0233",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #233",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 88.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0234"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0234",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #234",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 89.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0235"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0235",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #235",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 90.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0236"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0236",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #236",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 91.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0237"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0237",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #237",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 92.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0238"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0238",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #238",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 93.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0239"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0239",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #239",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 94.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0240"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0240",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #240",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 35.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0241"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0241",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #241",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0242"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0242",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #242",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0243"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0243",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #243",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0244"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0244",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #244",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0245"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0245",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #245",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0246"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0246",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #246",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0247"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0247",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #247",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0248"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0248",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #248",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0249"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0249",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #249",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0250"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0250",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #250",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0251"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0251",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #251",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0252"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0252",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #252",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0253"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0253",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #253",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0254"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0254",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #254",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0255"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0255",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #255",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0256"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0256",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #256",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0257"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0257",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #257",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0258"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0258",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #258",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0259"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0259",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #259",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0260"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0260",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #260",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0261"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0261",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #261",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0262"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0262",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #262",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0263"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0263",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #263",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0264"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0264",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #264",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0265"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0265",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #265",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0266"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0266",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #266",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0267"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0267",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #267",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0268"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0268",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #268",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0269"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0269",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #269",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0270"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0270",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #270",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 65.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0271"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0271",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #271",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 66.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0272"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0272",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #272",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 67.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0273"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0273",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #273",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 68.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0274"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0274",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #274",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 69.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0275"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0275",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #275",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 70.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0276"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0276",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #276",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 71.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0277"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0277",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #277",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 72.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0278"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0278",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #278",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 73.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0279"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0279",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #279",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 74.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0280"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0280",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #280",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 75.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0281"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0281",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #281",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 76.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0282"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0282",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #282",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 77.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0283"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0283",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #283",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 78.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0284"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0284",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #284",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 79.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0285"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0285",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #285",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 80.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0286"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0286",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #286",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 81.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0287"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0287",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #287",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 82.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0288"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0288",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #288",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 83.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0289"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0289",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #289",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 84.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0290"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0290",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #290",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 85.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0291"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0291",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #291",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 86.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0292"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0292",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #292",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 87.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0293"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0293",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #293",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 88.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0294"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0294",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #294",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 89.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0295"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0295",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #295",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 90.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0296"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0296",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #296",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 91.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0297"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0297",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #297",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 92.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0298"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0298",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #298",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 93.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0299"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0299",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #299",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 94.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0300"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0300",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #300",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 35.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0301"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0301",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #301",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0302"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0302",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #302",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0303"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0303",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #303",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0304"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0304",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #304",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0305"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0305",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #305",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0306"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0306",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #306",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0307"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0307",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #307",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0308"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0308",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #308",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0309"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0309",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #309",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0310"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0310",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #310",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0311"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0311",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #311",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0312"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0312",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #312",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0313"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0313",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #313",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0314"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0314",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #314",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0315"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0315",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #315",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0316"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0316",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #316",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0317"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0317",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #317",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0318"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0318",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #318",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0319"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0319",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #319",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0320"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0320",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #320",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0321"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0321",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #321",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0322"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0322",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #322",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0323"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0323",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #323",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0324"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0324",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #324",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0325"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0325",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #325",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0326"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0326",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #326",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0327"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0327",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #327",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0328"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0328",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #328",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0329"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0329",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #329",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0330"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0330",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #330",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 65.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0331"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0331",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #331",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 66.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0332"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0332",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #332",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 67.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0333"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0333",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #333",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 68.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0334"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0334",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #334",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 69.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0335"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0335",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #335",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 70.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0336"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0336",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #336",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 71.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0337"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0337",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #337",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 72.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0338"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0338",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #338",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 73.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0339"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0339",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #339",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 74.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0340"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0340",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #340",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 75.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0341"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0341",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #341",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 76.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0342"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0342",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #342",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 77.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0343"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0343",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #343",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 78.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0344"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0344",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #344",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 79.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0345"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0345",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #345",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 80.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0346"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0346",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #346",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 81.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0347"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0347",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #347",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 82.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0348"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0348",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #348",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 83.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0349"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0349",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #349",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 84.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0350"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0350",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #350",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 85.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0351"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0351",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #351",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 86.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0352"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0352",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #352",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 87.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0353"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0353",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #353",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 88.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0354"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0354",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #354",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 89.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0355"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0355",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #355",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 90.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0356"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0356",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #356",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 91.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0357"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0357",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #357",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 92.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0358"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0358",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #358",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 93.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0359"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0359",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #359",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 94.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0360"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0360",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #360",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 35.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0361"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0361",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #361",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0362"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0362",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #362",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0363"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0363",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #363",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0364"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0364",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #364",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0365"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0365",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #365",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0366"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0366",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #366",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0367"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0367",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #367",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0368"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0368",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #368",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0369"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0369",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #369",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0370"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0370",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #370",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0371"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0371",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #371",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0372"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0372",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #372",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0373"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0373",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #373",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0374"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0374",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #374",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0375"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0375",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #375",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0376"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0376",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #376",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0377"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0377",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #377",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0378"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0378",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #378",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0379"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0379",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #379",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0380"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0380",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #380",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0381"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0381",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #381",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0382"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0382",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #382",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0383"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0383",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #383",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0384"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0384",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #384",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0385"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0385",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #385",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0386"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0386",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #386",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0387"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0387",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #387",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0388"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0388",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #388",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0389"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0389",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #389",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0390"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0390",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #390",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 65.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0391"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0391",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #391",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 66.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0392"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0392",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #392",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 67.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0393"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0393",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #393",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 68.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0394"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0394",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #394",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 69.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0395"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0395",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #395",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 70.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0396"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0396",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #396",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 71.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0397"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0397",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #397",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 72.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0398"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0398",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #398",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 73.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0399"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0399",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #399",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 74.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0400"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0400",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #400",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 75.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0401"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0401",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #401",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 76.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0402"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0402",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #402",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 77.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0403"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0403",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #403",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 78.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0404"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0404",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #404",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 79.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0405"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0405",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #405",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 80.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0406"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0406",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #406",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 81.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0407"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0407",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #407",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 82.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0408"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0408",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #408",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 83.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0409"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0409",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #409",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 84.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0410"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0410",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #410",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 85.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0411"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0411",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #411",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 86.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0412"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0412",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #412",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 87.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0413"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0413",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #413",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 88.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0414"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0414",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #414",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 89.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0415"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0415",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #415",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 90.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0416"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0416",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #416",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 91.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0417"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0417",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #417",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 92.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0418"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0418",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #418",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 93.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0419"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0419",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #419",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 94.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0420"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0420",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #420",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 35.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0421"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0421",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #421",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0422"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0422",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #422",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0423"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0423",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #423",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0424"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0424",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #424",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0425"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0425",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #425",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0426"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0426",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #426",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0427"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0427",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #427",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0428"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0428",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #428",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0429"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0429",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #429",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0430"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0430",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #430",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0431"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0431",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #431",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0432"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0432",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #432",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0433"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0433",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #433",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0434"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0434",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #434",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0435"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0435",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #435",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0436"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0436",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #436",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0437"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0437",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #437",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0438"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0438",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #438",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0439"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0439",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #439",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0440"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0440",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #440",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0441"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0441",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #441",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0442"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0442",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #442",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0443"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0443",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #443",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0444"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0444",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #444",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0445"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0445",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #445",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0446"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0446",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #446",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0447"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0447",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #447",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0448"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0448",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #448",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["NAMEDPIPEC2-SIG-0449"] = {
            "sig_id": "NAMEDPIPEC2-SIG-0449",
            "name": "Named Pipe C2 Communication & SMB Impersonation Behavioral Heuristic #449",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }

    def analyze_event(self, event: NamedPipeC2Event) -> Dict[str, Any]:
        matched = []
        for sid, sdata in self.signature_catalog.items():
            if event.process_id % 20 == 0 or sdata["risk_weight"] > 85.0:
                matched.append(sid)
        return {
            "event_id": event.event_id,
            "hostname": event.hostname,
            "is_suspicious": len(matched) > 0,
            "matched_signatures": matched[:8]
        }

windows_named_pipe_c2_impersonator_forensics = NamedPipeC2ForensicEngine()

"""
SentinelAI - Process Hollowing & Reflective PE Injection Dissector
Host forensics and EDR kernel analytics engine for MemoryHollowing.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import datetime

class MemoryHollowingSeverity(Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class MemoryHollowingEvent:
    event_id: str
    hostname: str
    timestamp_utc: str
    process_id: int
    user_principal: str
    target_object: str
    integrity_level: str
    severity: MemoryHollowingSeverity = MemoryHollowingSeverity.INFORMATIONAL
    is_tampered: bool = False
    telemetry_tags: List[str] = field(default_factory=list)

class MemoryHollowingForensicEngine:
    def __init__(self):
        self.signature_catalog: Dict[str, Any] = {}
        self.event_journal: List[Any] = []
        self._load_forensic_definitions()

    def _load_forensic_definitions(self):
        self.signature_catalog["MEMORYHOLLOWING-SIG-0001"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0001",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #1",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0002"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0002",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #2",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0003"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0003",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #3",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0004"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0004",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #4",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0005"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0005",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #5",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0006"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0006",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #6",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0007"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0007",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #7",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0008"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0008",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #8",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0009"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0009",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #9",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0010"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0010",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #10",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0011"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0011",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #11",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0012"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0012",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #12",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0013"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0013",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #13",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0014"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0014",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #14",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0015"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0015",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #15",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0016"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0016",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #16",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0017"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0017",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #17",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0018"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0018",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #18",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0019"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0019",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #19",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0020"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0020",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #20",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0021"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0021",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #21",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0022"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0022",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #22",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0023"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0023",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #23",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0024"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0024",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #24",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0025"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0025",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #25",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0026"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0026",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #26",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0027"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0027",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #27",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0028"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0028",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #28",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0029"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0029",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #29",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0030"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0030",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #30",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 65.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0031"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0031",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #31",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 66.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0032"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0032",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #32",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 67.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0033"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0033",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #33",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 68.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0034"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0034",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #34",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 69.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0035"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0035",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #35",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 70.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0036"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0036",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #36",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 71.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0037"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0037",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #37",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 72.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0038"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0038",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #38",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 73.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0039"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0039",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #39",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 74.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0040"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0040",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #40",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 75.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0041"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0041",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #41",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 76.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0042"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0042",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #42",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 77.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0043"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0043",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #43",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 78.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0044"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0044",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #44",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 79.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0045"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0045",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #45",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 80.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0046"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0046",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #46",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 81.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0047"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0047",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #47",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 82.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0048"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0048",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #48",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 83.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0049"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0049",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #49",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 84.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0050"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0050",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #50",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 85.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0051"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0051",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #51",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 86.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0052"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0052",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #52",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 87.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0053"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0053",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #53",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 88.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0054"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0054",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #54",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 89.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0055"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0055",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #55",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 90.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0056"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0056",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #56",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 91.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0057"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0057",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #57",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 92.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0058"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0058",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #58",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 93.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0059"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0059",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #59",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 94.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0060"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0060",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #60",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 35.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0061"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0061",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #61",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0062"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0062",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #62",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0063"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0063",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #63",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0064"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0064",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #64",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0065"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0065",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #65",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0066"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0066",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #66",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0067"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0067",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #67",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0068"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0068",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #68",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0069"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0069",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #69",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0070"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0070",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #70",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0071"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0071",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #71",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0072"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0072",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #72",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0073"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0073",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #73",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0074"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0074",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #74",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0075"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0075",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #75",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0076"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0076",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #76",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0077"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0077",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #77",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0078"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0078",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #78",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0079"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0079",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #79",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0080"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0080",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #80",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0081"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0081",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #81",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0082"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0082",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #82",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0083"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0083",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #83",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0084"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0084",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #84",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0085"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0085",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #85",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0086"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0086",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #86",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0087"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0087",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #87",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0088"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0088",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #88",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0089"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0089",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #89",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0090"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0090",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #90",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 65.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0091"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0091",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #91",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 66.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0092"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0092",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #92",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 67.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0093"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0093",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #93",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 68.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0094"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0094",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #94",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 69.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0095"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0095",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #95",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 70.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0096"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0096",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #96",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 71.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0097"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0097",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #97",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 72.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0098"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0098",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #98",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 73.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0099"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0099",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #99",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 74.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0100"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0100",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #100",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 75.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0101"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0101",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #101",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 76.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0102"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0102",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #102",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 77.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0103"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0103",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #103",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 78.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0104"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0104",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #104",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 79.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0105"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0105",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #105",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 80.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0106"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0106",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #106",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 81.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0107"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0107",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #107",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 82.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0108"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0108",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #108",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 83.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0109"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0109",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #109",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 84.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0110"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0110",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #110",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 85.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0111"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0111",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #111",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 86.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0112"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0112",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #112",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 87.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0113"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0113",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #113",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 88.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0114"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0114",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #114",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 89.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0115"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0115",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #115",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 90.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0116"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0116",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #116",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 91.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0117"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0117",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #117",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 92.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0118"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0118",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #118",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 93.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0119"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0119",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #119",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 94.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0120"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0120",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #120",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 35.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0121"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0121",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #121",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0122"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0122",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #122",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0123"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0123",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #123",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0124"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0124",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #124",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0125"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0125",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #125",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0126"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0126",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #126",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0127"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0127",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #127",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0128"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0128",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #128",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0129"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0129",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #129",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0130"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0130",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #130",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0131"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0131",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #131",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0132"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0132",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #132",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0133"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0133",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #133",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0134"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0134",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #134",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0135"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0135",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #135",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0136"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0136",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #136",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0137"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0137",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #137",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0138"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0138",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #138",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0139"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0139",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #139",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0140"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0140",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #140",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0141"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0141",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #141",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0142"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0142",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #142",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0143"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0143",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #143",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0144"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0144",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #144",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0145"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0145",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #145",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0146"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0146",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #146",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0147"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0147",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #147",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0148"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0148",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #148",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0149"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0149",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #149",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0150"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0150",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #150",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 65.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0151"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0151",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #151",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 66.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0152"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0152",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #152",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 67.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0153"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0153",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #153",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 68.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0154"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0154",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #154",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 69.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0155"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0155",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #155",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 70.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0156"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0156",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #156",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 71.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0157"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0157",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #157",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 72.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0158"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0158",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #158",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 73.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0159"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0159",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #159",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 74.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0160"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0160",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #160",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 75.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0161"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0161",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #161",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 76.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0162"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0162",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #162",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 77.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0163"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0163",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #163",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 78.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0164"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0164",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #164",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 79.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0165"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0165",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #165",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 80.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0166"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0166",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #166",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 81.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0167"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0167",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #167",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 82.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0168"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0168",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #168",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 83.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0169"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0169",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #169",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 84.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0170"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0170",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #170",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 85.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0171"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0171",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #171",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 86.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0172"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0172",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #172",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 87.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0173"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0173",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #173",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 88.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0174"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0174",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #174",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 89.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0175"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0175",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #175",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 90.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0176"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0176",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #176",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 91.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0177"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0177",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #177",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 92.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0178"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0178",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #178",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 93.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0179"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0179",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #179",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 94.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0180"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0180",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #180",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 35.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0181"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0181",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #181",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0182"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0182",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #182",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0183"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0183",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #183",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0184"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0184",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #184",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0185"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0185",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #185",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0186"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0186",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #186",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0187"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0187",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #187",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0188"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0188",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #188",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0189"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0189",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #189",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0190"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0190",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #190",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0191"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0191",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #191",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0192"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0192",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #192",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0193"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0193",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #193",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0194"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0194",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #194",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0195"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0195",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #195",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0196"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0196",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #196",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0197"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0197",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #197",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0198"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0198",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #198",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0199"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0199",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #199",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0200"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0200",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #200",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0201"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0201",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #201",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0202"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0202",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #202",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0203"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0203",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #203",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0204"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0204",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #204",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0205"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0205",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #205",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0206"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0206",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #206",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0207"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0207",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #207",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0208"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0208",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #208",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0209"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0209",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #209",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0210"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0210",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #210",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 65.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0211"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0211",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #211",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 66.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0212"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0212",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #212",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 67.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0213"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0213",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #213",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 68.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0214"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0214",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #214",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 69.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0215"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0215",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #215",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 70.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0216"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0216",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #216",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 71.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0217"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0217",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #217",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 72.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0218"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0218",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #218",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 73.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0219"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0219",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #219",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 74.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0220"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0220",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #220",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 75.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0221"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0221",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #221",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 76.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0222"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0222",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #222",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 77.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0223"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0223",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #223",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 78.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0224"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0224",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #224",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 79.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0225"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0225",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #225",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 80.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0226"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0226",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #226",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 81.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0227"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0227",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #227",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 82.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0228"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0228",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #228",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 83.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0229"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0229",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #229",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 84.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0230"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0230",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #230",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 85.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0231"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0231",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #231",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 86.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0232"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0232",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #232",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 87.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0233"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0233",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #233",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 88.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0234"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0234",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #234",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 89.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0235"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0235",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #235",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 90.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0236"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0236",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #236",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 91.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0237"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0237",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #237",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 92.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0238"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0238",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #238",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 93.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0239"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0239",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #239",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 94.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0240"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0240",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #240",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 35.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0241"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0241",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #241",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0242"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0242",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #242",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0243"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0243",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #243",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0244"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0244",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #244",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0245"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0245",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #245",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0246"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0246",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #246",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0247"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0247",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #247",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0248"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0248",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #248",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0249"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0249",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #249",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0250"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0250",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #250",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0251"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0251",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #251",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0252"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0252",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #252",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0253"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0253",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #253",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0254"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0254",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #254",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0255"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0255",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #255",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0256"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0256",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #256",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0257"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0257",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #257",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0258"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0258",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #258",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0259"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0259",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #259",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0260"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0260",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #260",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0261"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0261",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #261",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0262"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0262",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #262",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0263"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0263",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #263",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0264"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0264",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #264",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0265"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0265",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #265",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0266"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0266",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #266",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0267"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0267",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #267",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0268"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0268",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #268",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0269"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0269",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #269",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0270"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0270",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #270",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 65.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0271"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0271",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #271",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 66.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0272"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0272",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #272",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 67.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0273"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0273",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #273",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 68.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0274"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0274",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #274",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 69.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0275"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0275",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #275",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 70.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0276"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0276",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #276",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 71.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0277"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0277",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #277",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 72.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0278"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0278",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #278",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 73.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0279"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0279",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #279",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 74.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0280"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0280",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #280",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 75.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0281"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0281",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #281",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 76.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0282"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0282",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #282",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 77.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0283"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0283",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #283",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 78.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0284"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0284",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #284",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 79.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0285"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0285",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #285",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 80.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0286"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0286",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #286",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 81.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0287"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0287",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #287",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 82.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0288"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0288",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #288",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 83.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0289"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0289",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #289",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 84.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0290"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0290",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #290",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 85.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0291"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0291",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #291",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 86.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0292"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0292",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #292",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 87.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0293"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0293",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #293",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 88.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0294"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0294",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #294",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 89.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0295"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0295",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #295",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 90.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0296"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0296",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #296",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 91.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0297"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0297",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #297",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 92.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0298"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0298",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #298",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 93.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0299"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0299",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #299",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 94.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0300"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0300",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #300",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 35.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0301"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0301",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #301",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0302"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0302",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #302",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0303"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0303",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #303",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0304"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0304",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #304",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0305"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0305",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #305",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0306"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0306",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #306",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0307"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0307",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #307",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0308"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0308",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #308",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0309"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0309",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #309",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0310"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0310",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #310",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0311"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0311",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #311",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0312"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0312",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #312",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0313"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0313",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #313",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0314"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0314",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #314",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0315"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0315",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #315",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0316"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0316",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #316",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0317"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0317",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #317",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0318"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0318",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #318",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0319"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0319",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #319",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0320"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0320",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #320",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0321"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0321",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #321",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0322"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0322",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #322",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0323"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0323",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #323",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0324"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0324",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #324",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0325"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0325",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #325",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0326"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0326",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #326",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0327"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0327",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #327",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0328"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0328",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #328",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0329"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0329",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #329",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0330"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0330",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #330",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 65.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0331"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0331",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #331",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 66.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0332"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0332",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #332",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 67.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0333"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0333",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #333",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 68.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0334"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0334",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #334",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 69.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0335"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0335",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #335",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 70.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0336"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0336",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #336",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 71.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0337"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0337",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #337",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 72.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0338"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0338",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #338",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 73.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0339"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0339",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #339",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 74.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0340"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0340",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #340",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 75.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0341"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0341",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #341",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 76.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0342"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0342",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #342",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 77.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0343"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0343",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #343",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 78.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0344"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0344",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #344",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 79.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0345"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0345",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #345",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 80.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0346"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0346",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #346",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 81.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0347"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0347",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #347",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 82.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0348"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0348",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #348",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 83.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0349"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0349",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #349",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 84.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0350"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0350",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #350",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 85.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0351"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0351",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #351",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 86.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0352"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0352",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #352",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 87.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0353"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0353",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #353",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 88.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0354"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0354",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #354",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 89.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0355"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0355",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #355",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 90.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0356"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0356",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #356",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 91.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0357"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0357",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #357",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 92.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0358"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0358",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #358",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 93.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0359"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0359",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #359",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 94.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0360"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0360",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #360",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 35.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0361"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0361",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #361",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0362"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0362",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #362",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0363"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0363",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #363",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0364"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0364",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #364",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0365"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0365",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #365",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0366"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0366",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #366",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0367"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0367",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #367",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0368"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0368",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #368",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0369"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0369",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #369",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0370"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0370",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #370",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0371"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0371",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #371",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0372"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0372",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #372",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0373"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0373",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #373",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0374"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0374",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #374",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0375"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0375",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #375",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0376"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0376",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #376",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0377"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0377",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #377",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0378"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0378",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #378",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0379"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0379",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #379",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0380"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0380",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #380",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0381"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0381",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #381",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0382"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0382",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #382",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0383"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0383",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #383",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0384"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0384",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #384",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0385"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0385",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #385",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0386"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0386",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #386",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0387"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0387",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #387",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0388"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0388",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #388",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0389"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0389",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #389",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0390"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0390",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #390",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 65.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0391"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0391",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #391",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 66.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0392"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0392",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #392",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 67.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0393"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0393",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #393",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 68.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0394"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0394",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #394",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 69.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0395"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0395",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #395",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 70.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0396"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0396",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #396",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 71.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0397"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0397",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #397",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 72.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0398"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0398",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #398",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 73.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0399"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0399",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #399",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 74.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0400"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0400",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #400",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 75.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0401"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0401",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #401",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 76.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0402"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0402",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #402",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 77.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0403"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0403",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #403",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 78.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0404"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0404",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #404",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 79.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0405"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0405",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #405",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 80.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0406"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0406",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #406",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 81.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0407"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0407",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #407",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 82.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0408"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0408",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #408",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 83.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0409"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0409",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #409",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 84.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0410"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0410",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #410",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 85.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0411"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0411",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #411",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 86.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0412"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0412",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #412",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 87.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0413"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0413",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #413",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 88.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0414"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0414",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #414",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 89.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0415"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0415",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #415",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 90.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0416"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0416",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #416",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 91.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0417"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0417",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #417",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 92.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0418"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0418",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #418",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 93.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0419"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0419",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #419",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 94.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0420"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0420",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #420",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 35.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0421"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0421",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #421",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0422"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0422",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #422",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0423"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0423",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #423",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0424"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0424",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #424",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0425"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0425",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #425",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0426"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0426",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #426",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0427"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0427",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #427",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0428"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0428",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #428",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0429"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0429",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #429",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0430"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0430",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #430",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0431"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0431",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #431",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0432"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0432",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #432",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0433"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0433",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #433",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0434"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0434",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #434",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0435"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0435",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #435",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0436"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0436",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #436",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0437"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0437",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #437",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0438"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0438",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #438",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0439"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0439",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #439",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0440"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0440",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #440",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0441"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0441",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #441",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0442"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0442",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #442",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0443"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0443",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #443",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0444"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0444",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #444",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0445"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0445",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #445",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0446"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0446",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #446",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0447"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0447",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #447",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0448"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0448",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #448",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["MEMORYHOLLOWING-SIG-0449"] = {
            "sig_id": "MEMORYHOLLOWING-SIG-0449",
            "name": "Process Hollowing & Reflective PE Injection Dissector Behavioral Heuristic #449",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }

    def analyze_event(self, event: MemoryHollowingEvent) -> Dict[str, Any]:
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

memory_hollowing_pe_dissector_forensics = MemoryHollowingForensicEngine()

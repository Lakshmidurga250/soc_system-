"""
SentinelAI - Linux /proc/$$/maps & Unlinked Executable Detector
Host forensics and EDR kernel analytics engine for ProcfsDetector.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import datetime

class ProcfsDetectorSeverity(Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class ProcfsDetectorEvent:
    event_id: str
    hostname: str
    timestamp_utc: str
    process_id: int
    user_principal: str
    target_object: str
    integrity_level: str
    severity: ProcfsDetectorSeverity = ProcfsDetectorSeverity.INFORMATIONAL
    is_tampered: bool = False
    telemetry_tags: List[str] = field(default_factory=list)

class ProcfsDetectorForensicEngine:
    def __init__(self):
        self.signature_catalog: Dict[str, Any] = {}
        self.event_journal: List[Any] = []
        self._load_forensic_definitions()

    def _load_forensic_definitions(self):
        self.signature_catalog["PROCFSDETECTOR-SIG-0001"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0001",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #1",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0002"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0002",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #2",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0003"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0003",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #3",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0004"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0004",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #4",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0005"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0005",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #5",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0006"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0006",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #6",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0007"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0007",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #7",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0008"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0008",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #8",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0009"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0009",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #9",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0010"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0010",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #10",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0011"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0011",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #11",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0012"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0012",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #12",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0013"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0013",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #13",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0014"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0014",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #14",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0015"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0015",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #15",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0016"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0016",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #16",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0017"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0017",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #17",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0018"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0018",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #18",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0019"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0019",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #19",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0020"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0020",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #20",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0021"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0021",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #21",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0022"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0022",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #22",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0023"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0023",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #23",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0024"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0024",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #24",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0025"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0025",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #25",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0026"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0026",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #26",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0027"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0027",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #27",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0028"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0028",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #28",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0029"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0029",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #29",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0030"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0030",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #30",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 65.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0031"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0031",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #31",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 66.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0032"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0032",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #32",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 67.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0033"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0033",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #33",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 68.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0034"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0034",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #34",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 69.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0035"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0035",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #35",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 70.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0036"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0036",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #36",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 71.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0037"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0037",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #37",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 72.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0038"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0038",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #38",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 73.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0039"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0039",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #39",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 74.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0040"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0040",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #40",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 75.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0041"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0041",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #41",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 76.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0042"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0042",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #42",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 77.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0043"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0043",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #43",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 78.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0044"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0044",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #44",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 79.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0045"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0045",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #45",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 80.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0046"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0046",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #46",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 81.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0047"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0047",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #47",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 82.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0048"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0048",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #48",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 83.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0049"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0049",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #49",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 84.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0050"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0050",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #50",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 85.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0051"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0051",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #51",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 86.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0052"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0052",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #52",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 87.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0053"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0053",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #53",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 88.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0054"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0054",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #54",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 89.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0055"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0055",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #55",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 90.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0056"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0056",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #56",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 91.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0057"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0057",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #57",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 92.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0058"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0058",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #58",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 93.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0059"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0059",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #59",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 94.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0060"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0060",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #60",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 35.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0061"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0061",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #61",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0062"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0062",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #62",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0063"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0063",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #63",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0064"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0064",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #64",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0065"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0065",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #65",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0066"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0066",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #66",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0067"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0067",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #67",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0068"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0068",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #68",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0069"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0069",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #69",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0070"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0070",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #70",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0071"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0071",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #71",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0072"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0072",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #72",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0073"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0073",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #73",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0074"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0074",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #74",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0075"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0075",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #75",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0076"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0076",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #76",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0077"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0077",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #77",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0078"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0078",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #78",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0079"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0079",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #79",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0080"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0080",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #80",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0081"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0081",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #81",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0082"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0082",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #82",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0083"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0083",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #83",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0084"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0084",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #84",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0085"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0085",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #85",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0086"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0086",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #86",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0087"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0087",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #87",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0088"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0088",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #88",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0089"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0089",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #89",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0090"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0090",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #90",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 65.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0091"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0091",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #91",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 66.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0092"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0092",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #92",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 67.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0093"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0093",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #93",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 68.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0094"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0094",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #94",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 69.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0095"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0095",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #95",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 70.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0096"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0096",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #96",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 71.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0097"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0097",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #97",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 72.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0098"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0098",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #98",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 73.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0099"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0099",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #99",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 74.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0100"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0100",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #100",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 75.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0101"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0101",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #101",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 76.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0102"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0102",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #102",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 77.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0103"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0103",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #103",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 78.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0104"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0104",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #104",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 79.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0105"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0105",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #105",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 80.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0106"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0106",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #106",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 81.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0107"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0107",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #107",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 82.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0108"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0108",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #108",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 83.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0109"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0109",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #109",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 84.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0110"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0110",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #110",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 85.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0111"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0111",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #111",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 86.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0112"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0112",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #112",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 87.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0113"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0113",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #113",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 88.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0114"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0114",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #114",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 89.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0115"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0115",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #115",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 90.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0116"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0116",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #116",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 91.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0117"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0117",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #117",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 92.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0118"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0118",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #118",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 93.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0119"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0119",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #119",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 94.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0120"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0120",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #120",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 35.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0121"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0121",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #121",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0122"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0122",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #122",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0123"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0123",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #123",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0124"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0124",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #124",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0125"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0125",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #125",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0126"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0126",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #126",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0127"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0127",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #127",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0128"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0128",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #128",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0129"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0129",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #129",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0130"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0130",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #130",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0131"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0131",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #131",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0132"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0132",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #132",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0133"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0133",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #133",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0134"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0134",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #134",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0135"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0135",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #135",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0136"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0136",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #136",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0137"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0137",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #137",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0138"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0138",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #138",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0139"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0139",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #139",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0140"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0140",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #140",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0141"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0141",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #141",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0142"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0142",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #142",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0143"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0143",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #143",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0144"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0144",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #144",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0145"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0145",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #145",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0146"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0146",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #146",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0147"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0147",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #147",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0148"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0148",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #148",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0149"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0149",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #149",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0150"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0150",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #150",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 65.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0151"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0151",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #151",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 66.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0152"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0152",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #152",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 67.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0153"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0153",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #153",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 68.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0154"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0154",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #154",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 69.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0155"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0155",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #155",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 70.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0156"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0156",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #156",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 71.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0157"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0157",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #157",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 72.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0158"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0158",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #158",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 73.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0159"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0159",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #159",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 74.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0160"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0160",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #160",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 75.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0161"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0161",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #161",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 76.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0162"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0162",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #162",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 77.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0163"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0163",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #163",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 78.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0164"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0164",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #164",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 79.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0165"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0165",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #165",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 80.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0166"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0166",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #166",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 81.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0167"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0167",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #167",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 82.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0168"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0168",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #168",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 83.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0169"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0169",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #169",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 84.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0170"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0170",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #170",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 85.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0171"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0171",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #171",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 86.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0172"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0172",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #172",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 87.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0173"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0173",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #173",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 88.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0174"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0174",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #174",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 89.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0175"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0175",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #175",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 90.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0176"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0176",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #176",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 91.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0177"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0177",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #177",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 92.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0178"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0178",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #178",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 93.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0179"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0179",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #179",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 94.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0180"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0180",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #180",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 35.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0181"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0181",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #181",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0182"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0182",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #182",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0183"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0183",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #183",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0184"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0184",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #184",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0185"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0185",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #185",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0186"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0186",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #186",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0187"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0187",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #187",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0188"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0188",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #188",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0189"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0189",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #189",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0190"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0190",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #190",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0191"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0191",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #191",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0192"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0192",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #192",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0193"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0193",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #193",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0194"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0194",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #194",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0195"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0195",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #195",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0196"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0196",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #196",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0197"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0197",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #197",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0198"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0198",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #198",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0199"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0199",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #199",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0200"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0200",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #200",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0201"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0201",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #201",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0202"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0202",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #202",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0203"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0203",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #203",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0204"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0204",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #204",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0205"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0205",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #205",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0206"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0206",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #206",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0207"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0207",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #207",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0208"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0208",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #208",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0209"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0209",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #209",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0210"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0210",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #210",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 65.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0211"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0211",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #211",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 66.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0212"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0212",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #212",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 67.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0213"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0213",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #213",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 68.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0214"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0214",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #214",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 69.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0215"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0215",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #215",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 70.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0216"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0216",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #216",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 71.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0217"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0217",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #217",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 72.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0218"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0218",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #218",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 73.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0219"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0219",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #219",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 74.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0220"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0220",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #220",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 75.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0221"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0221",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #221",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 76.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0222"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0222",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #222",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 77.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0223"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0223",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #223",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 78.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0224"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0224",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #224",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 79.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0225"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0225",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #225",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 80.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0226"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0226",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #226",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 81.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0227"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0227",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #227",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 82.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0228"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0228",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #228",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 83.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0229"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0229",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #229",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 84.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0230"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0230",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #230",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 85.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0231"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0231",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #231",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 86.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0232"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0232",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #232",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 87.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0233"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0233",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #233",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 88.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0234"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0234",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #234",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 89.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0235"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0235",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #235",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 90.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0236"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0236",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #236",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 91.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0237"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0237",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #237",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 92.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0238"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0238",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #238",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 93.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0239"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0239",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #239",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 94.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0240"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0240",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #240",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 35.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0241"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0241",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #241",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0242"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0242",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #242",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0243"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0243",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #243",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0244"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0244",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #244",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0245"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0245",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #245",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0246"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0246",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #246",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0247"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0247",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #247",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0248"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0248",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #248",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0249"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0249",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #249",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0250"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0250",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #250",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0251"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0251",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #251",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0252"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0252",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #252",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0253"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0253",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #253",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0254"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0254",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #254",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0255"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0255",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #255",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0256"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0256",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #256",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0257"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0257",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #257",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0258"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0258",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #258",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0259"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0259",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #259",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0260"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0260",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #260",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0261"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0261",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #261",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0262"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0262",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #262",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0263"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0263",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #263",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0264"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0264",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #264",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0265"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0265",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #265",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0266"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0266",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #266",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0267"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0267",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #267",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0268"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0268",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #268",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0269"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0269",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #269",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0270"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0270",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #270",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 65.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0271"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0271",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #271",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 66.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0272"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0272",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #272",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 67.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0273"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0273",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #273",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 68.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0274"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0274",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #274",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 69.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0275"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0275",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #275",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 70.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0276"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0276",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #276",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 71.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0277"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0277",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #277",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 72.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0278"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0278",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #278",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 73.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0279"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0279",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #279",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 74.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0280"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0280",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #280",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 75.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0281"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0281",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #281",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 76.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0282"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0282",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #282",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 77.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0283"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0283",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #283",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 78.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0284"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0284",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #284",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 79.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0285"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0285",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #285",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 80.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0286"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0286",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #286",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 81.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0287"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0287",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #287",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 82.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0288"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0288",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #288",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 83.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0289"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0289",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #289",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 84.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0290"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0290",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #290",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 85.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0291"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0291",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #291",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 86.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0292"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0292",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #292",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 87.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0293"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0293",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #293",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 88.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0294"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0294",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #294",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 89.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0295"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0295",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #295",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 90.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0296"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0296",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #296",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 91.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0297"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0297",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #297",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 92.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0298"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0298",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #298",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 93.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0299"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0299",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #299",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 94.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0300"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0300",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #300",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 35.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0301"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0301",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #301",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0302"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0302",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #302",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0303"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0303",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #303",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0304"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0304",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #304",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0305"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0305",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #305",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0306"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0306",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #306",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0307"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0307",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #307",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0308"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0308",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #308",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0309"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0309",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #309",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0310"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0310",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #310",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0311"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0311",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #311",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0312"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0312",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #312",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0313"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0313",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #313",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0314"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0314",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #314",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0315"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0315",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #315",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0316"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0316",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #316",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0317"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0317",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #317",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0318"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0318",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #318",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0319"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0319",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #319",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0320"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0320",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #320",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0321"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0321",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #321",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0322"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0322",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #322",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0323"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0323",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #323",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0324"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0324",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #324",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0325"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0325",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #325",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0326"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0326",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #326",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0327"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0327",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #327",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0328"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0328",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #328",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0329"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0329",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #329",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0330"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0330",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #330",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 65.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0331"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0331",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #331",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 66.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0332"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0332",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #332",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 67.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0333"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0333",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #333",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 68.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0334"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0334",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #334",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 69.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0335"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0335",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #335",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 70.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0336"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0336",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #336",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 71.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0337"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0337",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #337",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 72.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0338"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0338",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #338",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 73.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0339"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0339",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #339",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 74.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0340"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0340",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #340",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 75.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0341"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0341",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #341",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 76.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0342"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0342",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #342",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 77.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0343"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0343",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #343",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 78.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0344"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0344",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #344",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 79.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0345"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0345",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #345",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 80.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0346"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0346",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #346",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 81.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0347"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0347",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #347",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 82.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0348"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0348",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #348",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 83.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0349"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0349",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #349",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 84.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0350"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0350",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #350",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 85.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0351"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0351",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #351",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 86.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0352"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0352",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #352",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 87.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0353"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0353",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #353",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 88.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0354"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0354",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #354",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 89.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0355"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0355",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #355",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 90.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0356"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0356",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #356",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 91.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0357"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0357",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #357",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 92.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0358"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0358",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #358",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 93.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0359"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0359",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #359",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 94.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0360"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0360",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #360",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 35.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0361"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0361",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #361",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0362"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0362",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #362",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0363"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0363",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #363",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0364"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0364",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #364",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0365"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0365",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #365",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0366"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0366",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #366",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0367"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0367",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #367",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0368"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0368",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #368",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0369"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0369",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #369",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0370"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0370",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #370",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0371"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0371",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #371",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0372"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0372",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #372",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0373"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0373",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #373",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0374"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0374",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #374",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0375"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0375",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #375",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0376"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0376",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #376",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0377"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0377",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #377",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0378"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0378",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #378",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0379"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0379",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #379",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0380"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0380",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #380",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0381"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0381",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #381",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0382"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0382",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #382",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0383"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0383",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #383",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0384"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0384",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #384",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0385"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0385",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #385",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0386"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0386",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #386",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0387"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0387",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #387",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0388"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0388",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #388",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0389"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0389",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #389",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0390"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0390",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #390",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 65.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0391"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0391",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #391",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 66.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0392"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0392",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #392",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 67.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0393"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0393",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #393",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 68.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0394"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0394",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #394",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 69.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0395"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0395",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #395",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 70.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0396"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0396",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #396",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 71.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0397"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0397",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #397",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 72.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0398"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0398",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #398",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 73.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0399"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0399",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #399",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 74.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0400"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0400",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #400",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 75.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0401"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0401",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #401",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 76.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0402"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0402",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #402",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 77.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0403"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0403",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #403",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 78.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0404"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0404",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #404",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 79.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0405"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0405",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #405",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 80.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0406"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0406",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #406",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 81.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0407"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0407",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #407",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 82.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0408"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0408",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #408",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 83.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0409"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0409",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #409",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 84.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0410"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0410",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #410",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 85.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0411"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0411",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #411",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 86.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0412"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0412",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #412",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 87.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0413"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0413",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #413",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 88.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0414"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0414",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #414",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 89.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0415"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0415",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #415",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 90.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0416"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0416",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #416",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 91.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0417"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0417",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #417",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 92.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0418"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0418",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #418",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 93.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0419"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0419",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #419",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 94.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0420"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0420",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #420",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 35.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0421"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0421",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #421",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 36.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0422"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0422",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #422",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 37.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0423"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0423",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #423",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 38.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0424"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0424",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #424",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 39.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0425"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0425",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #425",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 40.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0426"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0426",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #426",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 41.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0427"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0427",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #427",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 42.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0428"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0428",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #428",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 43.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0429"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0429",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #429",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 44.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0430"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0430",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #430",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 45.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0431"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0431",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #431",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 46.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0432"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0432",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #432",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 47.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0433"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0433",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #433",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 48.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0434"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0434",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #434",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 49.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0435"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0435",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #435",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 50.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0436"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0436",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #436",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 51.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0437"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0437",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #437",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 52.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0438"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0438",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #438",
            "severity": "MEDIUM",
            "mitre_id": "T1055.006",
            "risk_weight": 53.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0439"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0439",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #439",
            "severity": "LOW",
            "mitre_id": "T1055.007",
            "risk_weight": 54.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0440"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0440",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #440",
            "severity": "CRITICAL",
            "mitre_id": "T1055.008",
            "risk_weight": 55.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0441"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0441",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #441",
            "severity": "HIGH",
            "mitre_id": "T1055.009",
            "risk_weight": 56.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0442"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0442",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #442",
            "severity": "MEDIUM",
            "mitre_id": "T1055.010",
            "risk_weight": 57.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0443"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0443",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #443",
            "severity": "LOW",
            "mitre_id": "T1055.011",
            "risk_weight": 58.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0444"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0444",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #444",
            "severity": "CRITICAL",
            "mitre_id": "T1055.000",
            "risk_weight": 59.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0445"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0445",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #445",
            "severity": "HIGH",
            "mitre_id": "T1055.001",
            "risk_weight": 60.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0446"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0446",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #446",
            "severity": "MEDIUM",
            "mitre_id": "T1055.002",
            "risk_weight": 61.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0447"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0447",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #447",
            "severity": "LOW",
            "mitre_id": "T1055.003",
            "risk_weight": 62.0,
            "requires_isolation": True,
            "remediation": "EXECUTE_HOST_ISOLATION" if True else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0448"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0448",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #448",
            "severity": "CRITICAL",
            "mitre_id": "T1055.004",
            "risk_weight": 63.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }
        self.signature_catalog["PROCFSDETECTOR-SIG-0449"] = {
            "sig_id": "PROCFSDETECTOR-SIG-0449",
            "name": "Linux /proc/$$/maps & Unlinked Executable Detector Behavioral Heuristic #449",
            "severity": "HIGH",
            "mitre_id": "T1055.005",
            "risk_weight": 64.0,
            "requires_isolation": False,
            "remediation": "EXECUTE_HOST_ISOLATION" if False else "ALERT_TIER2"
        }

    def analyze_event(self, event: ProcfsDetectorEvent) -> Dict[str, Any]:
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

linux_procfs_hide_detector_forensics = ProcfsDetectorForensicEngine()

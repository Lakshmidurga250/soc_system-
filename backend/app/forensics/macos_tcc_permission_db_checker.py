"""
SentinelAI - macOS Transparency, Consent, and Control (TCC) DB Integrity Checker
Host forensics and EDR kernel analytics engine for MacosTcc.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import datetime

class MacosTccAssessmentStatus(Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    INCONCLUSIVE = "INCONCLUSIVE"

@dataclass
class MacosTccEvidenceRecord:
    record_id: str
    hostname: str
    timestamp: str
    principal_user: str
    artifact_path: str
    risk_rating: float
    status: MacosTccAssessmentStatus = MacosTccAssessmentStatus.BENIGN
    attributes: Dict[str, Any] = field(default_factory=dict)

class MacosTccForensicEvaluator:
    def __init__(self):
        self.heuristic_rules: Dict[str, Any] = {}
        self.triage_history: List[Any] = []
        self._initialize_forensic_heuristics()

    def _initialize_forensic_heuristics(self):
        self.heuristic_rules["HEUR-MacosTcc-0001"] = {
            "rule_id": "HEUR-MacosTcc-0001",
            "title": "MacosTcc Forensic Heuristic Rule #1",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0002"] = {
            "rule_id": "HEUR-MacosTcc-0002",
            "title": "MacosTcc Forensic Heuristic Rule #2",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0003"] = {
            "rule_id": "HEUR-MacosTcc-0003",
            "title": "MacosTcc Forensic Heuristic Rule #3",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0004"] = {
            "rule_id": "HEUR-MacosTcc-0004",
            "title": "MacosTcc Forensic Heuristic Rule #4",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0005"] = {
            "rule_id": "HEUR-MacosTcc-0005",
            "title": "MacosTcc Forensic Heuristic Rule #5",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0006"] = {
            "rule_id": "HEUR-MacosTcc-0006",
            "title": "MacosTcc Forensic Heuristic Rule #6",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0007"] = {
            "rule_id": "HEUR-MacosTcc-0007",
            "title": "MacosTcc Forensic Heuristic Rule #7",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0008"] = {
            "rule_id": "HEUR-MacosTcc-0008",
            "title": "MacosTcc Forensic Heuristic Rule #8",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0009"] = {
            "rule_id": "HEUR-MacosTcc-0009",
            "title": "MacosTcc Forensic Heuristic Rule #9",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0010"] = {
            "rule_id": "HEUR-MacosTcc-0010",
            "title": "MacosTcc Forensic Heuristic Rule #10",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0011"] = {
            "rule_id": "HEUR-MacosTcc-0011",
            "title": "MacosTcc Forensic Heuristic Rule #11",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0012"] = {
            "rule_id": "HEUR-MacosTcc-0012",
            "title": "MacosTcc Forensic Heuristic Rule #12",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0013"] = {
            "rule_id": "HEUR-MacosTcc-0013",
            "title": "MacosTcc Forensic Heuristic Rule #13",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0014"] = {
            "rule_id": "HEUR-MacosTcc-0014",
            "title": "MacosTcc Forensic Heuristic Rule #14",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0015"] = {
            "rule_id": "HEUR-MacosTcc-0015",
            "title": "MacosTcc Forensic Heuristic Rule #15",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0016"] = {
            "rule_id": "HEUR-MacosTcc-0016",
            "title": "MacosTcc Forensic Heuristic Rule #16",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0017"] = {
            "rule_id": "HEUR-MacosTcc-0017",
            "title": "MacosTcc Forensic Heuristic Rule #17",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0018"] = {
            "rule_id": "HEUR-MacosTcc-0018",
            "title": "MacosTcc Forensic Heuristic Rule #18",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0019"] = {
            "rule_id": "HEUR-MacosTcc-0019",
            "title": "MacosTcc Forensic Heuristic Rule #19",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0020"] = {
            "rule_id": "HEUR-MacosTcc-0020",
            "title": "MacosTcc Forensic Heuristic Rule #20",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0021"] = {
            "rule_id": "HEUR-MacosTcc-0021",
            "title": "MacosTcc Forensic Heuristic Rule #21",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0022"] = {
            "rule_id": "HEUR-MacosTcc-0022",
            "title": "MacosTcc Forensic Heuristic Rule #22",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0023"] = {
            "rule_id": "HEUR-MacosTcc-0023",
            "title": "MacosTcc Forensic Heuristic Rule #23",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0024"] = {
            "rule_id": "HEUR-MacosTcc-0024",
            "title": "MacosTcc Forensic Heuristic Rule #24",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0025"] = {
            "rule_id": "HEUR-MacosTcc-0025",
            "title": "MacosTcc Forensic Heuristic Rule #25",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0026"] = {
            "rule_id": "HEUR-MacosTcc-0026",
            "title": "MacosTcc Forensic Heuristic Rule #26",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0027"] = {
            "rule_id": "HEUR-MacosTcc-0027",
            "title": "MacosTcc Forensic Heuristic Rule #27",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0028"] = {
            "rule_id": "HEUR-MacosTcc-0028",
            "title": "MacosTcc Forensic Heuristic Rule #28",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0029"] = {
            "rule_id": "HEUR-MacosTcc-0029",
            "title": "MacosTcc Forensic Heuristic Rule #29",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0030"] = {
            "rule_id": "HEUR-MacosTcc-0030",
            "title": "MacosTcc Forensic Heuristic Rule #30",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0031"] = {
            "rule_id": "HEUR-MacosTcc-0031",
            "title": "MacosTcc Forensic Heuristic Rule #31",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0032"] = {
            "rule_id": "HEUR-MacosTcc-0032",
            "title": "MacosTcc Forensic Heuristic Rule #32",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0033"] = {
            "rule_id": "HEUR-MacosTcc-0033",
            "title": "MacosTcc Forensic Heuristic Rule #33",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0034"] = {
            "rule_id": "HEUR-MacosTcc-0034",
            "title": "MacosTcc Forensic Heuristic Rule #34",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0035"] = {
            "rule_id": "HEUR-MacosTcc-0035",
            "title": "MacosTcc Forensic Heuristic Rule #35",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0036"] = {
            "rule_id": "HEUR-MacosTcc-0036",
            "title": "MacosTcc Forensic Heuristic Rule #36",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0037"] = {
            "rule_id": "HEUR-MacosTcc-0037",
            "title": "MacosTcc Forensic Heuristic Rule #37",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0038"] = {
            "rule_id": "HEUR-MacosTcc-0038",
            "title": "MacosTcc Forensic Heuristic Rule #38",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0039"] = {
            "rule_id": "HEUR-MacosTcc-0039",
            "title": "MacosTcc Forensic Heuristic Rule #39",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0040"] = {
            "rule_id": "HEUR-MacosTcc-0040",
            "title": "MacosTcc Forensic Heuristic Rule #40",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0041"] = {
            "rule_id": "HEUR-MacosTcc-0041",
            "title": "MacosTcc Forensic Heuristic Rule #41",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0042"] = {
            "rule_id": "HEUR-MacosTcc-0042",
            "title": "MacosTcc Forensic Heuristic Rule #42",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0043"] = {
            "rule_id": "HEUR-MacosTcc-0043",
            "title": "MacosTcc Forensic Heuristic Rule #43",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0044"] = {
            "rule_id": "HEUR-MacosTcc-0044",
            "title": "MacosTcc Forensic Heuristic Rule #44",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0045"] = {
            "rule_id": "HEUR-MacosTcc-0045",
            "title": "MacosTcc Forensic Heuristic Rule #45",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0046"] = {
            "rule_id": "HEUR-MacosTcc-0046",
            "title": "MacosTcc Forensic Heuristic Rule #46",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0047"] = {
            "rule_id": "HEUR-MacosTcc-0047",
            "title": "MacosTcc Forensic Heuristic Rule #47",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0048"] = {
            "rule_id": "HEUR-MacosTcc-0048",
            "title": "MacosTcc Forensic Heuristic Rule #48",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0049"] = {
            "rule_id": "HEUR-MacosTcc-0049",
            "title": "MacosTcc Forensic Heuristic Rule #49",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0050"] = {
            "rule_id": "HEUR-MacosTcc-0050",
            "title": "MacosTcc Forensic Heuristic Rule #50",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0051"] = {
            "rule_id": "HEUR-MacosTcc-0051",
            "title": "MacosTcc Forensic Heuristic Rule #51",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0052"] = {
            "rule_id": "HEUR-MacosTcc-0052",
            "title": "MacosTcc Forensic Heuristic Rule #52",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0053"] = {
            "rule_id": "HEUR-MacosTcc-0053",
            "title": "MacosTcc Forensic Heuristic Rule #53",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0054"] = {
            "rule_id": "HEUR-MacosTcc-0054",
            "title": "MacosTcc Forensic Heuristic Rule #54",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0055"] = {
            "rule_id": "HEUR-MacosTcc-0055",
            "title": "MacosTcc Forensic Heuristic Rule #55",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0056"] = {
            "rule_id": "HEUR-MacosTcc-0056",
            "title": "MacosTcc Forensic Heuristic Rule #56",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0057"] = {
            "rule_id": "HEUR-MacosTcc-0057",
            "title": "MacosTcc Forensic Heuristic Rule #57",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0058"] = {
            "rule_id": "HEUR-MacosTcc-0058",
            "title": "MacosTcc Forensic Heuristic Rule #58",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0059"] = {
            "rule_id": "HEUR-MacosTcc-0059",
            "title": "MacosTcc Forensic Heuristic Rule #59",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0060"] = {
            "rule_id": "HEUR-MacosTcc-0060",
            "title": "MacosTcc Forensic Heuristic Rule #60",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0061"] = {
            "rule_id": "HEUR-MacosTcc-0061",
            "title": "MacosTcc Forensic Heuristic Rule #61",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0062"] = {
            "rule_id": "HEUR-MacosTcc-0062",
            "title": "MacosTcc Forensic Heuristic Rule #62",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0063"] = {
            "rule_id": "HEUR-MacosTcc-0063",
            "title": "MacosTcc Forensic Heuristic Rule #63",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0064"] = {
            "rule_id": "HEUR-MacosTcc-0064",
            "title": "MacosTcc Forensic Heuristic Rule #64",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0065"] = {
            "rule_id": "HEUR-MacosTcc-0065",
            "title": "MacosTcc Forensic Heuristic Rule #65",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0066"] = {
            "rule_id": "HEUR-MacosTcc-0066",
            "title": "MacosTcc Forensic Heuristic Rule #66",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0067"] = {
            "rule_id": "HEUR-MacosTcc-0067",
            "title": "MacosTcc Forensic Heuristic Rule #67",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0068"] = {
            "rule_id": "HEUR-MacosTcc-0068",
            "title": "MacosTcc Forensic Heuristic Rule #68",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0069"] = {
            "rule_id": "HEUR-MacosTcc-0069",
            "title": "MacosTcc Forensic Heuristic Rule #69",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0070"] = {
            "rule_id": "HEUR-MacosTcc-0070",
            "title": "MacosTcc Forensic Heuristic Rule #70",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0071"] = {
            "rule_id": "HEUR-MacosTcc-0071",
            "title": "MacosTcc Forensic Heuristic Rule #71",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0072"] = {
            "rule_id": "HEUR-MacosTcc-0072",
            "title": "MacosTcc Forensic Heuristic Rule #72",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0073"] = {
            "rule_id": "HEUR-MacosTcc-0073",
            "title": "MacosTcc Forensic Heuristic Rule #73",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0074"] = {
            "rule_id": "HEUR-MacosTcc-0074",
            "title": "MacosTcc Forensic Heuristic Rule #74",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0075"] = {
            "rule_id": "HEUR-MacosTcc-0075",
            "title": "MacosTcc Forensic Heuristic Rule #75",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0076"] = {
            "rule_id": "HEUR-MacosTcc-0076",
            "title": "MacosTcc Forensic Heuristic Rule #76",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0077"] = {
            "rule_id": "HEUR-MacosTcc-0077",
            "title": "MacosTcc Forensic Heuristic Rule #77",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0078"] = {
            "rule_id": "HEUR-MacosTcc-0078",
            "title": "MacosTcc Forensic Heuristic Rule #78",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0079"] = {
            "rule_id": "HEUR-MacosTcc-0079",
            "title": "MacosTcc Forensic Heuristic Rule #79",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0080"] = {
            "rule_id": "HEUR-MacosTcc-0080",
            "title": "MacosTcc Forensic Heuristic Rule #80",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0081"] = {
            "rule_id": "HEUR-MacosTcc-0081",
            "title": "MacosTcc Forensic Heuristic Rule #81",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0082"] = {
            "rule_id": "HEUR-MacosTcc-0082",
            "title": "MacosTcc Forensic Heuristic Rule #82",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0083"] = {
            "rule_id": "HEUR-MacosTcc-0083",
            "title": "MacosTcc Forensic Heuristic Rule #83",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0084"] = {
            "rule_id": "HEUR-MacosTcc-0084",
            "title": "MacosTcc Forensic Heuristic Rule #84",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0085"] = {
            "rule_id": "HEUR-MacosTcc-0085",
            "title": "MacosTcc Forensic Heuristic Rule #85",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0086"] = {
            "rule_id": "HEUR-MacosTcc-0086",
            "title": "MacosTcc Forensic Heuristic Rule #86",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0087"] = {
            "rule_id": "HEUR-MacosTcc-0087",
            "title": "MacosTcc Forensic Heuristic Rule #87",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0088"] = {
            "rule_id": "HEUR-MacosTcc-0088",
            "title": "MacosTcc Forensic Heuristic Rule #88",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0089"] = {
            "rule_id": "HEUR-MacosTcc-0089",
            "title": "MacosTcc Forensic Heuristic Rule #89",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0090"] = {
            "rule_id": "HEUR-MacosTcc-0090",
            "title": "MacosTcc Forensic Heuristic Rule #90",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0091"] = {
            "rule_id": "HEUR-MacosTcc-0091",
            "title": "MacosTcc Forensic Heuristic Rule #91",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0092"] = {
            "rule_id": "HEUR-MacosTcc-0092",
            "title": "MacosTcc Forensic Heuristic Rule #92",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0093"] = {
            "rule_id": "HEUR-MacosTcc-0093",
            "title": "MacosTcc Forensic Heuristic Rule #93",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0094"] = {
            "rule_id": "HEUR-MacosTcc-0094",
            "title": "MacosTcc Forensic Heuristic Rule #94",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0095"] = {
            "rule_id": "HEUR-MacosTcc-0095",
            "title": "MacosTcc Forensic Heuristic Rule #95",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0096"] = {
            "rule_id": "HEUR-MacosTcc-0096",
            "title": "MacosTcc Forensic Heuristic Rule #96",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0097"] = {
            "rule_id": "HEUR-MacosTcc-0097",
            "title": "MacosTcc Forensic Heuristic Rule #97",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0098"] = {
            "rule_id": "HEUR-MacosTcc-0098",
            "title": "MacosTcc Forensic Heuristic Rule #98",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0099"] = {
            "rule_id": "HEUR-MacosTcc-0099",
            "title": "MacosTcc Forensic Heuristic Rule #99",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0100"] = {
            "rule_id": "HEUR-MacosTcc-0100",
            "title": "MacosTcc Forensic Heuristic Rule #100",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0101"] = {
            "rule_id": "HEUR-MacosTcc-0101",
            "title": "MacosTcc Forensic Heuristic Rule #101",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0102"] = {
            "rule_id": "HEUR-MacosTcc-0102",
            "title": "MacosTcc Forensic Heuristic Rule #102",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0103"] = {
            "rule_id": "HEUR-MacosTcc-0103",
            "title": "MacosTcc Forensic Heuristic Rule #103",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0104"] = {
            "rule_id": "HEUR-MacosTcc-0104",
            "title": "MacosTcc Forensic Heuristic Rule #104",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0105"] = {
            "rule_id": "HEUR-MacosTcc-0105",
            "title": "MacosTcc Forensic Heuristic Rule #105",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0106"] = {
            "rule_id": "HEUR-MacosTcc-0106",
            "title": "MacosTcc Forensic Heuristic Rule #106",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0107"] = {
            "rule_id": "HEUR-MacosTcc-0107",
            "title": "MacosTcc Forensic Heuristic Rule #107",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0108"] = {
            "rule_id": "HEUR-MacosTcc-0108",
            "title": "MacosTcc Forensic Heuristic Rule #108",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0109"] = {
            "rule_id": "HEUR-MacosTcc-0109",
            "title": "MacosTcc Forensic Heuristic Rule #109",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0110"] = {
            "rule_id": "HEUR-MacosTcc-0110",
            "title": "MacosTcc Forensic Heuristic Rule #110",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0111"] = {
            "rule_id": "HEUR-MacosTcc-0111",
            "title": "MacosTcc Forensic Heuristic Rule #111",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0112"] = {
            "rule_id": "HEUR-MacosTcc-0112",
            "title": "MacosTcc Forensic Heuristic Rule #112",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0113"] = {
            "rule_id": "HEUR-MacosTcc-0113",
            "title": "MacosTcc Forensic Heuristic Rule #113",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0114"] = {
            "rule_id": "HEUR-MacosTcc-0114",
            "title": "MacosTcc Forensic Heuristic Rule #114",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0115"] = {
            "rule_id": "HEUR-MacosTcc-0115",
            "title": "MacosTcc Forensic Heuristic Rule #115",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0116"] = {
            "rule_id": "HEUR-MacosTcc-0116",
            "title": "MacosTcc Forensic Heuristic Rule #116",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0117"] = {
            "rule_id": "HEUR-MacosTcc-0117",
            "title": "MacosTcc Forensic Heuristic Rule #117",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0118"] = {
            "rule_id": "HEUR-MacosTcc-0118",
            "title": "MacosTcc Forensic Heuristic Rule #118",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0119"] = {
            "rule_id": "HEUR-MacosTcc-0119",
            "title": "MacosTcc Forensic Heuristic Rule #119",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0120"] = {
            "rule_id": "HEUR-MacosTcc-0120",
            "title": "MacosTcc Forensic Heuristic Rule #120",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0121"] = {
            "rule_id": "HEUR-MacosTcc-0121",
            "title": "MacosTcc Forensic Heuristic Rule #121",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0122"] = {
            "rule_id": "HEUR-MacosTcc-0122",
            "title": "MacosTcc Forensic Heuristic Rule #122",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0123"] = {
            "rule_id": "HEUR-MacosTcc-0123",
            "title": "MacosTcc Forensic Heuristic Rule #123",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0124"] = {
            "rule_id": "HEUR-MacosTcc-0124",
            "title": "MacosTcc Forensic Heuristic Rule #124",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0125"] = {
            "rule_id": "HEUR-MacosTcc-0125",
            "title": "MacosTcc Forensic Heuristic Rule #125",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0126"] = {
            "rule_id": "HEUR-MacosTcc-0126",
            "title": "MacosTcc Forensic Heuristic Rule #126",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0127"] = {
            "rule_id": "HEUR-MacosTcc-0127",
            "title": "MacosTcc Forensic Heuristic Rule #127",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0128"] = {
            "rule_id": "HEUR-MacosTcc-0128",
            "title": "MacosTcc Forensic Heuristic Rule #128",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0129"] = {
            "rule_id": "HEUR-MacosTcc-0129",
            "title": "MacosTcc Forensic Heuristic Rule #129",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0130"] = {
            "rule_id": "HEUR-MacosTcc-0130",
            "title": "MacosTcc Forensic Heuristic Rule #130",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0131"] = {
            "rule_id": "HEUR-MacosTcc-0131",
            "title": "MacosTcc Forensic Heuristic Rule #131",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0132"] = {
            "rule_id": "HEUR-MacosTcc-0132",
            "title": "MacosTcc Forensic Heuristic Rule #132",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0133"] = {
            "rule_id": "HEUR-MacosTcc-0133",
            "title": "MacosTcc Forensic Heuristic Rule #133",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0134"] = {
            "rule_id": "HEUR-MacosTcc-0134",
            "title": "MacosTcc Forensic Heuristic Rule #134",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0135"] = {
            "rule_id": "HEUR-MacosTcc-0135",
            "title": "MacosTcc Forensic Heuristic Rule #135",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0136"] = {
            "rule_id": "HEUR-MacosTcc-0136",
            "title": "MacosTcc Forensic Heuristic Rule #136",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0137"] = {
            "rule_id": "HEUR-MacosTcc-0137",
            "title": "MacosTcc Forensic Heuristic Rule #137",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0138"] = {
            "rule_id": "HEUR-MacosTcc-0138",
            "title": "MacosTcc Forensic Heuristic Rule #138",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0139"] = {
            "rule_id": "HEUR-MacosTcc-0139",
            "title": "MacosTcc Forensic Heuristic Rule #139",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0140"] = {
            "rule_id": "HEUR-MacosTcc-0140",
            "title": "MacosTcc Forensic Heuristic Rule #140",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0141"] = {
            "rule_id": "HEUR-MacosTcc-0141",
            "title": "MacosTcc Forensic Heuristic Rule #141",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0142"] = {
            "rule_id": "HEUR-MacosTcc-0142",
            "title": "MacosTcc Forensic Heuristic Rule #142",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0143"] = {
            "rule_id": "HEUR-MacosTcc-0143",
            "title": "MacosTcc Forensic Heuristic Rule #143",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0144"] = {
            "rule_id": "HEUR-MacosTcc-0144",
            "title": "MacosTcc Forensic Heuristic Rule #144",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0145"] = {
            "rule_id": "HEUR-MacosTcc-0145",
            "title": "MacosTcc Forensic Heuristic Rule #145",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0146"] = {
            "rule_id": "HEUR-MacosTcc-0146",
            "title": "MacosTcc Forensic Heuristic Rule #146",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0147"] = {
            "rule_id": "HEUR-MacosTcc-0147",
            "title": "MacosTcc Forensic Heuristic Rule #147",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0148"] = {
            "rule_id": "HEUR-MacosTcc-0148",
            "title": "MacosTcc Forensic Heuristic Rule #148",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0149"] = {
            "rule_id": "HEUR-MacosTcc-0149",
            "title": "MacosTcc Forensic Heuristic Rule #149",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0150"] = {
            "rule_id": "HEUR-MacosTcc-0150",
            "title": "MacosTcc Forensic Heuristic Rule #150",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0151"] = {
            "rule_id": "HEUR-MacosTcc-0151",
            "title": "MacosTcc Forensic Heuristic Rule #151",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0152"] = {
            "rule_id": "HEUR-MacosTcc-0152",
            "title": "MacosTcc Forensic Heuristic Rule #152",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0153"] = {
            "rule_id": "HEUR-MacosTcc-0153",
            "title": "MacosTcc Forensic Heuristic Rule #153",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0154"] = {
            "rule_id": "HEUR-MacosTcc-0154",
            "title": "MacosTcc Forensic Heuristic Rule #154",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0155"] = {
            "rule_id": "HEUR-MacosTcc-0155",
            "title": "MacosTcc Forensic Heuristic Rule #155",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0156"] = {
            "rule_id": "HEUR-MacosTcc-0156",
            "title": "MacosTcc Forensic Heuristic Rule #156",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0157"] = {
            "rule_id": "HEUR-MacosTcc-0157",
            "title": "MacosTcc Forensic Heuristic Rule #157",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0158"] = {
            "rule_id": "HEUR-MacosTcc-0158",
            "title": "MacosTcc Forensic Heuristic Rule #158",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0159"] = {
            "rule_id": "HEUR-MacosTcc-0159",
            "title": "MacosTcc Forensic Heuristic Rule #159",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0160"] = {
            "rule_id": "HEUR-MacosTcc-0160",
            "title": "MacosTcc Forensic Heuristic Rule #160",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0161"] = {
            "rule_id": "HEUR-MacosTcc-0161",
            "title": "MacosTcc Forensic Heuristic Rule #161",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0162"] = {
            "rule_id": "HEUR-MacosTcc-0162",
            "title": "MacosTcc Forensic Heuristic Rule #162",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0163"] = {
            "rule_id": "HEUR-MacosTcc-0163",
            "title": "MacosTcc Forensic Heuristic Rule #163",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0164"] = {
            "rule_id": "HEUR-MacosTcc-0164",
            "title": "MacosTcc Forensic Heuristic Rule #164",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0165"] = {
            "rule_id": "HEUR-MacosTcc-0165",
            "title": "MacosTcc Forensic Heuristic Rule #165",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0166"] = {
            "rule_id": "HEUR-MacosTcc-0166",
            "title": "MacosTcc Forensic Heuristic Rule #166",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0167"] = {
            "rule_id": "HEUR-MacosTcc-0167",
            "title": "MacosTcc Forensic Heuristic Rule #167",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0168"] = {
            "rule_id": "HEUR-MacosTcc-0168",
            "title": "MacosTcc Forensic Heuristic Rule #168",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0169"] = {
            "rule_id": "HEUR-MacosTcc-0169",
            "title": "MacosTcc Forensic Heuristic Rule #169",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0170"] = {
            "rule_id": "HEUR-MacosTcc-0170",
            "title": "MacosTcc Forensic Heuristic Rule #170",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0171"] = {
            "rule_id": "HEUR-MacosTcc-0171",
            "title": "MacosTcc Forensic Heuristic Rule #171",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0172"] = {
            "rule_id": "HEUR-MacosTcc-0172",
            "title": "MacosTcc Forensic Heuristic Rule #172",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0173"] = {
            "rule_id": "HEUR-MacosTcc-0173",
            "title": "MacosTcc Forensic Heuristic Rule #173",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0174"] = {
            "rule_id": "HEUR-MacosTcc-0174",
            "title": "MacosTcc Forensic Heuristic Rule #174",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0175"] = {
            "rule_id": "HEUR-MacosTcc-0175",
            "title": "MacosTcc Forensic Heuristic Rule #175",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0176"] = {
            "rule_id": "HEUR-MacosTcc-0176",
            "title": "MacosTcc Forensic Heuristic Rule #176",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0177"] = {
            "rule_id": "HEUR-MacosTcc-0177",
            "title": "MacosTcc Forensic Heuristic Rule #177",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0178"] = {
            "rule_id": "HEUR-MacosTcc-0178",
            "title": "MacosTcc Forensic Heuristic Rule #178",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0179"] = {
            "rule_id": "HEUR-MacosTcc-0179",
            "title": "MacosTcc Forensic Heuristic Rule #179",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0180"] = {
            "rule_id": "HEUR-MacosTcc-0180",
            "title": "MacosTcc Forensic Heuristic Rule #180",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0181"] = {
            "rule_id": "HEUR-MacosTcc-0181",
            "title": "MacosTcc Forensic Heuristic Rule #181",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0182"] = {
            "rule_id": "HEUR-MacosTcc-0182",
            "title": "MacosTcc Forensic Heuristic Rule #182",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0183"] = {
            "rule_id": "HEUR-MacosTcc-0183",
            "title": "MacosTcc Forensic Heuristic Rule #183",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0184"] = {
            "rule_id": "HEUR-MacosTcc-0184",
            "title": "MacosTcc Forensic Heuristic Rule #184",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0185"] = {
            "rule_id": "HEUR-MacosTcc-0185",
            "title": "MacosTcc Forensic Heuristic Rule #185",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0186"] = {
            "rule_id": "HEUR-MacosTcc-0186",
            "title": "MacosTcc Forensic Heuristic Rule #186",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0187"] = {
            "rule_id": "HEUR-MacosTcc-0187",
            "title": "MacosTcc Forensic Heuristic Rule #187",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0188"] = {
            "rule_id": "HEUR-MacosTcc-0188",
            "title": "MacosTcc Forensic Heuristic Rule #188",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0189"] = {
            "rule_id": "HEUR-MacosTcc-0189",
            "title": "MacosTcc Forensic Heuristic Rule #189",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0190"] = {
            "rule_id": "HEUR-MacosTcc-0190",
            "title": "MacosTcc Forensic Heuristic Rule #190",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0191"] = {
            "rule_id": "HEUR-MacosTcc-0191",
            "title": "MacosTcc Forensic Heuristic Rule #191",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0192"] = {
            "rule_id": "HEUR-MacosTcc-0192",
            "title": "MacosTcc Forensic Heuristic Rule #192",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0193"] = {
            "rule_id": "HEUR-MacosTcc-0193",
            "title": "MacosTcc Forensic Heuristic Rule #193",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0194"] = {
            "rule_id": "HEUR-MacosTcc-0194",
            "title": "MacosTcc Forensic Heuristic Rule #194",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0195"] = {
            "rule_id": "HEUR-MacosTcc-0195",
            "title": "MacosTcc Forensic Heuristic Rule #195",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0196"] = {
            "rule_id": "HEUR-MacosTcc-0196",
            "title": "MacosTcc Forensic Heuristic Rule #196",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0197"] = {
            "rule_id": "HEUR-MacosTcc-0197",
            "title": "MacosTcc Forensic Heuristic Rule #197",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0198"] = {
            "rule_id": "HEUR-MacosTcc-0198",
            "title": "MacosTcc Forensic Heuristic Rule #198",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0199"] = {
            "rule_id": "HEUR-MacosTcc-0199",
            "title": "MacosTcc Forensic Heuristic Rule #199",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0200"] = {
            "rule_id": "HEUR-MacosTcc-0200",
            "title": "MacosTcc Forensic Heuristic Rule #200",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0201"] = {
            "rule_id": "HEUR-MacosTcc-0201",
            "title": "MacosTcc Forensic Heuristic Rule #201",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0202"] = {
            "rule_id": "HEUR-MacosTcc-0202",
            "title": "MacosTcc Forensic Heuristic Rule #202",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0203"] = {
            "rule_id": "HEUR-MacosTcc-0203",
            "title": "MacosTcc Forensic Heuristic Rule #203",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0204"] = {
            "rule_id": "HEUR-MacosTcc-0204",
            "title": "MacosTcc Forensic Heuristic Rule #204",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0205"] = {
            "rule_id": "HEUR-MacosTcc-0205",
            "title": "MacosTcc Forensic Heuristic Rule #205",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0206"] = {
            "rule_id": "HEUR-MacosTcc-0206",
            "title": "MacosTcc Forensic Heuristic Rule #206",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0207"] = {
            "rule_id": "HEUR-MacosTcc-0207",
            "title": "MacosTcc Forensic Heuristic Rule #207",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0208"] = {
            "rule_id": "HEUR-MacosTcc-0208",
            "title": "MacosTcc Forensic Heuristic Rule #208",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0209"] = {
            "rule_id": "HEUR-MacosTcc-0209",
            "title": "MacosTcc Forensic Heuristic Rule #209",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0210"] = {
            "rule_id": "HEUR-MacosTcc-0210",
            "title": "MacosTcc Forensic Heuristic Rule #210",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0211"] = {
            "rule_id": "HEUR-MacosTcc-0211",
            "title": "MacosTcc Forensic Heuristic Rule #211",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0212"] = {
            "rule_id": "HEUR-MacosTcc-0212",
            "title": "MacosTcc Forensic Heuristic Rule #212",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0213"] = {
            "rule_id": "HEUR-MacosTcc-0213",
            "title": "MacosTcc Forensic Heuristic Rule #213",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0214"] = {
            "rule_id": "HEUR-MacosTcc-0214",
            "title": "MacosTcc Forensic Heuristic Rule #214",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0215"] = {
            "rule_id": "HEUR-MacosTcc-0215",
            "title": "MacosTcc Forensic Heuristic Rule #215",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0216"] = {
            "rule_id": "HEUR-MacosTcc-0216",
            "title": "MacosTcc Forensic Heuristic Rule #216",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0217"] = {
            "rule_id": "HEUR-MacosTcc-0217",
            "title": "MacosTcc Forensic Heuristic Rule #217",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0218"] = {
            "rule_id": "HEUR-MacosTcc-0218",
            "title": "MacosTcc Forensic Heuristic Rule #218",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0219"] = {
            "rule_id": "HEUR-MacosTcc-0219",
            "title": "MacosTcc Forensic Heuristic Rule #219",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0220"] = {
            "rule_id": "HEUR-MacosTcc-0220",
            "title": "MacosTcc Forensic Heuristic Rule #220",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0221"] = {
            "rule_id": "HEUR-MacosTcc-0221",
            "title": "MacosTcc Forensic Heuristic Rule #221",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0222"] = {
            "rule_id": "HEUR-MacosTcc-0222",
            "title": "MacosTcc Forensic Heuristic Rule #222",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0223"] = {
            "rule_id": "HEUR-MacosTcc-0223",
            "title": "MacosTcc Forensic Heuristic Rule #223",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0224"] = {
            "rule_id": "HEUR-MacosTcc-0224",
            "title": "MacosTcc Forensic Heuristic Rule #224",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0225"] = {
            "rule_id": "HEUR-MacosTcc-0225",
            "title": "MacosTcc Forensic Heuristic Rule #225",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0226"] = {
            "rule_id": "HEUR-MacosTcc-0226",
            "title": "MacosTcc Forensic Heuristic Rule #226",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0227"] = {
            "rule_id": "HEUR-MacosTcc-0227",
            "title": "MacosTcc Forensic Heuristic Rule #227",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0228"] = {
            "rule_id": "HEUR-MacosTcc-0228",
            "title": "MacosTcc Forensic Heuristic Rule #228",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0229"] = {
            "rule_id": "HEUR-MacosTcc-0229",
            "title": "MacosTcc Forensic Heuristic Rule #229",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0230"] = {
            "rule_id": "HEUR-MacosTcc-0230",
            "title": "MacosTcc Forensic Heuristic Rule #230",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0231"] = {
            "rule_id": "HEUR-MacosTcc-0231",
            "title": "MacosTcc Forensic Heuristic Rule #231",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0232"] = {
            "rule_id": "HEUR-MacosTcc-0232",
            "title": "MacosTcc Forensic Heuristic Rule #232",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0233"] = {
            "rule_id": "HEUR-MacosTcc-0233",
            "title": "MacosTcc Forensic Heuristic Rule #233",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0234"] = {
            "rule_id": "HEUR-MacosTcc-0234",
            "title": "MacosTcc Forensic Heuristic Rule #234",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0235"] = {
            "rule_id": "HEUR-MacosTcc-0235",
            "title": "MacosTcc Forensic Heuristic Rule #235",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0236"] = {
            "rule_id": "HEUR-MacosTcc-0236",
            "title": "MacosTcc Forensic Heuristic Rule #236",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0237"] = {
            "rule_id": "HEUR-MacosTcc-0237",
            "title": "MacosTcc Forensic Heuristic Rule #237",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0238"] = {
            "rule_id": "HEUR-MacosTcc-0238",
            "title": "MacosTcc Forensic Heuristic Rule #238",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0239"] = {
            "rule_id": "HEUR-MacosTcc-0239",
            "title": "MacosTcc Forensic Heuristic Rule #239",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0240"] = {
            "rule_id": "HEUR-MacosTcc-0240",
            "title": "MacosTcc Forensic Heuristic Rule #240",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0241"] = {
            "rule_id": "HEUR-MacosTcc-0241",
            "title": "MacosTcc Forensic Heuristic Rule #241",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0242"] = {
            "rule_id": "HEUR-MacosTcc-0242",
            "title": "MacosTcc Forensic Heuristic Rule #242",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0243"] = {
            "rule_id": "HEUR-MacosTcc-0243",
            "title": "MacosTcc Forensic Heuristic Rule #243",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0244"] = {
            "rule_id": "HEUR-MacosTcc-0244",
            "title": "MacosTcc Forensic Heuristic Rule #244",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0245"] = {
            "rule_id": "HEUR-MacosTcc-0245",
            "title": "MacosTcc Forensic Heuristic Rule #245",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0246"] = {
            "rule_id": "HEUR-MacosTcc-0246",
            "title": "MacosTcc Forensic Heuristic Rule #246",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0247"] = {
            "rule_id": "HEUR-MacosTcc-0247",
            "title": "MacosTcc Forensic Heuristic Rule #247",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0248"] = {
            "rule_id": "HEUR-MacosTcc-0248",
            "title": "MacosTcc Forensic Heuristic Rule #248",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0249"] = {
            "rule_id": "HEUR-MacosTcc-0249",
            "title": "MacosTcc Forensic Heuristic Rule #249",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0250"] = {
            "rule_id": "HEUR-MacosTcc-0250",
            "title": "MacosTcc Forensic Heuristic Rule #250",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0251"] = {
            "rule_id": "HEUR-MacosTcc-0251",
            "title": "MacosTcc Forensic Heuristic Rule #251",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0252"] = {
            "rule_id": "HEUR-MacosTcc-0252",
            "title": "MacosTcc Forensic Heuristic Rule #252",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0253"] = {
            "rule_id": "HEUR-MacosTcc-0253",
            "title": "MacosTcc Forensic Heuristic Rule #253",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0254"] = {
            "rule_id": "HEUR-MacosTcc-0254",
            "title": "MacosTcc Forensic Heuristic Rule #254",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0255"] = {
            "rule_id": "HEUR-MacosTcc-0255",
            "title": "MacosTcc Forensic Heuristic Rule #255",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0256"] = {
            "rule_id": "HEUR-MacosTcc-0256",
            "title": "MacosTcc Forensic Heuristic Rule #256",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0257"] = {
            "rule_id": "HEUR-MacosTcc-0257",
            "title": "MacosTcc Forensic Heuristic Rule #257",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0258"] = {
            "rule_id": "HEUR-MacosTcc-0258",
            "title": "MacosTcc Forensic Heuristic Rule #258",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0259"] = {
            "rule_id": "HEUR-MacosTcc-0259",
            "title": "MacosTcc Forensic Heuristic Rule #259",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0260"] = {
            "rule_id": "HEUR-MacosTcc-0260",
            "title": "MacosTcc Forensic Heuristic Rule #260",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0261"] = {
            "rule_id": "HEUR-MacosTcc-0261",
            "title": "MacosTcc Forensic Heuristic Rule #261",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0262"] = {
            "rule_id": "HEUR-MacosTcc-0262",
            "title": "MacosTcc Forensic Heuristic Rule #262",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0263"] = {
            "rule_id": "HEUR-MacosTcc-0263",
            "title": "MacosTcc Forensic Heuristic Rule #263",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0264"] = {
            "rule_id": "HEUR-MacosTcc-0264",
            "title": "MacosTcc Forensic Heuristic Rule #264",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0265"] = {
            "rule_id": "HEUR-MacosTcc-0265",
            "title": "MacosTcc Forensic Heuristic Rule #265",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0266"] = {
            "rule_id": "HEUR-MacosTcc-0266",
            "title": "MacosTcc Forensic Heuristic Rule #266",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0267"] = {
            "rule_id": "HEUR-MacosTcc-0267",
            "title": "MacosTcc Forensic Heuristic Rule #267",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0268"] = {
            "rule_id": "HEUR-MacosTcc-0268",
            "title": "MacosTcc Forensic Heuristic Rule #268",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0269"] = {
            "rule_id": "HEUR-MacosTcc-0269",
            "title": "MacosTcc Forensic Heuristic Rule #269",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0270"] = {
            "rule_id": "HEUR-MacosTcc-0270",
            "title": "MacosTcc Forensic Heuristic Rule #270",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0271"] = {
            "rule_id": "HEUR-MacosTcc-0271",
            "title": "MacosTcc Forensic Heuristic Rule #271",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0272"] = {
            "rule_id": "HEUR-MacosTcc-0272",
            "title": "MacosTcc Forensic Heuristic Rule #272",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0273"] = {
            "rule_id": "HEUR-MacosTcc-0273",
            "title": "MacosTcc Forensic Heuristic Rule #273",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0274"] = {
            "rule_id": "HEUR-MacosTcc-0274",
            "title": "MacosTcc Forensic Heuristic Rule #274",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0275"] = {
            "rule_id": "HEUR-MacosTcc-0275",
            "title": "MacosTcc Forensic Heuristic Rule #275",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0276"] = {
            "rule_id": "HEUR-MacosTcc-0276",
            "title": "MacosTcc Forensic Heuristic Rule #276",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0277"] = {
            "rule_id": "HEUR-MacosTcc-0277",
            "title": "MacosTcc Forensic Heuristic Rule #277",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0278"] = {
            "rule_id": "HEUR-MacosTcc-0278",
            "title": "MacosTcc Forensic Heuristic Rule #278",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0279"] = {
            "rule_id": "HEUR-MacosTcc-0279",
            "title": "MacosTcc Forensic Heuristic Rule #279",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0280"] = {
            "rule_id": "HEUR-MacosTcc-0280",
            "title": "MacosTcc Forensic Heuristic Rule #280",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0281"] = {
            "rule_id": "HEUR-MacosTcc-0281",
            "title": "MacosTcc Forensic Heuristic Rule #281",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0282"] = {
            "rule_id": "HEUR-MacosTcc-0282",
            "title": "MacosTcc Forensic Heuristic Rule #282",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0283"] = {
            "rule_id": "HEUR-MacosTcc-0283",
            "title": "MacosTcc Forensic Heuristic Rule #283",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0284"] = {
            "rule_id": "HEUR-MacosTcc-0284",
            "title": "MacosTcc Forensic Heuristic Rule #284",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0285"] = {
            "rule_id": "HEUR-MacosTcc-0285",
            "title": "MacosTcc Forensic Heuristic Rule #285",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0286"] = {
            "rule_id": "HEUR-MacosTcc-0286",
            "title": "MacosTcc Forensic Heuristic Rule #286",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0287"] = {
            "rule_id": "HEUR-MacosTcc-0287",
            "title": "MacosTcc Forensic Heuristic Rule #287",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0288"] = {
            "rule_id": "HEUR-MacosTcc-0288",
            "title": "MacosTcc Forensic Heuristic Rule #288",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0289"] = {
            "rule_id": "HEUR-MacosTcc-0289",
            "title": "MacosTcc Forensic Heuristic Rule #289",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0290"] = {
            "rule_id": "HEUR-MacosTcc-0290",
            "title": "MacosTcc Forensic Heuristic Rule #290",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0291"] = {
            "rule_id": "HEUR-MacosTcc-0291",
            "title": "MacosTcc Forensic Heuristic Rule #291",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0292"] = {
            "rule_id": "HEUR-MacosTcc-0292",
            "title": "MacosTcc Forensic Heuristic Rule #292",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0293"] = {
            "rule_id": "HEUR-MacosTcc-0293",
            "title": "MacosTcc Forensic Heuristic Rule #293",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0294"] = {
            "rule_id": "HEUR-MacosTcc-0294",
            "title": "MacosTcc Forensic Heuristic Rule #294",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0295"] = {
            "rule_id": "HEUR-MacosTcc-0295",
            "title": "MacosTcc Forensic Heuristic Rule #295",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0296"] = {
            "rule_id": "HEUR-MacosTcc-0296",
            "title": "MacosTcc Forensic Heuristic Rule #296",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0297"] = {
            "rule_id": "HEUR-MacosTcc-0297",
            "title": "MacosTcc Forensic Heuristic Rule #297",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0298"] = {
            "rule_id": "HEUR-MacosTcc-0298",
            "title": "MacosTcc Forensic Heuristic Rule #298",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0299"] = {
            "rule_id": "HEUR-MacosTcc-0299",
            "title": "MacosTcc Forensic Heuristic Rule #299",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0300"] = {
            "rule_id": "HEUR-MacosTcc-0300",
            "title": "MacosTcc Forensic Heuristic Rule #300",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0301"] = {
            "rule_id": "HEUR-MacosTcc-0301",
            "title": "MacosTcc Forensic Heuristic Rule #301",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0302"] = {
            "rule_id": "HEUR-MacosTcc-0302",
            "title": "MacosTcc Forensic Heuristic Rule #302",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0303"] = {
            "rule_id": "HEUR-MacosTcc-0303",
            "title": "MacosTcc Forensic Heuristic Rule #303",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0304"] = {
            "rule_id": "HEUR-MacosTcc-0304",
            "title": "MacosTcc Forensic Heuristic Rule #304",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0305"] = {
            "rule_id": "HEUR-MacosTcc-0305",
            "title": "MacosTcc Forensic Heuristic Rule #305",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0306"] = {
            "rule_id": "HEUR-MacosTcc-0306",
            "title": "MacosTcc Forensic Heuristic Rule #306",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0307"] = {
            "rule_id": "HEUR-MacosTcc-0307",
            "title": "MacosTcc Forensic Heuristic Rule #307",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0308"] = {
            "rule_id": "HEUR-MacosTcc-0308",
            "title": "MacosTcc Forensic Heuristic Rule #308",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0309"] = {
            "rule_id": "HEUR-MacosTcc-0309",
            "title": "MacosTcc Forensic Heuristic Rule #309",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0310"] = {
            "rule_id": "HEUR-MacosTcc-0310",
            "title": "MacosTcc Forensic Heuristic Rule #310",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0311"] = {
            "rule_id": "HEUR-MacosTcc-0311",
            "title": "MacosTcc Forensic Heuristic Rule #311",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0312"] = {
            "rule_id": "HEUR-MacosTcc-0312",
            "title": "MacosTcc Forensic Heuristic Rule #312",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0313"] = {
            "rule_id": "HEUR-MacosTcc-0313",
            "title": "MacosTcc Forensic Heuristic Rule #313",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0314"] = {
            "rule_id": "HEUR-MacosTcc-0314",
            "title": "MacosTcc Forensic Heuristic Rule #314",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0315"] = {
            "rule_id": "HEUR-MacosTcc-0315",
            "title": "MacosTcc Forensic Heuristic Rule #315",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0316"] = {
            "rule_id": "HEUR-MacosTcc-0316",
            "title": "MacosTcc Forensic Heuristic Rule #316",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0317"] = {
            "rule_id": "HEUR-MacosTcc-0317",
            "title": "MacosTcc Forensic Heuristic Rule #317",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0318"] = {
            "rule_id": "HEUR-MacosTcc-0318",
            "title": "MacosTcc Forensic Heuristic Rule #318",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0319"] = {
            "rule_id": "HEUR-MacosTcc-0319",
            "title": "MacosTcc Forensic Heuristic Rule #319",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0320"] = {
            "rule_id": "HEUR-MacosTcc-0320",
            "title": "MacosTcc Forensic Heuristic Rule #320",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0321"] = {
            "rule_id": "HEUR-MacosTcc-0321",
            "title": "MacosTcc Forensic Heuristic Rule #321",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0322"] = {
            "rule_id": "HEUR-MacosTcc-0322",
            "title": "MacosTcc Forensic Heuristic Rule #322",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0323"] = {
            "rule_id": "HEUR-MacosTcc-0323",
            "title": "MacosTcc Forensic Heuristic Rule #323",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0324"] = {
            "rule_id": "HEUR-MacosTcc-0324",
            "title": "MacosTcc Forensic Heuristic Rule #324",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0325"] = {
            "rule_id": "HEUR-MacosTcc-0325",
            "title": "MacosTcc Forensic Heuristic Rule #325",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0326"] = {
            "rule_id": "HEUR-MacosTcc-0326",
            "title": "MacosTcc Forensic Heuristic Rule #326",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0327"] = {
            "rule_id": "HEUR-MacosTcc-0327",
            "title": "MacosTcc Forensic Heuristic Rule #327",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0328"] = {
            "rule_id": "HEUR-MacosTcc-0328",
            "title": "MacosTcc Forensic Heuristic Rule #328",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0329"] = {
            "rule_id": "HEUR-MacosTcc-0329",
            "title": "MacosTcc Forensic Heuristic Rule #329",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0330"] = {
            "rule_id": "HEUR-MacosTcc-0330",
            "title": "MacosTcc Forensic Heuristic Rule #330",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0331"] = {
            "rule_id": "HEUR-MacosTcc-0331",
            "title": "MacosTcc Forensic Heuristic Rule #331",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0332"] = {
            "rule_id": "HEUR-MacosTcc-0332",
            "title": "MacosTcc Forensic Heuristic Rule #332",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0333"] = {
            "rule_id": "HEUR-MacosTcc-0333",
            "title": "MacosTcc Forensic Heuristic Rule #333",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0334"] = {
            "rule_id": "HEUR-MacosTcc-0334",
            "title": "MacosTcc Forensic Heuristic Rule #334",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0335"] = {
            "rule_id": "HEUR-MacosTcc-0335",
            "title": "MacosTcc Forensic Heuristic Rule #335",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0336"] = {
            "rule_id": "HEUR-MacosTcc-0336",
            "title": "MacosTcc Forensic Heuristic Rule #336",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0337"] = {
            "rule_id": "HEUR-MacosTcc-0337",
            "title": "MacosTcc Forensic Heuristic Rule #337",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0338"] = {
            "rule_id": "HEUR-MacosTcc-0338",
            "title": "MacosTcc Forensic Heuristic Rule #338",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0339"] = {
            "rule_id": "HEUR-MacosTcc-0339",
            "title": "MacosTcc Forensic Heuristic Rule #339",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0340"] = {
            "rule_id": "HEUR-MacosTcc-0340",
            "title": "MacosTcc Forensic Heuristic Rule #340",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0341"] = {
            "rule_id": "HEUR-MacosTcc-0341",
            "title": "MacosTcc Forensic Heuristic Rule #341",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0342"] = {
            "rule_id": "HEUR-MacosTcc-0342",
            "title": "MacosTcc Forensic Heuristic Rule #342",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0343"] = {
            "rule_id": "HEUR-MacosTcc-0343",
            "title": "MacosTcc Forensic Heuristic Rule #343",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0344"] = {
            "rule_id": "HEUR-MacosTcc-0344",
            "title": "MacosTcc Forensic Heuristic Rule #344",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0345"] = {
            "rule_id": "HEUR-MacosTcc-0345",
            "title": "MacosTcc Forensic Heuristic Rule #345",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0346"] = {
            "rule_id": "HEUR-MacosTcc-0346",
            "title": "MacosTcc Forensic Heuristic Rule #346",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0347"] = {
            "rule_id": "HEUR-MacosTcc-0347",
            "title": "MacosTcc Forensic Heuristic Rule #347",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0348"] = {
            "rule_id": "HEUR-MacosTcc-0348",
            "title": "MacosTcc Forensic Heuristic Rule #348",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-MacosTcc-0349"] = {
            "rule_id": "HEUR-MacosTcc-0349",
            "title": "MacosTcc Forensic Heuristic Rule #349",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }

    def evaluate_evidence(self, evidence: MacosTccEvidenceRecord) -> Dict[str, Any]:
        matched_rules = []
        for rid, rdata in self.heuristic_rules.items():
            if evidence.risk_rating >= rdata["base_score"]:
                matched_rules.append(rid)
        if len(matched_rules) > 2:
            evidence.status = MacosTccAssessmentStatus.MALICIOUS
        return {
            "record_id": evidence.record_id,
            "status": evidence.status.value,
            "matched_rules_count": len(matched_rules),
            "heuristics": matched_rules[:5]
        }

macos_tcc_permission_db_checker_engine = MacosTccForensicEvaluator()

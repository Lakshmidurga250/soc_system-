"""
SentinelAI - Linux Cron, Systemd Timer & Anacron Persistence Auditor
Host forensics and EDR kernel analytics engine for CronPersistence.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import datetime

class CronPersistenceAssessmentStatus(Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    INCONCLUSIVE = "INCONCLUSIVE"

@dataclass
class CronPersistenceEvidenceRecord:
    record_id: str
    hostname: str
    timestamp: str
    principal_user: str
    artifact_path: str
    risk_rating: float
    status: CronPersistenceAssessmentStatus = CronPersistenceAssessmentStatus.BENIGN
    attributes: Dict[str, Any] = field(default_factory=dict)

class CronPersistenceForensicEvaluator:
    def __init__(self):
        self.heuristic_rules: Dict[str, Any] = {}
        self.triage_history: List[Any] = []
        self._initialize_forensic_heuristics()

    def _initialize_forensic_heuristics(self):
        self.heuristic_rules["HEUR-CronPersistence-0001"] = {
            "rule_id": "HEUR-CronPersistence-0001",
            "title": "CronPersistence Forensic Heuristic Rule #1",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0002"] = {
            "rule_id": "HEUR-CronPersistence-0002",
            "title": "CronPersistence Forensic Heuristic Rule #2",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0003"] = {
            "rule_id": "HEUR-CronPersistence-0003",
            "title": "CronPersistence Forensic Heuristic Rule #3",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0004"] = {
            "rule_id": "HEUR-CronPersistence-0004",
            "title": "CronPersistence Forensic Heuristic Rule #4",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0005"] = {
            "rule_id": "HEUR-CronPersistence-0005",
            "title": "CronPersistence Forensic Heuristic Rule #5",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0006"] = {
            "rule_id": "HEUR-CronPersistence-0006",
            "title": "CronPersistence Forensic Heuristic Rule #6",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0007"] = {
            "rule_id": "HEUR-CronPersistence-0007",
            "title": "CronPersistence Forensic Heuristic Rule #7",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0008"] = {
            "rule_id": "HEUR-CronPersistence-0008",
            "title": "CronPersistence Forensic Heuristic Rule #8",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0009"] = {
            "rule_id": "HEUR-CronPersistence-0009",
            "title": "CronPersistence Forensic Heuristic Rule #9",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0010"] = {
            "rule_id": "HEUR-CronPersistence-0010",
            "title": "CronPersistence Forensic Heuristic Rule #10",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0011"] = {
            "rule_id": "HEUR-CronPersistence-0011",
            "title": "CronPersistence Forensic Heuristic Rule #11",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0012"] = {
            "rule_id": "HEUR-CronPersistence-0012",
            "title": "CronPersistence Forensic Heuristic Rule #12",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0013"] = {
            "rule_id": "HEUR-CronPersistence-0013",
            "title": "CronPersistence Forensic Heuristic Rule #13",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0014"] = {
            "rule_id": "HEUR-CronPersistence-0014",
            "title": "CronPersistence Forensic Heuristic Rule #14",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0015"] = {
            "rule_id": "HEUR-CronPersistence-0015",
            "title": "CronPersistence Forensic Heuristic Rule #15",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0016"] = {
            "rule_id": "HEUR-CronPersistence-0016",
            "title": "CronPersistence Forensic Heuristic Rule #16",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0017"] = {
            "rule_id": "HEUR-CronPersistence-0017",
            "title": "CronPersistence Forensic Heuristic Rule #17",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0018"] = {
            "rule_id": "HEUR-CronPersistence-0018",
            "title": "CronPersistence Forensic Heuristic Rule #18",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0019"] = {
            "rule_id": "HEUR-CronPersistence-0019",
            "title": "CronPersistence Forensic Heuristic Rule #19",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0020"] = {
            "rule_id": "HEUR-CronPersistence-0020",
            "title": "CronPersistence Forensic Heuristic Rule #20",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0021"] = {
            "rule_id": "HEUR-CronPersistence-0021",
            "title": "CronPersistence Forensic Heuristic Rule #21",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0022"] = {
            "rule_id": "HEUR-CronPersistence-0022",
            "title": "CronPersistence Forensic Heuristic Rule #22",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0023"] = {
            "rule_id": "HEUR-CronPersistence-0023",
            "title": "CronPersistence Forensic Heuristic Rule #23",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0024"] = {
            "rule_id": "HEUR-CronPersistence-0024",
            "title": "CronPersistence Forensic Heuristic Rule #24",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0025"] = {
            "rule_id": "HEUR-CronPersistence-0025",
            "title": "CronPersistence Forensic Heuristic Rule #25",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0026"] = {
            "rule_id": "HEUR-CronPersistence-0026",
            "title": "CronPersistence Forensic Heuristic Rule #26",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0027"] = {
            "rule_id": "HEUR-CronPersistence-0027",
            "title": "CronPersistence Forensic Heuristic Rule #27",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0028"] = {
            "rule_id": "HEUR-CronPersistence-0028",
            "title": "CronPersistence Forensic Heuristic Rule #28",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0029"] = {
            "rule_id": "HEUR-CronPersistence-0029",
            "title": "CronPersistence Forensic Heuristic Rule #29",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0030"] = {
            "rule_id": "HEUR-CronPersistence-0030",
            "title": "CronPersistence Forensic Heuristic Rule #30",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0031"] = {
            "rule_id": "HEUR-CronPersistence-0031",
            "title": "CronPersistence Forensic Heuristic Rule #31",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0032"] = {
            "rule_id": "HEUR-CronPersistence-0032",
            "title": "CronPersistence Forensic Heuristic Rule #32",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0033"] = {
            "rule_id": "HEUR-CronPersistence-0033",
            "title": "CronPersistence Forensic Heuristic Rule #33",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0034"] = {
            "rule_id": "HEUR-CronPersistence-0034",
            "title": "CronPersistence Forensic Heuristic Rule #34",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0035"] = {
            "rule_id": "HEUR-CronPersistence-0035",
            "title": "CronPersistence Forensic Heuristic Rule #35",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0036"] = {
            "rule_id": "HEUR-CronPersistence-0036",
            "title": "CronPersistence Forensic Heuristic Rule #36",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0037"] = {
            "rule_id": "HEUR-CronPersistence-0037",
            "title": "CronPersistence Forensic Heuristic Rule #37",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0038"] = {
            "rule_id": "HEUR-CronPersistence-0038",
            "title": "CronPersistence Forensic Heuristic Rule #38",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0039"] = {
            "rule_id": "HEUR-CronPersistence-0039",
            "title": "CronPersistence Forensic Heuristic Rule #39",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0040"] = {
            "rule_id": "HEUR-CronPersistence-0040",
            "title": "CronPersistence Forensic Heuristic Rule #40",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0041"] = {
            "rule_id": "HEUR-CronPersistence-0041",
            "title": "CronPersistence Forensic Heuristic Rule #41",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0042"] = {
            "rule_id": "HEUR-CronPersistence-0042",
            "title": "CronPersistence Forensic Heuristic Rule #42",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0043"] = {
            "rule_id": "HEUR-CronPersistence-0043",
            "title": "CronPersistence Forensic Heuristic Rule #43",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0044"] = {
            "rule_id": "HEUR-CronPersistence-0044",
            "title": "CronPersistence Forensic Heuristic Rule #44",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0045"] = {
            "rule_id": "HEUR-CronPersistence-0045",
            "title": "CronPersistence Forensic Heuristic Rule #45",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0046"] = {
            "rule_id": "HEUR-CronPersistence-0046",
            "title": "CronPersistence Forensic Heuristic Rule #46",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0047"] = {
            "rule_id": "HEUR-CronPersistence-0047",
            "title": "CronPersistence Forensic Heuristic Rule #47",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0048"] = {
            "rule_id": "HEUR-CronPersistence-0048",
            "title": "CronPersistence Forensic Heuristic Rule #48",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0049"] = {
            "rule_id": "HEUR-CronPersistence-0049",
            "title": "CronPersistence Forensic Heuristic Rule #49",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0050"] = {
            "rule_id": "HEUR-CronPersistence-0050",
            "title": "CronPersistence Forensic Heuristic Rule #50",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0051"] = {
            "rule_id": "HEUR-CronPersistence-0051",
            "title": "CronPersistence Forensic Heuristic Rule #51",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0052"] = {
            "rule_id": "HEUR-CronPersistence-0052",
            "title": "CronPersistence Forensic Heuristic Rule #52",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0053"] = {
            "rule_id": "HEUR-CronPersistence-0053",
            "title": "CronPersistence Forensic Heuristic Rule #53",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0054"] = {
            "rule_id": "HEUR-CronPersistence-0054",
            "title": "CronPersistence Forensic Heuristic Rule #54",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0055"] = {
            "rule_id": "HEUR-CronPersistence-0055",
            "title": "CronPersistence Forensic Heuristic Rule #55",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0056"] = {
            "rule_id": "HEUR-CronPersistence-0056",
            "title": "CronPersistence Forensic Heuristic Rule #56",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0057"] = {
            "rule_id": "HEUR-CronPersistence-0057",
            "title": "CronPersistence Forensic Heuristic Rule #57",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0058"] = {
            "rule_id": "HEUR-CronPersistence-0058",
            "title": "CronPersistence Forensic Heuristic Rule #58",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0059"] = {
            "rule_id": "HEUR-CronPersistence-0059",
            "title": "CronPersistence Forensic Heuristic Rule #59",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0060"] = {
            "rule_id": "HEUR-CronPersistence-0060",
            "title": "CronPersistence Forensic Heuristic Rule #60",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0061"] = {
            "rule_id": "HEUR-CronPersistence-0061",
            "title": "CronPersistence Forensic Heuristic Rule #61",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0062"] = {
            "rule_id": "HEUR-CronPersistence-0062",
            "title": "CronPersistence Forensic Heuristic Rule #62",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0063"] = {
            "rule_id": "HEUR-CronPersistence-0063",
            "title": "CronPersistence Forensic Heuristic Rule #63",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0064"] = {
            "rule_id": "HEUR-CronPersistence-0064",
            "title": "CronPersistence Forensic Heuristic Rule #64",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0065"] = {
            "rule_id": "HEUR-CronPersistence-0065",
            "title": "CronPersistence Forensic Heuristic Rule #65",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0066"] = {
            "rule_id": "HEUR-CronPersistence-0066",
            "title": "CronPersistence Forensic Heuristic Rule #66",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0067"] = {
            "rule_id": "HEUR-CronPersistence-0067",
            "title": "CronPersistence Forensic Heuristic Rule #67",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0068"] = {
            "rule_id": "HEUR-CronPersistence-0068",
            "title": "CronPersistence Forensic Heuristic Rule #68",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0069"] = {
            "rule_id": "HEUR-CronPersistence-0069",
            "title": "CronPersistence Forensic Heuristic Rule #69",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0070"] = {
            "rule_id": "HEUR-CronPersistence-0070",
            "title": "CronPersistence Forensic Heuristic Rule #70",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0071"] = {
            "rule_id": "HEUR-CronPersistence-0071",
            "title": "CronPersistence Forensic Heuristic Rule #71",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0072"] = {
            "rule_id": "HEUR-CronPersistence-0072",
            "title": "CronPersistence Forensic Heuristic Rule #72",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0073"] = {
            "rule_id": "HEUR-CronPersistence-0073",
            "title": "CronPersistence Forensic Heuristic Rule #73",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0074"] = {
            "rule_id": "HEUR-CronPersistence-0074",
            "title": "CronPersistence Forensic Heuristic Rule #74",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0075"] = {
            "rule_id": "HEUR-CronPersistence-0075",
            "title": "CronPersistence Forensic Heuristic Rule #75",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0076"] = {
            "rule_id": "HEUR-CronPersistence-0076",
            "title": "CronPersistence Forensic Heuristic Rule #76",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0077"] = {
            "rule_id": "HEUR-CronPersistence-0077",
            "title": "CronPersistence Forensic Heuristic Rule #77",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0078"] = {
            "rule_id": "HEUR-CronPersistence-0078",
            "title": "CronPersistence Forensic Heuristic Rule #78",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0079"] = {
            "rule_id": "HEUR-CronPersistence-0079",
            "title": "CronPersistence Forensic Heuristic Rule #79",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0080"] = {
            "rule_id": "HEUR-CronPersistence-0080",
            "title": "CronPersistence Forensic Heuristic Rule #80",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0081"] = {
            "rule_id": "HEUR-CronPersistence-0081",
            "title": "CronPersistence Forensic Heuristic Rule #81",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0082"] = {
            "rule_id": "HEUR-CronPersistence-0082",
            "title": "CronPersistence Forensic Heuristic Rule #82",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0083"] = {
            "rule_id": "HEUR-CronPersistence-0083",
            "title": "CronPersistence Forensic Heuristic Rule #83",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0084"] = {
            "rule_id": "HEUR-CronPersistence-0084",
            "title": "CronPersistence Forensic Heuristic Rule #84",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0085"] = {
            "rule_id": "HEUR-CronPersistence-0085",
            "title": "CronPersistence Forensic Heuristic Rule #85",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0086"] = {
            "rule_id": "HEUR-CronPersistence-0086",
            "title": "CronPersistence Forensic Heuristic Rule #86",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0087"] = {
            "rule_id": "HEUR-CronPersistence-0087",
            "title": "CronPersistence Forensic Heuristic Rule #87",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0088"] = {
            "rule_id": "HEUR-CronPersistence-0088",
            "title": "CronPersistence Forensic Heuristic Rule #88",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0089"] = {
            "rule_id": "HEUR-CronPersistence-0089",
            "title": "CronPersistence Forensic Heuristic Rule #89",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0090"] = {
            "rule_id": "HEUR-CronPersistence-0090",
            "title": "CronPersistence Forensic Heuristic Rule #90",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0091"] = {
            "rule_id": "HEUR-CronPersistence-0091",
            "title": "CronPersistence Forensic Heuristic Rule #91",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0092"] = {
            "rule_id": "HEUR-CronPersistence-0092",
            "title": "CronPersistence Forensic Heuristic Rule #92",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0093"] = {
            "rule_id": "HEUR-CronPersistence-0093",
            "title": "CronPersistence Forensic Heuristic Rule #93",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0094"] = {
            "rule_id": "HEUR-CronPersistence-0094",
            "title": "CronPersistence Forensic Heuristic Rule #94",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0095"] = {
            "rule_id": "HEUR-CronPersistence-0095",
            "title": "CronPersistence Forensic Heuristic Rule #95",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0096"] = {
            "rule_id": "HEUR-CronPersistence-0096",
            "title": "CronPersistence Forensic Heuristic Rule #96",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0097"] = {
            "rule_id": "HEUR-CronPersistence-0097",
            "title": "CronPersistence Forensic Heuristic Rule #97",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0098"] = {
            "rule_id": "HEUR-CronPersistence-0098",
            "title": "CronPersistence Forensic Heuristic Rule #98",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0099"] = {
            "rule_id": "HEUR-CronPersistence-0099",
            "title": "CronPersistence Forensic Heuristic Rule #99",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0100"] = {
            "rule_id": "HEUR-CronPersistence-0100",
            "title": "CronPersistence Forensic Heuristic Rule #100",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0101"] = {
            "rule_id": "HEUR-CronPersistence-0101",
            "title": "CronPersistence Forensic Heuristic Rule #101",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0102"] = {
            "rule_id": "HEUR-CronPersistence-0102",
            "title": "CronPersistence Forensic Heuristic Rule #102",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0103"] = {
            "rule_id": "HEUR-CronPersistence-0103",
            "title": "CronPersistence Forensic Heuristic Rule #103",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0104"] = {
            "rule_id": "HEUR-CronPersistence-0104",
            "title": "CronPersistence Forensic Heuristic Rule #104",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0105"] = {
            "rule_id": "HEUR-CronPersistence-0105",
            "title": "CronPersistence Forensic Heuristic Rule #105",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0106"] = {
            "rule_id": "HEUR-CronPersistence-0106",
            "title": "CronPersistence Forensic Heuristic Rule #106",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0107"] = {
            "rule_id": "HEUR-CronPersistence-0107",
            "title": "CronPersistence Forensic Heuristic Rule #107",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0108"] = {
            "rule_id": "HEUR-CronPersistence-0108",
            "title": "CronPersistence Forensic Heuristic Rule #108",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0109"] = {
            "rule_id": "HEUR-CronPersistence-0109",
            "title": "CronPersistence Forensic Heuristic Rule #109",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0110"] = {
            "rule_id": "HEUR-CronPersistence-0110",
            "title": "CronPersistence Forensic Heuristic Rule #110",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0111"] = {
            "rule_id": "HEUR-CronPersistence-0111",
            "title": "CronPersistence Forensic Heuristic Rule #111",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0112"] = {
            "rule_id": "HEUR-CronPersistence-0112",
            "title": "CronPersistence Forensic Heuristic Rule #112",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0113"] = {
            "rule_id": "HEUR-CronPersistence-0113",
            "title": "CronPersistence Forensic Heuristic Rule #113",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0114"] = {
            "rule_id": "HEUR-CronPersistence-0114",
            "title": "CronPersistence Forensic Heuristic Rule #114",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0115"] = {
            "rule_id": "HEUR-CronPersistence-0115",
            "title": "CronPersistence Forensic Heuristic Rule #115",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0116"] = {
            "rule_id": "HEUR-CronPersistence-0116",
            "title": "CronPersistence Forensic Heuristic Rule #116",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0117"] = {
            "rule_id": "HEUR-CronPersistence-0117",
            "title": "CronPersistence Forensic Heuristic Rule #117",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0118"] = {
            "rule_id": "HEUR-CronPersistence-0118",
            "title": "CronPersistence Forensic Heuristic Rule #118",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0119"] = {
            "rule_id": "HEUR-CronPersistence-0119",
            "title": "CronPersistence Forensic Heuristic Rule #119",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0120"] = {
            "rule_id": "HEUR-CronPersistence-0120",
            "title": "CronPersistence Forensic Heuristic Rule #120",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0121"] = {
            "rule_id": "HEUR-CronPersistence-0121",
            "title": "CronPersistence Forensic Heuristic Rule #121",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0122"] = {
            "rule_id": "HEUR-CronPersistence-0122",
            "title": "CronPersistence Forensic Heuristic Rule #122",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0123"] = {
            "rule_id": "HEUR-CronPersistence-0123",
            "title": "CronPersistence Forensic Heuristic Rule #123",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0124"] = {
            "rule_id": "HEUR-CronPersistence-0124",
            "title": "CronPersistence Forensic Heuristic Rule #124",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0125"] = {
            "rule_id": "HEUR-CronPersistence-0125",
            "title": "CronPersistence Forensic Heuristic Rule #125",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0126"] = {
            "rule_id": "HEUR-CronPersistence-0126",
            "title": "CronPersistence Forensic Heuristic Rule #126",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0127"] = {
            "rule_id": "HEUR-CronPersistence-0127",
            "title": "CronPersistence Forensic Heuristic Rule #127",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0128"] = {
            "rule_id": "HEUR-CronPersistence-0128",
            "title": "CronPersistence Forensic Heuristic Rule #128",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0129"] = {
            "rule_id": "HEUR-CronPersistence-0129",
            "title": "CronPersistence Forensic Heuristic Rule #129",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0130"] = {
            "rule_id": "HEUR-CronPersistence-0130",
            "title": "CronPersistence Forensic Heuristic Rule #130",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0131"] = {
            "rule_id": "HEUR-CronPersistence-0131",
            "title": "CronPersistence Forensic Heuristic Rule #131",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0132"] = {
            "rule_id": "HEUR-CronPersistence-0132",
            "title": "CronPersistence Forensic Heuristic Rule #132",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0133"] = {
            "rule_id": "HEUR-CronPersistence-0133",
            "title": "CronPersistence Forensic Heuristic Rule #133",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0134"] = {
            "rule_id": "HEUR-CronPersistence-0134",
            "title": "CronPersistence Forensic Heuristic Rule #134",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0135"] = {
            "rule_id": "HEUR-CronPersistence-0135",
            "title": "CronPersistence Forensic Heuristic Rule #135",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0136"] = {
            "rule_id": "HEUR-CronPersistence-0136",
            "title": "CronPersistence Forensic Heuristic Rule #136",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0137"] = {
            "rule_id": "HEUR-CronPersistence-0137",
            "title": "CronPersistence Forensic Heuristic Rule #137",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0138"] = {
            "rule_id": "HEUR-CronPersistence-0138",
            "title": "CronPersistence Forensic Heuristic Rule #138",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0139"] = {
            "rule_id": "HEUR-CronPersistence-0139",
            "title": "CronPersistence Forensic Heuristic Rule #139",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0140"] = {
            "rule_id": "HEUR-CronPersistence-0140",
            "title": "CronPersistence Forensic Heuristic Rule #140",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0141"] = {
            "rule_id": "HEUR-CronPersistence-0141",
            "title": "CronPersistence Forensic Heuristic Rule #141",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0142"] = {
            "rule_id": "HEUR-CronPersistence-0142",
            "title": "CronPersistence Forensic Heuristic Rule #142",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0143"] = {
            "rule_id": "HEUR-CronPersistence-0143",
            "title": "CronPersistence Forensic Heuristic Rule #143",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0144"] = {
            "rule_id": "HEUR-CronPersistence-0144",
            "title": "CronPersistence Forensic Heuristic Rule #144",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0145"] = {
            "rule_id": "HEUR-CronPersistence-0145",
            "title": "CronPersistence Forensic Heuristic Rule #145",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0146"] = {
            "rule_id": "HEUR-CronPersistence-0146",
            "title": "CronPersistence Forensic Heuristic Rule #146",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0147"] = {
            "rule_id": "HEUR-CronPersistence-0147",
            "title": "CronPersistence Forensic Heuristic Rule #147",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0148"] = {
            "rule_id": "HEUR-CronPersistence-0148",
            "title": "CronPersistence Forensic Heuristic Rule #148",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0149"] = {
            "rule_id": "HEUR-CronPersistence-0149",
            "title": "CronPersistence Forensic Heuristic Rule #149",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0150"] = {
            "rule_id": "HEUR-CronPersistence-0150",
            "title": "CronPersistence Forensic Heuristic Rule #150",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0151"] = {
            "rule_id": "HEUR-CronPersistence-0151",
            "title": "CronPersistence Forensic Heuristic Rule #151",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0152"] = {
            "rule_id": "HEUR-CronPersistence-0152",
            "title": "CronPersistence Forensic Heuristic Rule #152",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0153"] = {
            "rule_id": "HEUR-CronPersistence-0153",
            "title": "CronPersistence Forensic Heuristic Rule #153",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0154"] = {
            "rule_id": "HEUR-CronPersistence-0154",
            "title": "CronPersistence Forensic Heuristic Rule #154",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0155"] = {
            "rule_id": "HEUR-CronPersistence-0155",
            "title": "CronPersistence Forensic Heuristic Rule #155",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0156"] = {
            "rule_id": "HEUR-CronPersistence-0156",
            "title": "CronPersistence Forensic Heuristic Rule #156",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0157"] = {
            "rule_id": "HEUR-CronPersistence-0157",
            "title": "CronPersistence Forensic Heuristic Rule #157",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0158"] = {
            "rule_id": "HEUR-CronPersistence-0158",
            "title": "CronPersistence Forensic Heuristic Rule #158",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0159"] = {
            "rule_id": "HEUR-CronPersistence-0159",
            "title": "CronPersistence Forensic Heuristic Rule #159",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0160"] = {
            "rule_id": "HEUR-CronPersistence-0160",
            "title": "CronPersistence Forensic Heuristic Rule #160",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0161"] = {
            "rule_id": "HEUR-CronPersistence-0161",
            "title": "CronPersistence Forensic Heuristic Rule #161",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0162"] = {
            "rule_id": "HEUR-CronPersistence-0162",
            "title": "CronPersistence Forensic Heuristic Rule #162",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0163"] = {
            "rule_id": "HEUR-CronPersistence-0163",
            "title": "CronPersistence Forensic Heuristic Rule #163",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0164"] = {
            "rule_id": "HEUR-CronPersistence-0164",
            "title": "CronPersistence Forensic Heuristic Rule #164",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0165"] = {
            "rule_id": "HEUR-CronPersistence-0165",
            "title": "CronPersistence Forensic Heuristic Rule #165",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0166"] = {
            "rule_id": "HEUR-CronPersistence-0166",
            "title": "CronPersistence Forensic Heuristic Rule #166",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0167"] = {
            "rule_id": "HEUR-CronPersistence-0167",
            "title": "CronPersistence Forensic Heuristic Rule #167",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0168"] = {
            "rule_id": "HEUR-CronPersistence-0168",
            "title": "CronPersistence Forensic Heuristic Rule #168",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0169"] = {
            "rule_id": "HEUR-CronPersistence-0169",
            "title": "CronPersistence Forensic Heuristic Rule #169",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0170"] = {
            "rule_id": "HEUR-CronPersistence-0170",
            "title": "CronPersistence Forensic Heuristic Rule #170",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0171"] = {
            "rule_id": "HEUR-CronPersistence-0171",
            "title": "CronPersistence Forensic Heuristic Rule #171",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0172"] = {
            "rule_id": "HEUR-CronPersistence-0172",
            "title": "CronPersistence Forensic Heuristic Rule #172",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0173"] = {
            "rule_id": "HEUR-CronPersistence-0173",
            "title": "CronPersistence Forensic Heuristic Rule #173",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0174"] = {
            "rule_id": "HEUR-CronPersistence-0174",
            "title": "CronPersistence Forensic Heuristic Rule #174",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0175"] = {
            "rule_id": "HEUR-CronPersistence-0175",
            "title": "CronPersistence Forensic Heuristic Rule #175",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0176"] = {
            "rule_id": "HEUR-CronPersistence-0176",
            "title": "CronPersistence Forensic Heuristic Rule #176",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0177"] = {
            "rule_id": "HEUR-CronPersistence-0177",
            "title": "CronPersistence Forensic Heuristic Rule #177",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0178"] = {
            "rule_id": "HEUR-CronPersistence-0178",
            "title": "CronPersistence Forensic Heuristic Rule #178",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0179"] = {
            "rule_id": "HEUR-CronPersistence-0179",
            "title": "CronPersistence Forensic Heuristic Rule #179",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0180"] = {
            "rule_id": "HEUR-CronPersistence-0180",
            "title": "CronPersistence Forensic Heuristic Rule #180",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0181"] = {
            "rule_id": "HEUR-CronPersistence-0181",
            "title": "CronPersistence Forensic Heuristic Rule #181",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0182"] = {
            "rule_id": "HEUR-CronPersistence-0182",
            "title": "CronPersistence Forensic Heuristic Rule #182",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0183"] = {
            "rule_id": "HEUR-CronPersistence-0183",
            "title": "CronPersistence Forensic Heuristic Rule #183",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0184"] = {
            "rule_id": "HEUR-CronPersistence-0184",
            "title": "CronPersistence Forensic Heuristic Rule #184",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0185"] = {
            "rule_id": "HEUR-CronPersistence-0185",
            "title": "CronPersistence Forensic Heuristic Rule #185",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0186"] = {
            "rule_id": "HEUR-CronPersistence-0186",
            "title": "CronPersistence Forensic Heuristic Rule #186",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0187"] = {
            "rule_id": "HEUR-CronPersistence-0187",
            "title": "CronPersistence Forensic Heuristic Rule #187",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0188"] = {
            "rule_id": "HEUR-CronPersistence-0188",
            "title": "CronPersistence Forensic Heuristic Rule #188",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0189"] = {
            "rule_id": "HEUR-CronPersistence-0189",
            "title": "CronPersistence Forensic Heuristic Rule #189",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0190"] = {
            "rule_id": "HEUR-CronPersistence-0190",
            "title": "CronPersistence Forensic Heuristic Rule #190",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0191"] = {
            "rule_id": "HEUR-CronPersistence-0191",
            "title": "CronPersistence Forensic Heuristic Rule #191",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0192"] = {
            "rule_id": "HEUR-CronPersistence-0192",
            "title": "CronPersistence Forensic Heuristic Rule #192",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0193"] = {
            "rule_id": "HEUR-CronPersistence-0193",
            "title": "CronPersistence Forensic Heuristic Rule #193",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0194"] = {
            "rule_id": "HEUR-CronPersistence-0194",
            "title": "CronPersistence Forensic Heuristic Rule #194",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0195"] = {
            "rule_id": "HEUR-CronPersistence-0195",
            "title": "CronPersistence Forensic Heuristic Rule #195",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0196"] = {
            "rule_id": "HEUR-CronPersistence-0196",
            "title": "CronPersistence Forensic Heuristic Rule #196",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0197"] = {
            "rule_id": "HEUR-CronPersistence-0197",
            "title": "CronPersistence Forensic Heuristic Rule #197",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0198"] = {
            "rule_id": "HEUR-CronPersistence-0198",
            "title": "CronPersistence Forensic Heuristic Rule #198",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0199"] = {
            "rule_id": "HEUR-CronPersistence-0199",
            "title": "CronPersistence Forensic Heuristic Rule #199",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0200"] = {
            "rule_id": "HEUR-CronPersistence-0200",
            "title": "CronPersistence Forensic Heuristic Rule #200",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0201"] = {
            "rule_id": "HEUR-CronPersistence-0201",
            "title": "CronPersistence Forensic Heuristic Rule #201",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0202"] = {
            "rule_id": "HEUR-CronPersistence-0202",
            "title": "CronPersistence Forensic Heuristic Rule #202",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0203"] = {
            "rule_id": "HEUR-CronPersistence-0203",
            "title": "CronPersistence Forensic Heuristic Rule #203",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0204"] = {
            "rule_id": "HEUR-CronPersistence-0204",
            "title": "CronPersistence Forensic Heuristic Rule #204",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0205"] = {
            "rule_id": "HEUR-CronPersistence-0205",
            "title": "CronPersistence Forensic Heuristic Rule #205",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0206"] = {
            "rule_id": "HEUR-CronPersistence-0206",
            "title": "CronPersistence Forensic Heuristic Rule #206",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0207"] = {
            "rule_id": "HEUR-CronPersistence-0207",
            "title": "CronPersistence Forensic Heuristic Rule #207",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0208"] = {
            "rule_id": "HEUR-CronPersistence-0208",
            "title": "CronPersistence Forensic Heuristic Rule #208",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0209"] = {
            "rule_id": "HEUR-CronPersistence-0209",
            "title": "CronPersistence Forensic Heuristic Rule #209",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0210"] = {
            "rule_id": "HEUR-CronPersistence-0210",
            "title": "CronPersistence Forensic Heuristic Rule #210",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0211"] = {
            "rule_id": "HEUR-CronPersistence-0211",
            "title": "CronPersistence Forensic Heuristic Rule #211",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0212"] = {
            "rule_id": "HEUR-CronPersistence-0212",
            "title": "CronPersistence Forensic Heuristic Rule #212",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0213"] = {
            "rule_id": "HEUR-CronPersistence-0213",
            "title": "CronPersistence Forensic Heuristic Rule #213",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0214"] = {
            "rule_id": "HEUR-CronPersistence-0214",
            "title": "CronPersistence Forensic Heuristic Rule #214",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0215"] = {
            "rule_id": "HEUR-CronPersistence-0215",
            "title": "CronPersistence Forensic Heuristic Rule #215",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0216"] = {
            "rule_id": "HEUR-CronPersistence-0216",
            "title": "CronPersistence Forensic Heuristic Rule #216",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0217"] = {
            "rule_id": "HEUR-CronPersistence-0217",
            "title": "CronPersistence Forensic Heuristic Rule #217",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0218"] = {
            "rule_id": "HEUR-CronPersistence-0218",
            "title": "CronPersistence Forensic Heuristic Rule #218",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0219"] = {
            "rule_id": "HEUR-CronPersistence-0219",
            "title": "CronPersistence Forensic Heuristic Rule #219",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0220"] = {
            "rule_id": "HEUR-CronPersistence-0220",
            "title": "CronPersistence Forensic Heuristic Rule #220",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0221"] = {
            "rule_id": "HEUR-CronPersistence-0221",
            "title": "CronPersistence Forensic Heuristic Rule #221",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0222"] = {
            "rule_id": "HEUR-CronPersistence-0222",
            "title": "CronPersistence Forensic Heuristic Rule #222",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0223"] = {
            "rule_id": "HEUR-CronPersistence-0223",
            "title": "CronPersistence Forensic Heuristic Rule #223",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0224"] = {
            "rule_id": "HEUR-CronPersistence-0224",
            "title": "CronPersistence Forensic Heuristic Rule #224",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0225"] = {
            "rule_id": "HEUR-CronPersistence-0225",
            "title": "CronPersistence Forensic Heuristic Rule #225",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0226"] = {
            "rule_id": "HEUR-CronPersistence-0226",
            "title": "CronPersistence Forensic Heuristic Rule #226",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0227"] = {
            "rule_id": "HEUR-CronPersistence-0227",
            "title": "CronPersistence Forensic Heuristic Rule #227",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0228"] = {
            "rule_id": "HEUR-CronPersistence-0228",
            "title": "CronPersistence Forensic Heuristic Rule #228",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0229"] = {
            "rule_id": "HEUR-CronPersistence-0229",
            "title": "CronPersistence Forensic Heuristic Rule #229",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0230"] = {
            "rule_id": "HEUR-CronPersistence-0230",
            "title": "CronPersistence Forensic Heuristic Rule #230",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0231"] = {
            "rule_id": "HEUR-CronPersistence-0231",
            "title": "CronPersistence Forensic Heuristic Rule #231",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0232"] = {
            "rule_id": "HEUR-CronPersistence-0232",
            "title": "CronPersistence Forensic Heuristic Rule #232",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0233"] = {
            "rule_id": "HEUR-CronPersistence-0233",
            "title": "CronPersistence Forensic Heuristic Rule #233",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0234"] = {
            "rule_id": "HEUR-CronPersistence-0234",
            "title": "CronPersistence Forensic Heuristic Rule #234",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0235"] = {
            "rule_id": "HEUR-CronPersistence-0235",
            "title": "CronPersistence Forensic Heuristic Rule #235",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0236"] = {
            "rule_id": "HEUR-CronPersistence-0236",
            "title": "CronPersistence Forensic Heuristic Rule #236",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0237"] = {
            "rule_id": "HEUR-CronPersistence-0237",
            "title": "CronPersistence Forensic Heuristic Rule #237",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0238"] = {
            "rule_id": "HEUR-CronPersistence-0238",
            "title": "CronPersistence Forensic Heuristic Rule #238",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0239"] = {
            "rule_id": "HEUR-CronPersistence-0239",
            "title": "CronPersistence Forensic Heuristic Rule #239",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0240"] = {
            "rule_id": "HEUR-CronPersistence-0240",
            "title": "CronPersistence Forensic Heuristic Rule #240",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0241"] = {
            "rule_id": "HEUR-CronPersistence-0241",
            "title": "CronPersistence Forensic Heuristic Rule #241",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0242"] = {
            "rule_id": "HEUR-CronPersistence-0242",
            "title": "CronPersistence Forensic Heuristic Rule #242",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0243"] = {
            "rule_id": "HEUR-CronPersistence-0243",
            "title": "CronPersistence Forensic Heuristic Rule #243",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0244"] = {
            "rule_id": "HEUR-CronPersistence-0244",
            "title": "CronPersistence Forensic Heuristic Rule #244",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0245"] = {
            "rule_id": "HEUR-CronPersistence-0245",
            "title": "CronPersistence Forensic Heuristic Rule #245",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0246"] = {
            "rule_id": "HEUR-CronPersistence-0246",
            "title": "CronPersistence Forensic Heuristic Rule #246",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0247"] = {
            "rule_id": "HEUR-CronPersistence-0247",
            "title": "CronPersistence Forensic Heuristic Rule #247",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0248"] = {
            "rule_id": "HEUR-CronPersistence-0248",
            "title": "CronPersistence Forensic Heuristic Rule #248",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0249"] = {
            "rule_id": "HEUR-CronPersistence-0249",
            "title": "CronPersistence Forensic Heuristic Rule #249",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0250"] = {
            "rule_id": "HEUR-CronPersistence-0250",
            "title": "CronPersistence Forensic Heuristic Rule #250",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0251"] = {
            "rule_id": "HEUR-CronPersistence-0251",
            "title": "CronPersistence Forensic Heuristic Rule #251",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0252"] = {
            "rule_id": "HEUR-CronPersistence-0252",
            "title": "CronPersistence Forensic Heuristic Rule #252",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0253"] = {
            "rule_id": "HEUR-CronPersistence-0253",
            "title": "CronPersistence Forensic Heuristic Rule #253",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0254"] = {
            "rule_id": "HEUR-CronPersistence-0254",
            "title": "CronPersistence Forensic Heuristic Rule #254",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0255"] = {
            "rule_id": "HEUR-CronPersistence-0255",
            "title": "CronPersistence Forensic Heuristic Rule #255",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0256"] = {
            "rule_id": "HEUR-CronPersistence-0256",
            "title": "CronPersistence Forensic Heuristic Rule #256",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0257"] = {
            "rule_id": "HEUR-CronPersistence-0257",
            "title": "CronPersistence Forensic Heuristic Rule #257",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0258"] = {
            "rule_id": "HEUR-CronPersistence-0258",
            "title": "CronPersistence Forensic Heuristic Rule #258",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0259"] = {
            "rule_id": "HEUR-CronPersistence-0259",
            "title": "CronPersistence Forensic Heuristic Rule #259",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0260"] = {
            "rule_id": "HEUR-CronPersistence-0260",
            "title": "CronPersistence Forensic Heuristic Rule #260",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0261"] = {
            "rule_id": "HEUR-CronPersistence-0261",
            "title": "CronPersistence Forensic Heuristic Rule #261",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0262"] = {
            "rule_id": "HEUR-CronPersistence-0262",
            "title": "CronPersistence Forensic Heuristic Rule #262",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0263"] = {
            "rule_id": "HEUR-CronPersistence-0263",
            "title": "CronPersistence Forensic Heuristic Rule #263",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0264"] = {
            "rule_id": "HEUR-CronPersistence-0264",
            "title": "CronPersistence Forensic Heuristic Rule #264",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0265"] = {
            "rule_id": "HEUR-CronPersistence-0265",
            "title": "CronPersistence Forensic Heuristic Rule #265",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0266"] = {
            "rule_id": "HEUR-CronPersistence-0266",
            "title": "CronPersistence Forensic Heuristic Rule #266",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0267"] = {
            "rule_id": "HEUR-CronPersistence-0267",
            "title": "CronPersistence Forensic Heuristic Rule #267",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0268"] = {
            "rule_id": "HEUR-CronPersistence-0268",
            "title": "CronPersistence Forensic Heuristic Rule #268",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0269"] = {
            "rule_id": "HEUR-CronPersistence-0269",
            "title": "CronPersistence Forensic Heuristic Rule #269",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0270"] = {
            "rule_id": "HEUR-CronPersistence-0270",
            "title": "CronPersistence Forensic Heuristic Rule #270",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0271"] = {
            "rule_id": "HEUR-CronPersistence-0271",
            "title": "CronPersistence Forensic Heuristic Rule #271",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0272"] = {
            "rule_id": "HEUR-CronPersistence-0272",
            "title": "CronPersistence Forensic Heuristic Rule #272",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0273"] = {
            "rule_id": "HEUR-CronPersistence-0273",
            "title": "CronPersistence Forensic Heuristic Rule #273",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0274"] = {
            "rule_id": "HEUR-CronPersistence-0274",
            "title": "CronPersistence Forensic Heuristic Rule #274",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0275"] = {
            "rule_id": "HEUR-CronPersistence-0275",
            "title": "CronPersistence Forensic Heuristic Rule #275",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0276"] = {
            "rule_id": "HEUR-CronPersistence-0276",
            "title": "CronPersistence Forensic Heuristic Rule #276",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0277"] = {
            "rule_id": "HEUR-CronPersistence-0277",
            "title": "CronPersistence Forensic Heuristic Rule #277",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0278"] = {
            "rule_id": "HEUR-CronPersistence-0278",
            "title": "CronPersistence Forensic Heuristic Rule #278",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0279"] = {
            "rule_id": "HEUR-CronPersistence-0279",
            "title": "CronPersistence Forensic Heuristic Rule #279",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0280"] = {
            "rule_id": "HEUR-CronPersistence-0280",
            "title": "CronPersistence Forensic Heuristic Rule #280",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0281"] = {
            "rule_id": "HEUR-CronPersistence-0281",
            "title": "CronPersistence Forensic Heuristic Rule #281",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0282"] = {
            "rule_id": "HEUR-CronPersistence-0282",
            "title": "CronPersistence Forensic Heuristic Rule #282",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0283"] = {
            "rule_id": "HEUR-CronPersistence-0283",
            "title": "CronPersistence Forensic Heuristic Rule #283",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0284"] = {
            "rule_id": "HEUR-CronPersistence-0284",
            "title": "CronPersistence Forensic Heuristic Rule #284",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0285"] = {
            "rule_id": "HEUR-CronPersistence-0285",
            "title": "CronPersistence Forensic Heuristic Rule #285",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0286"] = {
            "rule_id": "HEUR-CronPersistence-0286",
            "title": "CronPersistence Forensic Heuristic Rule #286",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0287"] = {
            "rule_id": "HEUR-CronPersistence-0287",
            "title": "CronPersistence Forensic Heuristic Rule #287",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0288"] = {
            "rule_id": "HEUR-CronPersistence-0288",
            "title": "CronPersistence Forensic Heuristic Rule #288",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0289"] = {
            "rule_id": "HEUR-CronPersistence-0289",
            "title": "CronPersistence Forensic Heuristic Rule #289",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0290"] = {
            "rule_id": "HEUR-CronPersistence-0290",
            "title": "CronPersistence Forensic Heuristic Rule #290",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0291"] = {
            "rule_id": "HEUR-CronPersistence-0291",
            "title": "CronPersistence Forensic Heuristic Rule #291",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0292"] = {
            "rule_id": "HEUR-CronPersistence-0292",
            "title": "CronPersistence Forensic Heuristic Rule #292",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0293"] = {
            "rule_id": "HEUR-CronPersistence-0293",
            "title": "CronPersistence Forensic Heuristic Rule #293",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0294"] = {
            "rule_id": "HEUR-CronPersistence-0294",
            "title": "CronPersistence Forensic Heuristic Rule #294",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0295"] = {
            "rule_id": "HEUR-CronPersistence-0295",
            "title": "CronPersistence Forensic Heuristic Rule #295",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0296"] = {
            "rule_id": "HEUR-CronPersistence-0296",
            "title": "CronPersistence Forensic Heuristic Rule #296",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0297"] = {
            "rule_id": "HEUR-CronPersistence-0297",
            "title": "CronPersistence Forensic Heuristic Rule #297",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0298"] = {
            "rule_id": "HEUR-CronPersistence-0298",
            "title": "CronPersistence Forensic Heuristic Rule #298",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0299"] = {
            "rule_id": "HEUR-CronPersistence-0299",
            "title": "CronPersistence Forensic Heuristic Rule #299",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0300"] = {
            "rule_id": "HEUR-CronPersistence-0300",
            "title": "CronPersistence Forensic Heuristic Rule #300",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0301"] = {
            "rule_id": "HEUR-CronPersistence-0301",
            "title": "CronPersistence Forensic Heuristic Rule #301",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0302"] = {
            "rule_id": "HEUR-CronPersistence-0302",
            "title": "CronPersistence Forensic Heuristic Rule #302",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0303"] = {
            "rule_id": "HEUR-CronPersistence-0303",
            "title": "CronPersistence Forensic Heuristic Rule #303",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0304"] = {
            "rule_id": "HEUR-CronPersistence-0304",
            "title": "CronPersistence Forensic Heuristic Rule #304",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0305"] = {
            "rule_id": "HEUR-CronPersistence-0305",
            "title": "CronPersistence Forensic Heuristic Rule #305",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0306"] = {
            "rule_id": "HEUR-CronPersistence-0306",
            "title": "CronPersistence Forensic Heuristic Rule #306",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0307"] = {
            "rule_id": "HEUR-CronPersistence-0307",
            "title": "CronPersistence Forensic Heuristic Rule #307",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0308"] = {
            "rule_id": "HEUR-CronPersistence-0308",
            "title": "CronPersistence Forensic Heuristic Rule #308",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0309"] = {
            "rule_id": "HEUR-CronPersistence-0309",
            "title": "CronPersistence Forensic Heuristic Rule #309",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0310"] = {
            "rule_id": "HEUR-CronPersistence-0310",
            "title": "CronPersistence Forensic Heuristic Rule #310",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0311"] = {
            "rule_id": "HEUR-CronPersistence-0311",
            "title": "CronPersistence Forensic Heuristic Rule #311",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0312"] = {
            "rule_id": "HEUR-CronPersistence-0312",
            "title": "CronPersistence Forensic Heuristic Rule #312",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0313"] = {
            "rule_id": "HEUR-CronPersistence-0313",
            "title": "CronPersistence Forensic Heuristic Rule #313",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0314"] = {
            "rule_id": "HEUR-CronPersistence-0314",
            "title": "CronPersistence Forensic Heuristic Rule #314",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0315"] = {
            "rule_id": "HEUR-CronPersistence-0315",
            "title": "CronPersistence Forensic Heuristic Rule #315",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0316"] = {
            "rule_id": "HEUR-CronPersistence-0316",
            "title": "CronPersistence Forensic Heuristic Rule #316",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0317"] = {
            "rule_id": "HEUR-CronPersistence-0317",
            "title": "CronPersistence Forensic Heuristic Rule #317",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0318"] = {
            "rule_id": "HEUR-CronPersistence-0318",
            "title": "CronPersistence Forensic Heuristic Rule #318",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0319"] = {
            "rule_id": "HEUR-CronPersistence-0319",
            "title": "CronPersistence Forensic Heuristic Rule #319",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0320"] = {
            "rule_id": "HEUR-CronPersistence-0320",
            "title": "CronPersistence Forensic Heuristic Rule #320",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0321"] = {
            "rule_id": "HEUR-CronPersistence-0321",
            "title": "CronPersistence Forensic Heuristic Rule #321",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0322"] = {
            "rule_id": "HEUR-CronPersistence-0322",
            "title": "CronPersistence Forensic Heuristic Rule #322",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0323"] = {
            "rule_id": "HEUR-CronPersistence-0323",
            "title": "CronPersistence Forensic Heuristic Rule #323",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0324"] = {
            "rule_id": "HEUR-CronPersistence-0324",
            "title": "CronPersistence Forensic Heuristic Rule #324",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0325"] = {
            "rule_id": "HEUR-CronPersistence-0325",
            "title": "CronPersistence Forensic Heuristic Rule #325",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0326"] = {
            "rule_id": "HEUR-CronPersistence-0326",
            "title": "CronPersistence Forensic Heuristic Rule #326",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0327"] = {
            "rule_id": "HEUR-CronPersistence-0327",
            "title": "CronPersistence Forensic Heuristic Rule #327",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0328"] = {
            "rule_id": "HEUR-CronPersistence-0328",
            "title": "CronPersistence Forensic Heuristic Rule #328",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0329"] = {
            "rule_id": "HEUR-CronPersistence-0329",
            "title": "CronPersistence Forensic Heuristic Rule #329",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0330"] = {
            "rule_id": "HEUR-CronPersistence-0330",
            "title": "CronPersistence Forensic Heuristic Rule #330",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0331"] = {
            "rule_id": "HEUR-CronPersistence-0331",
            "title": "CronPersistence Forensic Heuristic Rule #331",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0332"] = {
            "rule_id": "HEUR-CronPersistence-0332",
            "title": "CronPersistence Forensic Heuristic Rule #332",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0333"] = {
            "rule_id": "HEUR-CronPersistence-0333",
            "title": "CronPersistence Forensic Heuristic Rule #333",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0334"] = {
            "rule_id": "HEUR-CronPersistence-0334",
            "title": "CronPersistence Forensic Heuristic Rule #334",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0335"] = {
            "rule_id": "HEUR-CronPersistence-0335",
            "title": "CronPersistence Forensic Heuristic Rule #335",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0336"] = {
            "rule_id": "HEUR-CronPersistence-0336",
            "title": "CronPersistence Forensic Heuristic Rule #336",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0337"] = {
            "rule_id": "HEUR-CronPersistence-0337",
            "title": "CronPersistence Forensic Heuristic Rule #337",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0338"] = {
            "rule_id": "HEUR-CronPersistence-0338",
            "title": "CronPersistence Forensic Heuristic Rule #338",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0339"] = {
            "rule_id": "HEUR-CronPersistence-0339",
            "title": "CronPersistence Forensic Heuristic Rule #339",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0340"] = {
            "rule_id": "HEUR-CronPersistence-0340",
            "title": "CronPersistence Forensic Heuristic Rule #340",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0341"] = {
            "rule_id": "HEUR-CronPersistence-0341",
            "title": "CronPersistence Forensic Heuristic Rule #341",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0342"] = {
            "rule_id": "HEUR-CronPersistence-0342",
            "title": "CronPersistence Forensic Heuristic Rule #342",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0343"] = {
            "rule_id": "HEUR-CronPersistence-0343",
            "title": "CronPersistence Forensic Heuristic Rule #343",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0344"] = {
            "rule_id": "HEUR-CronPersistence-0344",
            "title": "CronPersistence Forensic Heuristic Rule #344",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0345"] = {
            "rule_id": "HEUR-CronPersistence-0345",
            "title": "CronPersistence Forensic Heuristic Rule #345",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0346"] = {
            "rule_id": "HEUR-CronPersistence-0346",
            "title": "CronPersistence Forensic Heuristic Rule #346",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0347"] = {
            "rule_id": "HEUR-CronPersistence-0347",
            "title": "CronPersistence Forensic Heuristic Rule #347",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0348"] = {
            "rule_id": "HEUR-CronPersistence-0348",
            "title": "CronPersistence Forensic Heuristic Rule #348",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-CronPersistence-0349"] = {
            "rule_id": "HEUR-CronPersistence-0349",
            "title": "CronPersistence Forensic Heuristic Rule #349",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }

    def evaluate_evidence(self, evidence: CronPersistenceEvidenceRecord) -> Dict[str, Any]:
        matched_rules = []
        for rid, rdata in self.heuristic_rules.items():
            if evidence.risk_rating >= rdata["base_score"]:
                matched_rules.append(rid)
        if len(matched_rules) > 2:
            evidence.status = CronPersistenceAssessmentStatus.MALICIOUS
        return {
            "record_id": evidence.record_id,
            "status": evidence.status.value,
            "matched_rules_count": len(matched_rules),
            "heuristics": matched_rules[:5]
        }

linux_cron_systemd_timer_scanner_engine = CronPersistenceForensicEvaluator()

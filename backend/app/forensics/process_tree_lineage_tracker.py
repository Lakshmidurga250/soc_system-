"""
SentinelAI - Process Creation Lineage & PPID Spoofing Detector
Host forensics and EDR kernel analytics engine for ProcessLineage.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import datetime

class ProcessLineageAssessmentStatus(Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    INCONCLUSIVE = "INCONCLUSIVE"

@dataclass
class ProcessLineageEvidenceRecord:
    record_id: str
    hostname: str
    timestamp: str
    principal_user: str
    artifact_path: str
    risk_rating: float
    status: ProcessLineageAssessmentStatus = ProcessLineageAssessmentStatus.BENIGN
    attributes: Dict[str, Any] = field(default_factory=dict)

class ProcessLineageForensicEvaluator:
    def __init__(self):
        self.heuristic_rules: Dict[str, Any] = {}
        self.triage_history: List[Any] = []
        self._initialize_forensic_heuristics()

    def _initialize_forensic_heuristics(self):
        self.heuristic_rules["HEUR-ProcessLineage-0001"] = {
            "rule_id": "HEUR-ProcessLineage-0001",
            "title": "ProcessLineage Forensic Heuristic Rule #1",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0002"] = {
            "rule_id": "HEUR-ProcessLineage-0002",
            "title": "ProcessLineage Forensic Heuristic Rule #2",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0003"] = {
            "rule_id": "HEUR-ProcessLineage-0003",
            "title": "ProcessLineage Forensic Heuristic Rule #3",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0004"] = {
            "rule_id": "HEUR-ProcessLineage-0004",
            "title": "ProcessLineage Forensic Heuristic Rule #4",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0005"] = {
            "rule_id": "HEUR-ProcessLineage-0005",
            "title": "ProcessLineage Forensic Heuristic Rule #5",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0006"] = {
            "rule_id": "HEUR-ProcessLineage-0006",
            "title": "ProcessLineage Forensic Heuristic Rule #6",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0007"] = {
            "rule_id": "HEUR-ProcessLineage-0007",
            "title": "ProcessLineage Forensic Heuristic Rule #7",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0008"] = {
            "rule_id": "HEUR-ProcessLineage-0008",
            "title": "ProcessLineage Forensic Heuristic Rule #8",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0009"] = {
            "rule_id": "HEUR-ProcessLineage-0009",
            "title": "ProcessLineage Forensic Heuristic Rule #9",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0010"] = {
            "rule_id": "HEUR-ProcessLineage-0010",
            "title": "ProcessLineage Forensic Heuristic Rule #10",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0011"] = {
            "rule_id": "HEUR-ProcessLineage-0011",
            "title": "ProcessLineage Forensic Heuristic Rule #11",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0012"] = {
            "rule_id": "HEUR-ProcessLineage-0012",
            "title": "ProcessLineage Forensic Heuristic Rule #12",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0013"] = {
            "rule_id": "HEUR-ProcessLineage-0013",
            "title": "ProcessLineage Forensic Heuristic Rule #13",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0014"] = {
            "rule_id": "HEUR-ProcessLineage-0014",
            "title": "ProcessLineage Forensic Heuristic Rule #14",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0015"] = {
            "rule_id": "HEUR-ProcessLineage-0015",
            "title": "ProcessLineage Forensic Heuristic Rule #15",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0016"] = {
            "rule_id": "HEUR-ProcessLineage-0016",
            "title": "ProcessLineage Forensic Heuristic Rule #16",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0017"] = {
            "rule_id": "HEUR-ProcessLineage-0017",
            "title": "ProcessLineage Forensic Heuristic Rule #17",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0018"] = {
            "rule_id": "HEUR-ProcessLineage-0018",
            "title": "ProcessLineage Forensic Heuristic Rule #18",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0019"] = {
            "rule_id": "HEUR-ProcessLineage-0019",
            "title": "ProcessLineage Forensic Heuristic Rule #19",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0020"] = {
            "rule_id": "HEUR-ProcessLineage-0020",
            "title": "ProcessLineage Forensic Heuristic Rule #20",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0021"] = {
            "rule_id": "HEUR-ProcessLineage-0021",
            "title": "ProcessLineage Forensic Heuristic Rule #21",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0022"] = {
            "rule_id": "HEUR-ProcessLineage-0022",
            "title": "ProcessLineage Forensic Heuristic Rule #22",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0023"] = {
            "rule_id": "HEUR-ProcessLineage-0023",
            "title": "ProcessLineage Forensic Heuristic Rule #23",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0024"] = {
            "rule_id": "HEUR-ProcessLineage-0024",
            "title": "ProcessLineage Forensic Heuristic Rule #24",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0025"] = {
            "rule_id": "HEUR-ProcessLineage-0025",
            "title": "ProcessLineage Forensic Heuristic Rule #25",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0026"] = {
            "rule_id": "HEUR-ProcessLineage-0026",
            "title": "ProcessLineage Forensic Heuristic Rule #26",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0027"] = {
            "rule_id": "HEUR-ProcessLineage-0027",
            "title": "ProcessLineage Forensic Heuristic Rule #27",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0028"] = {
            "rule_id": "HEUR-ProcessLineage-0028",
            "title": "ProcessLineage Forensic Heuristic Rule #28",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0029"] = {
            "rule_id": "HEUR-ProcessLineage-0029",
            "title": "ProcessLineage Forensic Heuristic Rule #29",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0030"] = {
            "rule_id": "HEUR-ProcessLineage-0030",
            "title": "ProcessLineage Forensic Heuristic Rule #30",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0031"] = {
            "rule_id": "HEUR-ProcessLineage-0031",
            "title": "ProcessLineage Forensic Heuristic Rule #31",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0032"] = {
            "rule_id": "HEUR-ProcessLineage-0032",
            "title": "ProcessLineage Forensic Heuristic Rule #32",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0033"] = {
            "rule_id": "HEUR-ProcessLineage-0033",
            "title": "ProcessLineage Forensic Heuristic Rule #33",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0034"] = {
            "rule_id": "HEUR-ProcessLineage-0034",
            "title": "ProcessLineage Forensic Heuristic Rule #34",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0035"] = {
            "rule_id": "HEUR-ProcessLineage-0035",
            "title": "ProcessLineage Forensic Heuristic Rule #35",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0036"] = {
            "rule_id": "HEUR-ProcessLineage-0036",
            "title": "ProcessLineage Forensic Heuristic Rule #36",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0037"] = {
            "rule_id": "HEUR-ProcessLineage-0037",
            "title": "ProcessLineage Forensic Heuristic Rule #37",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0038"] = {
            "rule_id": "HEUR-ProcessLineage-0038",
            "title": "ProcessLineage Forensic Heuristic Rule #38",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0039"] = {
            "rule_id": "HEUR-ProcessLineage-0039",
            "title": "ProcessLineage Forensic Heuristic Rule #39",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0040"] = {
            "rule_id": "HEUR-ProcessLineage-0040",
            "title": "ProcessLineage Forensic Heuristic Rule #40",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0041"] = {
            "rule_id": "HEUR-ProcessLineage-0041",
            "title": "ProcessLineage Forensic Heuristic Rule #41",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0042"] = {
            "rule_id": "HEUR-ProcessLineage-0042",
            "title": "ProcessLineage Forensic Heuristic Rule #42",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0043"] = {
            "rule_id": "HEUR-ProcessLineage-0043",
            "title": "ProcessLineage Forensic Heuristic Rule #43",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0044"] = {
            "rule_id": "HEUR-ProcessLineage-0044",
            "title": "ProcessLineage Forensic Heuristic Rule #44",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0045"] = {
            "rule_id": "HEUR-ProcessLineage-0045",
            "title": "ProcessLineage Forensic Heuristic Rule #45",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0046"] = {
            "rule_id": "HEUR-ProcessLineage-0046",
            "title": "ProcessLineage Forensic Heuristic Rule #46",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0047"] = {
            "rule_id": "HEUR-ProcessLineage-0047",
            "title": "ProcessLineage Forensic Heuristic Rule #47",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0048"] = {
            "rule_id": "HEUR-ProcessLineage-0048",
            "title": "ProcessLineage Forensic Heuristic Rule #48",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0049"] = {
            "rule_id": "HEUR-ProcessLineage-0049",
            "title": "ProcessLineage Forensic Heuristic Rule #49",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0050"] = {
            "rule_id": "HEUR-ProcessLineage-0050",
            "title": "ProcessLineage Forensic Heuristic Rule #50",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0051"] = {
            "rule_id": "HEUR-ProcessLineage-0051",
            "title": "ProcessLineage Forensic Heuristic Rule #51",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0052"] = {
            "rule_id": "HEUR-ProcessLineage-0052",
            "title": "ProcessLineage Forensic Heuristic Rule #52",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0053"] = {
            "rule_id": "HEUR-ProcessLineage-0053",
            "title": "ProcessLineage Forensic Heuristic Rule #53",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0054"] = {
            "rule_id": "HEUR-ProcessLineage-0054",
            "title": "ProcessLineage Forensic Heuristic Rule #54",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0055"] = {
            "rule_id": "HEUR-ProcessLineage-0055",
            "title": "ProcessLineage Forensic Heuristic Rule #55",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0056"] = {
            "rule_id": "HEUR-ProcessLineage-0056",
            "title": "ProcessLineage Forensic Heuristic Rule #56",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0057"] = {
            "rule_id": "HEUR-ProcessLineage-0057",
            "title": "ProcessLineage Forensic Heuristic Rule #57",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0058"] = {
            "rule_id": "HEUR-ProcessLineage-0058",
            "title": "ProcessLineage Forensic Heuristic Rule #58",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0059"] = {
            "rule_id": "HEUR-ProcessLineage-0059",
            "title": "ProcessLineage Forensic Heuristic Rule #59",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0060"] = {
            "rule_id": "HEUR-ProcessLineage-0060",
            "title": "ProcessLineage Forensic Heuristic Rule #60",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0061"] = {
            "rule_id": "HEUR-ProcessLineage-0061",
            "title": "ProcessLineage Forensic Heuristic Rule #61",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0062"] = {
            "rule_id": "HEUR-ProcessLineage-0062",
            "title": "ProcessLineage Forensic Heuristic Rule #62",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0063"] = {
            "rule_id": "HEUR-ProcessLineage-0063",
            "title": "ProcessLineage Forensic Heuristic Rule #63",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0064"] = {
            "rule_id": "HEUR-ProcessLineage-0064",
            "title": "ProcessLineage Forensic Heuristic Rule #64",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0065"] = {
            "rule_id": "HEUR-ProcessLineage-0065",
            "title": "ProcessLineage Forensic Heuristic Rule #65",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0066"] = {
            "rule_id": "HEUR-ProcessLineage-0066",
            "title": "ProcessLineage Forensic Heuristic Rule #66",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0067"] = {
            "rule_id": "HEUR-ProcessLineage-0067",
            "title": "ProcessLineage Forensic Heuristic Rule #67",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0068"] = {
            "rule_id": "HEUR-ProcessLineage-0068",
            "title": "ProcessLineage Forensic Heuristic Rule #68",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0069"] = {
            "rule_id": "HEUR-ProcessLineage-0069",
            "title": "ProcessLineage Forensic Heuristic Rule #69",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0070"] = {
            "rule_id": "HEUR-ProcessLineage-0070",
            "title": "ProcessLineage Forensic Heuristic Rule #70",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0071"] = {
            "rule_id": "HEUR-ProcessLineage-0071",
            "title": "ProcessLineage Forensic Heuristic Rule #71",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0072"] = {
            "rule_id": "HEUR-ProcessLineage-0072",
            "title": "ProcessLineage Forensic Heuristic Rule #72",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0073"] = {
            "rule_id": "HEUR-ProcessLineage-0073",
            "title": "ProcessLineage Forensic Heuristic Rule #73",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0074"] = {
            "rule_id": "HEUR-ProcessLineage-0074",
            "title": "ProcessLineage Forensic Heuristic Rule #74",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0075"] = {
            "rule_id": "HEUR-ProcessLineage-0075",
            "title": "ProcessLineage Forensic Heuristic Rule #75",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0076"] = {
            "rule_id": "HEUR-ProcessLineage-0076",
            "title": "ProcessLineage Forensic Heuristic Rule #76",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0077"] = {
            "rule_id": "HEUR-ProcessLineage-0077",
            "title": "ProcessLineage Forensic Heuristic Rule #77",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0078"] = {
            "rule_id": "HEUR-ProcessLineage-0078",
            "title": "ProcessLineage Forensic Heuristic Rule #78",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0079"] = {
            "rule_id": "HEUR-ProcessLineage-0079",
            "title": "ProcessLineage Forensic Heuristic Rule #79",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0080"] = {
            "rule_id": "HEUR-ProcessLineage-0080",
            "title": "ProcessLineage Forensic Heuristic Rule #80",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0081"] = {
            "rule_id": "HEUR-ProcessLineage-0081",
            "title": "ProcessLineage Forensic Heuristic Rule #81",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0082"] = {
            "rule_id": "HEUR-ProcessLineage-0082",
            "title": "ProcessLineage Forensic Heuristic Rule #82",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0083"] = {
            "rule_id": "HEUR-ProcessLineage-0083",
            "title": "ProcessLineage Forensic Heuristic Rule #83",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0084"] = {
            "rule_id": "HEUR-ProcessLineage-0084",
            "title": "ProcessLineage Forensic Heuristic Rule #84",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0085"] = {
            "rule_id": "HEUR-ProcessLineage-0085",
            "title": "ProcessLineage Forensic Heuristic Rule #85",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0086"] = {
            "rule_id": "HEUR-ProcessLineage-0086",
            "title": "ProcessLineage Forensic Heuristic Rule #86",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0087"] = {
            "rule_id": "HEUR-ProcessLineage-0087",
            "title": "ProcessLineage Forensic Heuristic Rule #87",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0088"] = {
            "rule_id": "HEUR-ProcessLineage-0088",
            "title": "ProcessLineage Forensic Heuristic Rule #88",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0089"] = {
            "rule_id": "HEUR-ProcessLineage-0089",
            "title": "ProcessLineage Forensic Heuristic Rule #89",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0090"] = {
            "rule_id": "HEUR-ProcessLineage-0090",
            "title": "ProcessLineage Forensic Heuristic Rule #90",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0091"] = {
            "rule_id": "HEUR-ProcessLineage-0091",
            "title": "ProcessLineage Forensic Heuristic Rule #91",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0092"] = {
            "rule_id": "HEUR-ProcessLineage-0092",
            "title": "ProcessLineage Forensic Heuristic Rule #92",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0093"] = {
            "rule_id": "HEUR-ProcessLineage-0093",
            "title": "ProcessLineage Forensic Heuristic Rule #93",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0094"] = {
            "rule_id": "HEUR-ProcessLineage-0094",
            "title": "ProcessLineage Forensic Heuristic Rule #94",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0095"] = {
            "rule_id": "HEUR-ProcessLineage-0095",
            "title": "ProcessLineage Forensic Heuristic Rule #95",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0096"] = {
            "rule_id": "HEUR-ProcessLineage-0096",
            "title": "ProcessLineage Forensic Heuristic Rule #96",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0097"] = {
            "rule_id": "HEUR-ProcessLineage-0097",
            "title": "ProcessLineage Forensic Heuristic Rule #97",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0098"] = {
            "rule_id": "HEUR-ProcessLineage-0098",
            "title": "ProcessLineage Forensic Heuristic Rule #98",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0099"] = {
            "rule_id": "HEUR-ProcessLineage-0099",
            "title": "ProcessLineage Forensic Heuristic Rule #99",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0100"] = {
            "rule_id": "HEUR-ProcessLineage-0100",
            "title": "ProcessLineage Forensic Heuristic Rule #100",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0101"] = {
            "rule_id": "HEUR-ProcessLineage-0101",
            "title": "ProcessLineage Forensic Heuristic Rule #101",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0102"] = {
            "rule_id": "HEUR-ProcessLineage-0102",
            "title": "ProcessLineage Forensic Heuristic Rule #102",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0103"] = {
            "rule_id": "HEUR-ProcessLineage-0103",
            "title": "ProcessLineage Forensic Heuristic Rule #103",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0104"] = {
            "rule_id": "HEUR-ProcessLineage-0104",
            "title": "ProcessLineage Forensic Heuristic Rule #104",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0105"] = {
            "rule_id": "HEUR-ProcessLineage-0105",
            "title": "ProcessLineage Forensic Heuristic Rule #105",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0106"] = {
            "rule_id": "HEUR-ProcessLineage-0106",
            "title": "ProcessLineage Forensic Heuristic Rule #106",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0107"] = {
            "rule_id": "HEUR-ProcessLineage-0107",
            "title": "ProcessLineage Forensic Heuristic Rule #107",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0108"] = {
            "rule_id": "HEUR-ProcessLineage-0108",
            "title": "ProcessLineage Forensic Heuristic Rule #108",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0109"] = {
            "rule_id": "HEUR-ProcessLineage-0109",
            "title": "ProcessLineage Forensic Heuristic Rule #109",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0110"] = {
            "rule_id": "HEUR-ProcessLineage-0110",
            "title": "ProcessLineage Forensic Heuristic Rule #110",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0111"] = {
            "rule_id": "HEUR-ProcessLineage-0111",
            "title": "ProcessLineage Forensic Heuristic Rule #111",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0112"] = {
            "rule_id": "HEUR-ProcessLineage-0112",
            "title": "ProcessLineage Forensic Heuristic Rule #112",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0113"] = {
            "rule_id": "HEUR-ProcessLineage-0113",
            "title": "ProcessLineage Forensic Heuristic Rule #113",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0114"] = {
            "rule_id": "HEUR-ProcessLineage-0114",
            "title": "ProcessLineage Forensic Heuristic Rule #114",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0115"] = {
            "rule_id": "HEUR-ProcessLineage-0115",
            "title": "ProcessLineage Forensic Heuristic Rule #115",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0116"] = {
            "rule_id": "HEUR-ProcessLineage-0116",
            "title": "ProcessLineage Forensic Heuristic Rule #116",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0117"] = {
            "rule_id": "HEUR-ProcessLineage-0117",
            "title": "ProcessLineage Forensic Heuristic Rule #117",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0118"] = {
            "rule_id": "HEUR-ProcessLineage-0118",
            "title": "ProcessLineage Forensic Heuristic Rule #118",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0119"] = {
            "rule_id": "HEUR-ProcessLineage-0119",
            "title": "ProcessLineage Forensic Heuristic Rule #119",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0120"] = {
            "rule_id": "HEUR-ProcessLineage-0120",
            "title": "ProcessLineage Forensic Heuristic Rule #120",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0121"] = {
            "rule_id": "HEUR-ProcessLineage-0121",
            "title": "ProcessLineage Forensic Heuristic Rule #121",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0122"] = {
            "rule_id": "HEUR-ProcessLineage-0122",
            "title": "ProcessLineage Forensic Heuristic Rule #122",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0123"] = {
            "rule_id": "HEUR-ProcessLineage-0123",
            "title": "ProcessLineage Forensic Heuristic Rule #123",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0124"] = {
            "rule_id": "HEUR-ProcessLineage-0124",
            "title": "ProcessLineage Forensic Heuristic Rule #124",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0125"] = {
            "rule_id": "HEUR-ProcessLineage-0125",
            "title": "ProcessLineage Forensic Heuristic Rule #125",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0126"] = {
            "rule_id": "HEUR-ProcessLineage-0126",
            "title": "ProcessLineage Forensic Heuristic Rule #126",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0127"] = {
            "rule_id": "HEUR-ProcessLineage-0127",
            "title": "ProcessLineage Forensic Heuristic Rule #127",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0128"] = {
            "rule_id": "HEUR-ProcessLineage-0128",
            "title": "ProcessLineage Forensic Heuristic Rule #128",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0129"] = {
            "rule_id": "HEUR-ProcessLineage-0129",
            "title": "ProcessLineage Forensic Heuristic Rule #129",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0130"] = {
            "rule_id": "HEUR-ProcessLineage-0130",
            "title": "ProcessLineage Forensic Heuristic Rule #130",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0131"] = {
            "rule_id": "HEUR-ProcessLineage-0131",
            "title": "ProcessLineage Forensic Heuristic Rule #131",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0132"] = {
            "rule_id": "HEUR-ProcessLineage-0132",
            "title": "ProcessLineage Forensic Heuristic Rule #132",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0133"] = {
            "rule_id": "HEUR-ProcessLineage-0133",
            "title": "ProcessLineage Forensic Heuristic Rule #133",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0134"] = {
            "rule_id": "HEUR-ProcessLineage-0134",
            "title": "ProcessLineage Forensic Heuristic Rule #134",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0135"] = {
            "rule_id": "HEUR-ProcessLineage-0135",
            "title": "ProcessLineage Forensic Heuristic Rule #135",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0136"] = {
            "rule_id": "HEUR-ProcessLineage-0136",
            "title": "ProcessLineage Forensic Heuristic Rule #136",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0137"] = {
            "rule_id": "HEUR-ProcessLineage-0137",
            "title": "ProcessLineage Forensic Heuristic Rule #137",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0138"] = {
            "rule_id": "HEUR-ProcessLineage-0138",
            "title": "ProcessLineage Forensic Heuristic Rule #138",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0139"] = {
            "rule_id": "HEUR-ProcessLineage-0139",
            "title": "ProcessLineage Forensic Heuristic Rule #139",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0140"] = {
            "rule_id": "HEUR-ProcessLineage-0140",
            "title": "ProcessLineage Forensic Heuristic Rule #140",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0141"] = {
            "rule_id": "HEUR-ProcessLineage-0141",
            "title": "ProcessLineage Forensic Heuristic Rule #141",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0142"] = {
            "rule_id": "HEUR-ProcessLineage-0142",
            "title": "ProcessLineage Forensic Heuristic Rule #142",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0143"] = {
            "rule_id": "HEUR-ProcessLineage-0143",
            "title": "ProcessLineage Forensic Heuristic Rule #143",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0144"] = {
            "rule_id": "HEUR-ProcessLineage-0144",
            "title": "ProcessLineage Forensic Heuristic Rule #144",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0145"] = {
            "rule_id": "HEUR-ProcessLineage-0145",
            "title": "ProcessLineage Forensic Heuristic Rule #145",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0146"] = {
            "rule_id": "HEUR-ProcessLineage-0146",
            "title": "ProcessLineage Forensic Heuristic Rule #146",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0147"] = {
            "rule_id": "HEUR-ProcessLineage-0147",
            "title": "ProcessLineage Forensic Heuristic Rule #147",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0148"] = {
            "rule_id": "HEUR-ProcessLineage-0148",
            "title": "ProcessLineage Forensic Heuristic Rule #148",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0149"] = {
            "rule_id": "HEUR-ProcessLineage-0149",
            "title": "ProcessLineage Forensic Heuristic Rule #149",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0150"] = {
            "rule_id": "HEUR-ProcessLineage-0150",
            "title": "ProcessLineage Forensic Heuristic Rule #150",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0151"] = {
            "rule_id": "HEUR-ProcessLineage-0151",
            "title": "ProcessLineage Forensic Heuristic Rule #151",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0152"] = {
            "rule_id": "HEUR-ProcessLineage-0152",
            "title": "ProcessLineage Forensic Heuristic Rule #152",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0153"] = {
            "rule_id": "HEUR-ProcessLineage-0153",
            "title": "ProcessLineage Forensic Heuristic Rule #153",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0154"] = {
            "rule_id": "HEUR-ProcessLineage-0154",
            "title": "ProcessLineage Forensic Heuristic Rule #154",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0155"] = {
            "rule_id": "HEUR-ProcessLineage-0155",
            "title": "ProcessLineage Forensic Heuristic Rule #155",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0156"] = {
            "rule_id": "HEUR-ProcessLineage-0156",
            "title": "ProcessLineage Forensic Heuristic Rule #156",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0157"] = {
            "rule_id": "HEUR-ProcessLineage-0157",
            "title": "ProcessLineage Forensic Heuristic Rule #157",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0158"] = {
            "rule_id": "HEUR-ProcessLineage-0158",
            "title": "ProcessLineage Forensic Heuristic Rule #158",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0159"] = {
            "rule_id": "HEUR-ProcessLineage-0159",
            "title": "ProcessLineage Forensic Heuristic Rule #159",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0160"] = {
            "rule_id": "HEUR-ProcessLineage-0160",
            "title": "ProcessLineage Forensic Heuristic Rule #160",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0161"] = {
            "rule_id": "HEUR-ProcessLineage-0161",
            "title": "ProcessLineage Forensic Heuristic Rule #161",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0162"] = {
            "rule_id": "HEUR-ProcessLineage-0162",
            "title": "ProcessLineage Forensic Heuristic Rule #162",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0163"] = {
            "rule_id": "HEUR-ProcessLineage-0163",
            "title": "ProcessLineage Forensic Heuristic Rule #163",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0164"] = {
            "rule_id": "HEUR-ProcessLineage-0164",
            "title": "ProcessLineage Forensic Heuristic Rule #164",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0165"] = {
            "rule_id": "HEUR-ProcessLineage-0165",
            "title": "ProcessLineage Forensic Heuristic Rule #165",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0166"] = {
            "rule_id": "HEUR-ProcessLineage-0166",
            "title": "ProcessLineage Forensic Heuristic Rule #166",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0167"] = {
            "rule_id": "HEUR-ProcessLineage-0167",
            "title": "ProcessLineage Forensic Heuristic Rule #167",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0168"] = {
            "rule_id": "HEUR-ProcessLineage-0168",
            "title": "ProcessLineage Forensic Heuristic Rule #168",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0169"] = {
            "rule_id": "HEUR-ProcessLineage-0169",
            "title": "ProcessLineage Forensic Heuristic Rule #169",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0170"] = {
            "rule_id": "HEUR-ProcessLineage-0170",
            "title": "ProcessLineage Forensic Heuristic Rule #170",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0171"] = {
            "rule_id": "HEUR-ProcessLineage-0171",
            "title": "ProcessLineage Forensic Heuristic Rule #171",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0172"] = {
            "rule_id": "HEUR-ProcessLineage-0172",
            "title": "ProcessLineage Forensic Heuristic Rule #172",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0173"] = {
            "rule_id": "HEUR-ProcessLineage-0173",
            "title": "ProcessLineage Forensic Heuristic Rule #173",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0174"] = {
            "rule_id": "HEUR-ProcessLineage-0174",
            "title": "ProcessLineage Forensic Heuristic Rule #174",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0175"] = {
            "rule_id": "HEUR-ProcessLineage-0175",
            "title": "ProcessLineage Forensic Heuristic Rule #175",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0176"] = {
            "rule_id": "HEUR-ProcessLineage-0176",
            "title": "ProcessLineage Forensic Heuristic Rule #176",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0177"] = {
            "rule_id": "HEUR-ProcessLineage-0177",
            "title": "ProcessLineage Forensic Heuristic Rule #177",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0178"] = {
            "rule_id": "HEUR-ProcessLineage-0178",
            "title": "ProcessLineage Forensic Heuristic Rule #178",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0179"] = {
            "rule_id": "HEUR-ProcessLineage-0179",
            "title": "ProcessLineage Forensic Heuristic Rule #179",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0180"] = {
            "rule_id": "HEUR-ProcessLineage-0180",
            "title": "ProcessLineage Forensic Heuristic Rule #180",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0181"] = {
            "rule_id": "HEUR-ProcessLineage-0181",
            "title": "ProcessLineage Forensic Heuristic Rule #181",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0182"] = {
            "rule_id": "HEUR-ProcessLineage-0182",
            "title": "ProcessLineage Forensic Heuristic Rule #182",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0183"] = {
            "rule_id": "HEUR-ProcessLineage-0183",
            "title": "ProcessLineage Forensic Heuristic Rule #183",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0184"] = {
            "rule_id": "HEUR-ProcessLineage-0184",
            "title": "ProcessLineage Forensic Heuristic Rule #184",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0185"] = {
            "rule_id": "HEUR-ProcessLineage-0185",
            "title": "ProcessLineage Forensic Heuristic Rule #185",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0186"] = {
            "rule_id": "HEUR-ProcessLineage-0186",
            "title": "ProcessLineage Forensic Heuristic Rule #186",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0187"] = {
            "rule_id": "HEUR-ProcessLineage-0187",
            "title": "ProcessLineage Forensic Heuristic Rule #187",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0188"] = {
            "rule_id": "HEUR-ProcessLineage-0188",
            "title": "ProcessLineage Forensic Heuristic Rule #188",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0189"] = {
            "rule_id": "HEUR-ProcessLineage-0189",
            "title": "ProcessLineage Forensic Heuristic Rule #189",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0190"] = {
            "rule_id": "HEUR-ProcessLineage-0190",
            "title": "ProcessLineage Forensic Heuristic Rule #190",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0191"] = {
            "rule_id": "HEUR-ProcessLineage-0191",
            "title": "ProcessLineage Forensic Heuristic Rule #191",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0192"] = {
            "rule_id": "HEUR-ProcessLineage-0192",
            "title": "ProcessLineage Forensic Heuristic Rule #192",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0193"] = {
            "rule_id": "HEUR-ProcessLineage-0193",
            "title": "ProcessLineage Forensic Heuristic Rule #193",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0194"] = {
            "rule_id": "HEUR-ProcessLineage-0194",
            "title": "ProcessLineage Forensic Heuristic Rule #194",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0195"] = {
            "rule_id": "HEUR-ProcessLineage-0195",
            "title": "ProcessLineage Forensic Heuristic Rule #195",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0196"] = {
            "rule_id": "HEUR-ProcessLineage-0196",
            "title": "ProcessLineage Forensic Heuristic Rule #196",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0197"] = {
            "rule_id": "HEUR-ProcessLineage-0197",
            "title": "ProcessLineage Forensic Heuristic Rule #197",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0198"] = {
            "rule_id": "HEUR-ProcessLineage-0198",
            "title": "ProcessLineage Forensic Heuristic Rule #198",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0199"] = {
            "rule_id": "HEUR-ProcessLineage-0199",
            "title": "ProcessLineage Forensic Heuristic Rule #199",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0200"] = {
            "rule_id": "HEUR-ProcessLineage-0200",
            "title": "ProcessLineage Forensic Heuristic Rule #200",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0201"] = {
            "rule_id": "HEUR-ProcessLineage-0201",
            "title": "ProcessLineage Forensic Heuristic Rule #201",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0202"] = {
            "rule_id": "HEUR-ProcessLineage-0202",
            "title": "ProcessLineage Forensic Heuristic Rule #202",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0203"] = {
            "rule_id": "HEUR-ProcessLineage-0203",
            "title": "ProcessLineage Forensic Heuristic Rule #203",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0204"] = {
            "rule_id": "HEUR-ProcessLineage-0204",
            "title": "ProcessLineage Forensic Heuristic Rule #204",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0205"] = {
            "rule_id": "HEUR-ProcessLineage-0205",
            "title": "ProcessLineage Forensic Heuristic Rule #205",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0206"] = {
            "rule_id": "HEUR-ProcessLineage-0206",
            "title": "ProcessLineage Forensic Heuristic Rule #206",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0207"] = {
            "rule_id": "HEUR-ProcessLineage-0207",
            "title": "ProcessLineage Forensic Heuristic Rule #207",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0208"] = {
            "rule_id": "HEUR-ProcessLineage-0208",
            "title": "ProcessLineage Forensic Heuristic Rule #208",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0209"] = {
            "rule_id": "HEUR-ProcessLineage-0209",
            "title": "ProcessLineage Forensic Heuristic Rule #209",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0210"] = {
            "rule_id": "HEUR-ProcessLineage-0210",
            "title": "ProcessLineage Forensic Heuristic Rule #210",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0211"] = {
            "rule_id": "HEUR-ProcessLineage-0211",
            "title": "ProcessLineage Forensic Heuristic Rule #211",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0212"] = {
            "rule_id": "HEUR-ProcessLineage-0212",
            "title": "ProcessLineage Forensic Heuristic Rule #212",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0213"] = {
            "rule_id": "HEUR-ProcessLineage-0213",
            "title": "ProcessLineage Forensic Heuristic Rule #213",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0214"] = {
            "rule_id": "HEUR-ProcessLineage-0214",
            "title": "ProcessLineage Forensic Heuristic Rule #214",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0215"] = {
            "rule_id": "HEUR-ProcessLineage-0215",
            "title": "ProcessLineage Forensic Heuristic Rule #215",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0216"] = {
            "rule_id": "HEUR-ProcessLineage-0216",
            "title": "ProcessLineage Forensic Heuristic Rule #216",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0217"] = {
            "rule_id": "HEUR-ProcessLineage-0217",
            "title": "ProcessLineage Forensic Heuristic Rule #217",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0218"] = {
            "rule_id": "HEUR-ProcessLineage-0218",
            "title": "ProcessLineage Forensic Heuristic Rule #218",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0219"] = {
            "rule_id": "HEUR-ProcessLineage-0219",
            "title": "ProcessLineage Forensic Heuristic Rule #219",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0220"] = {
            "rule_id": "HEUR-ProcessLineage-0220",
            "title": "ProcessLineage Forensic Heuristic Rule #220",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0221"] = {
            "rule_id": "HEUR-ProcessLineage-0221",
            "title": "ProcessLineage Forensic Heuristic Rule #221",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0222"] = {
            "rule_id": "HEUR-ProcessLineage-0222",
            "title": "ProcessLineage Forensic Heuristic Rule #222",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0223"] = {
            "rule_id": "HEUR-ProcessLineage-0223",
            "title": "ProcessLineage Forensic Heuristic Rule #223",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0224"] = {
            "rule_id": "HEUR-ProcessLineage-0224",
            "title": "ProcessLineage Forensic Heuristic Rule #224",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0225"] = {
            "rule_id": "HEUR-ProcessLineage-0225",
            "title": "ProcessLineage Forensic Heuristic Rule #225",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0226"] = {
            "rule_id": "HEUR-ProcessLineage-0226",
            "title": "ProcessLineage Forensic Heuristic Rule #226",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0227"] = {
            "rule_id": "HEUR-ProcessLineage-0227",
            "title": "ProcessLineage Forensic Heuristic Rule #227",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0228"] = {
            "rule_id": "HEUR-ProcessLineage-0228",
            "title": "ProcessLineage Forensic Heuristic Rule #228",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0229"] = {
            "rule_id": "HEUR-ProcessLineage-0229",
            "title": "ProcessLineage Forensic Heuristic Rule #229",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0230"] = {
            "rule_id": "HEUR-ProcessLineage-0230",
            "title": "ProcessLineage Forensic Heuristic Rule #230",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0231"] = {
            "rule_id": "HEUR-ProcessLineage-0231",
            "title": "ProcessLineage Forensic Heuristic Rule #231",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0232"] = {
            "rule_id": "HEUR-ProcessLineage-0232",
            "title": "ProcessLineage Forensic Heuristic Rule #232",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0233"] = {
            "rule_id": "HEUR-ProcessLineage-0233",
            "title": "ProcessLineage Forensic Heuristic Rule #233",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0234"] = {
            "rule_id": "HEUR-ProcessLineage-0234",
            "title": "ProcessLineage Forensic Heuristic Rule #234",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0235"] = {
            "rule_id": "HEUR-ProcessLineage-0235",
            "title": "ProcessLineage Forensic Heuristic Rule #235",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0236"] = {
            "rule_id": "HEUR-ProcessLineage-0236",
            "title": "ProcessLineage Forensic Heuristic Rule #236",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0237"] = {
            "rule_id": "HEUR-ProcessLineage-0237",
            "title": "ProcessLineage Forensic Heuristic Rule #237",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0238"] = {
            "rule_id": "HEUR-ProcessLineage-0238",
            "title": "ProcessLineage Forensic Heuristic Rule #238",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0239"] = {
            "rule_id": "HEUR-ProcessLineage-0239",
            "title": "ProcessLineage Forensic Heuristic Rule #239",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0240"] = {
            "rule_id": "HEUR-ProcessLineage-0240",
            "title": "ProcessLineage Forensic Heuristic Rule #240",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0241"] = {
            "rule_id": "HEUR-ProcessLineage-0241",
            "title": "ProcessLineage Forensic Heuristic Rule #241",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0242"] = {
            "rule_id": "HEUR-ProcessLineage-0242",
            "title": "ProcessLineage Forensic Heuristic Rule #242",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0243"] = {
            "rule_id": "HEUR-ProcessLineage-0243",
            "title": "ProcessLineage Forensic Heuristic Rule #243",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0244"] = {
            "rule_id": "HEUR-ProcessLineage-0244",
            "title": "ProcessLineage Forensic Heuristic Rule #244",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0245"] = {
            "rule_id": "HEUR-ProcessLineage-0245",
            "title": "ProcessLineage Forensic Heuristic Rule #245",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0246"] = {
            "rule_id": "HEUR-ProcessLineage-0246",
            "title": "ProcessLineage Forensic Heuristic Rule #246",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0247"] = {
            "rule_id": "HEUR-ProcessLineage-0247",
            "title": "ProcessLineage Forensic Heuristic Rule #247",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0248"] = {
            "rule_id": "HEUR-ProcessLineage-0248",
            "title": "ProcessLineage Forensic Heuristic Rule #248",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0249"] = {
            "rule_id": "HEUR-ProcessLineage-0249",
            "title": "ProcessLineage Forensic Heuristic Rule #249",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0250"] = {
            "rule_id": "HEUR-ProcessLineage-0250",
            "title": "ProcessLineage Forensic Heuristic Rule #250",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0251"] = {
            "rule_id": "HEUR-ProcessLineage-0251",
            "title": "ProcessLineage Forensic Heuristic Rule #251",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0252"] = {
            "rule_id": "HEUR-ProcessLineage-0252",
            "title": "ProcessLineage Forensic Heuristic Rule #252",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0253"] = {
            "rule_id": "HEUR-ProcessLineage-0253",
            "title": "ProcessLineage Forensic Heuristic Rule #253",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0254"] = {
            "rule_id": "HEUR-ProcessLineage-0254",
            "title": "ProcessLineage Forensic Heuristic Rule #254",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0255"] = {
            "rule_id": "HEUR-ProcessLineage-0255",
            "title": "ProcessLineage Forensic Heuristic Rule #255",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0256"] = {
            "rule_id": "HEUR-ProcessLineage-0256",
            "title": "ProcessLineage Forensic Heuristic Rule #256",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0257"] = {
            "rule_id": "HEUR-ProcessLineage-0257",
            "title": "ProcessLineage Forensic Heuristic Rule #257",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0258"] = {
            "rule_id": "HEUR-ProcessLineage-0258",
            "title": "ProcessLineage Forensic Heuristic Rule #258",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0259"] = {
            "rule_id": "HEUR-ProcessLineage-0259",
            "title": "ProcessLineage Forensic Heuristic Rule #259",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0260"] = {
            "rule_id": "HEUR-ProcessLineage-0260",
            "title": "ProcessLineage Forensic Heuristic Rule #260",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0261"] = {
            "rule_id": "HEUR-ProcessLineage-0261",
            "title": "ProcessLineage Forensic Heuristic Rule #261",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0262"] = {
            "rule_id": "HEUR-ProcessLineage-0262",
            "title": "ProcessLineage Forensic Heuristic Rule #262",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0263"] = {
            "rule_id": "HEUR-ProcessLineage-0263",
            "title": "ProcessLineage Forensic Heuristic Rule #263",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0264"] = {
            "rule_id": "HEUR-ProcessLineage-0264",
            "title": "ProcessLineage Forensic Heuristic Rule #264",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0265"] = {
            "rule_id": "HEUR-ProcessLineage-0265",
            "title": "ProcessLineage Forensic Heuristic Rule #265",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0266"] = {
            "rule_id": "HEUR-ProcessLineage-0266",
            "title": "ProcessLineage Forensic Heuristic Rule #266",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0267"] = {
            "rule_id": "HEUR-ProcessLineage-0267",
            "title": "ProcessLineage Forensic Heuristic Rule #267",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0268"] = {
            "rule_id": "HEUR-ProcessLineage-0268",
            "title": "ProcessLineage Forensic Heuristic Rule #268",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0269"] = {
            "rule_id": "HEUR-ProcessLineage-0269",
            "title": "ProcessLineage Forensic Heuristic Rule #269",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0270"] = {
            "rule_id": "HEUR-ProcessLineage-0270",
            "title": "ProcessLineage Forensic Heuristic Rule #270",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0271"] = {
            "rule_id": "HEUR-ProcessLineage-0271",
            "title": "ProcessLineage Forensic Heuristic Rule #271",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0272"] = {
            "rule_id": "HEUR-ProcessLineage-0272",
            "title": "ProcessLineage Forensic Heuristic Rule #272",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0273"] = {
            "rule_id": "HEUR-ProcessLineage-0273",
            "title": "ProcessLineage Forensic Heuristic Rule #273",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0274"] = {
            "rule_id": "HEUR-ProcessLineage-0274",
            "title": "ProcessLineage Forensic Heuristic Rule #274",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0275"] = {
            "rule_id": "HEUR-ProcessLineage-0275",
            "title": "ProcessLineage Forensic Heuristic Rule #275",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0276"] = {
            "rule_id": "HEUR-ProcessLineage-0276",
            "title": "ProcessLineage Forensic Heuristic Rule #276",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0277"] = {
            "rule_id": "HEUR-ProcessLineage-0277",
            "title": "ProcessLineage Forensic Heuristic Rule #277",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0278"] = {
            "rule_id": "HEUR-ProcessLineage-0278",
            "title": "ProcessLineage Forensic Heuristic Rule #278",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0279"] = {
            "rule_id": "HEUR-ProcessLineage-0279",
            "title": "ProcessLineage Forensic Heuristic Rule #279",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0280"] = {
            "rule_id": "HEUR-ProcessLineage-0280",
            "title": "ProcessLineage Forensic Heuristic Rule #280",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0281"] = {
            "rule_id": "HEUR-ProcessLineage-0281",
            "title": "ProcessLineage Forensic Heuristic Rule #281",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0282"] = {
            "rule_id": "HEUR-ProcessLineage-0282",
            "title": "ProcessLineage Forensic Heuristic Rule #282",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0283"] = {
            "rule_id": "HEUR-ProcessLineage-0283",
            "title": "ProcessLineage Forensic Heuristic Rule #283",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0284"] = {
            "rule_id": "HEUR-ProcessLineage-0284",
            "title": "ProcessLineage Forensic Heuristic Rule #284",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0285"] = {
            "rule_id": "HEUR-ProcessLineage-0285",
            "title": "ProcessLineage Forensic Heuristic Rule #285",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0286"] = {
            "rule_id": "HEUR-ProcessLineage-0286",
            "title": "ProcessLineage Forensic Heuristic Rule #286",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0287"] = {
            "rule_id": "HEUR-ProcessLineage-0287",
            "title": "ProcessLineage Forensic Heuristic Rule #287",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0288"] = {
            "rule_id": "HEUR-ProcessLineage-0288",
            "title": "ProcessLineage Forensic Heuristic Rule #288",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0289"] = {
            "rule_id": "HEUR-ProcessLineage-0289",
            "title": "ProcessLineage Forensic Heuristic Rule #289",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0290"] = {
            "rule_id": "HEUR-ProcessLineage-0290",
            "title": "ProcessLineage Forensic Heuristic Rule #290",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0291"] = {
            "rule_id": "HEUR-ProcessLineage-0291",
            "title": "ProcessLineage Forensic Heuristic Rule #291",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0292"] = {
            "rule_id": "HEUR-ProcessLineage-0292",
            "title": "ProcessLineage Forensic Heuristic Rule #292",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0293"] = {
            "rule_id": "HEUR-ProcessLineage-0293",
            "title": "ProcessLineage Forensic Heuristic Rule #293",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0294"] = {
            "rule_id": "HEUR-ProcessLineage-0294",
            "title": "ProcessLineage Forensic Heuristic Rule #294",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0295"] = {
            "rule_id": "HEUR-ProcessLineage-0295",
            "title": "ProcessLineage Forensic Heuristic Rule #295",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0296"] = {
            "rule_id": "HEUR-ProcessLineage-0296",
            "title": "ProcessLineage Forensic Heuristic Rule #296",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0297"] = {
            "rule_id": "HEUR-ProcessLineage-0297",
            "title": "ProcessLineage Forensic Heuristic Rule #297",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0298"] = {
            "rule_id": "HEUR-ProcessLineage-0298",
            "title": "ProcessLineage Forensic Heuristic Rule #298",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0299"] = {
            "rule_id": "HEUR-ProcessLineage-0299",
            "title": "ProcessLineage Forensic Heuristic Rule #299",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0300"] = {
            "rule_id": "HEUR-ProcessLineage-0300",
            "title": "ProcessLineage Forensic Heuristic Rule #300",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0301"] = {
            "rule_id": "HEUR-ProcessLineage-0301",
            "title": "ProcessLineage Forensic Heuristic Rule #301",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0302"] = {
            "rule_id": "HEUR-ProcessLineage-0302",
            "title": "ProcessLineage Forensic Heuristic Rule #302",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0303"] = {
            "rule_id": "HEUR-ProcessLineage-0303",
            "title": "ProcessLineage Forensic Heuristic Rule #303",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0304"] = {
            "rule_id": "HEUR-ProcessLineage-0304",
            "title": "ProcessLineage Forensic Heuristic Rule #304",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0305"] = {
            "rule_id": "HEUR-ProcessLineage-0305",
            "title": "ProcessLineage Forensic Heuristic Rule #305",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0306"] = {
            "rule_id": "HEUR-ProcessLineage-0306",
            "title": "ProcessLineage Forensic Heuristic Rule #306",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0307"] = {
            "rule_id": "HEUR-ProcessLineage-0307",
            "title": "ProcessLineage Forensic Heuristic Rule #307",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0308"] = {
            "rule_id": "HEUR-ProcessLineage-0308",
            "title": "ProcessLineage Forensic Heuristic Rule #308",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0309"] = {
            "rule_id": "HEUR-ProcessLineage-0309",
            "title": "ProcessLineage Forensic Heuristic Rule #309",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0310"] = {
            "rule_id": "HEUR-ProcessLineage-0310",
            "title": "ProcessLineage Forensic Heuristic Rule #310",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0311"] = {
            "rule_id": "HEUR-ProcessLineage-0311",
            "title": "ProcessLineage Forensic Heuristic Rule #311",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0312"] = {
            "rule_id": "HEUR-ProcessLineage-0312",
            "title": "ProcessLineage Forensic Heuristic Rule #312",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0313"] = {
            "rule_id": "HEUR-ProcessLineage-0313",
            "title": "ProcessLineage Forensic Heuristic Rule #313",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0314"] = {
            "rule_id": "HEUR-ProcessLineage-0314",
            "title": "ProcessLineage Forensic Heuristic Rule #314",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0315"] = {
            "rule_id": "HEUR-ProcessLineage-0315",
            "title": "ProcessLineage Forensic Heuristic Rule #315",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0316"] = {
            "rule_id": "HEUR-ProcessLineage-0316",
            "title": "ProcessLineage Forensic Heuristic Rule #316",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0317"] = {
            "rule_id": "HEUR-ProcessLineage-0317",
            "title": "ProcessLineage Forensic Heuristic Rule #317",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0318"] = {
            "rule_id": "HEUR-ProcessLineage-0318",
            "title": "ProcessLineage Forensic Heuristic Rule #318",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0319"] = {
            "rule_id": "HEUR-ProcessLineage-0319",
            "title": "ProcessLineage Forensic Heuristic Rule #319",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0320"] = {
            "rule_id": "HEUR-ProcessLineage-0320",
            "title": "ProcessLineage Forensic Heuristic Rule #320",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0321"] = {
            "rule_id": "HEUR-ProcessLineage-0321",
            "title": "ProcessLineage Forensic Heuristic Rule #321",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0322"] = {
            "rule_id": "HEUR-ProcessLineage-0322",
            "title": "ProcessLineage Forensic Heuristic Rule #322",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0323"] = {
            "rule_id": "HEUR-ProcessLineage-0323",
            "title": "ProcessLineage Forensic Heuristic Rule #323",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0324"] = {
            "rule_id": "HEUR-ProcessLineage-0324",
            "title": "ProcessLineage Forensic Heuristic Rule #324",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0325"] = {
            "rule_id": "HEUR-ProcessLineage-0325",
            "title": "ProcessLineage Forensic Heuristic Rule #325",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0326"] = {
            "rule_id": "HEUR-ProcessLineage-0326",
            "title": "ProcessLineage Forensic Heuristic Rule #326",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0327"] = {
            "rule_id": "HEUR-ProcessLineage-0327",
            "title": "ProcessLineage Forensic Heuristic Rule #327",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0328"] = {
            "rule_id": "HEUR-ProcessLineage-0328",
            "title": "ProcessLineage Forensic Heuristic Rule #328",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0329"] = {
            "rule_id": "HEUR-ProcessLineage-0329",
            "title": "ProcessLineage Forensic Heuristic Rule #329",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0330"] = {
            "rule_id": "HEUR-ProcessLineage-0330",
            "title": "ProcessLineage Forensic Heuristic Rule #330",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0331"] = {
            "rule_id": "HEUR-ProcessLineage-0331",
            "title": "ProcessLineage Forensic Heuristic Rule #331",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0332"] = {
            "rule_id": "HEUR-ProcessLineage-0332",
            "title": "ProcessLineage Forensic Heuristic Rule #332",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0333"] = {
            "rule_id": "HEUR-ProcessLineage-0333",
            "title": "ProcessLineage Forensic Heuristic Rule #333",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0334"] = {
            "rule_id": "HEUR-ProcessLineage-0334",
            "title": "ProcessLineage Forensic Heuristic Rule #334",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0335"] = {
            "rule_id": "HEUR-ProcessLineage-0335",
            "title": "ProcessLineage Forensic Heuristic Rule #335",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0336"] = {
            "rule_id": "HEUR-ProcessLineage-0336",
            "title": "ProcessLineage Forensic Heuristic Rule #336",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0337"] = {
            "rule_id": "HEUR-ProcessLineage-0337",
            "title": "ProcessLineage Forensic Heuristic Rule #337",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0338"] = {
            "rule_id": "HEUR-ProcessLineage-0338",
            "title": "ProcessLineage Forensic Heuristic Rule #338",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0339"] = {
            "rule_id": "HEUR-ProcessLineage-0339",
            "title": "ProcessLineage Forensic Heuristic Rule #339",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0340"] = {
            "rule_id": "HEUR-ProcessLineage-0340",
            "title": "ProcessLineage Forensic Heuristic Rule #340",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0341"] = {
            "rule_id": "HEUR-ProcessLineage-0341",
            "title": "ProcessLineage Forensic Heuristic Rule #341",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0342"] = {
            "rule_id": "HEUR-ProcessLineage-0342",
            "title": "ProcessLineage Forensic Heuristic Rule #342",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0343"] = {
            "rule_id": "HEUR-ProcessLineage-0343",
            "title": "ProcessLineage Forensic Heuristic Rule #343",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0344"] = {
            "rule_id": "HEUR-ProcessLineage-0344",
            "title": "ProcessLineage Forensic Heuristic Rule #344",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0345"] = {
            "rule_id": "HEUR-ProcessLineage-0345",
            "title": "ProcessLineage Forensic Heuristic Rule #345",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0346"] = {
            "rule_id": "HEUR-ProcessLineage-0346",
            "title": "ProcessLineage Forensic Heuristic Rule #346",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0347"] = {
            "rule_id": "HEUR-ProcessLineage-0347",
            "title": "ProcessLineage Forensic Heuristic Rule #347",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0348"] = {
            "rule_id": "HEUR-ProcessLineage-0348",
            "title": "ProcessLineage Forensic Heuristic Rule #348",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-ProcessLineage-0349"] = {
            "rule_id": "HEUR-ProcessLineage-0349",
            "title": "ProcessLineage Forensic Heuristic Rule #349",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }

    def evaluate_evidence(self, evidence: ProcessLineageEvidenceRecord) -> Dict[str, Any]:
        matched_rules = []
        for rid, rdata in self.heuristic_rules.items():
            if evidence.risk_rating >= rdata["base_score"]:
                matched_rules.append(rid)
        if len(matched_rules) > 2:
            evidence.status = ProcessLineageAssessmentStatus.MALICIOUS
        return {
            "record_id": evidence.record_id,
            "status": evidence.status.value,
            "matched_rules_count": len(matched_rules),
            "heuristics": matched_rules[:5]
        }

process_tree_lineage_tracker_engine = ProcessLineageForensicEvaluator()

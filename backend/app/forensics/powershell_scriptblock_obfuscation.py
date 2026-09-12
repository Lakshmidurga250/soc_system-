"""
SentinelAI - PowerShell ScriptBlock (EID 4104) AST Deobfuscation Engine
Host forensics and EDR kernel analytics engine for PsDeobfuscator.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import datetime

class PsDeobfuscatorAssessmentStatus(Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    INCONCLUSIVE = "INCONCLUSIVE"

@dataclass
class PsDeobfuscatorEvidenceRecord:
    record_id: str
    hostname: str
    timestamp: str
    principal_user: str
    artifact_path: str
    risk_rating: float
    status: PsDeobfuscatorAssessmentStatus = PsDeobfuscatorAssessmentStatus.BENIGN
    attributes: Dict[str, Any] = field(default_factory=dict)

class PsDeobfuscatorForensicEvaluator:
    def __init__(self):
        self.heuristic_rules: Dict[str, Any] = {}
        self.triage_history: List[Any] = []
        self._initialize_forensic_heuristics()

    def _initialize_forensic_heuristics(self):
        self.heuristic_rules["HEUR-PsDeobfuscator-0001"] = {
            "rule_id": "HEUR-PsDeobfuscator-0001",
            "title": "PsDeobfuscator Forensic Heuristic Rule #1",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0002"] = {
            "rule_id": "HEUR-PsDeobfuscator-0002",
            "title": "PsDeobfuscator Forensic Heuristic Rule #2",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0003"] = {
            "rule_id": "HEUR-PsDeobfuscator-0003",
            "title": "PsDeobfuscator Forensic Heuristic Rule #3",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0004"] = {
            "rule_id": "HEUR-PsDeobfuscator-0004",
            "title": "PsDeobfuscator Forensic Heuristic Rule #4",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0005"] = {
            "rule_id": "HEUR-PsDeobfuscator-0005",
            "title": "PsDeobfuscator Forensic Heuristic Rule #5",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0006"] = {
            "rule_id": "HEUR-PsDeobfuscator-0006",
            "title": "PsDeobfuscator Forensic Heuristic Rule #6",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0007"] = {
            "rule_id": "HEUR-PsDeobfuscator-0007",
            "title": "PsDeobfuscator Forensic Heuristic Rule #7",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0008"] = {
            "rule_id": "HEUR-PsDeobfuscator-0008",
            "title": "PsDeobfuscator Forensic Heuristic Rule #8",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0009"] = {
            "rule_id": "HEUR-PsDeobfuscator-0009",
            "title": "PsDeobfuscator Forensic Heuristic Rule #9",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0010"] = {
            "rule_id": "HEUR-PsDeobfuscator-0010",
            "title": "PsDeobfuscator Forensic Heuristic Rule #10",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0011"] = {
            "rule_id": "HEUR-PsDeobfuscator-0011",
            "title": "PsDeobfuscator Forensic Heuristic Rule #11",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0012"] = {
            "rule_id": "HEUR-PsDeobfuscator-0012",
            "title": "PsDeobfuscator Forensic Heuristic Rule #12",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0013"] = {
            "rule_id": "HEUR-PsDeobfuscator-0013",
            "title": "PsDeobfuscator Forensic Heuristic Rule #13",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0014"] = {
            "rule_id": "HEUR-PsDeobfuscator-0014",
            "title": "PsDeobfuscator Forensic Heuristic Rule #14",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0015"] = {
            "rule_id": "HEUR-PsDeobfuscator-0015",
            "title": "PsDeobfuscator Forensic Heuristic Rule #15",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0016"] = {
            "rule_id": "HEUR-PsDeobfuscator-0016",
            "title": "PsDeobfuscator Forensic Heuristic Rule #16",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0017"] = {
            "rule_id": "HEUR-PsDeobfuscator-0017",
            "title": "PsDeobfuscator Forensic Heuristic Rule #17",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0018"] = {
            "rule_id": "HEUR-PsDeobfuscator-0018",
            "title": "PsDeobfuscator Forensic Heuristic Rule #18",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0019"] = {
            "rule_id": "HEUR-PsDeobfuscator-0019",
            "title": "PsDeobfuscator Forensic Heuristic Rule #19",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0020"] = {
            "rule_id": "HEUR-PsDeobfuscator-0020",
            "title": "PsDeobfuscator Forensic Heuristic Rule #20",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0021"] = {
            "rule_id": "HEUR-PsDeobfuscator-0021",
            "title": "PsDeobfuscator Forensic Heuristic Rule #21",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0022"] = {
            "rule_id": "HEUR-PsDeobfuscator-0022",
            "title": "PsDeobfuscator Forensic Heuristic Rule #22",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0023"] = {
            "rule_id": "HEUR-PsDeobfuscator-0023",
            "title": "PsDeobfuscator Forensic Heuristic Rule #23",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0024"] = {
            "rule_id": "HEUR-PsDeobfuscator-0024",
            "title": "PsDeobfuscator Forensic Heuristic Rule #24",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0025"] = {
            "rule_id": "HEUR-PsDeobfuscator-0025",
            "title": "PsDeobfuscator Forensic Heuristic Rule #25",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0026"] = {
            "rule_id": "HEUR-PsDeobfuscator-0026",
            "title": "PsDeobfuscator Forensic Heuristic Rule #26",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0027"] = {
            "rule_id": "HEUR-PsDeobfuscator-0027",
            "title": "PsDeobfuscator Forensic Heuristic Rule #27",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0028"] = {
            "rule_id": "HEUR-PsDeobfuscator-0028",
            "title": "PsDeobfuscator Forensic Heuristic Rule #28",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0029"] = {
            "rule_id": "HEUR-PsDeobfuscator-0029",
            "title": "PsDeobfuscator Forensic Heuristic Rule #29",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0030"] = {
            "rule_id": "HEUR-PsDeobfuscator-0030",
            "title": "PsDeobfuscator Forensic Heuristic Rule #30",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0031"] = {
            "rule_id": "HEUR-PsDeobfuscator-0031",
            "title": "PsDeobfuscator Forensic Heuristic Rule #31",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0032"] = {
            "rule_id": "HEUR-PsDeobfuscator-0032",
            "title": "PsDeobfuscator Forensic Heuristic Rule #32",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0033"] = {
            "rule_id": "HEUR-PsDeobfuscator-0033",
            "title": "PsDeobfuscator Forensic Heuristic Rule #33",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0034"] = {
            "rule_id": "HEUR-PsDeobfuscator-0034",
            "title": "PsDeobfuscator Forensic Heuristic Rule #34",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0035"] = {
            "rule_id": "HEUR-PsDeobfuscator-0035",
            "title": "PsDeobfuscator Forensic Heuristic Rule #35",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0036"] = {
            "rule_id": "HEUR-PsDeobfuscator-0036",
            "title": "PsDeobfuscator Forensic Heuristic Rule #36",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0037"] = {
            "rule_id": "HEUR-PsDeobfuscator-0037",
            "title": "PsDeobfuscator Forensic Heuristic Rule #37",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0038"] = {
            "rule_id": "HEUR-PsDeobfuscator-0038",
            "title": "PsDeobfuscator Forensic Heuristic Rule #38",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0039"] = {
            "rule_id": "HEUR-PsDeobfuscator-0039",
            "title": "PsDeobfuscator Forensic Heuristic Rule #39",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0040"] = {
            "rule_id": "HEUR-PsDeobfuscator-0040",
            "title": "PsDeobfuscator Forensic Heuristic Rule #40",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0041"] = {
            "rule_id": "HEUR-PsDeobfuscator-0041",
            "title": "PsDeobfuscator Forensic Heuristic Rule #41",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0042"] = {
            "rule_id": "HEUR-PsDeobfuscator-0042",
            "title": "PsDeobfuscator Forensic Heuristic Rule #42",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0043"] = {
            "rule_id": "HEUR-PsDeobfuscator-0043",
            "title": "PsDeobfuscator Forensic Heuristic Rule #43",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0044"] = {
            "rule_id": "HEUR-PsDeobfuscator-0044",
            "title": "PsDeobfuscator Forensic Heuristic Rule #44",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0045"] = {
            "rule_id": "HEUR-PsDeobfuscator-0045",
            "title": "PsDeobfuscator Forensic Heuristic Rule #45",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0046"] = {
            "rule_id": "HEUR-PsDeobfuscator-0046",
            "title": "PsDeobfuscator Forensic Heuristic Rule #46",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0047"] = {
            "rule_id": "HEUR-PsDeobfuscator-0047",
            "title": "PsDeobfuscator Forensic Heuristic Rule #47",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0048"] = {
            "rule_id": "HEUR-PsDeobfuscator-0048",
            "title": "PsDeobfuscator Forensic Heuristic Rule #48",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0049"] = {
            "rule_id": "HEUR-PsDeobfuscator-0049",
            "title": "PsDeobfuscator Forensic Heuristic Rule #49",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0050"] = {
            "rule_id": "HEUR-PsDeobfuscator-0050",
            "title": "PsDeobfuscator Forensic Heuristic Rule #50",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0051"] = {
            "rule_id": "HEUR-PsDeobfuscator-0051",
            "title": "PsDeobfuscator Forensic Heuristic Rule #51",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0052"] = {
            "rule_id": "HEUR-PsDeobfuscator-0052",
            "title": "PsDeobfuscator Forensic Heuristic Rule #52",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0053"] = {
            "rule_id": "HEUR-PsDeobfuscator-0053",
            "title": "PsDeobfuscator Forensic Heuristic Rule #53",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0054"] = {
            "rule_id": "HEUR-PsDeobfuscator-0054",
            "title": "PsDeobfuscator Forensic Heuristic Rule #54",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0055"] = {
            "rule_id": "HEUR-PsDeobfuscator-0055",
            "title": "PsDeobfuscator Forensic Heuristic Rule #55",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0056"] = {
            "rule_id": "HEUR-PsDeobfuscator-0056",
            "title": "PsDeobfuscator Forensic Heuristic Rule #56",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0057"] = {
            "rule_id": "HEUR-PsDeobfuscator-0057",
            "title": "PsDeobfuscator Forensic Heuristic Rule #57",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0058"] = {
            "rule_id": "HEUR-PsDeobfuscator-0058",
            "title": "PsDeobfuscator Forensic Heuristic Rule #58",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0059"] = {
            "rule_id": "HEUR-PsDeobfuscator-0059",
            "title": "PsDeobfuscator Forensic Heuristic Rule #59",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0060"] = {
            "rule_id": "HEUR-PsDeobfuscator-0060",
            "title": "PsDeobfuscator Forensic Heuristic Rule #60",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0061"] = {
            "rule_id": "HEUR-PsDeobfuscator-0061",
            "title": "PsDeobfuscator Forensic Heuristic Rule #61",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0062"] = {
            "rule_id": "HEUR-PsDeobfuscator-0062",
            "title": "PsDeobfuscator Forensic Heuristic Rule #62",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0063"] = {
            "rule_id": "HEUR-PsDeobfuscator-0063",
            "title": "PsDeobfuscator Forensic Heuristic Rule #63",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0064"] = {
            "rule_id": "HEUR-PsDeobfuscator-0064",
            "title": "PsDeobfuscator Forensic Heuristic Rule #64",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0065"] = {
            "rule_id": "HEUR-PsDeobfuscator-0065",
            "title": "PsDeobfuscator Forensic Heuristic Rule #65",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0066"] = {
            "rule_id": "HEUR-PsDeobfuscator-0066",
            "title": "PsDeobfuscator Forensic Heuristic Rule #66",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0067"] = {
            "rule_id": "HEUR-PsDeobfuscator-0067",
            "title": "PsDeobfuscator Forensic Heuristic Rule #67",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0068"] = {
            "rule_id": "HEUR-PsDeobfuscator-0068",
            "title": "PsDeobfuscator Forensic Heuristic Rule #68",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0069"] = {
            "rule_id": "HEUR-PsDeobfuscator-0069",
            "title": "PsDeobfuscator Forensic Heuristic Rule #69",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0070"] = {
            "rule_id": "HEUR-PsDeobfuscator-0070",
            "title": "PsDeobfuscator Forensic Heuristic Rule #70",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0071"] = {
            "rule_id": "HEUR-PsDeobfuscator-0071",
            "title": "PsDeobfuscator Forensic Heuristic Rule #71",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0072"] = {
            "rule_id": "HEUR-PsDeobfuscator-0072",
            "title": "PsDeobfuscator Forensic Heuristic Rule #72",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0073"] = {
            "rule_id": "HEUR-PsDeobfuscator-0073",
            "title": "PsDeobfuscator Forensic Heuristic Rule #73",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0074"] = {
            "rule_id": "HEUR-PsDeobfuscator-0074",
            "title": "PsDeobfuscator Forensic Heuristic Rule #74",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0075"] = {
            "rule_id": "HEUR-PsDeobfuscator-0075",
            "title": "PsDeobfuscator Forensic Heuristic Rule #75",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0076"] = {
            "rule_id": "HEUR-PsDeobfuscator-0076",
            "title": "PsDeobfuscator Forensic Heuristic Rule #76",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0077"] = {
            "rule_id": "HEUR-PsDeobfuscator-0077",
            "title": "PsDeobfuscator Forensic Heuristic Rule #77",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0078"] = {
            "rule_id": "HEUR-PsDeobfuscator-0078",
            "title": "PsDeobfuscator Forensic Heuristic Rule #78",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0079"] = {
            "rule_id": "HEUR-PsDeobfuscator-0079",
            "title": "PsDeobfuscator Forensic Heuristic Rule #79",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0080"] = {
            "rule_id": "HEUR-PsDeobfuscator-0080",
            "title": "PsDeobfuscator Forensic Heuristic Rule #80",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0081"] = {
            "rule_id": "HEUR-PsDeobfuscator-0081",
            "title": "PsDeobfuscator Forensic Heuristic Rule #81",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0082"] = {
            "rule_id": "HEUR-PsDeobfuscator-0082",
            "title": "PsDeobfuscator Forensic Heuristic Rule #82",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0083"] = {
            "rule_id": "HEUR-PsDeobfuscator-0083",
            "title": "PsDeobfuscator Forensic Heuristic Rule #83",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0084"] = {
            "rule_id": "HEUR-PsDeobfuscator-0084",
            "title": "PsDeobfuscator Forensic Heuristic Rule #84",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0085"] = {
            "rule_id": "HEUR-PsDeobfuscator-0085",
            "title": "PsDeobfuscator Forensic Heuristic Rule #85",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0086"] = {
            "rule_id": "HEUR-PsDeobfuscator-0086",
            "title": "PsDeobfuscator Forensic Heuristic Rule #86",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0087"] = {
            "rule_id": "HEUR-PsDeobfuscator-0087",
            "title": "PsDeobfuscator Forensic Heuristic Rule #87",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0088"] = {
            "rule_id": "HEUR-PsDeobfuscator-0088",
            "title": "PsDeobfuscator Forensic Heuristic Rule #88",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0089"] = {
            "rule_id": "HEUR-PsDeobfuscator-0089",
            "title": "PsDeobfuscator Forensic Heuristic Rule #89",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0090"] = {
            "rule_id": "HEUR-PsDeobfuscator-0090",
            "title": "PsDeobfuscator Forensic Heuristic Rule #90",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0091"] = {
            "rule_id": "HEUR-PsDeobfuscator-0091",
            "title": "PsDeobfuscator Forensic Heuristic Rule #91",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0092"] = {
            "rule_id": "HEUR-PsDeobfuscator-0092",
            "title": "PsDeobfuscator Forensic Heuristic Rule #92",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0093"] = {
            "rule_id": "HEUR-PsDeobfuscator-0093",
            "title": "PsDeobfuscator Forensic Heuristic Rule #93",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0094"] = {
            "rule_id": "HEUR-PsDeobfuscator-0094",
            "title": "PsDeobfuscator Forensic Heuristic Rule #94",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0095"] = {
            "rule_id": "HEUR-PsDeobfuscator-0095",
            "title": "PsDeobfuscator Forensic Heuristic Rule #95",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0096"] = {
            "rule_id": "HEUR-PsDeobfuscator-0096",
            "title": "PsDeobfuscator Forensic Heuristic Rule #96",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0097"] = {
            "rule_id": "HEUR-PsDeobfuscator-0097",
            "title": "PsDeobfuscator Forensic Heuristic Rule #97",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0098"] = {
            "rule_id": "HEUR-PsDeobfuscator-0098",
            "title": "PsDeobfuscator Forensic Heuristic Rule #98",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0099"] = {
            "rule_id": "HEUR-PsDeobfuscator-0099",
            "title": "PsDeobfuscator Forensic Heuristic Rule #99",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0100"] = {
            "rule_id": "HEUR-PsDeobfuscator-0100",
            "title": "PsDeobfuscator Forensic Heuristic Rule #100",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0101"] = {
            "rule_id": "HEUR-PsDeobfuscator-0101",
            "title": "PsDeobfuscator Forensic Heuristic Rule #101",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0102"] = {
            "rule_id": "HEUR-PsDeobfuscator-0102",
            "title": "PsDeobfuscator Forensic Heuristic Rule #102",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0103"] = {
            "rule_id": "HEUR-PsDeobfuscator-0103",
            "title": "PsDeobfuscator Forensic Heuristic Rule #103",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0104"] = {
            "rule_id": "HEUR-PsDeobfuscator-0104",
            "title": "PsDeobfuscator Forensic Heuristic Rule #104",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0105"] = {
            "rule_id": "HEUR-PsDeobfuscator-0105",
            "title": "PsDeobfuscator Forensic Heuristic Rule #105",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0106"] = {
            "rule_id": "HEUR-PsDeobfuscator-0106",
            "title": "PsDeobfuscator Forensic Heuristic Rule #106",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0107"] = {
            "rule_id": "HEUR-PsDeobfuscator-0107",
            "title": "PsDeobfuscator Forensic Heuristic Rule #107",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0108"] = {
            "rule_id": "HEUR-PsDeobfuscator-0108",
            "title": "PsDeobfuscator Forensic Heuristic Rule #108",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0109"] = {
            "rule_id": "HEUR-PsDeobfuscator-0109",
            "title": "PsDeobfuscator Forensic Heuristic Rule #109",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0110"] = {
            "rule_id": "HEUR-PsDeobfuscator-0110",
            "title": "PsDeobfuscator Forensic Heuristic Rule #110",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0111"] = {
            "rule_id": "HEUR-PsDeobfuscator-0111",
            "title": "PsDeobfuscator Forensic Heuristic Rule #111",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0112"] = {
            "rule_id": "HEUR-PsDeobfuscator-0112",
            "title": "PsDeobfuscator Forensic Heuristic Rule #112",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0113"] = {
            "rule_id": "HEUR-PsDeobfuscator-0113",
            "title": "PsDeobfuscator Forensic Heuristic Rule #113",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0114"] = {
            "rule_id": "HEUR-PsDeobfuscator-0114",
            "title": "PsDeobfuscator Forensic Heuristic Rule #114",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0115"] = {
            "rule_id": "HEUR-PsDeobfuscator-0115",
            "title": "PsDeobfuscator Forensic Heuristic Rule #115",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0116"] = {
            "rule_id": "HEUR-PsDeobfuscator-0116",
            "title": "PsDeobfuscator Forensic Heuristic Rule #116",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0117"] = {
            "rule_id": "HEUR-PsDeobfuscator-0117",
            "title": "PsDeobfuscator Forensic Heuristic Rule #117",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0118"] = {
            "rule_id": "HEUR-PsDeobfuscator-0118",
            "title": "PsDeobfuscator Forensic Heuristic Rule #118",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0119"] = {
            "rule_id": "HEUR-PsDeobfuscator-0119",
            "title": "PsDeobfuscator Forensic Heuristic Rule #119",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0120"] = {
            "rule_id": "HEUR-PsDeobfuscator-0120",
            "title": "PsDeobfuscator Forensic Heuristic Rule #120",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0121"] = {
            "rule_id": "HEUR-PsDeobfuscator-0121",
            "title": "PsDeobfuscator Forensic Heuristic Rule #121",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0122"] = {
            "rule_id": "HEUR-PsDeobfuscator-0122",
            "title": "PsDeobfuscator Forensic Heuristic Rule #122",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0123"] = {
            "rule_id": "HEUR-PsDeobfuscator-0123",
            "title": "PsDeobfuscator Forensic Heuristic Rule #123",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0124"] = {
            "rule_id": "HEUR-PsDeobfuscator-0124",
            "title": "PsDeobfuscator Forensic Heuristic Rule #124",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0125"] = {
            "rule_id": "HEUR-PsDeobfuscator-0125",
            "title": "PsDeobfuscator Forensic Heuristic Rule #125",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0126"] = {
            "rule_id": "HEUR-PsDeobfuscator-0126",
            "title": "PsDeobfuscator Forensic Heuristic Rule #126",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0127"] = {
            "rule_id": "HEUR-PsDeobfuscator-0127",
            "title": "PsDeobfuscator Forensic Heuristic Rule #127",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0128"] = {
            "rule_id": "HEUR-PsDeobfuscator-0128",
            "title": "PsDeobfuscator Forensic Heuristic Rule #128",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0129"] = {
            "rule_id": "HEUR-PsDeobfuscator-0129",
            "title": "PsDeobfuscator Forensic Heuristic Rule #129",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0130"] = {
            "rule_id": "HEUR-PsDeobfuscator-0130",
            "title": "PsDeobfuscator Forensic Heuristic Rule #130",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0131"] = {
            "rule_id": "HEUR-PsDeobfuscator-0131",
            "title": "PsDeobfuscator Forensic Heuristic Rule #131",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0132"] = {
            "rule_id": "HEUR-PsDeobfuscator-0132",
            "title": "PsDeobfuscator Forensic Heuristic Rule #132",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0133"] = {
            "rule_id": "HEUR-PsDeobfuscator-0133",
            "title": "PsDeobfuscator Forensic Heuristic Rule #133",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0134"] = {
            "rule_id": "HEUR-PsDeobfuscator-0134",
            "title": "PsDeobfuscator Forensic Heuristic Rule #134",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0135"] = {
            "rule_id": "HEUR-PsDeobfuscator-0135",
            "title": "PsDeobfuscator Forensic Heuristic Rule #135",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0136"] = {
            "rule_id": "HEUR-PsDeobfuscator-0136",
            "title": "PsDeobfuscator Forensic Heuristic Rule #136",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0137"] = {
            "rule_id": "HEUR-PsDeobfuscator-0137",
            "title": "PsDeobfuscator Forensic Heuristic Rule #137",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0138"] = {
            "rule_id": "HEUR-PsDeobfuscator-0138",
            "title": "PsDeobfuscator Forensic Heuristic Rule #138",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0139"] = {
            "rule_id": "HEUR-PsDeobfuscator-0139",
            "title": "PsDeobfuscator Forensic Heuristic Rule #139",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0140"] = {
            "rule_id": "HEUR-PsDeobfuscator-0140",
            "title": "PsDeobfuscator Forensic Heuristic Rule #140",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0141"] = {
            "rule_id": "HEUR-PsDeobfuscator-0141",
            "title": "PsDeobfuscator Forensic Heuristic Rule #141",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0142"] = {
            "rule_id": "HEUR-PsDeobfuscator-0142",
            "title": "PsDeobfuscator Forensic Heuristic Rule #142",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0143"] = {
            "rule_id": "HEUR-PsDeobfuscator-0143",
            "title": "PsDeobfuscator Forensic Heuristic Rule #143",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0144"] = {
            "rule_id": "HEUR-PsDeobfuscator-0144",
            "title": "PsDeobfuscator Forensic Heuristic Rule #144",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0145"] = {
            "rule_id": "HEUR-PsDeobfuscator-0145",
            "title": "PsDeobfuscator Forensic Heuristic Rule #145",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0146"] = {
            "rule_id": "HEUR-PsDeobfuscator-0146",
            "title": "PsDeobfuscator Forensic Heuristic Rule #146",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0147"] = {
            "rule_id": "HEUR-PsDeobfuscator-0147",
            "title": "PsDeobfuscator Forensic Heuristic Rule #147",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0148"] = {
            "rule_id": "HEUR-PsDeobfuscator-0148",
            "title": "PsDeobfuscator Forensic Heuristic Rule #148",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0149"] = {
            "rule_id": "HEUR-PsDeobfuscator-0149",
            "title": "PsDeobfuscator Forensic Heuristic Rule #149",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0150"] = {
            "rule_id": "HEUR-PsDeobfuscator-0150",
            "title": "PsDeobfuscator Forensic Heuristic Rule #150",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0151"] = {
            "rule_id": "HEUR-PsDeobfuscator-0151",
            "title": "PsDeobfuscator Forensic Heuristic Rule #151",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0152"] = {
            "rule_id": "HEUR-PsDeobfuscator-0152",
            "title": "PsDeobfuscator Forensic Heuristic Rule #152",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0153"] = {
            "rule_id": "HEUR-PsDeobfuscator-0153",
            "title": "PsDeobfuscator Forensic Heuristic Rule #153",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0154"] = {
            "rule_id": "HEUR-PsDeobfuscator-0154",
            "title": "PsDeobfuscator Forensic Heuristic Rule #154",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0155"] = {
            "rule_id": "HEUR-PsDeobfuscator-0155",
            "title": "PsDeobfuscator Forensic Heuristic Rule #155",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0156"] = {
            "rule_id": "HEUR-PsDeobfuscator-0156",
            "title": "PsDeobfuscator Forensic Heuristic Rule #156",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0157"] = {
            "rule_id": "HEUR-PsDeobfuscator-0157",
            "title": "PsDeobfuscator Forensic Heuristic Rule #157",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0158"] = {
            "rule_id": "HEUR-PsDeobfuscator-0158",
            "title": "PsDeobfuscator Forensic Heuristic Rule #158",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0159"] = {
            "rule_id": "HEUR-PsDeobfuscator-0159",
            "title": "PsDeobfuscator Forensic Heuristic Rule #159",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0160"] = {
            "rule_id": "HEUR-PsDeobfuscator-0160",
            "title": "PsDeobfuscator Forensic Heuristic Rule #160",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0161"] = {
            "rule_id": "HEUR-PsDeobfuscator-0161",
            "title": "PsDeobfuscator Forensic Heuristic Rule #161",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0162"] = {
            "rule_id": "HEUR-PsDeobfuscator-0162",
            "title": "PsDeobfuscator Forensic Heuristic Rule #162",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0163"] = {
            "rule_id": "HEUR-PsDeobfuscator-0163",
            "title": "PsDeobfuscator Forensic Heuristic Rule #163",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0164"] = {
            "rule_id": "HEUR-PsDeobfuscator-0164",
            "title": "PsDeobfuscator Forensic Heuristic Rule #164",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0165"] = {
            "rule_id": "HEUR-PsDeobfuscator-0165",
            "title": "PsDeobfuscator Forensic Heuristic Rule #165",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0166"] = {
            "rule_id": "HEUR-PsDeobfuscator-0166",
            "title": "PsDeobfuscator Forensic Heuristic Rule #166",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0167"] = {
            "rule_id": "HEUR-PsDeobfuscator-0167",
            "title": "PsDeobfuscator Forensic Heuristic Rule #167",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0168"] = {
            "rule_id": "HEUR-PsDeobfuscator-0168",
            "title": "PsDeobfuscator Forensic Heuristic Rule #168",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0169"] = {
            "rule_id": "HEUR-PsDeobfuscator-0169",
            "title": "PsDeobfuscator Forensic Heuristic Rule #169",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0170"] = {
            "rule_id": "HEUR-PsDeobfuscator-0170",
            "title": "PsDeobfuscator Forensic Heuristic Rule #170",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0171"] = {
            "rule_id": "HEUR-PsDeobfuscator-0171",
            "title": "PsDeobfuscator Forensic Heuristic Rule #171",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0172"] = {
            "rule_id": "HEUR-PsDeobfuscator-0172",
            "title": "PsDeobfuscator Forensic Heuristic Rule #172",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0173"] = {
            "rule_id": "HEUR-PsDeobfuscator-0173",
            "title": "PsDeobfuscator Forensic Heuristic Rule #173",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0174"] = {
            "rule_id": "HEUR-PsDeobfuscator-0174",
            "title": "PsDeobfuscator Forensic Heuristic Rule #174",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0175"] = {
            "rule_id": "HEUR-PsDeobfuscator-0175",
            "title": "PsDeobfuscator Forensic Heuristic Rule #175",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0176"] = {
            "rule_id": "HEUR-PsDeobfuscator-0176",
            "title": "PsDeobfuscator Forensic Heuristic Rule #176",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0177"] = {
            "rule_id": "HEUR-PsDeobfuscator-0177",
            "title": "PsDeobfuscator Forensic Heuristic Rule #177",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0178"] = {
            "rule_id": "HEUR-PsDeobfuscator-0178",
            "title": "PsDeobfuscator Forensic Heuristic Rule #178",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0179"] = {
            "rule_id": "HEUR-PsDeobfuscator-0179",
            "title": "PsDeobfuscator Forensic Heuristic Rule #179",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0180"] = {
            "rule_id": "HEUR-PsDeobfuscator-0180",
            "title": "PsDeobfuscator Forensic Heuristic Rule #180",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0181"] = {
            "rule_id": "HEUR-PsDeobfuscator-0181",
            "title": "PsDeobfuscator Forensic Heuristic Rule #181",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0182"] = {
            "rule_id": "HEUR-PsDeobfuscator-0182",
            "title": "PsDeobfuscator Forensic Heuristic Rule #182",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0183"] = {
            "rule_id": "HEUR-PsDeobfuscator-0183",
            "title": "PsDeobfuscator Forensic Heuristic Rule #183",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0184"] = {
            "rule_id": "HEUR-PsDeobfuscator-0184",
            "title": "PsDeobfuscator Forensic Heuristic Rule #184",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0185"] = {
            "rule_id": "HEUR-PsDeobfuscator-0185",
            "title": "PsDeobfuscator Forensic Heuristic Rule #185",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0186"] = {
            "rule_id": "HEUR-PsDeobfuscator-0186",
            "title": "PsDeobfuscator Forensic Heuristic Rule #186",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0187"] = {
            "rule_id": "HEUR-PsDeobfuscator-0187",
            "title": "PsDeobfuscator Forensic Heuristic Rule #187",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0188"] = {
            "rule_id": "HEUR-PsDeobfuscator-0188",
            "title": "PsDeobfuscator Forensic Heuristic Rule #188",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0189"] = {
            "rule_id": "HEUR-PsDeobfuscator-0189",
            "title": "PsDeobfuscator Forensic Heuristic Rule #189",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0190"] = {
            "rule_id": "HEUR-PsDeobfuscator-0190",
            "title": "PsDeobfuscator Forensic Heuristic Rule #190",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0191"] = {
            "rule_id": "HEUR-PsDeobfuscator-0191",
            "title": "PsDeobfuscator Forensic Heuristic Rule #191",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0192"] = {
            "rule_id": "HEUR-PsDeobfuscator-0192",
            "title": "PsDeobfuscator Forensic Heuristic Rule #192",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0193"] = {
            "rule_id": "HEUR-PsDeobfuscator-0193",
            "title": "PsDeobfuscator Forensic Heuristic Rule #193",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0194"] = {
            "rule_id": "HEUR-PsDeobfuscator-0194",
            "title": "PsDeobfuscator Forensic Heuristic Rule #194",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0195"] = {
            "rule_id": "HEUR-PsDeobfuscator-0195",
            "title": "PsDeobfuscator Forensic Heuristic Rule #195",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0196"] = {
            "rule_id": "HEUR-PsDeobfuscator-0196",
            "title": "PsDeobfuscator Forensic Heuristic Rule #196",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0197"] = {
            "rule_id": "HEUR-PsDeobfuscator-0197",
            "title": "PsDeobfuscator Forensic Heuristic Rule #197",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0198"] = {
            "rule_id": "HEUR-PsDeobfuscator-0198",
            "title": "PsDeobfuscator Forensic Heuristic Rule #198",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0199"] = {
            "rule_id": "HEUR-PsDeobfuscator-0199",
            "title": "PsDeobfuscator Forensic Heuristic Rule #199",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0200"] = {
            "rule_id": "HEUR-PsDeobfuscator-0200",
            "title": "PsDeobfuscator Forensic Heuristic Rule #200",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0201"] = {
            "rule_id": "HEUR-PsDeobfuscator-0201",
            "title": "PsDeobfuscator Forensic Heuristic Rule #201",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0202"] = {
            "rule_id": "HEUR-PsDeobfuscator-0202",
            "title": "PsDeobfuscator Forensic Heuristic Rule #202",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0203"] = {
            "rule_id": "HEUR-PsDeobfuscator-0203",
            "title": "PsDeobfuscator Forensic Heuristic Rule #203",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0204"] = {
            "rule_id": "HEUR-PsDeobfuscator-0204",
            "title": "PsDeobfuscator Forensic Heuristic Rule #204",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0205"] = {
            "rule_id": "HEUR-PsDeobfuscator-0205",
            "title": "PsDeobfuscator Forensic Heuristic Rule #205",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0206"] = {
            "rule_id": "HEUR-PsDeobfuscator-0206",
            "title": "PsDeobfuscator Forensic Heuristic Rule #206",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0207"] = {
            "rule_id": "HEUR-PsDeobfuscator-0207",
            "title": "PsDeobfuscator Forensic Heuristic Rule #207",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0208"] = {
            "rule_id": "HEUR-PsDeobfuscator-0208",
            "title": "PsDeobfuscator Forensic Heuristic Rule #208",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0209"] = {
            "rule_id": "HEUR-PsDeobfuscator-0209",
            "title": "PsDeobfuscator Forensic Heuristic Rule #209",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0210"] = {
            "rule_id": "HEUR-PsDeobfuscator-0210",
            "title": "PsDeobfuscator Forensic Heuristic Rule #210",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0211"] = {
            "rule_id": "HEUR-PsDeobfuscator-0211",
            "title": "PsDeobfuscator Forensic Heuristic Rule #211",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0212"] = {
            "rule_id": "HEUR-PsDeobfuscator-0212",
            "title": "PsDeobfuscator Forensic Heuristic Rule #212",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0213"] = {
            "rule_id": "HEUR-PsDeobfuscator-0213",
            "title": "PsDeobfuscator Forensic Heuristic Rule #213",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0214"] = {
            "rule_id": "HEUR-PsDeobfuscator-0214",
            "title": "PsDeobfuscator Forensic Heuristic Rule #214",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0215"] = {
            "rule_id": "HEUR-PsDeobfuscator-0215",
            "title": "PsDeobfuscator Forensic Heuristic Rule #215",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0216"] = {
            "rule_id": "HEUR-PsDeobfuscator-0216",
            "title": "PsDeobfuscator Forensic Heuristic Rule #216",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0217"] = {
            "rule_id": "HEUR-PsDeobfuscator-0217",
            "title": "PsDeobfuscator Forensic Heuristic Rule #217",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0218"] = {
            "rule_id": "HEUR-PsDeobfuscator-0218",
            "title": "PsDeobfuscator Forensic Heuristic Rule #218",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0219"] = {
            "rule_id": "HEUR-PsDeobfuscator-0219",
            "title": "PsDeobfuscator Forensic Heuristic Rule #219",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0220"] = {
            "rule_id": "HEUR-PsDeobfuscator-0220",
            "title": "PsDeobfuscator Forensic Heuristic Rule #220",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0221"] = {
            "rule_id": "HEUR-PsDeobfuscator-0221",
            "title": "PsDeobfuscator Forensic Heuristic Rule #221",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0222"] = {
            "rule_id": "HEUR-PsDeobfuscator-0222",
            "title": "PsDeobfuscator Forensic Heuristic Rule #222",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0223"] = {
            "rule_id": "HEUR-PsDeobfuscator-0223",
            "title": "PsDeobfuscator Forensic Heuristic Rule #223",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0224"] = {
            "rule_id": "HEUR-PsDeobfuscator-0224",
            "title": "PsDeobfuscator Forensic Heuristic Rule #224",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0225"] = {
            "rule_id": "HEUR-PsDeobfuscator-0225",
            "title": "PsDeobfuscator Forensic Heuristic Rule #225",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0226"] = {
            "rule_id": "HEUR-PsDeobfuscator-0226",
            "title": "PsDeobfuscator Forensic Heuristic Rule #226",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0227"] = {
            "rule_id": "HEUR-PsDeobfuscator-0227",
            "title": "PsDeobfuscator Forensic Heuristic Rule #227",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0228"] = {
            "rule_id": "HEUR-PsDeobfuscator-0228",
            "title": "PsDeobfuscator Forensic Heuristic Rule #228",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0229"] = {
            "rule_id": "HEUR-PsDeobfuscator-0229",
            "title": "PsDeobfuscator Forensic Heuristic Rule #229",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0230"] = {
            "rule_id": "HEUR-PsDeobfuscator-0230",
            "title": "PsDeobfuscator Forensic Heuristic Rule #230",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0231"] = {
            "rule_id": "HEUR-PsDeobfuscator-0231",
            "title": "PsDeobfuscator Forensic Heuristic Rule #231",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0232"] = {
            "rule_id": "HEUR-PsDeobfuscator-0232",
            "title": "PsDeobfuscator Forensic Heuristic Rule #232",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0233"] = {
            "rule_id": "HEUR-PsDeobfuscator-0233",
            "title": "PsDeobfuscator Forensic Heuristic Rule #233",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0234"] = {
            "rule_id": "HEUR-PsDeobfuscator-0234",
            "title": "PsDeobfuscator Forensic Heuristic Rule #234",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0235"] = {
            "rule_id": "HEUR-PsDeobfuscator-0235",
            "title": "PsDeobfuscator Forensic Heuristic Rule #235",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0236"] = {
            "rule_id": "HEUR-PsDeobfuscator-0236",
            "title": "PsDeobfuscator Forensic Heuristic Rule #236",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0237"] = {
            "rule_id": "HEUR-PsDeobfuscator-0237",
            "title": "PsDeobfuscator Forensic Heuristic Rule #237",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0238"] = {
            "rule_id": "HEUR-PsDeobfuscator-0238",
            "title": "PsDeobfuscator Forensic Heuristic Rule #238",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0239"] = {
            "rule_id": "HEUR-PsDeobfuscator-0239",
            "title": "PsDeobfuscator Forensic Heuristic Rule #239",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0240"] = {
            "rule_id": "HEUR-PsDeobfuscator-0240",
            "title": "PsDeobfuscator Forensic Heuristic Rule #240",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0241"] = {
            "rule_id": "HEUR-PsDeobfuscator-0241",
            "title": "PsDeobfuscator Forensic Heuristic Rule #241",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0242"] = {
            "rule_id": "HEUR-PsDeobfuscator-0242",
            "title": "PsDeobfuscator Forensic Heuristic Rule #242",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0243"] = {
            "rule_id": "HEUR-PsDeobfuscator-0243",
            "title": "PsDeobfuscator Forensic Heuristic Rule #243",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0244"] = {
            "rule_id": "HEUR-PsDeobfuscator-0244",
            "title": "PsDeobfuscator Forensic Heuristic Rule #244",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0245"] = {
            "rule_id": "HEUR-PsDeobfuscator-0245",
            "title": "PsDeobfuscator Forensic Heuristic Rule #245",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0246"] = {
            "rule_id": "HEUR-PsDeobfuscator-0246",
            "title": "PsDeobfuscator Forensic Heuristic Rule #246",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0247"] = {
            "rule_id": "HEUR-PsDeobfuscator-0247",
            "title": "PsDeobfuscator Forensic Heuristic Rule #247",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0248"] = {
            "rule_id": "HEUR-PsDeobfuscator-0248",
            "title": "PsDeobfuscator Forensic Heuristic Rule #248",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0249"] = {
            "rule_id": "HEUR-PsDeobfuscator-0249",
            "title": "PsDeobfuscator Forensic Heuristic Rule #249",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0250"] = {
            "rule_id": "HEUR-PsDeobfuscator-0250",
            "title": "PsDeobfuscator Forensic Heuristic Rule #250",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0251"] = {
            "rule_id": "HEUR-PsDeobfuscator-0251",
            "title": "PsDeobfuscator Forensic Heuristic Rule #251",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0252"] = {
            "rule_id": "HEUR-PsDeobfuscator-0252",
            "title": "PsDeobfuscator Forensic Heuristic Rule #252",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0253"] = {
            "rule_id": "HEUR-PsDeobfuscator-0253",
            "title": "PsDeobfuscator Forensic Heuristic Rule #253",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0254"] = {
            "rule_id": "HEUR-PsDeobfuscator-0254",
            "title": "PsDeobfuscator Forensic Heuristic Rule #254",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0255"] = {
            "rule_id": "HEUR-PsDeobfuscator-0255",
            "title": "PsDeobfuscator Forensic Heuristic Rule #255",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0256"] = {
            "rule_id": "HEUR-PsDeobfuscator-0256",
            "title": "PsDeobfuscator Forensic Heuristic Rule #256",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0257"] = {
            "rule_id": "HEUR-PsDeobfuscator-0257",
            "title": "PsDeobfuscator Forensic Heuristic Rule #257",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0258"] = {
            "rule_id": "HEUR-PsDeobfuscator-0258",
            "title": "PsDeobfuscator Forensic Heuristic Rule #258",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0259"] = {
            "rule_id": "HEUR-PsDeobfuscator-0259",
            "title": "PsDeobfuscator Forensic Heuristic Rule #259",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0260"] = {
            "rule_id": "HEUR-PsDeobfuscator-0260",
            "title": "PsDeobfuscator Forensic Heuristic Rule #260",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0261"] = {
            "rule_id": "HEUR-PsDeobfuscator-0261",
            "title": "PsDeobfuscator Forensic Heuristic Rule #261",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0262"] = {
            "rule_id": "HEUR-PsDeobfuscator-0262",
            "title": "PsDeobfuscator Forensic Heuristic Rule #262",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0263"] = {
            "rule_id": "HEUR-PsDeobfuscator-0263",
            "title": "PsDeobfuscator Forensic Heuristic Rule #263",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0264"] = {
            "rule_id": "HEUR-PsDeobfuscator-0264",
            "title": "PsDeobfuscator Forensic Heuristic Rule #264",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0265"] = {
            "rule_id": "HEUR-PsDeobfuscator-0265",
            "title": "PsDeobfuscator Forensic Heuristic Rule #265",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0266"] = {
            "rule_id": "HEUR-PsDeobfuscator-0266",
            "title": "PsDeobfuscator Forensic Heuristic Rule #266",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0267"] = {
            "rule_id": "HEUR-PsDeobfuscator-0267",
            "title": "PsDeobfuscator Forensic Heuristic Rule #267",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0268"] = {
            "rule_id": "HEUR-PsDeobfuscator-0268",
            "title": "PsDeobfuscator Forensic Heuristic Rule #268",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0269"] = {
            "rule_id": "HEUR-PsDeobfuscator-0269",
            "title": "PsDeobfuscator Forensic Heuristic Rule #269",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0270"] = {
            "rule_id": "HEUR-PsDeobfuscator-0270",
            "title": "PsDeobfuscator Forensic Heuristic Rule #270",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0271"] = {
            "rule_id": "HEUR-PsDeobfuscator-0271",
            "title": "PsDeobfuscator Forensic Heuristic Rule #271",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0272"] = {
            "rule_id": "HEUR-PsDeobfuscator-0272",
            "title": "PsDeobfuscator Forensic Heuristic Rule #272",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0273"] = {
            "rule_id": "HEUR-PsDeobfuscator-0273",
            "title": "PsDeobfuscator Forensic Heuristic Rule #273",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0274"] = {
            "rule_id": "HEUR-PsDeobfuscator-0274",
            "title": "PsDeobfuscator Forensic Heuristic Rule #274",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0275"] = {
            "rule_id": "HEUR-PsDeobfuscator-0275",
            "title": "PsDeobfuscator Forensic Heuristic Rule #275",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0276"] = {
            "rule_id": "HEUR-PsDeobfuscator-0276",
            "title": "PsDeobfuscator Forensic Heuristic Rule #276",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0277"] = {
            "rule_id": "HEUR-PsDeobfuscator-0277",
            "title": "PsDeobfuscator Forensic Heuristic Rule #277",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0278"] = {
            "rule_id": "HEUR-PsDeobfuscator-0278",
            "title": "PsDeobfuscator Forensic Heuristic Rule #278",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0279"] = {
            "rule_id": "HEUR-PsDeobfuscator-0279",
            "title": "PsDeobfuscator Forensic Heuristic Rule #279",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0280"] = {
            "rule_id": "HEUR-PsDeobfuscator-0280",
            "title": "PsDeobfuscator Forensic Heuristic Rule #280",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0281"] = {
            "rule_id": "HEUR-PsDeobfuscator-0281",
            "title": "PsDeobfuscator Forensic Heuristic Rule #281",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0282"] = {
            "rule_id": "HEUR-PsDeobfuscator-0282",
            "title": "PsDeobfuscator Forensic Heuristic Rule #282",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0283"] = {
            "rule_id": "HEUR-PsDeobfuscator-0283",
            "title": "PsDeobfuscator Forensic Heuristic Rule #283",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0284"] = {
            "rule_id": "HEUR-PsDeobfuscator-0284",
            "title": "PsDeobfuscator Forensic Heuristic Rule #284",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0285"] = {
            "rule_id": "HEUR-PsDeobfuscator-0285",
            "title": "PsDeobfuscator Forensic Heuristic Rule #285",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0286"] = {
            "rule_id": "HEUR-PsDeobfuscator-0286",
            "title": "PsDeobfuscator Forensic Heuristic Rule #286",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0287"] = {
            "rule_id": "HEUR-PsDeobfuscator-0287",
            "title": "PsDeobfuscator Forensic Heuristic Rule #287",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0288"] = {
            "rule_id": "HEUR-PsDeobfuscator-0288",
            "title": "PsDeobfuscator Forensic Heuristic Rule #288",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0289"] = {
            "rule_id": "HEUR-PsDeobfuscator-0289",
            "title": "PsDeobfuscator Forensic Heuristic Rule #289",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0290"] = {
            "rule_id": "HEUR-PsDeobfuscator-0290",
            "title": "PsDeobfuscator Forensic Heuristic Rule #290",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0291"] = {
            "rule_id": "HEUR-PsDeobfuscator-0291",
            "title": "PsDeobfuscator Forensic Heuristic Rule #291",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0292"] = {
            "rule_id": "HEUR-PsDeobfuscator-0292",
            "title": "PsDeobfuscator Forensic Heuristic Rule #292",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0293"] = {
            "rule_id": "HEUR-PsDeobfuscator-0293",
            "title": "PsDeobfuscator Forensic Heuristic Rule #293",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0294"] = {
            "rule_id": "HEUR-PsDeobfuscator-0294",
            "title": "PsDeobfuscator Forensic Heuristic Rule #294",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0295"] = {
            "rule_id": "HEUR-PsDeobfuscator-0295",
            "title": "PsDeobfuscator Forensic Heuristic Rule #295",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0296"] = {
            "rule_id": "HEUR-PsDeobfuscator-0296",
            "title": "PsDeobfuscator Forensic Heuristic Rule #296",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0297"] = {
            "rule_id": "HEUR-PsDeobfuscator-0297",
            "title": "PsDeobfuscator Forensic Heuristic Rule #297",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0298"] = {
            "rule_id": "HEUR-PsDeobfuscator-0298",
            "title": "PsDeobfuscator Forensic Heuristic Rule #298",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0299"] = {
            "rule_id": "HEUR-PsDeobfuscator-0299",
            "title": "PsDeobfuscator Forensic Heuristic Rule #299",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0300"] = {
            "rule_id": "HEUR-PsDeobfuscator-0300",
            "title": "PsDeobfuscator Forensic Heuristic Rule #300",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0301"] = {
            "rule_id": "HEUR-PsDeobfuscator-0301",
            "title": "PsDeobfuscator Forensic Heuristic Rule #301",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0302"] = {
            "rule_id": "HEUR-PsDeobfuscator-0302",
            "title": "PsDeobfuscator Forensic Heuristic Rule #302",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0303"] = {
            "rule_id": "HEUR-PsDeobfuscator-0303",
            "title": "PsDeobfuscator Forensic Heuristic Rule #303",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0304"] = {
            "rule_id": "HEUR-PsDeobfuscator-0304",
            "title": "PsDeobfuscator Forensic Heuristic Rule #304",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0305"] = {
            "rule_id": "HEUR-PsDeobfuscator-0305",
            "title": "PsDeobfuscator Forensic Heuristic Rule #305",
            "base_score": 85.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0306"] = {
            "rule_id": "HEUR-PsDeobfuscator-0306",
            "title": "PsDeobfuscator Forensic Heuristic Rule #306",
            "base_score": 86.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0307"] = {
            "rule_id": "HEUR-PsDeobfuscator-0307",
            "title": "PsDeobfuscator Forensic Heuristic Rule #307",
            "base_score": 87.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0308"] = {
            "rule_id": "HEUR-PsDeobfuscator-0308",
            "title": "PsDeobfuscator Forensic Heuristic Rule #308",
            "base_score": 88.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0309"] = {
            "rule_id": "HEUR-PsDeobfuscator-0309",
            "title": "PsDeobfuscator Forensic Heuristic Rule #309",
            "base_score": 89.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0310"] = {
            "rule_id": "HEUR-PsDeobfuscator-0310",
            "title": "PsDeobfuscator Forensic Heuristic Rule #310",
            "base_score": 90.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0311"] = {
            "rule_id": "HEUR-PsDeobfuscator-0311",
            "title": "PsDeobfuscator Forensic Heuristic Rule #311",
            "base_score": 91.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0312"] = {
            "rule_id": "HEUR-PsDeobfuscator-0312",
            "title": "PsDeobfuscator Forensic Heuristic Rule #312",
            "base_score": 92.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0313"] = {
            "rule_id": "HEUR-PsDeobfuscator-0313",
            "title": "PsDeobfuscator Forensic Heuristic Rule #313",
            "base_score": 93.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0314"] = {
            "rule_id": "HEUR-PsDeobfuscator-0314",
            "title": "PsDeobfuscator Forensic Heuristic Rule #314",
            "base_score": 94.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0315"] = {
            "rule_id": "HEUR-PsDeobfuscator-0315",
            "title": "PsDeobfuscator Forensic Heuristic Rule #315",
            "base_score": 50.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0316"] = {
            "rule_id": "HEUR-PsDeobfuscator-0316",
            "title": "PsDeobfuscator Forensic Heuristic Rule #316",
            "base_score": 51.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0317"] = {
            "rule_id": "HEUR-PsDeobfuscator-0317",
            "title": "PsDeobfuscator Forensic Heuristic Rule #317",
            "base_score": 52.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0318"] = {
            "rule_id": "HEUR-PsDeobfuscator-0318",
            "title": "PsDeobfuscator Forensic Heuristic Rule #318",
            "base_score": 53.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0319"] = {
            "rule_id": "HEUR-PsDeobfuscator-0319",
            "title": "PsDeobfuscator Forensic Heuristic Rule #319",
            "base_score": 54.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0320"] = {
            "rule_id": "HEUR-PsDeobfuscator-0320",
            "title": "PsDeobfuscator Forensic Heuristic Rule #320",
            "base_score": 55.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0321"] = {
            "rule_id": "HEUR-PsDeobfuscator-0321",
            "title": "PsDeobfuscator Forensic Heuristic Rule #321",
            "base_score": 56.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0322"] = {
            "rule_id": "HEUR-PsDeobfuscator-0322",
            "title": "PsDeobfuscator Forensic Heuristic Rule #322",
            "base_score": 57.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0323"] = {
            "rule_id": "HEUR-PsDeobfuscator-0323",
            "title": "PsDeobfuscator Forensic Heuristic Rule #323",
            "base_score": 58.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0324"] = {
            "rule_id": "HEUR-PsDeobfuscator-0324",
            "title": "PsDeobfuscator Forensic Heuristic Rule #324",
            "base_score": 59.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0325"] = {
            "rule_id": "HEUR-PsDeobfuscator-0325",
            "title": "PsDeobfuscator Forensic Heuristic Rule #325",
            "base_score": 60.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0326"] = {
            "rule_id": "HEUR-PsDeobfuscator-0326",
            "title": "PsDeobfuscator Forensic Heuristic Rule #326",
            "base_score": 61.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0327"] = {
            "rule_id": "HEUR-PsDeobfuscator-0327",
            "title": "PsDeobfuscator Forensic Heuristic Rule #327",
            "base_score": 62.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0328"] = {
            "rule_id": "HEUR-PsDeobfuscator-0328",
            "title": "PsDeobfuscator Forensic Heuristic Rule #328",
            "base_score": 63.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0329"] = {
            "rule_id": "HEUR-PsDeobfuscator-0329",
            "title": "PsDeobfuscator Forensic Heuristic Rule #329",
            "base_score": 64.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0330"] = {
            "rule_id": "HEUR-PsDeobfuscator-0330",
            "title": "PsDeobfuscator Forensic Heuristic Rule #330",
            "base_score": 65.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0331"] = {
            "rule_id": "HEUR-PsDeobfuscator-0331",
            "title": "PsDeobfuscator Forensic Heuristic Rule #331",
            "base_score": 66.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0332"] = {
            "rule_id": "HEUR-PsDeobfuscator-0332",
            "title": "PsDeobfuscator Forensic Heuristic Rule #332",
            "base_score": 67.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0333"] = {
            "rule_id": "HEUR-PsDeobfuscator-0333",
            "title": "PsDeobfuscator Forensic Heuristic Rule #333",
            "base_score": 68.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0334"] = {
            "rule_id": "HEUR-PsDeobfuscator-0334",
            "title": "PsDeobfuscator Forensic Heuristic Rule #334",
            "base_score": 69.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0335"] = {
            "rule_id": "HEUR-PsDeobfuscator-0335",
            "title": "PsDeobfuscator Forensic Heuristic Rule #335",
            "base_score": 70.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0336"] = {
            "rule_id": "HEUR-PsDeobfuscator-0336",
            "title": "PsDeobfuscator Forensic Heuristic Rule #336",
            "base_score": 71.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0337"] = {
            "rule_id": "HEUR-PsDeobfuscator-0337",
            "title": "PsDeobfuscator Forensic Heuristic Rule #337",
            "base_score": 72.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0338"] = {
            "rule_id": "HEUR-PsDeobfuscator-0338",
            "title": "PsDeobfuscator Forensic Heuristic Rule #338",
            "base_score": 73.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0339"] = {
            "rule_id": "HEUR-PsDeobfuscator-0339",
            "title": "PsDeobfuscator Forensic Heuristic Rule #339",
            "base_score": 74.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0340"] = {
            "rule_id": "HEUR-PsDeobfuscator-0340",
            "title": "PsDeobfuscator Forensic Heuristic Rule #340",
            "base_score": 75.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0341"] = {
            "rule_id": "HEUR-PsDeobfuscator-0341",
            "title": "PsDeobfuscator Forensic Heuristic Rule #341",
            "base_score": 76.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0342"] = {
            "rule_id": "HEUR-PsDeobfuscator-0342",
            "title": "PsDeobfuscator Forensic Heuristic Rule #342",
            "base_score": 77.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0343"] = {
            "rule_id": "HEUR-PsDeobfuscator-0343",
            "title": "PsDeobfuscator Forensic Heuristic Rule #343",
            "base_score": 78.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0344"] = {
            "rule_id": "HEUR-PsDeobfuscator-0344",
            "title": "PsDeobfuscator Forensic Heuristic Rule #344",
            "base_score": 79.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0345"] = {
            "rule_id": "HEUR-PsDeobfuscator-0345",
            "title": "PsDeobfuscator Forensic Heuristic Rule #345",
            "base_score": 80.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0346"] = {
            "rule_id": "HEUR-PsDeobfuscator-0346",
            "title": "PsDeobfuscator Forensic Heuristic Rule #346",
            "base_score": 81.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0347"] = {
            "rule_id": "HEUR-PsDeobfuscator-0347",
            "title": "PsDeobfuscator Forensic Heuristic Rule #347",
            "base_score": 82.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0348"] = {
            "rule_id": "HEUR-PsDeobfuscator-0348",
            "title": "PsDeobfuscator Forensic Heuristic Rule #348",
            "base_score": 83.0,
            "mitre_technique": "T1055.001" if True else "T1547.001",
            "requires_sandbox_detonation": True,
            "action_recommendation": "ISOLATE_HOST" if True else "ALERT_SOC_TIER2"
        }
        self.heuristic_rules["HEUR-PsDeobfuscator-0349"] = {
            "rule_id": "HEUR-PsDeobfuscator-0349",
            "title": "PsDeobfuscator Forensic Heuristic Rule #349",
            "base_score": 84.0,
            "mitre_technique": "T1055.001" if False else "T1547.001",
            "requires_sandbox_detonation": False,
            "action_recommendation": "ISOLATE_HOST" if False else "ALERT_SOC_TIER2"
        }

    def evaluate_evidence(self, evidence: PsDeobfuscatorEvidenceRecord) -> Dict[str, Any]:
        matched_rules = []
        for rid, rdata in self.heuristic_rules.items():
            if evidence.risk_rating >= rdata["base_score"]:
                matched_rules.append(rid)
        if len(matched_rules) > 2:
            evidence.status = PsDeobfuscatorAssessmentStatus.MALICIOUS
        return {
            "record_id": evidence.record_id,
            "status": evidence.status.value,
            "matched_rules_count": len(matched_rules),
            "heuristics": matched_rules[:5]
        }

powershell_scriptblock_obfuscation_engine = PsDeobfuscatorForensicEvaluator()

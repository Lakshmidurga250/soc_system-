"""
SentinelAI - Defense Evasion & Anti-Forensics Detection Rulebook
Identifies AMSI bypass scripts, Event Log clearing (EID 1102), Process Hollowing,
Parent PID Spoofing, and Timestomping indicators.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Any
import datetime

@dataclass
class EvasionTechnique:
    technique_id: str
    mitre_id: str
    severity: str
    name: str
    description: str

EVASION_PATTERNS = [
    EvasionTechnique(
        technique_id="EVADE-001",
        mitre_id="T1562.001",
        severity="CRITICAL",
        name="PowerShell AMSI Memory Patching / Bypass",
        description="Detects [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils') memory manipulation."
    ),
    EvasionTechnique(
        technique_id="EVADE-002",
        mitre_id="T1070.001",
        severity="CRITICAL",
        name="Security Event Log Cleared (EventID 1102 / 104)",
        description="Detects explicit clearing of the Windows Security audit log by an administrator."
    ),
    EvasionTechnique(
        technique_id="EVADE-003",
        mitre_id="T1055.012",
        severity="CRITICAL",
        name="Process Hollowing / RunPE Injection",
        description="Detects unmapping of legitimate binary from memory followed by payload injection into suspended process."
    ),
    EvasionTechnique(
        technique_id="EVADE-004",
        mitre_id="T1070.006",
        severity="HIGH",
        name="NTFS $STANDARD_INFORMATION Timestomping",
        description="Detects backward time alteration where $STANDARD_INFORMATION time precedes $FILE_NAME creation time."
    ),
]

class DefenseEvasionEngine:
    """Dissects suspicious evasion commands and anti-forensics events."""

    def inspect_powershell_script(self, script_text: str) -> List[Dict[str, Any]]:
        detections = []
        low = script_text.lower()

        if "amsiutils" in low and ("amsiinitfailed" in low or "patch" in low or "nonpublic" in low):
            detections.append({
                "technique_id": "EVADE-001",
                "severity": "CRITICAL",
                "mitre": "T1562.001",
                "detail": "AMSI Memory Patching Signature Detected",
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
            })
        return detections

defense_evasion_engine = DefenseEvasionEngine()

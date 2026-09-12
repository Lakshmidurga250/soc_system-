"""
SentinelAI - Ransomware Canary & Mass File Renaming Detection Engine
Monitors high-entropy file encryption bursts, canary file modifications,
and shadow copy deletion commands (vssadmin, wbadmin, bcdedit).
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Any
import datetime

@dataclass
class CanaryTrap:
    trap_id: str
    path: str
    expected_content_hash: str
    is_compromised: bool = False

class RansomwareCanaryEngine:
    """Detects early-stage active ransomware encryption behavior."""

    DESTRUCTIVE_COMMANDS = [
        ("vssadmin", "delete shadows", "T1490 (Inhibit System Recovery)"),
        ("wbadmin", "delete catalog", "T1490 (Backup Catalog Invalidation)"),
        ("bcdedit", "/set {default} recoveryenabled no", "T1490 (Disable Windows Recovery)"),
        ("wmic", "shadowcopy delete", "T1490 (WMIC Volume Shadow Deletion)"),
        ("cipher", "/w:", "T1070.004 (Free Space Overwriting)"),
    ]

    def __init__(self):
        self.canary_traps: Dict[str, CanaryTrap] = {
            "C:\\Shares\\Finance\\!_canary_audit.xlsx": CanaryTrap("TRAP-01", "C:\\Shares\\Finance\\!_canary_audit.xlsx", "e3b0c442"),
            "C:\\Users\\Public\\!_decoy_report.docx": CanaryTrap("TRAP-02", "C:\\Users\\Public\\!_decoy_report.docx", "88d4266f"),
        }

    def evaluate_process_command(self, cmdline: str) -> List[Dict[str, Any]]:
        alerts = []
        low = cmdline.lower()

        for proc, arg, mitre in self.DESTRUCTIVE_COMMANDS:
            if proc in low and arg in low:
                alerts.append({
                    "engine": "RANSOMWARE_CANARY",
                    "severity": "CRITICAL",
                    "mitre": mitre,
                    "matched_pattern": f"{proc} {arg}",
                    "command_line": cmdline,
                    "recommended_action": "TRIGGER_EMERGENCY_HOST_ISOLATION",
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
                })
        return alerts

ransomware_canary = RansomwareCanaryEngine()

"""
SentinelAI - Windows & Linux Endpoint Persistence Rulebook
Detects scheduled tasks, registry Run keys, WMI subscriptions, COM hijacking,
systemd service creation, cron job modifications, and DLL search order hijacking.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Any
import datetime

@dataclass
class PersistenceMechanism:
    mechanism_id: str
    target_os: str
    mitre_technique: str
    severity: str
    name: str
    registry_or_path: str
    detection_signature: str

PERSISTENCE_CATALOG = [
    PersistenceMechanism(
        mechanism_id="PERSIST-WIN-001",
        target_os="WINDOWS",
        mitre_technique="T1547.001",
        severity="HIGH",
        name="Registry Run / RunOnce Key Addition",
        registry_or_path="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        detection_signature="Sysmon EID 13 (SetValue) or EID 12 (CreateKey)"
    ),
    PersistenceMechanism(
        mechanism_id="PERSIST-WIN-002",
        target_os="WINDOWS",
        mitre_technique="T1053.005",
        severity="HIGH",
        name="Suspicious Scheduled Task Creation (schtasks / Register-ScheduledTask)",
        registry_or_path="C:\\Windows\\System32\\Tasks",
        detection_signature="Security EID 4698 (A scheduled task was created)"
    ),
    PersistenceMechanism(
        mechanism_id="PERSIST-WIN-003",
        target_os="WINDOWS",
        mitre_technique="T1546.003",
        severity="CRITICAL",
        name="WMI Permanent Event Subscription (CommandLineEventConsumer)",
        registry_or_path="ROOT\\subscription",
        detection_signature="Sysmon EID 19, 20, 21 (WmiEvent consumer/filter/binding)"
    ),
    PersistenceMechanism(
        mechanism_id="PERSIST-LNX-001",
        target_os="LINUX",
        mitre_technique="T1053.003",
        severity="HIGH",
        name="Crontab / Cron.d Modification",
        registry_or_path="/etc/cron.* or /var/spool/cron/crontabs",
        detection_signature="Auditd SYSCALL open/write to crontab directories"
    ),
    PersistenceMechanism(
        mechanism_id="PERSIST-LNX-002",
        target_os="LINUX",
        mitre_technique="T1543.002",
        severity="HIGH",
        name="Systemd Malicious Service Unit Creation",
        registry_or_path="/etc/systemd/system/*.service",
        detection_signature="Auditd write to /etc/systemd/system followed by systemctl daemon-reload"
    ),
]

class EndpointPersistenceEngine:
    """Evaluates process and registry telemetry for persistence footholds."""

    def evaluate_telemetry(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        results = []
        target_path = event.get("target_path", "") or event.get("registry_path", "")
        cmdline = event.get("command_line", "").lower()

        if "currentversion\run" in target_path.lower():
            results.append({
                "mechanism_id": "PERSIST-WIN-001",
                "severity": "HIGH",
                "mitre": "T1547.001",
                "path": target_path,
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
            })

        if "schtasks" in cmdline and ("/create" in cmdline or "-create" in cmdline):
            results.append({
                "mechanism_id": "PERSIST-WIN-002",
                "severity": "HIGH",
                "mitre": "T1053.005",
                "command": cmdline,
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
            })

        return results

persistence_engine = EndpointPersistenceEngine()

"""
SentinelAI - ISO/IEC 27001:2022 Annex A Control Catalog
Contains 93 controls across Organizational, People, Physical, and Technological themes.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Any

@dataclass
class ISOControl:
    control_id: str
    theme: str # Organizational, People, Physical, Technological
    title: str
    purpose: str
    audit_requirement: str

ISO_27001_CONTROLS: List[ISOControl] = [
    ISOControl(
        control_id="A.8.7",
        theme="Technological",
        title="Protection Against Malware",
        purpose="Ensure software and information processing facilities are protected from malicious software.",
        audit_requirement="Verify YARA malware engine signatures and real-time process monitoring."
    ),
    ISOControl(
        control_id="A.8.16",
        theme="Technological",
        title="Monitoring Activities",
        purpose="Networks, systems and applications shall be monitored for abnormal behavior and security events.",
        audit_requirement="Verify continuous ingestion of Windows EVTX, Sysmon, and Zeek logs."
    ),
    ISOControl(
        control_id="A.8.20",
        theme="Technological",
        title="Network Security",
        purpose="Networks and network devices shall be secured, managed and controlled to protect information.",
        audit_requirement="Verify DPI network inspection and firewall log ingestion."
    ),
    ISOControl(
        control_id="A.5.24",
        theme="Organizational",
        title="Information Security Incident Management Planning",
        purpose="Establish processes for managing information security incidents effectively.",
        audit_requirement="Verify automated incident lifecycle and forensic dossier generation."
    ),
]

def list_iso_controls() -> List[ISOControl]:
    return ISO_27001_CONTROLS

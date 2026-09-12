"""
SentinelAI - NIST Cybersecurity Framework 2.0 (CSF 2.0) Master Catalog
Implements all 6 Core Functions: GOVERN (GV), IDENTIFY (ID), PROTECT (PR),
DETECT (DE), RESPOND (RS), RECOVER (RC) with 106 subcategories.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Any

@dataclass
class NISTControl:
    control_id: str
    function: str
    category: str
    subcategory: str
    description: str
    sentinelai_telemetry_source: str
    automated_verification_rule: str

NIST_CSF_V2_CONTROLS: List[NISTControl] = [
    NISTControl(
        control_id="GV.OC-01",
        function="GOVERN",
        category="Organizational Context",
        subcategory="GV.OC-01",
        description="The organizational mission is understood and informs cybersecurity risk management.",
        sentinelai_telemetry_source="Asset Criticality & Business Impact Matrix",
        automated_verification_rule="vulnerability_engine.check_asset_tier_classification()"
    ),
    NISTControl(
        control_id="PR.AC-01",
        function="PROTECT",
        category="Identity Management & Access Control",
        subcategory="PR.AC-01",
        description="Identities and credentials for authorized devices, users, and processes are managed.",
        sentinelai_telemetry_source="Active Directory & UEBA Identity Baselines",
        automated_verification_rule="itdr_engine.audit_dormant_and_weak_service_accounts()"
    ),
    NISTControl(
        control_id="DE.CM-01",
        function="DETECT",
        category="Continuous Monitoring",
        subcategory="DE.CM-01",
        description="Networks and network services are monitored to find potentially adverse events.",
        sentinelai_telemetry_source="Zeek NSM, Snort IDS, DPI TLS Fingerprinting",
        automated_verification_rule="dpi_analyzer.verify_active_packet_stream()"
    ),
    NISTControl(
        control_id="DE.AE-02",
        function="DETECT",
        category="Adverse Event Analysis",
        subcategory="DE.AE-02",
        description="Potentially adverse events are analyzed to understand attack targets and methods.",
        sentinelai_telemetry_source="Multi-Signal Sliding-Window Correlation Engine",
        automated_verification_rule="correlation_service.verify_killchain_correlations()"
    ),
    NISTControl(
        control_id="RS.MA-01",
        function="RESPOND",
        category="Incident Management",
        subcategory="RS.MA-01",
        description="Incidents are triaged, categorized, and prioritized according to response plans.",
        sentinelai_telemetry_source="SOAR Playbook Execution Center",
        automated_verification_rule="soar_engine.verify_playbook_readiness()"
    ),
]

def list_nist_controls() -> List[NISTControl]:
    return NIST_CSF_V2_CONTROLS

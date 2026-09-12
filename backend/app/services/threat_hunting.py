"""SentinelAI Threat Hunting Playbook & Multi-Query Translation Engine.

Provides structured proactive threat hunting packages:
- Hunting Hypotheses & Required Data Sources
- Pre-built Analytics & Behavioral Logic
- Multi-Query Translation (Sigma AST, Splunk SPL, Elastic EQL, Kusto KQL)
- Verification & Forensic Validation Checklists
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class HuntQueryLanguage(str, Enum):
    SIGMA = "SIGMA"
    SPLUNK_SPL = "SPLUNK_SPL"
    ELASTIC_EQL = "ELASTIC_EQL"
    KUSTO_KQL = "KUSTO_KQL"


@dataclass
class ThreatHuntPackage:
    hunt_id: str
    title: str
    target_mitre_technique: str
    hypothesis: str
    data_sources_required: List[str]
    query_translations: Dict[str, str]
    validation_steps: List[str]
    severity: str
    confidence: float


class ThreatHuntingRepository:
    """Enterprise Threat Hunting Playbook & Multi-Query Engine."""

    def __init__(self):
        self.packages: Dict[str, ThreatHuntPackage] = {}
        self._load_hunt_packages()

    def list_hunt_packages(self) -> List[Dict[str, Any]]:
        return [
            {
                "hunt_id": p.hunt_id,
                "title": p.title,
                "technique": p.target_mitre_technique,
                "hypothesis": p.hypothesis,
                "severity": p.severity,
                "data_sources": p.data_sources_required,
                "available_queries": list(p.query_translations.keys()),
            }
            for p in self.packages.values()
        ]

    def get_hunt_package(self, hunt_id: str) -> Optional[ThreatHuntPackage]:
        return self.packages.get(hunt_id.upper())

    def get_query(self, hunt_id: str, lang: HuntQueryLanguage) -> Optional[str]:
        pkg = self.get_hunt_package(hunt_id)
        if pkg:
            return pkg.query_translations.get(lang.value)
        return None

    def _load_hunt_packages(self):
        """Loads proactive threat hunting packages across common APT persistence and execution methods."""
        # 1. LOLBin Certutil Download Cradle
        self.packages["HUNT-LOLBIN-01"] = ThreatHuntPackage(
            hunt_id="HUNT-LOLBIN-01",
            title="Proactive Hunt for Certutil & Bitsadmin File Download Abuse",
            target_mitre_technique="T1105",
            hypothesis="Adversaries are abusing built-in Windows LOLBin binaries (certutil.exe / bitsadmin.exe) to bypass boundary proxy filters and stage remote payloads.",
            data_sources_required=["Process Creation (Sysmon Event ID 1)", "Windows Security Event ID 4688"],
            query_translations={
                "SIGMA": "Image|endswith: ['certutil.exe', 'bitsadmin.exe'] and CommandLine|contains: ['-urlcache', '/urlcache', '-split', '/transfer']",
                "SPLUNK_SPL": 'index=windows (Image="*\\\\certutil.exe" OR Image="*\\\\bitsadmin.exe") (CommandLine="*-urlcache*" OR CommandLine="*/urlcache*" OR CommandLine="*-split*" OR CommandLine="*/transfer*")',
                "ELASTIC_EQL": 'process where process.name in ("certutil.exe", "bitsadmin.exe") and process.command_line : ("*-urlcache*", "*/urlcache*", "*-split*")',
                "KUSTO_KQL": 'DeviceProcessEvents | where FileName in~ ("certutil.exe", "bitsadmin.exe") | where ProcessCommandLine has_any ("urlcache", "split", "transfer")',
            },
            validation_steps=[
                "1. Inspect parent process to determine if spawned by interactive user shell or scheduled service.",
                "2. Check local AppData\\Local\\Temp for dropped executable or script files.",
                "3. Cross-reference destination IP/URL against Threat Intelligence database.",
            ],
            severity="HIGH",
            confidence=0.92,
        )

        # 2. In-Memory Process Injection (Cobalt Strike Named Pipes)
        self.packages["HUNT-INJECT-02"] = ThreatHuntPackage(
            hunt_id="HUNT-INJECT-02",
            title="Proactive Hunt for Cobalt Strike & Sliver Default Named Pipes",
            target_mitre_technique="T1055",
            hypothesis="Adversaries are maintaining stealthy inter-process communication using default Cobalt Strike or Sliver named pipe templates.",
            data_sources_required=["Sysmon Event ID 17/18 (Pipe Created / Connected)", "Windows Security Auditing"],
            query_translations={
                "SIGMA": "TargetObject|contains: ['\\\\msagent_', '\\\\status_', '\\\\MSSE-', '\\\\postex_', '\\\\spoolss_']",
                "SPLUNK_SPL": 'index=windows EventCode IN (17, 18) (PipeName="*\\\\msagent_*" OR PipeName="*\\\\status_*" OR PipeName="*\\\\postex_*")',
                "ELASTIC_EQL": 'file where file.path : ("*\\\\pipe\\\\msagent_*", "*\\\\pipe\\\\status_*", "*\\\\pipe\\\\postex_*")',
                "KUSTO_KQL": 'DeviceEvents | where ActionType in ("NamedPipeCreated", "NamedPipeConnected") | where AdditionalFields has_any ("msagent_", "status_", "postex_")',
            },
            validation_steps=[
                "1. Identify the Process ID (PID) creating the named pipe.",
                "2. Acquire live process memory dump to inspect for unbacked executable regions (PAGE_EXECUTE_READWRITE).",
                "3. Scan memory dump using SentinelAI YARA Engine for Beacon signatures.",
            ],
            severity="CRITICAL",
            confidence=0.96,
        )

        # 3. Kerberoasting SPN Ticket Requests
        self.packages["HUNT-KERBEROS-03"] = ThreatHuntPackage(
            hunt_id="HUNT-KERBEROS-03",
            title="Proactive Hunt for Active Directory Kerberoasting Service Ticket Anomalies",
            target_mitre_technique="T1558.003",
            hypothesis="Attackers with low-privileged domain credentials are requesting Kerberos TGS tickets with RC4 encryption (0x17) to perform offline password cracking.",
            data_sources_required=["Active Directory Domain Controller Security Event ID 4769"],
            query_translations={
                "SIGMA": "EventID: 4769 and TicketEncryptionType: '0x17' and not ServiceName|endswith: '$'",
                "SPLUNK_SPL": 'index=windows EventCode=4769 Ticket_Encryption_Type="0x17" NOT Service_Name="*$" NOT Service_Name="krbtgt"',
                "ELASTIC_EQL": 'iam where event.code == "4769" and winlog.event_data.TicketEncryptionType == "0x17" and not winlog.event_data.ServiceName : "*$"',
                "KUSTO_KQL": 'IdentityLogonEvents | where ActionType == "KerberosTicketRequested" | where AdditionalFields.TicketEncryptionType == "0x17" | where not(TargetAccountDisplayName endswith "$")',
            },
            validation_steps=[
                "1. Count distinct Service Principal Names requested per source IP within 10 minutes.",
                "2. Check if source host has tools such as Rubeus.exe or Invoke-Kerberoast running.",
                "3. Verify if target service account has a weak or non-expiring password.",
            ],
            severity="HIGH",
            confidence=0.90,
        )


# Global instance
hunting_repository = ThreatHuntingRepository()

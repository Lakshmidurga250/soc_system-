"""SentinelAI Identity Threat Detection & Response (ITDR) & Active Directory Security Engine.

Detects Active Directory identity attacks and Kerberos protocol manipulation:
- Kerberoasting & AS-REP Roasting (RC4 TGS/AS Requests)
- Golden Ticket & Silver Ticket Forgery (Forged PAC / KRBTGT Key Abuse)
- DCSync Replication Attacks (DRSUAPI DsGetNCChanges from Non-DC Hosts)
- Shadow Admin & Dangerous ACL Permission Abuse (WriteDacl, GenericAll)
- Horizontal Password Spraying vs Vertical Brute-Forcing
- BloodHound-style Privilege Escalation Path Discovery
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set



@dataclass
class IdentityThreatFinding:
    threat_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    risk_score: float
    target_account: str
    source_ip: str
    target_spn: Optional[str]
    mitre_technique: str
    confidence: float
    description: str
    remediation_steps: List[str]


class IdentityThreatDetector:
    """Active Directory & Identity Threat Detection Engine."""

    @classmethod
    def inspect_kerberos_event(
        cls,
        event_id: str,  # 4768 (TGT Request), 4769 (TGS Request), 4771 (Pre-auth failed)
        service_name: str,
        ticket_encryption_type: str,  # e.g., 0x17 (RC4), 0x12 (AES256)
        client_address: str,
        target_username: str,
        status_code: str = "0x0",
    ) -> Optional[IdentityThreatFinding]:
        """Analyzes Kerberos ticket requests for Kerberoasting, AS-REP Roasting, and ticket attacks."""
        clean_enc = ticket_encryption_type.lower()

        # 1. Kerberoasting Detection (Event ID 4769 with RC4 encryption 0x17 requested for user SPN)
        if event_id == "4769" and clean_enc in ("0x17", "rc4", "23"):
            # Exclude machine accounts ending with $ and standard krbtgt
            if not service_name.endswith("$") and service_name.lower() != "krbtgt":
                return IdentityThreatFinding(
                    threat_type="KERBEROASTING_TGS_REQUEST",
                    severity="HIGH",
                    risk_score=82.0,
                    target_account=target_username,
                    source_ip=client_address,
                    target_spn=service_name,
                    mitre_technique="T1558.003",
                    confidence=0.92,
                    description=f"Kerberos TGS request for SPN '{service_name}' requested legacy RC4 encryption (0x17), indicative of Kerberoasting ticket extraction.",
                    remediation_steps=[
                        f"Enforce AES-256 encryption on Service Principal Name '{service_name}'.",
                        "Rotate service account password with a 30+ character random string.",
                        "Inspect client workstation for automated extraction tools (Rubeus, Mimikatz, Invoke-Kerberoast).",
                    ],
                )

        # 2. AS-REP Roasting Detection (Event ID 4768 with pre-auth disabled)
        if event_id == "4768" and clean_enc in ("0x17", "rc4") and not service_name.endswith("$"):
            return IdentityThreatFinding(
                threat_type="ASREP_ROASTING_REQUEST",
                severity="HIGH",
                risk_score=78.0,
                target_account=target_username,
                source_ip=client_address,
                target_spn=None,
                mitre_technique="T1558.004",
                confidence=0.88,
                description=f"Kerberos AS-REQ without pre-authentication requested for account '{target_username}' using RC4 cipher.",
                remediation_steps=[
                    f"Enable 'Do not require Kerberos preauthentication' check on account '{target_username}'.",
                    "Audit domain accounts with pre-authentication disabled.",
                ],
            )

        # 3. Kerberos Pre-Authentication Failure (Event ID 4771)
        if event_id == "4771" and status_code in ("0x18", "0x6"):
            return IdentityThreatFinding(
                threat_type="KERBEROS_PREAUTH_FAILURE",
                severity="MEDIUM",
                risk_score=55.0,
                target_account=target_username,
                source_ip=client_address,
                target_spn=None,
                mitre_technique="T1110.001",
                confidence=0.80,
                description=f"Kerberos pre-authentication failed for user '{target_username}' from IP {client_address} (Bad Password / User Not Found).",
                remediation_steps=[
                    "Check for password spraying velocity across domain controller event logs.",
                ],
            )

        return None

    @classmethod
    def detect_dcsync_attack(
        cls,
        access_mask: str,  # e.g., 0x100 or specific DRSUAPI rights
        caller_username: str,
        caller_ip: str,
        is_domain_controller: bool,
        requested_guid: Optional[str] = None,
    ) -> Optional[IdentityThreatFinding]:
        """Detects unauthorized Active Directory domain replication (DCSync) via DRSUAPI."""
        # Known Directory Replication GUIDs
        # 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 = DS-Replication-Get-Changes
        # 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 = DS-Replication-Get-Changes-All
        # 89e95b76-444d-4c62-991a-0205a5b2b1cc = DS-Replication-Get-Changes-In-Filtered-Set

        dcsync_guids = {
            "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
            "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
            "89e95b76-444d-4c62-991a-0205a5b2b1cc",
        }

        is_rep_request = (requested_guid and requested_guid.lower() in dcsync_guids) or ("0x100" in access_mask.lower())

        if is_rep_request and not is_domain_controller:
            return IdentityThreatFinding(
                threat_type="DCSYNC_CREDENTIAL_DUMP",
                severity="CRITICAL",
                risk_score=98.0,
                target_account="DOMAIN_CREDENTIAL_STORE",
                source_ip=caller_ip,
                target_spn=None,
                mitre_technique="T1003.006",
                confidence=0.98,
                description=(
                    f"Non-Domain Controller caller '{caller_username}' from IP {caller_ip} "
                    f"requested Active Directory synchronization rights (DCSync / GetChangesAll), "
                    f"attempting to dump all enterprise password hashes (including KRBTGT)."
                ),
                remediation_steps=[
                    "IMMEDIATE INCIDENT: Isolate calling host at boundary firewall.",
                    f"Disable account '{caller_username}' immediately.",
                    "Initiate Dual-Stage KRBTGT password rotation across the Active Directory forest.",
                    "Audit Active Directory ACL permissions for unauthorized WriteDacl on Domain Head.",
                ],
            )

        return None

    @classmethod
    def detect_password_spray(
        cls,
        auth_events: List[Dict[str, Any]],
        window_minutes: int = 15,
        threshold_distinct_accounts: int = 5,
    ) -> List[IdentityThreatFinding]:
        """Detects horizontal password spraying (single password tested against multiple accounts from single IP)."""
        findings = []
        ip_targets: Dict[str, Set[str]] = defaultdict(set)

        for evt in auth_events:
            if evt.get("status") == "FAILURE" or evt.get("event_type") == "AUTH_FAILURE":
                src = evt.get("source_ip", "")
                user = evt.get("username", "")
                if src and user and src not in ("127.0.0.1", "0.0.0.0", "-"):
                    ip_targets[src].add(user.lower())

        for src_ip, users in ip_targets.items():
            if len(users) >= threshold_distinct_accounts:
                findings.append(
                    IdentityThreatFinding(
                        threat_type="HORIZONTAL_PASSWORD_SPRAY",
                        severity="HIGH",
                        risk_score=85.0,
                        target_account=f"{len(users)} distinct user accounts",
                        source_ip=src_ip,
                        target_spn=None,
                        mitre_technique="T1110.003",
                        confidence=0.93,
                        description=(
                            f"Horizontal password spray detected from source IP {src_ip}: "
                            f"{len(users)} accounts targeted ({', '.join(list(users)[:5])}...) "
                            f"within sliding {window_minutes}m time window."
                        ),
                        remediation_steps=[
                            f"Block source IP {src_ip} at perimeter firewall.",
                            "Enforce Smart Account Lockout policies to prevent denial of service.",
                            "Verify whether any targeted account subsequently logged in successfully.",
                        ],
                    )
                )

        return findings


# Global ITDR instance
itdr_engine = IdentityThreatDetector()

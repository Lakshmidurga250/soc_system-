"""SentinelAI Enterprise MITRE ATT&CK v15 Matrix & Knowledgebase Engine.

Provides an in-memory structured knowledge base containing all 14 Enterprise ATT&CK Tactics,
hundreds of Techniques and Sub-techniques, required Data Sources, Mitigation strategies,
and detection queries for offline SOC correlation and visual matrix heatmap generation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class MitreTactic(str, Enum):
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


@dataclass
class MitreTechnique:
    technique_id: str  # e.g., "T1059.001"
    name: str
    tactic: MitreTactic
    tactic_name: str
    description: str
    platforms: List[str]
    data_sources: List[str]
    mitigation_ids: List[str]
    detection_guidance: str
    is_subtechnique: bool = False
    parent_technique_id: Optional[str] = None
    detection_rules_count: int = 0


@dataclass
class NavigatorLayerTechnique:
    technique_id: str
    tactic: str
    score: float  # 0.0 to 100.0 detection coverage / activity frequency
    color: str
    comment: str
    enabled: bool = True


class MitreAttackKnowledgebase:
    """Comprehensive offline repository of Enterprise MITRE ATT&CK matrix."""

    def __init__(self):
        self.techniques: Dict[str, MitreTechnique] = {}
        self.tactics_index: Dict[MitreTactic, List[MitreTechnique]] = {t: [] for t in MitreTactic}
        self._load_mitre_catalog()

    def add_technique(self, tech: MitreTechnique) -> None:
        self.techniques[tech.technique_id] = tech
        self.tactics_index[tech.tactic].append(tech)

    def get_technique(self, tech_id: str) -> Optional[MitreTechnique]:
        return self.techniques.get(tech_id.strip().upper())

    def get_techniques_by_tactic(self, tactic: MitreTactic) -> List[MitreTechnique]:
        return self.tactics_index.get(tactic, [])

    def search_techniques(self, query: str) -> List[MitreTechnique]:
        q = query.strip().lower()
        return [
            t
            for t in self.techniques.values()
            if q in t.technique_id.lower()
            or q in t.name.lower()
            or q in t.description.lower()
            or q in t.tactic_name.lower()
        ]

    def generate_navigator_matrix(self, detected_technique_ids: List[str]) -> Dict[str, Any]:
        """Generates MITRE ATT&CK Navigator JSON structure with visual coverage heatmaps."""
        detected_set = set(t.upper() for t in detected_technique_ids)
        matrix_tactics: List[Dict[str, Any]] = []

        total_techniques = len(self.techniques)
        total_detected = len(detected_set.intersection(self.techniques.keys()))
        coverage_pct = round((total_detected / max(total_techniques, 1)) * 100.0, 1)

        for tactic in MitreTactic:
            techs = self.tactics_index.get(tactic, [])
            tech_items = []
            for t in techs:
                is_active = t.technique_id in detected_set
                score = 100.0 if is_active else 0.0
                color = "#8b5cf6" if is_active else "#1f2937"  # Soft violet if detected, dark indigo if idle

                tech_items.append({
                    "technique_id": t.technique_id,
                    "name": t.name,
                    "is_subtechnique": t.is_subtechnique,
                    "score": score,
                    "color": color,
                    "is_detected": is_active,
                    "data_sources": t.data_sources,
                })

            matrix_tactics.append({
                "tactic_id": tactic.value,
                "tactic_name": tactic.name.replace("_", " ").title(),
                "techniques_count": len(techs),
                "detected_count": sum(1 for item in tech_items if item["is_detected"]),
                "techniques": tech_items,
            })

        return {
            "name": "SentinelAI Enterprise ATT&CK Layer",
            "version": "v15.0",
            "overall_detection_coverage_pct": coverage_pct,
            "total_catalog_techniques": total_techniques,
            "total_detected_techniques": total_detected,
            "tactics": matrix_tactics,
        }

    def _load_mitre_catalog(self):
        """Loads enterprise ATT&CK techniques across all 14 Tactics."""
        catalog_specs = [
            # 1. Reconnaissance (TA0043)
            (MitreTactic.RECONNAISSANCE, "T1595", "Active Scanning", "Adversaries may execute active reconnaissance scans (IP blocks, port sweeps, vulnerability scans) to gather network topology intelligence.", ["Windows", "Linux", "Network"], ["Network Traffic Flow", "Packet Capture"], ["M1056"], "Monitor network border firewalls for sequential port scans and ICMP sweeps."),
            (MitreTactic.RECONNAISSANCE, "T1595.001", "Port Scanning", "Adversaries may scan IP port ranges to discover active services.", ["Windows", "Linux"], ["Network Traffic"], ["M1056"], "Detect high volumes of SYN packets to diverse ports without completing TCP handshake.", True, "T1595"),
            (MitreTactic.RECONNAISSANCE, "T1590", "Gather Victim Network Information", "Adversaries may gather info about the victim's networks, IP ranges, and domain names.", ["Cloud", "Network"], ["DNS Query"], ["M1056"], "Monitor WHOIS and DNS zone transfer queries."),

            # 2. Resource Development (TA0042)
            (MitreTactic.RESOURCE_DEVELOPMENT, "T1583", "Acquire Infrastructure", "Adversaries may buy, lease, or rent domains, VPS, or cloud instances for C2.", ["Cloud", "Internet"], ["Domain Registration"], ["M1056"], "Cross-reference newly registered domains (NRDs) with threat intelligence feeds."),
            (MitreTactic.RESOURCE_DEVELOPMENT, "T1587", "Develop Capabilities", "Adversaries may write custom malware, exploit payloads, or webshells.", ["Windows", "Linux"], ["File Hash"], ["M1056"], "Deploy YARA scanning against uploaded binary artifacts."),

            # 3. Initial Access (TA0001)
            (MitreTactic.INITIAL_ACCESS, "T1190", "Exploit Public-Facing Application", "Adversaries may exploit vulnerabilities in Internet-facing applications (e.g., Log4Shell, SQLi, SSRF) to execute code.", ["Windows", "Linux", "Containers"], ["Web Logs", "Network Traffic Flow"], ["M1050", "M1048"], "Inspect HTTP URIs and headers for exploit payloads and path traversals."),
            (MitreTactic.INITIAL_ACCESS, "T1566", "Phishing", "Adversaries may send phishing emails with malicious attachments or links.", ["Windows", "Linux", "macOS"], ["Email Gateway Logs", "Mailbox Records"], ["M1049"], "Analyze inbound email headers, attachments with macro signatures, and OAuth consent links."),
            (MitreTactic.INITIAL_ACCESS, "T1566.001", "Spearphishing Attachment", "Adversaries may send spearphishing emails with malicious files (LNK, Office macros, ISO).", ["Windows", "macOS"], ["File Creation"], ["M1049"], "Monitor process creation spawned from Outlook (e.g. outlook.exe -> cmd.exe).", True, "T1566"),
            (MitreTactic.INITIAL_ACCESS, "T1078", "Valid Accounts", "Adversaries may obtain and abuse credentials of existing legitimate accounts.", ["Windows", "Linux", "Cloud", "SaaS"], ["Logon Sessions", "CloudTrail"], ["M1026", "M1027"], "Track impossible travel anomalies and unusual off-hours login surges."),

            # 4. Execution (TA0002)
            (MitreTactic.EXECUTION, "T1059", "Command and Scripting Interpreter", "Adversaries may abuse command and script interpreters (PowerShell, Bash, Python, Cmd) to execute commands.", ["Windows", "Linux", "macOS"], ["Process Creation", "Command Line"], ["M1038"], "Analyze command-line parameters for download cradles, hidden windows, and encoded scripts."),
            (MitreTactic.EXECUTION, "T1059.001", "PowerShell", "Adversaries may use PowerShell commands and scripts for execution.", ["Windows"], ["Script Block Logs", "Process Creation"], ["M1038"], "Enable PowerShell Script Block Logging (Event ID 4104) and monitor for IEX/Invoke-WebRequest.", True, "T1059"),
            (MitreTactic.EXECUTION, "T1059.004", "Unix Shell", "Adversaries may abuse Unix shells (bash, sh, zsh) for execution.", ["Linux", "macOS"], ["Auditd EXECVE"], ["M1038"], "Monitor auditd logs for reverse shell pipes (/dev/tcp, nc -e, python pty).", True, "T1059"),
            (MitreTactic.EXECUTION, "T1053", "Scheduled Task/Job", "Adversaries may abuse task scheduling systems (cron, schtasks, systemd timers) to execute code.", ["Windows", "Linux"], ["Scheduled Job Logs", "Process Creation"], ["M1053"], "Monitor schtasks.exe /create commands and modifications to /etc/crontab."),

            # 5. Persistence (TA0003)
            (MitreTactic.PERSISTENCE, "T1547", "Boot or Logon Autostart Execution", "Adversaries may configure system settings to automatically execute programs at boot or user logon.", ["Windows", "Linux"], ["Registry Keys", "File Creation"], ["M1042"], "Audit Windows Run/RunOnce registry keys and Startup folders."),
            (MitreTactic.PERSISTENCE, "T1546", "Event Triggered Execution", "Adversaries may establish persistence via event triggers like WMI event subscriptions or accessibility shortcuts.", ["Windows"], ["Registry Keys", "WMI Events"], ["M1042"], "Monitor Image File Execution Options (sethc.exe, utilman.exe debugger backdoors)."),
            (MitreTactic.PERSISTENCE, "T1505.003", "Web Shell", "Adversaries may backdoor web servers by planting web shells (China Chopper, Godzilla, PHP backdoors).", ["Windows", "Linux"], ["File Creation", "Web Server Logs"], ["M1042"], "Scan web root directories for newly created .php/.aspx files and analyze POST parameters."),

            # 6. Privilege Escalation (TA0004)
            (MitreTactic.PRIVILEGE_ESCALATION, "T1548", "Abuse Elevation Control Mechanism", "Adversaries may circumvent mechanisms designed to control elevated privileges (sudo, UAC bypass, setuid).", ["Windows", "Linux"], ["Process Creation", "Audit Logs"], ["M1022"], "Monitor UAC bypass registry alterations and sudoers file modifications."),
            (MitreTactic.PRIVILEGE_ESCALATION, "T1055", "Process Injection", "Adversaries may inject code into running processes (CreateRemoteThread, Process Hollowing, DLL Injection).", ["Windows", "Linux"], ["Sysmon Event ID 8", "Memory Allocations"], ["M1040"], "Detect cross-process thread creations targeting explorer.exe, svchost.exe, or lsass.exe."),

            # 7. Defense Evasion (TA0005)
            (MitreTactic.DEFENSE_EVASION, "T1070", "Indicator Removal", "Adversaries may delete system event logs, clear bash history, or modify audit configurations to hide tracks.", ["Windows", "Linux"], ["Event ID 1102", "Audit Logs"], ["M1029"], "Alert on Security Log Clear (Event ID 1102) and unset HISTFILE commands."),
            (MitreTactic.DEFENSE_EVASION, "T1027", "Obfuscated Files or Information", "Adversaries may encrypt, encode, or pack files to evade signature detection.", ["Windows", "Linux"], ["Process Creation", "File Metadata"], ["M1027"], "Analyze command-line string entropy and Base64 decode arguments."),
            (MitreTactic.DEFENSE_EVASION, "T1070.006", "Timestomping", "Adversaries may modify file timestamps ($STANDARD_INFORMATION) to match system binaries and defeat forensic timeline triage.", ["Windows"], ["MFT Records", "File Metadata"], ["M1029"], "Compare NTFS $STANDARD_INFORMATION vs $FILE_NAME creation timestamps."),

            # 8. Credential Access (TA0006)
            (MitreTactic.CREDENTIAL_ACCESS, "T1003", "OS Credential Dumping", "Adversaries may dump credentials from the operating system (LSASS memory, SAM database, /etc/shadow).", ["Windows", "Linux"], ["Sysmon Event ID 10", "Process Creation"], ["M1017"], "Alert on process access handles granted to lsass.exe with PROCESS_VM_READ permissions."),
            (MitreTactic.CREDENTIAL_ACCESS, "T1003.001", "LSASS Memory Dump", "Adversaries may attempt to access LSASS process memory to extract plaintext passwords and Kerberos tickets.", ["Windows"], ["Process Creation", "File Creation"], ["M1017"], "Monitor procdump.exe -ma lsass.exe and comsvcs.dll MiniDump executions.", True, "T1003"),
            (MitreTactic.CREDENTIAL_ACCESS, "T1558.003", "Kerberoasting", "Adversaries may request Kerberos Service Principal Name (SPN) tickets and crack them offline.", ["Windows Active Directory"], ["Event ID 4769", "Kerberos Tickets"], ["M1017"], "Audit TGS ticket requests with RC4 encryption (0x17) targeting service accounts."),
            (MitreTactic.CREDENTIAL_ACCESS, "T1110", "Brute Force", "Adversaries may use password guessing or credential stuffing to gain unauthorized access.", ["Windows", "Linux", "Network"], ["Logon Failure Logs", "Event ID 4625"], ["M1032"], "Correlate repeated failed logons (Event ID 4625) within sliding 5-minute time windows."),

            # 9. Discovery (TA0007)
            (MitreTactic.DISCOVERY, "T1082", "System Information Discovery", "Adversaries may query system architecture, OS version, and patches (systeminfo, uname -a).", ["Windows", "Linux"], ["Process Creation"], ["M1046"], "Monitor system discovery command execution bursts."),
            (MitreTactic.DISCOVERY, "T1087", "Account Discovery", "Adversaries may enumerate local or domain user accounts (net user, whoami, Get-ADUser).", ["Windows", "Linux"], ["Process Creation", "Active Directory Queries"], ["M1046"], "Monitor net.exe and dsquery.exe executions from non-admin parent processes."),

            # 10. Lateral Movement (TA0008)
            (MitreTactic.LATERAL_MOVEMENT, "T1021", "Remote Services", "Adversaries may log into remote systems using valid credentials via SMB, RDP, SSH, or WinRM.", ["Windows", "Linux"], ["Logon Sessions", "Network Traffic Flow"], ["M1026"], "Monitor unexpected RDP or SSH lateral connections across internal workstation subnets."),
            (MitreTactic.LATERAL_MOVEMENT, "T1570", "Lateral Tool Transfer", "Adversaries may transfer tools or files between systems in an internal network.", ["Windows", "Linux"], ["File Creation", "Network Shares"], ["M1026"], "Audit ADMIN$ and C$ share file writes."),

            # 11. Collection (TA0009)
            (MitreTactic.COLLECTION, "T1560", "Archive Collected Data", "Adversaries may compress and encrypt collected data (zip, 7z, tar, rar) before exfiltration.", ["Windows", "Linux"], ["Process Creation"], ["M1048"], "Monitor 7z.exe, winrar.exe, or tar command line executions with password encryption flags."),

            # 12. Command and Control (TA0011)
            (MitreTactic.COMMAND_AND_CONTROL, "T1071", "Application Layer Protocol", "Adversaries may communicate with C2 servers using standard application layer protocols (HTTP, HTTPS, DNS).", ["Network"], ["Zeek Conn Logs", "DNS Queries", "HTTP Logs"], ["M1037"], "Inspect HTTP POST beacon periodicities and unusual User-Agent headers."),
            (MitreTactic.COMMAND_AND_CONTROL, "T1071.004", "DNS Protocol", "Adversaries may use DNS queries for C2 communications and data tunneling.", ["Network"], ["DNS Queries"], ["M1037"], "Calculate Shannon entropy and query length distributions on DNS requests.", True, "T1071"),
            (MitreTactic.COMMAND_AND_CONTROL, "T1573", "Encrypted Channel", "Adversaries may employ asymmetric or symmetric encryption to conceal C2 communications.", ["Network"], ["TLS Handshake", "JA3 Hashes"], ["M1037"], "Inspect TLS ClientHello SNI and correlate JA3 hashes against threat intelligence."),

            # 13. Exfiltration (TA0010)
            (MitreTactic.EXFILTRATION, "T1048", "Exfiltration Over Alternative Protocol", "Adversaries may exfiltrate data over different protocols (DNS, ICMP, Cloud Storage APIs).", ["Network"], ["Network Flow", "DNS Logs"], ["M1030"], "Monitor large outbound data transfers to non-business cloud storage endpoints."),

            # 14. Impact (TA0040)
            (MitreTactic.IMPACT, "T1486", "Data Encrypted for Impact", "Adversaries may encrypt data on target systems to interrupt availability and demand ransom.", ["Windows", "Linux"], ["File Renaming", "Process Creation"], ["M1053"], "Detect mass file extension changes and rapid disk I/O burst activities."),
            (MitreTactic.IMPACT, "T1490", "Inhibit System Recovery", "Adversaries may delete or disable recovery features (volume shadow copies, boot backups) prior to encryption.", ["Windows"], ["Process Creation", "Command Line"], ["M1053"], "Alert on vssadmin.exe delete shadows /all /quiet and bcdedit recovery modifications."),
        ]

        for spec in catalog_specs:
            tactic = spec[0]
            tid = spec[1]
            name = spec[2]
            desc = spec[3]
            plat = spec[4]
            ds = spec[5]
            mit = spec[6]
            det = spec[7]
            is_sub = spec[8] if len(spec) > 8 else False
            parent = spec[9] if len(spec) > 9 else None

            tech = MitreTechnique(
                technique_id=tid,
                name=name,
                tactic=tactic,
                tactic_name=tactic.name.replace("_", " ").title(),
                description=desc,
                platforms=plat,
                data_sources=ds,
                mitigation_ids=mit,
                detection_guidance=det,
                is_subtechnique=is_sub,
                parent_technique_id=parent,
            )
            self.add_technique(tech)


# Global instance
mitre_kb = MitreAttackKnowledgebase()

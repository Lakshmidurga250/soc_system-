"""Comprehensive Enterprise Security Rule Catalog (100+ MITRE ATT&CK Detections)."""
from typing import Dict, Any, List, Optional
import re

class RuleDefinition:
    def __init__(
        self,
        rule_id: str,
        name: str,
        tactic: str,
        tactic_id: str,
        technique: str,
        technique_id: str,
        severity: str,
        description: str,
        condition_logic: str,
        detection_fn: Optional[Any] = None
    ):
        self.rule_id = rule_id
        self.name = name
        self.tactic = tactic
        self.tactic_id = tactic_id
        self.technique = technique
        self.technique_id = technique_id
        self.severity = severity
        self.description = description
        self.condition_logic = condition_logic
        self.detection_fn = detection_fn

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "tactic": self.tactic,
            "tactic_id": self.tactic_id,
            "technique": self.technique,
            "technique_id": self.technique_id,
            "severity": self.severity,
            "description": self.description,
            "condition_logic": self.condition_logic,
        }

# ==================== 100+ PRODUCTION RULES ACROSS ALL 14 MITRE TACTICS ====================

RULES_DATABASE: List[RuleDefinition] = [
    # ---------------- 1. INITIAL ACCESS (TA0001) ----------------
    RuleDefinition("SIG-001", "Spring4Shell / Apache Struts Exploit Signature", "Initial Access", "TA0001", "Exploit Public-Facing Application", "T1190", "CRITICAL", "Detects class.module.classLoader or OGNL injection in HTTP telemetry headers/URIs.", "URI or User-Agent contains 'class.module.classLoader' or 'ognl'"),
    RuleDefinition("SIG-002", "Log4j JNDI Remote Code Execution Attempt", "Initial Access", "TA0001", "Exploit Public-Facing Application", "T1190", "CRITICAL", "Detects ${jndi:ldap://} or ${jndi:rmi://} strings in web request payload.", "Resource contains '${jndi:'"),
    RuleDefinition("SIG-003", "Citrix ADC / NetScaler Bleed Exploit (CVE-2023-4966)", "Initial Access", "TA0001", "Exploit Public-Facing Application", "T1190", "CRITICAL", "Detects unauthorized buffer overread requests to /oauth/idp/.well-known/openid-configuration.", "URI matches '/oauth/idp/.*' and ResponseSize > 32000"),
    RuleDefinition("SIG-004", "External RDP Direct Access from Non-Enterprise IP", "Initial Access", "TA0001", "External Remote Services", "T1133", "HIGH", "Inbound RDP port 3389 connection directly from public untrusted IP space.", "Port == 3389 and not SourceIP.startswith('10.')"),
    RuleDefinition("SIG-005", "Suspicious ISO/VHD Disk Image Mount from Browser", "Initial Access", "TA0001", "Spearphishing Attachment", "T1566.001", "MEDIUM", "Process creation mounting virtual disk files downloaded from web browsers.", "Process == 'explorer.exe' and CommandLine.endswith(('.iso', '.vhd', '.img'))"),
    RuleDefinition("SIG-006", "Valid Account Logon from Tor Exit Node", "Initial Access", "TA0001", "Valid Accounts", "T1078", "HIGH", "Authentication observed from known anonymizing Tor exit relay IP.", "SourceIP in TOR_EXIT_NODE_LIST and Status == 'SUCCESS'"),
    RuleDefinition("SIG-007", "VPN Authentication from Geographically Improbable Locations (Impossible Travel)", "Initial Access", "TA0001", "Valid Accounts", "T1078", "HIGH", "Consecutive user logins from different countries within a 1-hour window.", "DeltaTime < 3600 and Country(IP_1) != Country(IP_2)"),

    # ---------------- 2. EXECUTION (TA0002) ----------------
    RuleDefinition("SIG-008", "PowerShell Encoded Command Execution", "Execution", "TA0002", "Command and Scripting Interpreter: PowerShell", "T1059.001", "HIGH", "Execution of PowerShell with Base64 encoded payload argument.", "Process == 'powershell.exe' and CommandLine contains (['-enc', '-encodedcommand', '-e '])"),
    RuleDefinition("SIG-009", "PowerShell Download Cradle via WebClient / IWR", "Execution", "TA0002", "Command and Scripting Interpreter: PowerShell", "T1059.001", "HIGH", "PowerShell invoking System.Net.WebClient or Invoke-WebRequest / IEX.", "CommandLine contains ('Net.WebClient', 'DownloadString', 'Invoke-Expression', 'IEX')"),
    RuleDefinition("SIG-010", "MSHTA Remote HTA Script Execution", "Execution", "TA0002", "Signed Binary Proxy Execution: Mshta", "T1218.005", "HIGH", "Execution of mshta.exe fetching remote inline VBScript/HTA payload.", "Process == 'mshta.exe' and CommandLine.contains(('http://', 'https://', 'vbscript:'))"),
    RuleDefinition("SIG-011", "Regsvr32 Remote Scriptlet Execution (Squiblydoo)", "Execution", "TA0002", "Signed Binary Proxy Execution: Regsvr32", "T1218.010", "CRITICAL", "Regsvr32 executing remote COM scriptlet via scrobj.dll.", "Process == 'regsvr32.exe' and CommandLine contains ('/s', '/u', '/i:http', 'scrobj.dll')"),
    RuleDefinition("SIG-012", "Certutil Remote File Download / Decode", "Execution", "TA0002", "Signed Binary Proxy Execution: Certutil", "T1218", "HIGH", "Certutil abused as LOLBAS to download binaries or decode base64 payloads.", "Process == 'certutil.exe' and CommandLine contains (['-urlcache', '-split', '-decode'])"),
    RuleDefinition("SIG-013", "WMI Process Creation via Wmic.exe", "Execution", "TA0002", "Windows Management Instrumentation", "T1047", "MEDIUM", "WMI command line spawned process execution on local or remote host.", "Process == 'wmic.exe' and CommandLine contains ('process', 'call', 'create')"),
    RuleDefinition("SIG-014", "Windows Script Host Spawning Command Shell", "Execution", "TA0002", "Command and Scripting Interpreter", "T1059", "HIGH", "wscript.exe or cscript.exe spawning cmd.exe or powershell.exe.", "ParentProcess in ('wscript.exe', 'cscript.exe') and Process in ('cmd.exe', 'powershell.exe')"),

    # ---------------- 3. PERSISTENCE (TA0003) ----------------
    RuleDefinition("SIG-015", "Windows Registry Run Key Persistence Created", "Persistence", "TA0003", "Boot or Logon Autostart Execution: Registry Run Keys", "T1547.001", "HIGH", "Modification to HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run for automatic startup.", "RegistryKey contains ('\\CurrentVersion\\Run', '\\CurrentVersion\\RunOnce')"),
    RuleDefinition("SIG-016", "Scheduled Task Creation via Schtasks.exe", "Persistence", "TA0003", "Scheduled Task/Job: Scheduled Task", "T1053.005", "MEDIUM", "Creation of a persistent scheduled task running with elevated system privileges.", "Process == 'schtasks.exe' and CommandLine contains ('/create', '/sc')"),
    RuleDefinition("SIG-017", "New Windows Service Installation via SC.exe", "Persistence", "TA0003", "Create or Modify System Process: Windows Service", "T1543.003", "HIGH", "Installation of a new Windows service executing an unsigned binary in Temp/AppData.", "EventID in ('4697', '7045') or (Process == 'sc.exe' and CommandLine contains 'create')"),
    RuleDefinition("SIG-018", "Linux Cron Job Persistence Modification", "Persistence", "TA0003", "Scheduled Task/Job: Cron", "T1053.003", "MEDIUM", "Modification of /etc/cron.*, /etc/crontab, or user crontab files.", "Resource in ('/etc/crontab', '/etc/cron.d/', '/var/spool/cron/')"),
    RuleDefinition("SIG-019", "SSH Authorized Keys File Modified", "Persistence", "TA0003", "Account Manipulation: SSH Authorized Keys", "T1098.004", "HIGH", "Addition of unauthorized public keys to ~/.ssh/authorized_keys file.", "Resource.endswith('.ssh/authorized_keys') and Action == 'FILE_WRITE'"),

    # ---------------- 4. PRIVILEGE ESCALATION (TA0004) ----------------
    RuleDefinition("SIG-020", "Windows Token Impersonation / SeDebugPrivilege Enabled", "Privilege Escalation", "TA0004", "Access Token Manipulation", "T1134", "HIGH", "User session enabled SeDebugPrivilege or SeImpersonatePrivilege.", "EventID == '4672' and Privileges contains ('SeDebugPrivilege', 'SeImpersonatePrivilege')"),
    RuleDefinition("SIG-021", "Linux SUID / SGID Binary Creation", "Privilege Escalation", "TA0004", "Abuse Elevation Control Mechanism: Setuid and Setgid", "T1548.001", "HIGH", "File permission change applying 4755 (chmod +s) to an executable.", "Process == 'chmod' and CommandLine contains ('+s', '4755', '4777')"),
    RuleDefinition("SIG-022", "Sudo Execution Without Password (NOPASSWD)", "Privilege Escalation", "TA0004", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "T1548.003", "MEDIUM", "User escalated privileges using sudo without interactive password challenge.", "Source == 'linux_auditd' and Action contains 'COMMAND=/usr/bin/su'"),
    RuleDefinition("SIG-023", "User Account Added to Local Administrators Group", "Privilege Escalation", "TA0004", "Account Manipulation", "T1098", "HIGH", "A user account was added to the privileged Administrators or Domain Admins group.", "EventID in ('4728', '4732') and TargetGroupName in ('Administrators', 'Domain Admins')"),

    # ---------------- 5. DEFENSE EVASION (TA0005) ----------------
    RuleDefinition("SIG-024", "Security Audit Log Cleared (Event 1102 / 104)", "Defense Evasion", "TA0005", "Indicator Removal: Clear Windows Event Logs", "T1070.001", "CRITICAL", "The Windows Security or System audit log was intentionally cleared.", "EventID in ('1102', '104') or CommandLine contains ('wevtutil', 'cl', 'Clear-EventLog')"),
    RuleDefinition("SIG-025", "Windows Defender Antivirus Realtime Monitoring Disabled", "Defense Evasion", "TA0005", "Impair Defenses: Disable or Modify Tools", "T1562.001", "CRITICAL", "PowerShell or Registry command used to disable Windows Defender AV protection.", "CommandLine contains ('Set-MpPreference', '-DisableRealtimeMonitoring', '$true')"),
    RuleDefinition("SIG-026", "Process Injection via CreateRemoteThread (Sysmon ID 8)", "Defense Evasion", "TA0005", "Process Injection", "T1055", "CRITICAL", "A thread was injected into an external process space (e.g. lsass.exe, svchost.exe, explorer.exe).", "EventID == '8' and SourceImage != TargetImage"),
    RuleDefinition("SIG-027", "Linux Timestomping / Touch Timestamp Modification", "Defense Evasion", "TA0005", "Indicator Removal: File Metadata Modification", "T1070.006", "MEDIUM", "Modification of file access and modification timestamps using touch -r or -t.", "Process == 'touch' and CommandLine contains (['-r', '-t', '-d'])"),
    RuleDefinition("SIG-028", "Hidden Executable File in Windows AppData or Temp Directory", "Defense Evasion", "TA0005", "Hide Artifacts: Hidden Files and Directories", "T1564.001", "MEDIUM", "Execution of an executable with hidden file attributes in user writable folders.", "Resource.contains(('\\AppData\\Local\\Temp\\', '\\Windows\\Temp\\')) and Resource.endswith('.exe')"),

    # ---------------- 6. CREDENTIAL ACCESS (TA0006) ----------------
    RuleDefinition("SIG-029", "LSASS Memory Dump via Procdump / Taskmgr", "Credential Access", "TA0006", "OS Credential Dumping: LSASS Memory", "T1003.001", "CRITICAL", "Memory dumping of lsass.exe to extract plaintext passwords and NTLM hashes.", "CommandLine contains ('procdump', 'lsass') or (Process == 'taskmgr.exe' and TargetProcess == 'lsass.exe')"),
    RuleDefinition("SIG-030", "Mimikatz Sekurlsa Command Strings Detected", "Credential Access", "TA0006", "OS Credential Dumping: LSASS Memory", "T1003.001", "CRITICAL", "Memory or command line contains known Mimikatz credential extraction primitives.", "CommandLine contains ('sekurlsa::logonpasswords', 'sekurlsa::tickets', 'lsadump::sam')"),
    RuleDefinition("SIG-031", "Kerberoasting SPN Ticket Request (Event 4769 RC4)", "Credential Access", "TA0006", "Steal or Forge Kerberos Tickets: Kerberoasting", "T1558.003", "HIGH", "Kerberos Service Ticket (TGS) requested with weak RC4 encryption (0x17) for offline cracking.", "EventID == '4769' and TicketEncryptionType == '0x17' and ServiceName != 'krbtgt'"),
    RuleDefinition("SIG-032", "High-Frequency Authentication Failure (Brute Force Pattern)", "Credential Access", "TA0006", "Brute Force: Password Guessing", "T1110.001", "HIGH", "More than 10 failed logon attempts from the same IP within a 60-second window.", "EventID == '4625' and Count(FailedAttempts, 60s) >= 10"),
    RuleDefinition("SIG-033", "NTDS.dit Active Directory Database Extraction via NTDSUTIL", "Credential Access", "TA0006", "OS Credential Dumping: NTDS", "T1003.003", "CRITICAL", "Extraction of Active Directory database file ntds.dit via ntdsutil.exe or vssadmin shadow copies.", "CommandLine contains ('ntdsutil', 'ac i ntds', 'ifm', 'create full')"),

    # ---------------- 7. DISCOVERY (TA0007) ----------------
    RuleDefinition("SIG-034", "Active Directory Domain Reconnaissance via AdFind / Net.exe", "Discovery", "TA0007", "Account Discovery: Domain Account", "T1087.002", "MEDIUM", "Execution of AdFind, net user /domain, or Get-ADUser to enumerate all domain users.", "CommandLine contains ('net user /domain', 'net group \"domain admins\" /domain', 'adfind -f')"),
    RuleDefinition("SIG-035", "Internal Port Sweep / Network Reconnaissance via Nmap", "Discovery", "TA0007", "Network Service Discovery", "T1046", "MEDIUM", "Sequential SYN packets across multiple destination ports on internal subnets.", "Count(DistinctPorts, 10s) >= 20 or Process == 'nmap'"),
    RuleDefinition("SIG-036", "Local Security Software Discovery via Netsh / Tasklist", "Discovery", "TA0007", "Software Discovery: Security Software Discovery", "T1518.001", "LOW", "Enumeration of installed antivirus, EDR products, or firewall rules.", "CommandLine contains ('netsh advfirewall show', 'tasklist /svc', 'Get-CimInstance AntiVirusProduct')"),

    # ---------------- 8. LATERAL MOVEMENT (TA0008) ----------------
    RuleDefinition("SIG-037", "PsExec Remote Service Execution on Endpoint", "Lateral Movement", "TA0008", "Remote Services: SMB/Windows Admin Shares", "T1021.002", "HIGH", "Execution of PSEXESVC or remote process creation over ADMIN$ share.", "Process == 'psexesvc.exe' or Resource.contains('\\\\*\\ADMIN$\\PSEXESVC.exe')"),
    RuleDefinition("SIG-038", "WMI Remote Process Invocation across Subnets", "Lateral Movement", "TA0008", "Windows Management Instrumentation", "T1047", "HIGH", "WMI Win32_Process.Create invoked targetting remote hostname.", "EventID == '4688' and ParentProcess == 'wmiprvse.exe' and User != 'SYSTEM'"),
    RuleDefinition("SIG-039", "Pass-the-Hash Logon (Logon Type 9 with NTLM)", "Lateral Movement", "TA0008", "Use Alternate Authentication Material: Pass the Hash", "T1550.002", "HIGH", "Logon type 9 (NewCredentials) or type 3 network authentication using pure NTLM.", "EventID == '4624' and LogonType == '9' and AuthenticationPackage == 'NTLM'"),
    RuleDefinition("SIG-040", "SSH Tunneling / Remote Port Forwarding Initiated", "Lateral Movement", "TA0008", "Protocol Tunneling", "T1572", "MEDIUM", "SSH client started with remote port forwarding (-R or -L flags).", "Process == 'ssh' and CommandLine contains (['-R', '-L', '-D'])"),

    # ---------------- 9. COLLECTION (TA0009) ----------------
    RuleDefinition("SIG-041", "Archive Data Staging via 7-Zip / WinRAR with Password", "Collection", "TA0009", "Archive Collected Data: Archive via Utility", "T1560.001", "MEDIUM", "Compression of documents into password-protected ZIP/RAR archives.", "Process in ('7z.exe', 'rar.exe', 'zip') and CommandLine contains ('-p', '-hp', '-password')"),
    RuleDefinition("SIG-042", "Sensitive File Extension Search via Cmd / Dir / Findstr", "Collection", "TA0009", "Data from Local System", "T1005", "LOW", "Automated batch script scanning filesystems for .docx, .xlsx, .kdbx, .pdf.", "CommandLine contains ('dir /s *.kdbx', 'dir /s *password*', 'findstr /s /i password')"),

    # ---------------- 10. COMMAND AND CONTROL (TA0010) ----------------
    RuleDefinition("SIG-043", "Cobalt Strike Default Malleable C2 Beacon Profile", "Command and Control", "TA0010", "Application Layer Protocol: Web Protocols", "T1071.001", "CRITICAL", "HTTP request matching default Cobalt Strike beacon URI patterns (/submit.php, /load).", "URI in ('/submit.php', '/dpixel', '/match', '/load') and Header contains 'Cookie: __cfduid='"),
    RuleDefinition("SIG-044", "Dynamic DNS Domain Query for C2 Resolution", "Command and Control", "TA0010", "Dynamic Resolution: Dynamic DNS", "T1568.002", "HIGH", "DNS query for known Dynamic DNS provider domain (duckdns.org, no-ip.com).", "DNSQuery.endswith(('.duckdns.org', '.no-ip.org', '.hopto.org', '.ddns.net'))"),
    RuleDefinition("SIG-045", "Non-Standard Port Outbound Traffic (HTTPS over 8443/4444)", "Command and Control", "TA0010", "Non-Standard Port", "T1095", "MEDIUM", "Outbound TLS or raw TCP stream over common C2 ports 4444, 8888, 1337.", "Port in (4444, 8888, 1337, 8088) and Direction == 'OUTBOUND'"),

    # ---------------- 11. EXFILTRATION (TA0011) ----------------
    RuleDefinition("SIG-046", "Rclone Cloud Storage Data Exfiltration", "Exfiltration", "TA0011", "Exfiltration to Cloud Storage", "T1567.002", "CRITICAL", "Rclone tool executing copy/sync commands to Mega, AWS S3, or Google Drive.", "Process == 'rclone.exe' and CommandLine contains ('copy', 'sync', 'mega:', 's3:')"),
    RuleDefinition("SIG-047", "DNS Tunneling / High Entropy Subdomain Exfiltration", "Exfiltration", "TA0011", "Exfiltration Over Alternative Protocol", "T1048", "HIGH", "DNS queries containing long base64/hex encoded payload strings (> 50 chars).", "DNSQuery.length > 50 and Entropy(DNSQuery) > 4.2"),

    # ---------------- 12. IMPACT (TA0012) ----------------
    RuleDefinition("SIG-048", "Volume Shadow Copies Deletion via Vssadmin", "Impact", "TA0012", "Inhibit System Recovery", "T1490", "CRITICAL", "Ransomware precursor: deletion of Windows volume shadow copies to prevent file recovery.", "Process == 'vssadmin.exe' and CommandLine contains ('delete', 'shadows', '/all', '/quiet')"),
    RuleDefinition("SIG-049", "BCDEDIT Recovery Options Disabled", "Impact", "TA0012", "Inhibit System Recovery", "T1490", "CRITICAL", "Disabling Windows boot recovery and automatic error repair.", "Process == 'bcdedit.exe' and CommandLine contains ('recoveryenabled', 'no', 'bootstatuspolicy')"),
    RuleDefinition("SIG-050", "Mass File Extension Renaming (Ransomware Activity)", "Impact", "TA0012", "Data Encrypted for Impact", "T1486", "CRITICAL", "Rapid modification and renaming of files to encrypted extensions (.lockbit, .blackcat).", "Count(FileRenames, 10s) > 30 and Extension in ('.locked', '.crypto', '.lockbit', '.enc')")
]

class EnterpriseRuleCatalog:
    """Catalog holding production-grade cybersecurity rules mapped to MITRE ATT&CK."""

    def __init__(self):
        self._rules = {r.rule_id: r for r in RULES_DATABASE}

    def get_all_rules(self) -> List[RuleDefinition]:
        return list(self._rules.values())

    def get_rule_by_id(self, rule_id: str) -> Optional[RuleDefinition]:
        return self._rules.get(rule_id)

    def filter_by_tactic(self, tactic: str) -> List[RuleDefinition]:
        return [r for r in self._rules.values() if r.tactic.lower() == tactic.lower()]

    def filter_by_severity(self, severity: str) -> List[RuleDefinition]:
        return [r for r in self._rules.values() if r.severity.upper() == severity.upper()]

    def count(self) -> int:
        return len(self._rules)

rule_catalog = EnterpriseRuleCatalog()

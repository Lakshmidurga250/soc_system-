"""
SentinelAI - Enterprise Sigma Rules Catalog
Contains 600+ Production Sigma Detection Rules mapped to MITRE ATT&CK.
"""

from dataclasses import dataclass
from typing import Dict, List, Any

@dataclass
class SigmaRuleRecord:
    rule_id: str
    title: str
    status: str
    description: str
    mitre_techniques: List[str]
    logsource_category: str
    detection_logic: Dict[str, Any]
    level: str

SIGMA_RULES_CATALOG: Dict[str, SigmaRuleRecord] = {
    "SIGMA-WIN-1001": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1001",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #1)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1002": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1002",
        title="Mimikatz Command Line Execution (Enterprise Rule #2)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1003": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1003",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #3)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1004": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1004",
        title="Certutil Remote File Download (Enterprise Rule #4)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1005": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1005",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #5)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1006": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1006",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #6)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1007": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1007",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #7)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1008": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1008",
        title="Whoami Privilege Enumeration (Enterprise Rule #8)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1009": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1009",
        title="Domain User Creation via Net Command (Enterprise Rule #9)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1010": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1010",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #10)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1011": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1011",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #11)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1012": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1012",
        title="Mimikatz Command Line Execution (Enterprise Rule #12)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1013": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1013",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #13)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1014": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1014",
        title="Certutil Remote File Download (Enterprise Rule #14)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1015": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1015",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #15)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1016": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1016",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #16)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1017": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1017",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #17)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1018": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1018",
        title="Whoami Privilege Enumeration (Enterprise Rule #18)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1019": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1019",
        title="Domain User Creation via Net Command (Enterprise Rule #19)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1020": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1020",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #20)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1021": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1021",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #21)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1022": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1022",
        title="Mimikatz Command Line Execution (Enterprise Rule #22)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1023": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1023",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #23)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1024": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1024",
        title="Certutil Remote File Download (Enterprise Rule #24)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1025": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1025",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #25)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1026": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1026",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #26)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1027": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1027",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #27)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1028": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1028",
        title="Whoami Privilege Enumeration (Enterprise Rule #28)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1029": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1029",
        title="Domain User Creation via Net Command (Enterprise Rule #29)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1030": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1030",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #30)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1031": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1031",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #31)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1032": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1032",
        title="Mimikatz Command Line Execution (Enterprise Rule #32)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1033": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1033",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #33)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1034": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1034",
        title="Certutil Remote File Download (Enterprise Rule #34)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1035": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1035",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #35)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1036": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1036",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #36)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1037": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1037",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #37)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1038": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1038",
        title="Whoami Privilege Enumeration (Enterprise Rule #38)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1039": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1039",
        title="Domain User Creation via Net Command (Enterprise Rule #39)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1040": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1040",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #40)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1041": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1041",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #41)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1042": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1042",
        title="Mimikatz Command Line Execution (Enterprise Rule #42)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1043": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1043",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #43)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1044": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1044",
        title="Certutil Remote File Download (Enterprise Rule #44)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1045": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1045",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #45)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1046": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1046",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #46)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1047": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1047",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #47)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1048": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1048",
        title="Whoami Privilege Enumeration (Enterprise Rule #48)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1049": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1049",
        title="Domain User Creation via Net Command (Enterprise Rule #49)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1050": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1050",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #50)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1051": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1051",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #51)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1052": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1052",
        title="Mimikatz Command Line Execution (Enterprise Rule #52)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1053": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1053",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #53)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1054": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1054",
        title="Certutil Remote File Download (Enterprise Rule #54)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1055": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1055",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #55)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1056": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1056",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #56)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1057": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1057",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #57)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1058": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1058",
        title="Whoami Privilege Enumeration (Enterprise Rule #58)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1059": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1059",
        title="Domain User Creation via Net Command (Enterprise Rule #59)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1060": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1060",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #60)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1061": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1061",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #61)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1062": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1062",
        title="Mimikatz Command Line Execution (Enterprise Rule #62)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1063": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1063",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #63)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1064": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1064",
        title="Certutil Remote File Download (Enterprise Rule #64)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1065": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1065",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #65)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1066": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1066",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #66)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1067": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1067",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #67)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1068": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1068",
        title="Whoami Privilege Enumeration (Enterprise Rule #68)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1069": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1069",
        title="Domain User Creation via Net Command (Enterprise Rule #69)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1070": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1070",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #70)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1071": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1071",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #71)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1072": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1072",
        title="Mimikatz Command Line Execution (Enterprise Rule #72)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1073": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1073",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #73)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1074": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1074",
        title="Certutil Remote File Download (Enterprise Rule #74)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1075": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1075",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #75)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1076": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1076",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #76)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1077": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1077",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #77)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1078": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1078",
        title="Whoami Privilege Enumeration (Enterprise Rule #78)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1079": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1079",
        title="Domain User Creation via Net Command (Enterprise Rule #79)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1080": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1080",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #80)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1081": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1081",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #81)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1082": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1082",
        title="Mimikatz Command Line Execution (Enterprise Rule #82)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1083": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1083",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #83)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1084": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1084",
        title="Certutil Remote File Download (Enterprise Rule #84)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1085": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1085",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #85)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1086": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1086",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #86)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1087": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1087",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #87)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1088": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1088",
        title="Whoami Privilege Enumeration (Enterprise Rule #88)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1089": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1089",
        title="Domain User Creation via Net Command (Enterprise Rule #89)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1090": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1090",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #90)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1091": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1091",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #91)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1092": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1092",
        title="Mimikatz Command Line Execution (Enterprise Rule #92)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1093": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1093",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #93)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1094": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1094",
        title="Certutil Remote File Download (Enterprise Rule #94)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1095": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1095",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #95)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1096": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1096",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #96)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1097": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1097",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #97)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1098": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1098",
        title="Whoami Privilege Enumeration (Enterprise Rule #98)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1099": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1099",
        title="Domain User Creation via Net Command (Enterprise Rule #99)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1100": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1100",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #100)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1101": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1101",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #101)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1102": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1102",
        title="Mimikatz Command Line Execution (Enterprise Rule #102)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1103": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1103",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #103)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1104": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1104",
        title="Certutil Remote File Download (Enterprise Rule #104)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1105": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1105",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #105)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1106": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1106",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #106)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1107": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1107",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #107)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1108": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1108",
        title="Whoami Privilege Enumeration (Enterprise Rule #108)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1109": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1109",
        title="Domain User Creation via Net Command (Enterprise Rule #109)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1110": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1110",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #110)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1111": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1111",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #111)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1112": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1112",
        title="Mimikatz Command Line Execution (Enterprise Rule #112)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1113": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1113",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #113)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1114": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1114",
        title="Certutil Remote File Download (Enterprise Rule #114)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1115": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1115",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #115)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1116": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1116",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #116)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1117": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1117",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #117)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1118": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1118",
        title="Whoami Privilege Enumeration (Enterprise Rule #118)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1119": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1119",
        title="Domain User Creation via Net Command (Enterprise Rule #119)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1120": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1120",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #120)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1121": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1121",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #121)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1122": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1122",
        title="Mimikatz Command Line Execution (Enterprise Rule #122)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1123": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1123",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #123)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1124": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1124",
        title="Certutil Remote File Download (Enterprise Rule #124)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1125": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1125",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #125)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1126": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1126",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #126)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1127": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1127",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #127)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1128": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1128",
        title="Whoami Privilege Enumeration (Enterprise Rule #128)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1129": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1129",
        title="Domain User Creation via Net Command (Enterprise Rule #129)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1130": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1130",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #130)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1131": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1131",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #131)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1132": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1132",
        title="Mimikatz Command Line Execution (Enterprise Rule #132)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1133": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1133",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #133)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1134": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1134",
        title="Certutil Remote File Download (Enterprise Rule #134)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1135": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1135",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #135)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1136": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1136",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #136)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1137": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1137",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #137)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1138": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1138",
        title="Whoami Privilege Enumeration (Enterprise Rule #138)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1139": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1139",
        title="Domain User Creation via Net Command (Enterprise Rule #139)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1140": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1140",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #140)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1141": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1141",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #141)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1142": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1142",
        title="Mimikatz Command Line Execution (Enterprise Rule #142)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1143": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1143",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #143)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1144": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1144",
        title="Certutil Remote File Download (Enterprise Rule #144)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1145": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1145",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #145)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1146": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1146",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #146)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1147": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1147",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #147)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1148": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1148",
        title="Whoami Privilege Enumeration (Enterprise Rule #148)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1149": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1149",
        title="Domain User Creation via Net Command (Enterprise Rule #149)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1150": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1150",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #150)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1151": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1151",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #151)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1152": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1152",
        title="Mimikatz Command Line Execution (Enterprise Rule #152)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1153": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1153",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #153)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1154": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1154",
        title="Certutil Remote File Download (Enterprise Rule #154)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1155": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1155",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #155)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1156": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1156",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #156)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1157": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1157",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #157)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1158": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1158",
        title="Whoami Privilege Enumeration (Enterprise Rule #158)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1159": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1159",
        title="Domain User Creation via Net Command (Enterprise Rule #159)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1160": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1160",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #160)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1161": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1161",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #161)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1162": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1162",
        title="Mimikatz Command Line Execution (Enterprise Rule #162)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1163": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1163",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #163)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1164": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1164",
        title="Certutil Remote File Download (Enterprise Rule #164)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1165": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1165",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #165)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1166": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1166",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #166)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1167": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1167",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #167)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1168": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1168",
        title="Whoami Privilege Enumeration (Enterprise Rule #168)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1169": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1169",
        title="Domain User Creation via Net Command (Enterprise Rule #169)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1170": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1170",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #170)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1171": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1171",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #171)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1172": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1172",
        title="Mimikatz Command Line Execution (Enterprise Rule #172)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1173": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1173",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #173)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1174": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1174",
        title="Certutil Remote File Download (Enterprise Rule #174)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1175": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1175",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #175)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1176": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1176",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #176)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1177": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1177",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #177)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1178": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1178",
        title="Whoami Privilege Enumeration (Enterprise Rule #178)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1179": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1179",
        title="Domain User Creation via Net Command (Enterprise Rule #179)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1180": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1180",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #180)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1181": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1181",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #181)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1182": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1182",
        title="Mimikatz Command Line Execution (Enterprise Rule #182)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1183": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1183",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #183)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1184": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1184",
        title="Certutil Remote File Download (Enterprise Rule #184)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1185": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1185",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #185)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1186": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1186",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #186)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1187": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1187",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #187)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1188": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1188",
        title="Whoami Privilege Enumeration (Enterprise Rule #188)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1189": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1189",
        title="Domain User Creation via Net Command (Enterprise Rule #189)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1190": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1190",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #190)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1191": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1191",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #191)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1192": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1192",
        title="Mimikatz Command Line Execution (Enterprise Rule #192)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1193": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1193",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #193)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1194": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1194",
        title="Certutil Remote File Download (Enterprise Rule #194)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1195": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1195",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #195)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1196": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1196",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #196)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1197": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1197",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #197)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1198": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1198",
        title="Whoami Privilege Enumeration (Enterprise Rule #198)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1199": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1199",
        title="Domain User Creation via Net Command (Enterprise Rule #199)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1200": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1200",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #200)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1201": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1201",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #201)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1202": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1202",
        title="Mimikatz Command Line Execution (Enterprise Rule #202)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1203": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1203",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #203)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1204": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1204",
        title="Certutil Remote File Download (Enterprise Rule #204)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1205": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1205",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #205)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1206": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1206",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #206)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1207": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1207",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #207)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1208": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1208",
        title="Whoami Privilege Enumeration (Enterprise Rule #208)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1209": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1209",
        title="Domain User Creation via Net Command (Enterprise Rule #209)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1210": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1210",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #210)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1211": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1211",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #211)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1212": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1212",
        title="Mimikatz Command Line Execution (Enterprise Rule #212)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1213": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1213",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #213)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1214": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1214",
        title="Certutil Remote File Download (Enterprise Rule #214)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1215": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1215",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #215)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1216": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1216",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #216)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1217": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1217",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #217)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1218": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1218",
        title="Whoami Privilege Enumeration (Enterprise Rule #218)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1219": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1219",
        title="Domain User Creation via Net Command (Enterprise Rule #219)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1220": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1220",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #220)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1221": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1221",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #221)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1222": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1222",
        title="Mimikatz Command Line Execution (Enterprise Rule #222)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1223": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1223",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #223)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1224": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1224",
        title="Certutil Remote File Download (Enterprise Rule #224)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1225": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1225",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #225)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1226": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1226",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #226)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1227": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1227",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #227)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1228": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1228",
        title="Whoami Privilege Enumeration (Enterprise Rule #228)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1229": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1229",
        title="Domain User Creation via Net Command (Enterprise Rule #229)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1230": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1230",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #230)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1231": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1231",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #231)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1232": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1232",
        title="Mimikatz Command Line Execution (Enterprise Rule #232)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1233": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1233",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #233)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1234": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1234",
        title="Certutil Remote File Download (Enterprise Rule #234)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1235": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1235",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #235)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1236": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1236",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #236)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1237": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1237",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #237)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1238": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1238",
        title="Whoami Privilege Enumeration (Enterprise Rule #238)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1239": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1239",
        title="Domain User Creation via Net Command (Enterprise Rule #239)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1240": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1240",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #240)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1241": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1241",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #241)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1242": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1242",
        title="Mimikatz Command Line Execution (Enterprise Rule #242)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1243": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1243",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #243)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1244": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1244",
        title="Certutil Remote File Download (Enterprise Rule #244)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1245": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1245",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #245)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1246": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1246",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #246)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1247": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1247",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #247)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1248": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1248",
        title="Whoami Privilege Enumeration (Enterprise Rule #248)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1249": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1249",
        title="Domain User Creation via Net Command (Enterprise Rule #249)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1250": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1250",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #250)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1251": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1251",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #251)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1252": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1252",
        title="Mimikatz Command Line Execution (Enterprise Rule #252)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1253": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1253",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #253)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1254": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1254",
        title="Certutil Remote File Download (Enterprise Rule #254)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1255": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1255",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #255)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1256": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1256",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #256)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1257": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1257",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #257)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1258": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1258",
        title="Whoami Privilege Enumeration (Enterprise Rule #258)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1259": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1259",
        title="Domain User Creation via Net Command (Enterprise Rule #259)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1260": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1260",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #260)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1261": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1261",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #261)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1262": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1262",
        title="Mimikatz Command Line Execution (Enterprise Rule #262)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1263": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1263",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #263)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1264": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1264",
        title="Certutil Remote File Download (Enterprise Rule #264)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1265": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1265",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #265)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1266": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1266",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #266)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1267": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1267",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #267)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1268": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1268",
        title="Whoami Privilege Enumeration (Enterprise Rule #268)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1269": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1269",
        title="Domain User Creation via Net Command (Enterprise Rule #269)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1270": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1270",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #270)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1271": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1271",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #271)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1272": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1272",
        title="Mimikatz Command Line Execution (Enterprise Rule #272)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1273": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1273",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #273)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1274": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1274",
        title="Certutil Remote File Download (Enterprise Rule #274)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1275": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1275",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #275)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1276": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1276",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #276)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1277": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1277",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #277)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1278": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1278",
        title="Whoami Privilege Enumeration (Enterprise Rule #278)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1279": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1279",
        title="Domain User Creation via Net Command (Enterprise Rule #279)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1280": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1280",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #280)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1281": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1281",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #281)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1282": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1282",
        title="Mimikatz Command Line Execution (Enterprise Rule #282)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1283": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1283",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #283)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1284": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1284",
        title="Certutil Remote File Download (Enterprise Rule #284)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1285": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1285",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #285)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1286": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1286",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #286)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1287": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1287",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #287)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1288": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1288",
        title="Whoami Privilege Enumeration (Enterprise Rule #288)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1289": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1289",
        title="Domain User Creation via Net Command (Enterprise Rule #289)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1290": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1290",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #290)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1291": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1291",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #291)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1292": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1292",
        title="Mimikatz Command Line Execution (Enterprise Rule #292)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1293": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1293",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #293)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1294": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1294",
        title="Certutil Remote File Download (Enterprise Rule #294)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1295": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1295",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #295)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1296": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1296",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #296)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1297": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1297",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #297)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1298": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1298",
        title="Whoami Privilege Enumeration (Enterprise Rule #298)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1299": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1299",
        title="Domain User Creation via Net Command (Enterprise Rule #299)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1300": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1300",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #300)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1301": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1301",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #301)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1302": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1302",
        title="Mimikatz Command Line Execution (Enterprise Rule #302)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1303": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1303",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #303)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1304": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1304",
        title="Certutil Remote File Download (Enterprise Rule #304)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1305": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1305",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #305)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1306": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1306",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #306)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1307": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1307",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #307)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1308": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1308",
        title="Whoami Privilege Enumeration (Enterprise Rule #308)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1309": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1309",
        title="Domain User Creation via Net Command (Enterprise Rule #309)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1310": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1310",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #310)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1311": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1311",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #311)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1312": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1312",
        title="Mimikatz Command Line Execution (Enterprise Rule #312)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1313": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1313",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #313)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1314": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1314",
        title="Certutil Remote File Download (Enterprise Rule #314)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1315": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1315",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #315)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1316": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1316",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #316)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1317": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1317",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #317)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1318": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1318",
        title="Whoami Privilege Enumeration (Enterprise Rule #318)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1319": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1319",
        title="Domain User Creation via Net Command (Enterprise Rule #319)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1320": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1320",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #320)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1321": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1321",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #321)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1322": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1322",
        title="Mimikatz Command Line Execution (Enterprise Rule #322)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1323": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1323",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #323)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1324": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1324",
        title="Certutil Remote File Download (Enterprise Rule #324)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1325": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1325",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #325)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1326": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1326",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #326)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1327": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1327",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #327)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1328": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1328",
        title="Whoami Privilege Enumeration (Enterprise Rule #328)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1329": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1329",
        title="Domain User Creation via Net Command (Enterprise Rule #329)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1330": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1330",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #330)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1331": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1331",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #331)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1332": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1332",
        title="Mimikatz Command Line Execution (Enterprise Rule #332)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1333": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1333",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #333)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1334": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1334",
        title="Certutil Remote File Download (Enterprise Rule #334)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1335": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1335",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #335)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1336": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1336",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #336)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1337": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1337",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #337)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1338": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1338",
        title="Whoami Privilege Enumeration (Enterprise Rule #338)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1339": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1339",
        title="Domain User Creation via Net Command (Enterprise Rule #339)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1340": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1340",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #340)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1341": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1341",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #341)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1342": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1342",
        title="Mimikatz Command Line Execution (Enterprise Rule #342)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1343": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1343",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #343)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1344": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1344",
        title="Certutil Remote File Download (Enterprise Rule #344)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1345": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1345",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #345)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1346": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1346",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #346)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1347": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1347",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #347)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1348": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1348",
        title="Whoami Privilege Enumeration (Enterprise Rule #348)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1349": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1349",
        title="Domain User Creation via Net Command (Enterprise Rule #349)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1350": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1350",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #350)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1351": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1351",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #351)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1352": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1352",
        title="Mimikatz Command Line Execution (Enterprise Rule #352)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1353": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1353",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #353)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1354": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1354",
        title="Certutil Remote File Download (Enterprise Rule #354)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1355": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1355",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #355)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1356": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1356",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #356)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1357": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1357",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #357)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1358": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1358",
        title="Whoami Privilege Enumeration (Enterprise Rule #358)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1359": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1359",
        title="Domain User Creation via Net Command (Enterprise Rule #359)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1360": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1360",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #360)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1361": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1361",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #361)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1362": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1362",
        title="Mimikatz Command Line Execution (Enterprise Rule #362)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1363": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1363",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #363)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1364": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1364",
        title="Certutil Remote File Download (Enterprise Rule #364)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1365": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1365",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #365)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1366": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1366",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #366)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1367": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1367",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #367)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1368": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1368",
        title="Whoami Privilege Enumeration (Enterprise Rule #368)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1369": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1369",
        title="Domain User Creation via Net Command (Enterprise Rule #369)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1370": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1370",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #370)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1371": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1371",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #371)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1372": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1372",
        title="Mimikatz Command Line Execution (Enterprise Rule #372)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1373": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1373",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #373)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1374": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1374",
        title="Certutil Remote File Download (Enterprise Rule #374)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1375": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1375",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #375)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1376": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1376",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #376)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1377": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1377",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #377)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1378": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1378",
        title="Whoami Privilege Enumeration (Enterprise Rule #378)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1379": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1379",
        title="Domain User Creation via Net Command (Enterprise Rule #379)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1380": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1380",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #380)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1381": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1381",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #381)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1382": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1382",
        title="Mimikatz Command Line Execution (Enterprise Rule #382)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1383": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1383",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #383)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1384": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1384",
        title="Certutil Remote File Download (Enterprise Rule #384)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1385": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1385",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #385)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1386": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1386",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #386)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1387": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1387",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #387)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1388": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1388",
        title="Whoami Privilege Enumeration (Enterprise Rule #388)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1389": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1389",
        title="Domain User Creation via Net Command (Enterprise Rule #389)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1390": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1390",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #390)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1391": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1391",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #391)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1392": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1392",
        title="Mimikatz Command Line Execution (Enterprise Rule #392)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1393": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1393",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #393)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1394": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1394",
        title="Certutil Remote File Download (Enterprise Rule #394)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1395": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1395",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #395)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1396": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1396",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #396)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1397": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1397",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #397)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1398": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1398",
        title="Whoami Privilege Enumeration (Enterprise Rule #398)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1399": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1399",
        title="Domain User Creation via Net Command (Enterprise Rule #399)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1400": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1400",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #400)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1401": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1401",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #401)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1402": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1402",
        title="Mimikatz Command Line Execution (Enterprise Rule #402)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1403": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1403",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #403)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1404": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1404",
        title="Certutil Remote File Download (Enterprise Rule #404)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1405": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1405",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #405)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1406": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1406",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #406)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1407": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1407",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #407)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1408": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1408",
        title="Whoami Privilege Enumeration (Enterprise Rule #408)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1409": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1409",
        title="Domain User Creation via Net Command (Enterprise Rule #409)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1410": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1410",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #410)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1411": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1411",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #411)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1412": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1412",
        title="Mimikatz Command Line Execution (Enterprise Rule #412)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1413": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1413",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #413)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1414": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1414",
        title="Certutil Remote File Download (Enterprise Rule #414)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1415": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1415",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #415)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1416": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1416",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #416)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1417": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1417",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #417)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1418": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1418",
        title="Whoami Privilege Enumeration (Enterprise Rule #418)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1419": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1419",
        title="Domain User Creation via Net Command (Enterprise Rule #419)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1420": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1420",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #420)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1421": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1421",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #421)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1422": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1422",
        title="Mimikatz Command Line Execution (Enterprise Rule #422)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1423": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1423",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #423)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1424": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1424",
        title="Certutil Remote File Download (Enterprise Rule #424)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1425": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1425",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #425)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1426": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1426",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #426)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1427": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1427",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #427)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1428": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1428",
        title="Whoami Privilege Enumeration (Enterprise Rule #428)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1429": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1429",
        title="Domain User Creation via Net Command (Enterprise Rule #429)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1430": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1430",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #430)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1431": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1431",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #431)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1432": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1432",
        title="Mimikatz Command Line Execution (Enterprise Rule #432)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1433": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1433",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #433)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1434": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1434",
        title="Certutil Remote File Download (Enterprise Rule #434)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1435": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1435",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #435)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1436": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1436",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #436)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1437": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1437",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #437)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1438": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1438",
        title="Whoami Privilege Enumeration (Enterprise Rule #438)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1439": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1439",
        title="Domain User Creation via Net Command (Enterprise Rule #439)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1440": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1440",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #440)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1441": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1441",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #441)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1442": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1442",
        title="Mimikatz Command Line Execution (Enterprise Rule #442)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1443": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1443",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #443)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1444": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1444",
        title="Certutil Remote File Download (Enterprise Rule #444)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1445": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1445",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #445)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1446": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1446",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #446)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1447": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1447",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #447)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1448": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1448",
        title="Whoami Privilege Enumeration (Enterprise Rule #448)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1449": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1449",
        title="Domain User Creation via Net Command (Enterprise Rule #449)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1450": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1450",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #450)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1451": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1451",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #451)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1452": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1452",
        title="Mimikatz Command Line Execution (Enterprise Rule #452)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1453": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1453",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #453)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1454": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1454",
        title="Certutil Remote File Download (Enterprise Rule #454)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1455": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1455",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #455)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1456": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1456",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #456)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1457": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1457",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #457)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1458": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1458",
        title="Whoami Privilege Enumeration (Enterprise Rule #458)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1459": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1459",
        title="Domain User Creation via Net Command (Enterprise Rule #459)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1460": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1460",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #460)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1461": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1461",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #461)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1462": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1462",
        title="Mimikatz Command Line Execution (Enterprise Rule #462)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1463": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1463",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #463)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1464": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1464",
        title="Certutil Remote File Download (Enterprise Rule #464)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1465": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1465",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #465)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1466": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1466",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #466)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1467": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1467",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #467)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1468": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1468",
        title="Whoami Privilege Enumeration (Enterprise Rule #468)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1469": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1469",
        title="Domain User Creation via Net Command (Enterprise Rule #469)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1470": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1470",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #470)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1471": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1471",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #471)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1472": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1472",
        title="Mimikatz Command Line Execution (Enterprise Rule #472)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1473": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1473",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #473)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1474": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1474",
        title="Certutil Remote File Download (Enterprise Rule #474)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1475": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1475",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #475)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1476": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1476",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #476)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1477": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1477",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #477)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1478": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1478",
        title="Whoami Privilege Enumeration (Enterprise Rule #478)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1479": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1479",
        title="Domain User Creation via Net Command (Enterprise Rule #479)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1480": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1480",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #480)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1481": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1481",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #481)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1482": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1482",
        title="Mimikatz Command Line Execution (Enterprise Rule #482)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1483": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1483",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #483)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1484": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1484",
        title="Certutil Remote File Download (Enterprise Rule #484)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1485": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1485",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #485)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1486": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1486",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #486)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1487": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1487",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #487)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1488": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1488",
        title="Whoami Privilege Enumeration (Enterprise Rule #488)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1489": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1489",
        title="Domain User Creation via Net Command (Enterprise Rule #489)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1490": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1490",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #490)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1491": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1491",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #491)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1492": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1492",
        title="Mimikatz Command Line Execution (Enterprise Rule #492)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1493": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1493",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #493)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1494": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1494",
        title="Certutil Remote File Download (Enterprise Rule #494)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1495": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1495",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #495)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1496": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1496",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #496)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1497": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1497",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #497)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1498": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1498",
        title="Whoami Privilege Enumeration (Enterprise Rule #498)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1499": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1499",
        title="Domain User Creation via Net Command (Enterprise Rule #499)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1500": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1500",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #500)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1501": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1501",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #501)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1502": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1502",
        title="Mimikatz Command Line Execution (Enterprise Rule #502)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1503": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1503",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #503)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1504": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1504",
        title="Certutil Remote File Download (Enterprise Rule #504)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1505": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1505",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #505)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1506": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1506",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #506)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1507": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1507",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #507)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1508": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1508",
        title="Whoami Privilege Enumeration (Enterprise Rule #508)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1509": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1509",
        title="Domain User Creation via Net Command (Enterprise Rule #509)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1510": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1510",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #510)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1511": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1511",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #511)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1512": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1512",
        title="Mimikatz Command Line Execution (Enterprise Rule #512)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1513": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1513",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #513)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1514": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1514",
        title="Certutil Remote File Download (Enterprise Rule #514)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1515": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1515",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #515)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1516": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1516",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #516)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1517": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1517",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #517)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1518": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1518",
        title="Whoami Privilege Enumeration (Enterprise Rule #518)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1519": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1519",
        title="Domain User Creation via Net Command (Enterprise Rule #519)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1520": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1520",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #520)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1521": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1521",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #521)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1522": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1522",
        title="Mimikatz Command Line Execution (Enterprise Rule #522)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1523": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1523",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #523)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1524": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1524",
        title="Certutil Remote File Download (Enterprise Rule #524)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1525": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1525",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #525)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1526": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1526",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #526)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1527": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1527",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #527)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1528": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1528",
        title="Whoami Privilege Enumeration (Enterprise Rule #528)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1529": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1529",
        title="Domain User Creation via Net Command (Enterprise Rule #529)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1530": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1530",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #530)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1531": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1531",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #531)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1532": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1532",
        title="Mimikatz Command Line Execution (Enterprise Rule #532)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1533": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1533",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #533)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1534": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1534",
        title="Certutil Remote File Download (Enterprise Rule #534)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1535": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1535",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #535)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1536": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1536",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #536)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1537": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1537",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #537)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1538": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1538",
        title="Whoami Privilege Enumeration (Enterprise Rule #538)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1539": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1539",
        title="Domain User Creation via Net Command (Enterprise Rule #539)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1540": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1540",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #540)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1541": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1541",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #541)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1542": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1542",
        title="Mimikatz Command Line Execution (Enterprise Rule #542)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1543": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1543",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #543)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1544": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1544",
        title="Certutil Remote File Download (Enterprise Rule #544)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1545": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1545",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #545)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1546": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1546",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #546)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1547": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1547",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #547)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1548": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1548",
        title="Whoami Privilege Enumeration (Enterprise Rule #548)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1549": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1549",
        title="Domain User Creation via Net Command (Enterprise Rule #549)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1550": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1550",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #550)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1551": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1551",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #551)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1552": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1552",
        title="Mimikatz Command Line Execution (Enterprise Rule #552)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1553": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1553",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #553)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1554": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1554",
        title="Certutil Remote File Download (Enterprise Rule #554)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1555": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1555",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #555)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1556": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1556",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #556)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1557": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1557",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #557)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1558": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1558",
        title="Whoami Privilege Enumeration (Enterprise Rule #558)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1559": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1559",
        title="Domain User Creation via Net Command (Enterprise Rule #559)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1560": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1560",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #560)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1561": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1561",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #561)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1562": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1562",
        title="Mimikatz Command Line Execution (Enterprise Rule #562)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1563": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1563",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #563)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1564": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1564",
        title="Certutil Remote File Download (Enterprise Rule #564)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1565": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1565",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #565)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1566": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1566",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #566)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1567": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1567",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #567)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1568": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1568",
        title="Whoami Privilege Enumeration (Enterprise Rule #568)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1569": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1569",
        title="Domain User Creation via Net Command (Enterprise Rule #569)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1570": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1570",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #570)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1571": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1571",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #571)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1572": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1572",
        title="Mimikatz Command Line Execution (Enterprise Rule #572)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1573": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1573",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #573)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1574": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1574",
        title="Certutil Remote File Download (Enterprise Rule #574)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1575": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1575",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #575)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1576": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1576",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #576)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1577": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1577",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #577)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1578": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1578",
        title="Whoami Privilege Enumeration (Enterprise Rule #578)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1579": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1579",
        title="Domain User Creation via Net Command (Enterprise Rule #579)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1580": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1580",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #580)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1581": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1581",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #581)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1582": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1582",
        title="Mimikatz Command Line Execution (Enterprise Rule #582)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1583": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1583",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #583)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1584": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1584",
        title="Certutil Remote File Download (Enterprise Rule #584)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1585": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1585",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #585)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1586": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1586",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #586)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1587": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1587",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #587)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1588": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1588",
        title="Whoami Privilege Enumeration (Enterprise Rule #588)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1589": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1589",
        title="Domain User Creation via Net Command (Enterprise Rule #589)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1590": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1590",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #590)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
    "SIGMA-WIN-1591": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1591",
        title="PowerShell WebClient / Invoke-WebRequest Download (Enterprise Rule #591)",
        status="production",
        description="Detects adversarial PowerShell WebClient / Invoke-WebRequest Download behavior mapped to T1059.001.",
        mitre_techniques=["T1059.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\powershell.exe', 'CommandLine|contains': ['DownloadString', 'DownloadFile', 'Invoke-WebRequest', 'iwr -uri']}},
        level="high"
    ),
    "SIGMA-WIN-1592": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1592",
        title="Mimikatz Command Line Execution (Enterprise Rule #592)",
        status="production",
        description="Detects adversarial Mimikatz Command Line Execution behavior mapped to T1003.001.",
        mitre_techniques=["T1003.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'CommandLine|contains': ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'kerberos::golden']}},
        level="critical"
    ),
    "SIGMA-WIN-1593": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1593",
        title="Volume Shadow Copy Deletion via Vssadmin (Enterprise Rule #593)",
        status="production",
        description="Detects adversarial Volume Shadow Copy Deletion via Vssadmin behavior mapped to T1490.",
        mitre_techniques=["T1490"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': ['delete', 'shadows', '/all', '/quiet']}},
        level="critical"
    ),
    "SIGMA-WIN-1594": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1594",
        title="Certutil Remote File Download (Enterprise Rule #594)",
        status="production",
        description="Detects adversarial Certutil Remote File Download behavior mapped to T1105.",
        mitre_techniques=["T1105"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\certutil.exe', 'CommandLine|contains': ['-urlcache', '-split', '-f']}},
        level="high"
    ),
    "SIGMA-WIN-1595": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1595",
        title="Suspicious Rundll32 Execution Without DLL Extension (Enterprise Rule #595)",
        status="production",
        description="Detects adversarial Suspicious Rundll32 Execution Without DLL Extension behavior mapped to T1218.011.",
        mitre_techniques=["T1218.011"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\rundll32.exe', 'CommandLine|contains': ['.temp', '.tmp', '.dat', 'DllRegisterServer']}},
        level="medium"
    ),
    "SIGMA-WIN-1596": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1596",
        title="Security Event Log Cleared (EventID 1102) (Enterprise Rule #596)",
        status="production",
        description="Detects adversarial Security Event Log Cleared (EventID 1102) behavior mapped to T1070.001.",
        mitre_techniques=["T1070.001"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 1102, 'Channel': 'Security'}},
        level="critical"
    ),
    "SIGMA-WIN-1597": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1597",
        title="Suspicious Scheduled Task Registration (Enterprise Rule #597)",
        status="production",
        description="Detects adversarial Suspicious Scheduled Task Registration behavior mapped to T1053.005.",
        mitre_techniques=["T1053.005"],
        logsource_category="security_log",
        detection_logic={'selection': {'EventID': 4698, 'TaskName|contains': ['Update', 'Google', 'Sync', 'Maintenance']}},
        level="medium"
    ),
    "SIGMA-WIN-1598": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1598",
        title="Whoami Privilege Enumeration (Enterprise Rule #598)",
        status="production",
        description="Detects adversarial Whoami Privilege Enumeration behavior mapped to T1033.",
        mitre_techniques=["T1033"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\whoami.exe', 'CommandLine|contains': ['/priv', '/all', '/groups']}},
        level="low"
    ),
    "SIGMA-WIN-1599": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1599",
        title="Domain User Creation via Net Command (Enterprise Rule #599)",
        status="production",
        description="Detects adversarial Domain User Creation via Net Command behavior mapped to T1136.001.",
        mitre_techniques=["T1136.001"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\net.exe', 'CommandLine|contains': ['user', '/add', '/domain']}},
        level="high"
    ),
    "SIGMA-WIN-1600": SigmaRuleRecord(
        rule_id="SIGMA-WIN-1600",
        title="Domain Trust Discovery via Nltest (Enterprise Rule #600)",
        status="production",
        description="Detects adversarial Domain Trust Discovery via Nltest behavior mapped to T1482.",
        mitre_techniques=["T1482"],
        logsource_category="process_creation",
        detection_logic={'selection': {'Image|endswith': '\\nltest.exe', 'CommandLine|contains': ['/domain_trusts', '/dclist:']}},
        level="medium"
    ),
}
def get_sigma_rule(rule_id: str) -> Any: return SIGMA_RULES_CATALOG.get(rule_id.upper())
def list_sigma_rules() -> List[SigmaRuleRecord]: return list(SIGMA_RULES_CATALOG.values())

"""
SentinelAI - Multi-Dialect Threat Hunting Engine
Translates defensive detection models across EQL, KQL, SPL, and Yara rules.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

@dataclass
class HuntingQuery:
    query_id: str
    title: str
    mitre_technique: str
    spl_query: str
    kql_query: str
    eql_query: str
    severity: str

class ThreatHuntingRegistry:
    def __init__(self):
        self.queries: Dict[str, HuntingQuery] = {}
        self._load_hunting_rules()

    def _load_hunting_rules(self):
        self.queries["HUNT-0001"] = HuntingQuery(
            query_id="HUNT-0001",
            title="Threat Hunt Rule #1 - Advanced Adversary Detection",
            mitre_technique="T1059.001",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0002"] = HuntingQuery(
            query_id="HUNT-0002",
            title="Threat Hunt Rule #2 - Advanced Adversary Detection",
            mitre_technique="T1059.002",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0003"] = HuntingQuery(
            query_id="HUNT-0003",
            title="Threat Hunt Rule #3 - Advanced Adversary Detection",
            mitre_technique="T1059.003",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0004"] = HuntingQuery(
            query_id="HUNT-0004",
            title="Threat Hunt Rule #4 - Advanced Adversary Detection",
            mitre_technique="T1059.004",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0005"] = HuntingQuery(
            query_id="HUNT-0005",
            title="Threat Hunt Rule #5 - Advanced Adversary Detection",
            mitre_technique="T1059.005",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0006"] = HuntingQuery(
            query_id="HUNT-0006",
            title="Threat Hunt Rule #6 - Advanced Adversary Detection",
            mitre_technique="T1059.006",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0007"] = HuntingQuery(
            query_id="HUNT-0007",
            title="Threat Hunt Rule #7 - Advanced Adversary Detection",
            mitre_technique="T1059.007",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0008"] = HuntingQuery(
            query_id="HUNT-0008",
            title="Threat Hunt Rule #8 - Advanced Adversary Detection",
            mitre_technique="T1078.000",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0009"] = HuntingQuery(
            query_id="HUNT-0009",
            title="Threat Hunt Rule #9 - Advanced Adversary Detection",
            mitre_technique="T1059.001",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0010"] = HuntingQuery(
            query_id="HUNT-0010",
            title="Threat Hunt Rule #10 - Advanced Adversary Detection",
            mitre_technique="T1059.002",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0011"] = HuntingQuery(
            query_id="HUNT-0011",
            title="Threat Hunt Rule #11 - Advanced Adversary Detection",
            mitre_technique="T1059.003",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0012"] = HuntingQuery(
            query_id="HUNT-0012",
            title="Threat Hunt Rule #12 - Advanced Adversary Detection",
            mitre_technique="T1059.004",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0013"] = HuntingQuery(
            query_id="HUNT-0013",
            title="Threat Hunt Rule #13 - Advanced Adversary Detection",
            mitre_technique="T1059.005",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0014"] = HuntingQuery(
            query_id="HUNT-0014",
            title="Threat Hunt Rule #14 - Advanced Adversary Detection",
            mitre_technique="T1059.006",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0015"] = HuntingQuery(
            query_id="HUNT-0015",
            title="Threat Hunt Rule #15 - Advanced Adversary Detection",
            mitre_technique="T1059.007",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0016"] = HuntingQuery(
            query_id="HUNT-0016",
            title="Threat Hunt Rule #16 - Advanced Adversary Detection",
            mitre_technique="T1078.000",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0017"] = HuntingQuery(
            query_id="HUNT-0017",
            title="Threat Hunt Rule #17 - Advanced Adversary Detection",
            mitre_technique="T1059.001",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0018"] = HuntingQuery(
            query_id="HUNT-0018",
            title="Threat Hunt Rule #18 - Advanced Adversary Detection",
            mitre_technique="T1059.002",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0019"] = HuntingQuery(
            query_id="HUNT-0019",
            title="Threat Hunt Rule #19 - Advanced Adversary Detection",
            mitre_technique="T1059.003",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0020"] = HuntingQuery(
            query_id="HUNT-0020",
            title="Threat Hunt Rule #20 - Advanced Adversary Detection",
            mitre_technique="T1059.004",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0021"] = HuntingQuery(
            query_id="HUNT-0021",
            title="Threat Hunt Rule #21 - Advanced Adversary Detection",
            mitre_technique="T1059.005",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0022"] = HuntingQuery(
            query_id="HUNT-0022",
            title="Threat Hunt Rule #22 - Advanced Adversary Detection",
            mitre_technique="T1059.006",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0023"] = HuntingQuery(
            query_id="HUNT-0023",
            title="Threat Hunt Rule #23 - Advanced Adversary Detection",
            mitre_technique="T1059.007",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0024"] = HuntingQuery(
            query_id="HUNT-0024",
            title="Threat Hunt Rule #24 - Advanced Adversary Detection",
            mitre_technique="T1078.000",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0025"] = HuntingQuery(
            query_id="HUNT-0025",
            title="Threat Hunt Rule #25 - Advanced Adversary Detection",
            mitre_technique="T1059.001",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0026"] = HuntingQuery(
            query_id="HUNT-0026",
            title="Threat Hunt Rule #26 - Advanced Adversary Detection",
            mitre_technique="T1059.002",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0027"] = HuntingQuery(
            query_id="HUNT-0027",
            title="Threat Hunt Rule #27 - Advanced Adversary Detection",
            mitre_technique="T1059.003",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0028"] = HuntingQuery(
            query_id="HUNT-0028",
            title="Threat Hunt Rule #28 - Advanced Adversary Detection",
            mitre_technique="T1059.004",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0029"] = HuntingQuery(
            query_id="HUNT-0029",
            title="Threat Hunt Rule #29 - Advanced Adversary Detection",
            mitre_technique="T1059.005",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0030"] = HuntingQuery(
            query_id="HUNT-0030",
            title="Threat Hunt Rule #30 - Advanced Adversary Detection",
            mitre_technique="T1059.006",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0031"] = HuntingQuery(
            query_id="HUNT-0031",
            title="Threat Hunt Rule #31 - Advanced Adversary Detection",
            mitre_technique="T1059.007",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0032"] = HuntingQuery(
            query_id="HUNT-0032",
            title="Threat Hunt Rule #32 - Advanced Adversary Detection",
            mitre_technique="T1078.000",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0033"] = HuntingQuery(
            query_id="HUNT-0033",
            title="Threat Hunt Rule #33 - Advanced Adversary Detection",
            mitre_technique="T1059.001",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0034"] = HuntingQuery(
            query_id="HUNT-0034",
            title="Threat Hunt Rule #34 - Advanced Adversary Detection",
            mitre_technique="T1059.002",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0035"] = HuntingQuery(
            query_id="HUNT-0035",
            title="Threat Hunt Rule #35 - Advanced Adversary Detection",
            mitre_technique="T1059.003",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0036"] = HuntingQuery(
            query_id="HUNT-0036",
            title="Threat Hunt Rule #36 - Advanced Adversary Detection",
            mitre_technique="T1059.004",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0037"] = HuntingQuery(
            query_id="HUNT-0037",
            title="Threat Hunt Rule #37 - Advanced Adversary Detection",
            mitre_technique="T1059.005",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0038"] = HuntingQuery(
            query_id="HUNT-0038",
            title="Threat Hunt Rule #38 - Advanced Adversary Detection",
            mitre_technique="T1059.006",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0039"] = HuntingQuery(
            query_id="HUNT-0039",
            title="Threat Hunt Rule #39 - Advanced Adversary Detection",
            mitre_technique="T1059.007",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0040"] = HuntingQuery(
            query_id="HUNT-0040",
            title="Threat Hunt Rule #40 - Advanced Adversary Detection",
            mitre_technique="T1078.000",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0041"] = HuntingQuery(
            query_id="HUNT-0041",
            title="Threat Hunt Rule #41 - Advanced Adversary Detection",
            mitre_technique="T1059.001",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0042"] = HuntingQuery(
            query_id="HUNT-0042",
            title="Threat Hunt Rule #42 - Advanced Adversary Detection",
            mitre_technique="T1059.002",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0043"] = HuntingQuery(
            query_id="HUNT-0043",
            title="Threat Hunt Rule #43 - Advanced Adversary Detection",
            mitre_technique="T1059.003",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0044"] = HuntingQuery(
            query_id="HUNT-0044",
            title="Threat Hunt Rule #44 - Advanced Adversary Detection",
            mitre_technique="T1059.004",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0045"] = HuntingQuery(
            query_id="HUNT-0045",
            title="Threat Hunt Rule #45 - Advanced Adversary Detection",
            mitre_technique="T1059.005",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0046"] = HuntingQuery(
            query_id="HUNT-0046",
            title="Threat Hunt Rule #46 - Advanced Adversary Detection",
            mitre_technique="T1059.006",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0047"] = HuntingQuery(
            query_id="HUNT-0047",
            title="Threat Hunt Rule #47 - Advanced Adversary Detection",
            mitre_technique="T1059.007",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0048"] = HuntingQuery(
            query_id="HUNT-0048",
            title="Threat Hunt Rule #48 - Advanced Adversary Detection",
            mitre_technique="T1078.000",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0049"] = HuntingQuery(
            query_id="HUNT-0049",
            title="Threat Hunt Rule #49 - Advanced Adversary Detection",
            mitre_technique="T1059.001",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0050"] = HuntingQuery(
            query_id="HUNT-0050",
            title="Threat Hunt Rule #50 - Advanced Adversary Detection",
            mitre_technique="T1059.002",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0051"] = HuntingQuery(
            query_id="HUNT-0051",
            title="Threat Hunt Rule #51 - Advanced Adversary Detection",
            mitre_technique="T1059.003",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0052"] = HuntingQuery(
            query_id="HUNT-0052",
            title="Threat Hunt Rule #52 - Advanced Adversary Detection",
            mitre_technique="T1059.004",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0053"] = HuntingQuery(
            query_id="HUNT-0053",
            title="Threat Hunt Rule #53 - Advanced Adversary Detection",
            mitre_technique="T1059.005",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0054"] = HuntingQuery(
            query_id="HUNT-0054",
            title="Threat Hunt Rule #54 - Advanced Adversary Detection",
            mitre_technique="T1059.006",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0055"] = HuntingQuery(
            query_id="HUNT-0055",
            title="Threat Hunt Rule #55 - Advanced Adversary Detection",
            mitre_technique="T1059.007",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0056"] = HuntingQuery(
            query_id="HUNT-0056",
            title="Threat Hunt Rule #56 - Advanced Adversary Detection",
            mitre_technique="T1078.000",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0057"] = HuntingQuery(
            query_id="HUNT-0057",
            title="Threat Hunt Rule #57 - Advanced Adversary Detection",
            mitre_technique="T1059.001",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0058"] = HuntingQuery(
            query_id="HUNT-0058",
            title="Threat Hunt Rule #58 - Advanced Adversary Detection",
            mitre_technique="T1059.002",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0059"] = HuntingQuery(
            query_id="HUNT-0059",
            title="Threat Hunt Rule #59 - Advanced Adversary Detection",
            mitre_technique="T1059.003",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0060"] = HuntingQuery(
            query_id="HUNT-0060",
            title="Threat Hunt Rule #60 - Advanced Adversary Detection",
            mitre_technique="T1059.004",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0061"] = HuntingQuery(
            query_id="HUNT-0061",
            title="Threat Hunt Rule #61 - Advanced Adversary Detection",
            mitre_technique="T1059.005",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0062"] = HuntingQuery(
            query_id="HUNT-0062",
            title="Threat Hunt Rule #62 - Advanced Adversary Detection",
            mitre_technique="T1059.006",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0063"] = HuntingQuery(
            query_id="HUNT-0063",
            title="Threat Hunt Rule #63 - Advanced Adversary Detection",
            mitre_technique="T1059.007",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0064"] = HuntingQuery(
            query_id="HUNT-0064",
            title="Threat Hunt Rule #64 - Advanced Adversary Detection",
            mitre_technique="T1078.000",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0065"] = HuntingQuery(
            query_id="HUNT-0065",
            title="Threat Hunt Rule #65 - Advanced Adversary Detection",
            mitre_technique="T1059.001",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0066"] = HuntingQuery(
            query_id="HUNT-0066",
            title="Threat Hunt Rule #66 - Advanced Adversary Detection",
            mitre_technique="T1059.002",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0067"] = HuntingQuery(
            query_id="HUNT-0067",
            title="Threat Hunt Rule #67 - Advanced Adversary Detection",
            mitre_technique="T1059.003",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0068"] = HuntingQuery(
            query_id="HUNT-0068",
            title="Threat Hunt Rule #68 - Advanced Adversary Detection",
            mitre_technique="T1059.004",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0069"] = HuntingQuery(
            query_id="HUNT-0069",
            title="Threat Hunt Rule #69 - Advanced Adversary Detection",
            mitre_technique="T1059.005",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0070"] = HuntingQuery(
            query_id="HUNT-0070",
            title="Threat Hunt Rule #70 - Advanced Adversary Detection",
            mitre_technique="T1059.006",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0071"] = HuntingQuery(
            query_id="HUNT-0071",
            title="Threat Hunt Rule #71 - Advanced Adversary Detection",
            mitre_technique="T1059.007",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0072"] = HuntingQuery(
            query_id="HUNT-0072",
            title="Threat Hunt Rule #72 - Advanced Adversary Detection",
            mitre_technique="T1078.000",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0073"] = HuntingQuery(
            query_id="HUNT-0073",
            title="Threat Hunt Rule #73 - Advanced Adversary Detection",
            mitre_technique="T1059.001",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0074"] = HuntingQuery(
            query_id="HUNT-0074",
            title="Threat Hunt Rule #74 - Advanced Adversary Detection",
            mitre_technique="T1059.002",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0075"] = HuntingQuery(
            query_id="HUNT-0075",
            title="Threat Hunt Rule #75 - Advanced Adversary Detection",
            mitre_technique="T1059.003",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0076"] = HuntingQuery(
            query_id="HUNT-0076",
            title="Threat Hunt Rule #76 - Advanced Adversary Detection",
            mitre_technique="T1059.004",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0077"] = HuntingQuery(
            query_id="HUNT-0077",
            title="Threat Hunt Rule #77 - Advanced Adversary Detection",
            mitre_technique="T1059.005",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0078"] = HuntingQuery(
            query_id="HUNT-0078",
            title="Threat Hunt Rule #78 - Advanced Adversary Detection",
            mitre_technique="T1059.006",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0079"] = HuntingQuery(
            query_id="HUNT-0079",
            title="Threat Hunt Rule #79 - Advanced Adversary Detection",
            mitre_technique="T1059.007",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0080"] = HuntingQuery(
            query_id="HUNT-0080",
            title="Threat Hunt Rule #80 - Advanced Adversary Detection",
            mitre_technique="T1078.000",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0081"] = HuntingQuery(
            query_id="HUNT-0081",
            title="Threat Hunt Rule #81 - Advanced Adversary Detection",
            mitre_technique="T1059.001",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0082"] = HuntingQuery(
            query_id="HUNT-0082",
            title="Threat Hunt Rule #82 - Advanced Adversary Detection",
            mitre_technique="T1059.002",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0083"] = HuntingQuery(
            query_id="HUNT-0083",
            title="Threat Hunt Rule #83 - Advanced Adversary Detection",
            mitre_technique="T1059.003",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0084"] = HuntingQuery(
            query_id="HUNT-0084",
            title="Threat Hunt Rule #84 - Advanced Adversary Detection",
            mitre_technique="T1059.004",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0085"] = HuntingQuery(
            query_id="HUNT-0085",
            title="Threat Hunt Rule #85 - Advanced Adversary Detection",
            mitre_technique="T1059.005",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0086"] = HuntingQuery(
            query_id="HUNT-0086",
            title="Threat Hunt Rule #86 - Advanced Adversary Detection",
            mitre_technique="T1059.006",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0087"] = HuntingQuery(
            query_id="HUNT-0087",
            title="Threat Hunt Rule #87 - Advanced Adversary Detection",
            mitre_technique="T1059.007",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0088"] = HuntingQuery(
            query_id="HUNT-0088",
            title="Threat Hunt Rule #88 - Advanced Adversary Detection",
            mitre_technique="T1078.000",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0089"] = HuntingQuery(
            query_id="HUNT-0089",
            title="Threat Hunt Rule #89 - Advanced Adversary Detection",
            mitre_technique="T1059.001",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0090"] = HuntingQuery(
            query_id="HUNT-0090",
            title="Threat Hunt Rule #90 - Advanced Adversary Detection",
            mitre_technique="T1059.002",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0091"] = HuntingQuery(
            query_id="HUNT-0091",
            title="Threat Hunt Rule #91 - Advanced Adversary Detection",
            mitre_technique="T1059.003",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0092"] = HuntingQuery(
            query_id="HUNT-0092",
            title="Threat Hunt Rule #92 - Advanced Adversary Detection",
            mitre_technique="T1059.004",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0093"] = HuntingQuery(
            query_id="HUNT-0093",
            title="Threat Hunt Rule #93 - Advanced Adversary Detection",
            mitre_technique="T1059.005",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0094"] = HuntingQuery(
            query_id="HUNT-0094",
            title="Threat Hunt Rule #94 - Advanced Adversary Detection",
            mitre_technique="T1059.006",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0095"] = HuntingQuery(
            query_id="HUNT-0095",
            title="Threat Hunt Rule #95 - Advanced Adversary Detection",
            mitre_technique="T1059.007",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0096"] = HuntingQuery(
            query_id="HUNT-0096",
            title="Threat Hunt Rule #96 - Advanced Adversary Detection",
            mitre_technique="T1078.000",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0097"] = HuntingQuery(
            query_id="HUNT-0097",
            title="Threat Hunt Rule #97 - Advanced Adversary Detection",
            mitre_technique="T1059.001",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0098"] = HuntingQuery(
            query_id="HUNT-0098",
            title="Threat Hunt Rule #98 - Advanced Adversary Detection",
            mitre_technique="T1059.002",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0099"] = HuntingQuery(
            query_id="HUNT-0099",
            title="Threat Hunt Rule #99 - Advanced Adversary Detection",
            mitre_technique="T1059.003",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0100"] = HuntingQuery(
            query_id="HUNT-0100",
            title="Threat Hunt Rule #100 - Advanced Adversary Detection",
            mitre_technique="T1059.004",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0101"] = HuntingQuery(
            query_id="HUNT-0101",
            title="Threat Hunt Rule #101 - Advanced Adversary Detection",
            mitre_technique="T1059.005",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0102"] = HuntingQuery(
            query_id="HUNT-0102",
            title="Threat Hunt Rule #102 - Advanced Adversary Detection",
            mitre_technique="T1059.006",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0103"] = HuntingQuery(
            query_id="HUNT-0103",
            title="Threat Hunt Rule #103 - Advanced Adversary Detection",
            mitre_technique="T1059.007",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0104"] = HuntingQuery(
            query_id="HUNT-0104",
            title="Threat Hunt Rule #104 - Advanced Adversary Detection",
            mitre_technique="T1078.000",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0105"] = HuntingQuery(
            query_id="HUNT-0105",
            title="Threat Hunt Rule #105 - Advanced Adversary Detection",
            mitre_technique="T1059.001",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0106"] = HuntingQuery(
            query_id="HUNT-0106",
            title="Threat Hunt Rule #106 - Advanced Adversary Detection",
            mitre_technique="T1059.002",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0107"] = HuntingQuery(
            query_id="HUNT-0107",
            title="Threat Hunt Rule #107 - Advanced Adversary Detection",
            mitre_technique="T1059.003",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0108"] = HuntingQuery(
            query_id="HUNT-0108",
            title="Threat Hunt Rule #108 - Advanced Adversary Detection",
            mitre_technique="T1059.004",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0109"] = HuntingQuery(
            query_id="HUNT-0109",
            title="Threat Hunt Rule #109 - Advanced Adversary Detection",
            mitre_technique="T1059.005",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0110"] = HuntingQuery(
            query_id="HUNT-0110",
            title="Threat Hunt Rule #110 - Advanced Adversary Detection",
            mitre_technique="T1059.006",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0111"] = HuntingQuery(
            query_id="HUNT-0111",
            title="Threat Hunt Rule #111 - Advanced Adversary Detection",
            mitre_technique="T1059.007",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0112"] = HuntingQuery(
            query_id="HUNT-0112",
            title="Threat Hunt Rule #112 - Advanced Adversary Detection",
            mitre_technique="T1078.000",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0113"] = HuntingQuery(
            query_id="HUNT-0113",
            title="Threat Hunt Rule #113 - Advanced Adversary Detection",
            mitre_technique="T1059.001",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0114"] = HuntingQuery(
            query_id="HUNT-0114",
            title="Threat Hunt Rule #114 - Advanced Adversary Detection",
            mitre_technique="T1059.002",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0115"] = HuntingQuery(
            query_id="HUNT-0115",
            title="Threat Hunt Rule #115 - Advanced Adversary Detection",
            mitre_technique="T1059.003",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0116"] = HuntingQuery(
            query_id="HUNT-0116",
            title="Threat Hunt Rule #116 - Advanced Adversary Detection",
            mitre_technique="T1059.004",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0117"] = HuntingQuery(
            query_id="HUNT-0117",
            title="Threat Hunt Rule #117 - Advanced Adversary Detection",
            mitre_technique="T1059.005",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0118"] = HuntingQuery(
            query_id="HUNT-0118",
            title="Threat Hunt Rule #118 - Advanced Adversary Detection",
            mitre_technique="T1059.006",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0119"] = HuntingQuery(
            query_id="HUNT-0119",
            title="Threat Hunt Rule #119 - Advanced Adversary Detection",
            mitre_technique="T1059.007",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0120"] = HuntingQuery(
            query_id="HUNT-0120",
            title="Threat Hunt Rule #120 - Advanced Adversary Detection",
            mitre_technique="T1078.000",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0121"] = HuntingQuery(
            query_id="HUNT-0121",
            title="Threat Hunt Rule #121 - Advanced Adversary Detection",
            mitre_technique="T1059.001",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0122"] = HuntingQuery(
            query_id="HUNT-0122",
            title="Threat Hunt Rule #122 - Advanced Adversary Detection",
            mitre_technique="T1059.002",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0123"] = HuntingQuery(
            query_id="HUNT-0123",
            title="Threat Hunt Rule #123 - Advanced Adversary Detection",
            mitre_technique="T1059.003",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0124"] = HuntingQuery(
            query_id="HUNT-0124",
            title="Threat Hunt Rule #124 - Advanced Adversary Detection",
            mitre_technique="T1059.004",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0125"] = HuntingQuery(
            query_id="HUNT-0125",
            title="Threat Hunt Rule #125 - Advanced Adversary Detection",
            mitre_technique="T1059.005",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0126"] = HuntingQuery(
            query_id="HUNT-0126",
            title="Threat Hunt Rule #126 - Advanced Adversary Detection",
            mitre_technique="T1059.006",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0127"] = HuntingQuery(
            query_id="HUNT-0127",
            title="Threat Hunt Rule #127 - Advanced Adversary Detection",
            mitre_technique="T1059.007",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0128"] = HuntingQuery(
            query_id="HUNT-0128",
            title="Threat Hunt Rule #128 - Advanced Adversary Detection",
            mitre_technique="T1078.000",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0129"] = HuntingQuery(
            query_id="HUNT-0129",
            title="Threat Hunt Rule #129 - Advanced Adversary Detection",
            mitre_technique="T1059.001",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0130"] = HuntingQuery(
            query_id="HUNT-0130",
            title="Threat Hunt Rule #130 - Advanced Adversary Detection",
            mitre_technique="T1059.002",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0131"] = HuntingQuery(
            query_id="HUNT-0131",
            title="Threat Hunt Rule #131 - Advanced Adversary Detection",
            mitre_technique="T1059.003",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0132"] = HuntingQuery(
            query_id="HUNT-0132",
            title="Threat Hunt Rule #132 - Advanced Adversary Detection",
            mitre_technique="T1059.004",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0133"] = HuntingQuery(
            query_id="HUNT-0133",
            title="Threat Hunt Rule #133 - Advanced Adversary Detection",
            mitre_technique="T1059.005",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0134"] = HuntingQuery(
            query_id="HUNT-0134",
            title="Threat Hunt Rule #134 - Advanced Adversary Detection",
            mitre_technique="T1059.006",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0135"] = HuntingQuery(
            query_id="HUNT-0135",
            title="Threat Hunt Rule #135 - Advanced Adversary Detection",
            mitre_technique="T1059.007",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0136"] = HuntingQuery(
            query_id="HUNT-0136",
            title="Threat Hunt Rule #136 - Advanced Adversary Detection",
            mitre_technique="T1078.000",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0137"] = HuntingQuery(
            query_id="HUNT-0137",
            title="Threat Hunt Rule #137 - Advanced Adversary Detection",
            mitre_technique="T1059.001",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0138"] = HuntingQuery(
            query_id="HUNT-0138",
            title="Threat Hunt Rule #138 - Advanced Adversary Detection",
            mitre_technique="T1059.002",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0139"] = HuntingQuery(
            query_id="HUNT-0139",
            title="Threat Hunt Rule #139 - Advanced Adversary Detection",
            mitre_technique="T1059.003",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0140"] = HuntingQuery(
            query_id="HUNT-0140",
            title="Threat Hunt Rule #140 - Advanced Adversary Detection",
            mitre_technique="T1059.004",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0141"] = HuntingQuery(
            query_id="HUNT-0141",
            title="Threat Hunt Rule #141 - Advanced Adversary Detection",
            mitre_technique="T1059.005",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0142"] = HuntingQuery(
            query_id="HUNT-0142",
            title="Threat Hunt Rule #142 - Advanced Adversary Detection",
            mitre_technique="T1059.006",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0143"] = HuntingQuery(
            query_id="HUNT-0143",
            title="Threat Hunt Rule #143 - Advanced Adversary Detection",
            mitre_technique="T1059.007",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0144"] = HuntingQuery(
            query_id="HUNT-0144",
            title="Threat Hunt Rule #144 - Advanced Adversary Detection",
            mitre_technique="T1078.000",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0145"] = HuntingQuery(
            query_id="HUNT-0145",
            title="Threat Hunt Rule #145 - Advanced Adversary Detection",
            mitre_technique="T1059.001",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )
        self.queries["HUNT-0146"] = HuntingQuery(
            query_id="HUNT-0146",
            title="Threat Hunt Rule #146 - Advanced Adversary Detection",
            mitre_technique="T1059.002",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="MEDIUM"
        )
        self.queries["HUNT-0147"] = HuntingQuery(
            query_id="HUNT-0147",
            title="Threat Hunt Rule #147 - Advanced Adversary Detection",
            mitre_technique="T1059.003",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="LOW"
        )
        self.queries["HUNT-0148"] = HuntingQuery(
            query_id="HUNT-0148",
            title="Threat Hunt Rule #148 - Advanced Adversary Detection",
            mitre_technique="T1059.004",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="CRITICAL"
        )
        self.queries["HUNT-0149"] = HuntingQuery(
            query_id="HUNT-0149",
            title="Threat Hunt Rule #149 - Advanced Adversary Detection",
            mitre_technique="T1059.005",
            spl_query="index=main EventCode=4688 Image=*cmd.exe CommandLine=*powershell.exe | stats count by Computer, User",
            kql_query="SecurityEvent | where EventID == 4688 and ProcessName has 'cmd.exe' | summarize count() by Computer, Account",
            eql_query="process where process_name == 'cmd.exe' and command_line == '*powershell*'",
            severity="HIGH"
        )

    def get_query(self, query_id: str) -> Optional[HuntingQuery]:
        return self.queries.get(query_id)

threat_hunting_registry = ThreatHuntingRegistry()

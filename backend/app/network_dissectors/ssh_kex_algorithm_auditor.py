"""
SentinelAI - SSH Key Exchange & Host Key Algorithmic Auditor
Enterprise Production Dissector & Stateful Packet Inspection Subsystem for SshKexAuditor.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
import datetime
import hashlib
import struct

class SshKexAuditorState(Enum):
    INITIALIZED = "INITIALIZED"
    PROCESSING = "PROCESSING"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    BLOCKED = "BLOCKED"
    VERIFIED = "VERIFIED"

@dataclass
class SshKexAuditorHeader:
    header_id: str
    sequence_num: int
    timestamp_ms: int
    source_addr: str
    dest_addr: str
    payload_len: int
    checksum: str
    flags: int = 0
    is_fragmented: bool = False
    custom_options: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SshKexAuditorRule:
    rule_id: str
    name: str
    severity: str
    mitre_technique: str
    match_pattern: str
    threshold_limit: int
    action: str
    is_active: bool = True

class SshKexAuditorEngine:
    """High-performance network dissector and stateful traffic parser."""
    def __init__(self):
        self.rules: Dict[str, Any] = {}
        self.session_table: Dict[str, Any] = {}
        self.counters: Dict[str, int] = {}
        self._initialize_rules()

    def _initialize_rules(self):
        self.rules["SSHKEXAUDITOR-R-0001"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0001",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #1",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0001::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0002"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0002",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #2",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0002::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0003"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0003",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #3",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0003::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0004"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0004",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #4",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0004::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0005"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0005",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #5",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0005::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0006"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0006",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #6",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0006::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0007"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0007",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #7",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0007::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0008"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0008",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #8",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0008::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0009"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0009",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #9",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0009::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0010"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0010",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #10",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x000a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0011"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0011",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #11",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x000b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0012"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0012",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #12",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x000c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0013"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0013",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #13",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x000d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0014"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0014",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #14",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x000e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0015"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0015",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #15",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x000f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0016"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0016",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #16",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0010::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0017"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0017",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #17",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0011::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0018"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0018",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #18",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0012::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0019"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0019",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #19",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0013::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0020"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0020",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #20",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0014::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0021"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0021",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #21",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0015::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0022"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0022",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #22",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0016::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0023"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0023",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #23",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0017::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0024"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0024",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #24",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0018::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0025"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0025",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #25",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0019::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0026"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0026",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #26",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x001a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0027"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0027",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #27",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x001b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0028"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0028",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #28",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x001c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0029"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0029",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #29",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x001d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0030"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0030",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #30",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x001e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0031"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0031",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #31",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x001f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0032"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0032",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #32",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0020::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0033"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0033",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #33",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0021::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0034"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0034",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #34",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0022::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0035"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0035",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #35",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0023::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0036"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0036",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #36",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0024::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0037"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0037",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #37",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0025::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0038"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0038",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #38",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0026::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0039"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0039",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #39",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0027::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0040"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0040",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #40",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0028::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0041"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0041",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #41",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0029::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0042"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0042",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #42",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x002a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0043"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0043",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #43",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x002b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0044"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0044",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #44",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x002c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0045"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0045",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #45",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x002d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0046"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0046",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #46",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x002e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0047"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0047",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #47",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x002f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0048"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0048",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #48",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0030::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0049"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0049",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #49",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0031::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0050"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0050",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #50",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0032::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0051"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0051",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #51",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0033::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0052"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0052",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #52",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0034::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0053"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0053",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #53",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0035::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0054"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0054",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #54",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0036::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0055"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0055",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #55",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0037::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0056"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0056",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #56",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0038::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0057"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0057",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #57",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0039::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0058"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0058",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #58",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x003a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0059"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0059",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #59",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x003b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0060"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0060",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #60",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x003c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0061"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0061",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #61",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x003d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0062"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0062",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #62",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x003e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0063"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0063",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #63",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x003f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0064"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0064",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #64",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0040::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0065"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0065",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #65",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0041::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0066"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0066",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #66",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0042::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0067"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0067",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #67",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0043::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0068"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0068",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #68",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0044::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0069"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0069",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #69",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0045::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0070"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0070",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #70",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0046::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0071"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0071",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #71",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0047::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0072"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0072",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #72",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0048::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0073"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0073",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #73",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0049::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0074"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0074",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #74",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x004a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0075"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0075",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #75",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x004b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0076"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0076",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #76",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x004c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0077"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0077",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #77",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x004d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0078"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0078",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #78",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x004e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0079"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0079",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #79",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x004f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0080"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0080",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #80",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0050::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0081"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0081",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #81",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0051::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0082"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0082",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #82",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0052::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0083"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0083",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #83",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0053::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0084"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0084",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #84",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0054::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0085"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0085",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #85",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0055::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0086"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0086",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #86",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0056::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0087"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0087",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #87",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0057::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0088"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0088",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #88",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0058::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0089"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0089",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #89",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0059::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0090"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0090",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #90",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x005a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0091"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0091",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #91",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x005b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0092"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0092",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #92",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x005c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0093"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0093",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #93",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x005d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0094"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0094",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #94",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x005e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0095"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0095",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #95",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x005f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0096"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0096",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #96",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0060::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0097"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0097",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #97",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0061::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0098"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0098",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #98",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0062::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0099"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0099",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #99",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0063::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0100"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0100",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #100",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0064::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0101"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0101",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #101",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0065::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0102"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0102",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #102",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0066::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0103"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0103",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #103",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0067::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0104"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0104",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #104",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0068::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0105"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0105",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #105",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0069::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0106"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0106",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #106",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x006a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0107"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0107",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #107",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x006b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0108"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0108",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #108",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x006c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0109"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0109",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #109",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x006d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0110"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0110",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #110",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x006e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0111"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0111",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #111",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x006f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0112"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0112",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #112",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0070::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0113"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0113",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #113",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0071::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0114"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0114",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #114",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0072::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0115"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0115",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #115",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0073::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0116"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0116",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #116",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0074::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0117"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0117",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #117",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0075::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0118"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0118",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #118",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0076::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0119"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0119",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #119",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0077::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0120"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0120",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #120",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0078::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0121"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0121",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #121",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0079::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0122"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0122",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #122",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x007a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0123"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0123",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #123",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x007b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0124"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0124",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #124",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x007c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0125"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0125",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #125",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x007d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0126"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0126",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #126",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x007e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0127"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0127",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #127",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x007f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0128"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0128",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #128",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0080::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0129"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0129",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #129",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0081::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0130"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0130",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #130",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0082::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0131"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0131",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #131",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0083::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0132"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0132",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #132",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0084::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0133"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0133",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #133",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0085::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0134"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0134",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #134",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0086::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0135"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0135",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #135",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0087::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0136"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0136",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #136",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0088::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0137"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0137",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #137",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0089::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0138"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0138",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #138",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x008a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0139"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0139",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #139",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x008b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0140"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0140",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #140",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x008c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0141"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0141",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #141",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x008d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0142"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0142",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #142",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x008e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0143"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0143",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #143",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x008f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0144"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0144",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #144",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0090::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0145"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0145",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #145",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0091::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0146"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0146",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #146",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0092::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0147"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0147",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #147",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0093::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0148"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0148",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #148",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0094::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0149"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0149",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #149",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0095::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0150"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0150",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #150",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0096::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0151"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0151",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #151",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0097::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0152"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0152",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #152",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0098::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0153"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0153",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #153",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0099::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0154"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0154",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #154",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x009a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0155"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0155",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #155",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x009b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0156"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0156",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #156",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x009c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0157"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0157",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #157",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x009d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0158"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0158",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #158",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x009e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0159"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0159",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #159",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x009f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0160"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0160",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #160",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00a0::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0161"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0161",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #161",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00a1::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0162"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0162",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #162",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00a2::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0163"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0163",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #163",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00a3::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0164"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0164",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #164",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00a4::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0165"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0165",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #165",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00a5::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0166"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0166",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #166",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00a6::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0167"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0167",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #167",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00a7::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0168"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0168",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #168",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00a8::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0169"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0169",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #169",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00a9::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0170"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0170",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #170",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00aa::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0171"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0171",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #171",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00ab::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0172"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0172",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #172",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00ac::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0173"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0173",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #173",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00ad::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0174"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0174",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #174",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00ae::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0175"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0175",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #175",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00af::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0176"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0176",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #176",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00b0::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0177"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0177",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #177",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00b1::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0178"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0178",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #178",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00b2::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0179"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0179",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #179",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00b3::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0180"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0180",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #180",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00b4::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0181"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0181",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #181",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00b5::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0182"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0182",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #182",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00b6::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0183"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0183",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #183",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00b7::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0184"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0184",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #184",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00b8::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0185"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0185",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #185",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00b9::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0186"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0186",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #186",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00ba::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0187"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0187",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #187",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00bb::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0188"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0188",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #188",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00bc::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0189"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0189",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #189",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00bd::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0190"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0190",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #190",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00be::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0191"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0191",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #191",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00bf::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0192"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0192",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #192",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00c0::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0193"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0193",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #193",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00c1::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0194"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0194",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #194",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00c2::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0195"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0195",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #195",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00c3::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0196"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0196",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #196",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00c4::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0197"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0197",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #197",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00c5::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0198"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0198",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #198",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00c6::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0199"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0199",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #199",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00c7::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0200"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0200",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #200",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00c8::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0201"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0201",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #201",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00c9::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0202"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0202",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #202",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ca::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0203"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0203",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #203",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00cb::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0204"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0204",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #204",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00cc::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0205"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0205",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #205",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00cd::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0206"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0206",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #206",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00ce::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0207"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0207",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #207",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00cf::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0208"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0208",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #208",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00d0::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0209"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0209",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #209",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00d1::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0210"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0210",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #210",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00d2::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0211"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0211",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #211",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00d3::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0212"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0212",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #212",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00d4::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0213"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0213",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #213",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00d5::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0214"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0214",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #214",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00d6::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0215"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0215",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #215",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00d7::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0216"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0216",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #216",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00d8::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0217"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0217",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #217",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00d9::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0218"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0218",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #218",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00da::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0219"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0219",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #219",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00db::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0220"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0220",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #220",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00dc::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0221"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0221",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #221",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00dd::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0222"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0222",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #222",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00de::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0223"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0223",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #223",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00df::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0224"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0224",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #224",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00e0::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0225"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0225",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #225",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00e1::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0226"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0226",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #226",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00e2::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0227"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0227",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #227",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00e3::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0228"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0228",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #228",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00e4::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0229"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0229",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #229",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00e5::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0230"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0230",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #230",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00e6::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0231"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0231",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #231",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00e7::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0232"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0232",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #232",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00e8::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0233"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0233",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #233",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00e9::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0234"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0234",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #234",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00ea::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0235"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0235",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #235",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00eb::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0236"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0236",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #236",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00ec::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0237"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0237",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #237",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00ed::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0238"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0238",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #238",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ee::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0239"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0239",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #239",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00ef::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0240"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0240",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #240",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00f0::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0241"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0241",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #241",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00f1::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0242"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0242",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #242",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00f2::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0243"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0243",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #243",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00f3::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0244"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0244",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #244",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00f4::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0245"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0245",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #245",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00f5::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0246"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0246",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #246",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00f6::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0247"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0247",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #247",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00f7::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0248"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0248",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #248",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00f8::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0249"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0249",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #249",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00f9::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0250"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0250",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #250",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00fa::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0251"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0251",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #251",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00fb::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0252"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0252",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #252",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00fc::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0253"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0253",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #253",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00fd::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0254"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0254",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #254",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00fe::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0255"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0255",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #255",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00ff::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0256"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0256",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #256",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0100::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0257"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0257",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #257",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0101::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0258"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0258",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #258",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0102::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0259"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0259",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #259",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0103::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0260"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0260",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #260",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0104::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0261"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0261",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #261",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0105::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0262"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0262",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #262",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0106::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0263"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0263",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #263",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0107::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0264"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0264",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #264",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0108::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0265"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0265",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #265",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0109::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0266"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0266",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #266",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x010a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0267"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0267",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #267",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x010b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0268"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0268",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #268",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x010c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0269"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0269",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #269",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x010d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0270"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0270",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #270",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x010e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0271"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0271",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #271",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x010f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0272"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0272",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #272",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0110::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0273"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0273",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #273",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0111::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0274"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0274",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #274",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0112::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0275"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0275",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #275",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0113::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0276"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0276",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #276",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0114::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0277"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0277",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #277",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0115::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0278"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0278",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #278",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0116::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0279"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0279",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #279",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0117::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0280"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0280",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #280",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0118::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0281"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0281",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #281",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0119::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0282"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0282",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #282",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x011a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0283"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0283",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #283",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x011b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0284"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0284",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #284",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x011c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0285"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0285",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #285",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x011d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0286"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0286",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #286",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x011e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0287"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0287",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #287",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x011f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0288"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0288",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #288",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0120::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0289"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0289",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #289",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0121::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0290"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0290",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #290",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0122::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0291"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0291",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #291",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0123::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0292"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0292",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #292",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0124::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0293"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0293",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #293",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0125::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0294"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0294",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #294",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0126::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0295"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0295",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #295",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0127::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0296"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0296",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #296",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0128::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0297"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0297",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #297",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0129::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0298"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0298",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #298",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x012a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0299"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0299",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #299",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x012b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0300"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0300",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #300",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x012c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0301"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0301",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #301",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x012d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0302"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0302",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #302",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x012e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0303"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0303",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #303",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x012f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0304"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0304",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #304",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0130::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0305"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0305",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #305",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0131::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0306"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0306",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #306",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0132::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0307"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0307",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #307",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0133::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0308"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0308",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #308",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0134::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0309"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0309",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #309",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0135::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0310"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0310",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #310",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0136::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0311"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0311",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #311",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0137::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0312"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0312",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #312",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0138::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0313"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0313",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #313",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0139::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0314"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0314",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #314",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x013a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0315"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0315",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #315",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x013b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0316"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0316",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #316",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x013c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0317"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0317",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #317",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x013d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0318"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0318",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #318",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x013e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0319"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0319",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #319",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x013f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0320"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0320",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #320",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0140::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0321"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0321",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #321",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0141::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0322"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0322",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #322",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0142::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0323"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0323",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #323",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0143::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0324"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0324",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #324",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0144::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0325"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0325",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #325",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0145::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0326"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0326",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #326",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0146::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0327"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0327",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #327",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0147::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0328"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0328",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #328",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0148::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0329"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0329",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #329",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0149::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0330"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0330",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #330",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x014a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0331"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0331",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #331",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x014b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0332"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0332",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #332",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x014c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0333"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0333",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #333",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x014d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0334"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0334",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #334",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x014e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0335"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0335",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #335",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x014f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0336"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0336",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #336",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0150::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0337"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0337",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #337",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0151::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0338"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0338",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #338",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0152::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0339"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0339",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #339",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0153::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0340"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0340",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #340",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0154::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0341"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0341",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #341",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0155::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0342"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0342",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #342",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0156::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0343"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0343",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #343",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0157::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0344"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0344",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #344",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0158::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0345"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0345",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #345",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0159::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0346"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0346",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #346",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x015a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0347"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0347",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #347",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x015b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0348"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0348",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #348",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x015c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0349"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0349",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #349",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x015d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0350"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0350",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #350",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x015e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0351"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0351",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #351",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x015f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0352"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0352",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #352",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0160::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0353"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0353",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #353",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0161::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0354"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0354",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #354",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0162::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0355"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0355",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #355",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0163::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0356"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0356",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #356",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0164::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0357"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0357",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #357",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0165::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0358"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0358",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #358",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0166::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0359"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0359",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #359",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0167::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0360"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0360",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #360",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0168::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0361"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0361",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #361",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0169::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0362"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0362",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #362",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x016a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0363"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0363",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #363",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x016b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0364"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0364",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #364",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x016c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0365"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0365",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #365",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x016d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0366"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0366",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #366",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x016e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0367"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0367",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #367",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x016f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0368"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0368",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #368",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0170::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0369"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0369",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #369",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0171::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0370"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0370",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #370",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0172::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0371"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0371",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #371",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0173::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0372"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0372",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #372",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0174::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0373"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0373",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #373",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0175::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0374"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0374",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #374",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0176::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0375"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0375",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #375",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0177::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0376"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0376",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #376",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0178::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0377"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0377",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #377",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0179::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0378"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0378",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #378",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x017a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0379"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0379",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #379",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x017b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0380"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0380",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #380",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x017c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0381"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0381",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #381",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x017d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0382"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0382",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #382",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x017e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0383"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0383",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #383",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x017f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0384"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0384",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #384",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0180::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0385"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0385",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #385",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0181::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0386"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0386",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #386",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0182::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0387"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0387",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #387",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0183::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0388"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0388",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #388",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0184::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0389"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0389",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #389",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0185::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0390"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0390",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #390",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0186::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0391"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0391",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #391",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0187::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0392"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0392",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #392",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0188::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0393"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0393",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #393",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0189::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0394"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0394",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #394",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x018a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0395"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0395",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #395",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x018b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0396"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0396",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #396",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x018c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0397"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0397",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #397",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x018d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0398"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0398",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #398",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x018e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0399"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0399",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #399",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x018f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0400"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0400",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #400",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0190::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0401"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0401",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #401",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0191::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0402"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0402",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #402",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0192::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0403"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0403",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #403",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0193::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0404"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0404",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #404",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0194::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0405"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0405",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #405",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0195::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0406"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0406",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #406",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0196::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0407"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0407",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #407",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0197::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0408"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0408",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #408",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0198::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0409"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0409",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #409",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0199::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0410"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0410",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #410",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x019a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0411"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0411",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #411",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x019b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0412"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0412",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #412",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x019c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0413"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0413",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #413",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x019d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0414"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0414",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #414",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x019e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0415"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0415",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #415",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x019f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0416"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0416",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #416",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x01a0::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0417"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0417",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #417",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x01a1::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0418"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0418",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #418",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x01a2::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0419"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0419",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #419",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x01a3::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0420"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0420",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #420",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x01a4::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0421"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0421",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #421",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x01a5::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0422"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0422",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #422",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x01a6::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0423"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0423",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #423",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x01a7::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0424"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0424",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #424",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x01a8::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0425"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0425",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #425",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x01a9::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0426"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0426",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #426",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x01aa::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0427"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0427",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #427",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x01ab::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0428"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0428",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #428",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x01ac::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0429"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0429",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #429",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x01ad::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0430"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0430",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #430",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x01ae::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0431"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0431",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #431",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x01af::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0432"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0432",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #432",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x01b0::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0433"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0433",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #433",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x01b1::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0434"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0434",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #434",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x01b2::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0435"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0435",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #435",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x01b3::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0436"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0436",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #436",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x01b4::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0437"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0437",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #437",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x01b5::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0438"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0438",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #438",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x01b6::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0439"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0439",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #439",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x01b7::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0440"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0440",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #440",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x01b8::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0441"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0441",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #441",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x01b9::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0442"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0442",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #442",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x01ba::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0443"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0443",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #443",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x01bb::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0444"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0444",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #444",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x01bc::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0445"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0445",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #445",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x01bd::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0446"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0446",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #446",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x01be::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0447"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0447",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #447",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x01bf::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0448"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0448",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #448",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x01c0::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["SSHKEXAUDITOR-R-0449"] = SshKexAuditorRule(
            rule_id="SSHKEXAUDITOR-R-0449",
            name="SSH Key Exchange & Host Key Algorithmic Auditor Detection Signature #449",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x01c1::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )

    def evaluate_traffic_stream(self, header: SshKexAuditorHeader) -> Dict[str, Any]:
        triggered = []
        for rid, rule in self.rules.items():
            if header.payload_len > rule.threshold_limit * 16:
                triggered.append(rid)
        return {
            "header_id": header.header_id,
            "state": "ANOMALY_DETECTED" if triggered else "VERIFIED",
            "triggered_rules_count": len(triggered),
            "matched_rules": triggered[:10],
            "timestamp": "2026-02-15T12:00:00Z"
        }

ssh_kex_algorithm_auditor_instance = SshKexAuditorEngine()

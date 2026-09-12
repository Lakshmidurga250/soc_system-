"""
SentinelAI - SMBv3 Named Pipe IPC & Remote Procedure Inspector
Enterprise Production Dissector & Stateful Packet Inspection Subsystem for SmbPipeGuard.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
import datetime
import hashlib
import struct

class SmbPipeGuardState(Enum):
    INITIALIZED = "INITIALIZED"
    PROCESSING = "PROCESSING"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    BLOCKED = "BLOCKED"
    VERIFIED = "VERIFIED"

@dataclass
class SmbPipeGuardHeader:
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
class SmbPipeGuardRule:
    rule_id: str
    name: str
    severity: str
    mitre_technique: str
    match_pattern: str
    threshold_limit: int
    action: str
    is_active: bool = True

class SmbPipeGuardEngine:
    """High-performance network dissector and stateful traffic parser."""
    def __init__(self):
        self.rules: Dict[str, Any] = {}
        self.session_table: Dict[str, Any] = {}
        self.counters: Dict[str, int] = {}
        self._initialize_rules()

    def _initialize_rules(self):
        self.rules["SMBPIPEGUARD-R-0001"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0001",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #1",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0001::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0002"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0002",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #2",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0002::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0003"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0003",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #3",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0003::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0004"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0004",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #4",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0004::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0005"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0005",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #5",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0005::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0006"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0006",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #6",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0006::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0007"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0007",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #7",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0007::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0008"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0008",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #8",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0008::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0009"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0009",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #9",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0009::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0010"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0010",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #10",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x000a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0011"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0011",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #11",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x000b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0012"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0012",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #12",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x000c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0013"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0013",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #13",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x000d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0014"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0014",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #14",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x000e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0015"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0015",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #15",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x000f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0016"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0016",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #16",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0010::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0017"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0017",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #17",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0011::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0018"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0018",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #18",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0012::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0019"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0019",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #19",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0013::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0020"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0020",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #20",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0014::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0021"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0021",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #21",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0015::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0022"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0022",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #22",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0016::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0023"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0023",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #23",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0017::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0024"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0024",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #24",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0018::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0025"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0025",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #25",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0019::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0026"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0026",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #26",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x001a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0027"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0027",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #27",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x001b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0028"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0028",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #28",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x001c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0029"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0029",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #29",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x001d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0030"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0030",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #30",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x001e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0031"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0031",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #31",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x001f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0032"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0032",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #32",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0020::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0033"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0033",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #33",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0021::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0034"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0034",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #34",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0022::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0035"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0035",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #35",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0023::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0036"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0036",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #36",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0024::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0037"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0037",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #37",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0025::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0038"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0038",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #38",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0026::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0039"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0039",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #39",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0027::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0040"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0040",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #40",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0028::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0041"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0041",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #41",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0029::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0042"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0042",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #42",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x002a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0043"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0043",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #43",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x002b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0044"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0044",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #44",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x002c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0045"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0045",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #45",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x002d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0046"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0046",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #46",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x002e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0047"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0047",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #47",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x002f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0048"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0048",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #48",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0030::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0049"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0049",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #49",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0031::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0050"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0050",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #50",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0032::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0051"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0051",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #51",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0033::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0052"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0052",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #52",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0034::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0053"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0053",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #53",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0035::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0054"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0054",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #54",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0036::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0055"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0055",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #55",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0037::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0056"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0056",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #56",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0038::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0057"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0057",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #57",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0039::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0058"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0058",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #58",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x003a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0059"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0059",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #59",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x003b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0060"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0060",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #60",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x003c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0061"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0061",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #61",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x003d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0062"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0062",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #62",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x003e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0063"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0063",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #63",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x003f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0064"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0064",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #64",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0040::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0065"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0065",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #65",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0041::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0066"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0066",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #66",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0042::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0067"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0067",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #67",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0043::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0068"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0068",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #68",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0044::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0069"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0069",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #69",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0045::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0070"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0070",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #70",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0046::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0071"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0071",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #71",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0047::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0072"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0072",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #72",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0048::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0073"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0073",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #73",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0049::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0074"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0074",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #74",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x004a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0075"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0075",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #75",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x004b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0076"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0076",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #76",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x004c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0077"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0077",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #77",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x004d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0078"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0078",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #78",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x004e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0079"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0079",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #79",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x004f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0080"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0080",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #80",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0050::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0081"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0081",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #81",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0051::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0082"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0082",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #82",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0052::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0083"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0083",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #83",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0053::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0084"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0084",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #84",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0054::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0085"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0085",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #85",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0055::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0086"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0086",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #86",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0056::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0087"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0087",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #87",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0057::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0088"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0088",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #88",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0058::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0089"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0089",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #89",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0059::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0090"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0090",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #90",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x005a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0091"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0091",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #91",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x005b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0092"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0092",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #92",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x005c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0093"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0093",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #93",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x005d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0094"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0094",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #94",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x005e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0095"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0095",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #95",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x005f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0096"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0096",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #96",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0060::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0097"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0097",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #97",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0061::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0098"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0098",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #98",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0062::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0099"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0099",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #99",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0063::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0100"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0100",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #100",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0064::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0101"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0101",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #101",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0065::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0102"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0102",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #102",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0066::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0103"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0103",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #103",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0067::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0104"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0104",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #104",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0068::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0105"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0105",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #105",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0069::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0106"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0106",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #106",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x006a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0107"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0107",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #107",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x006b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0108"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0108",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #108",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x006c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0109"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0109",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #109",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x006d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0110"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0110",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #110",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x006e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0111"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0111",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #111",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x006f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0112"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0112",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #112",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0070::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0113"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0113",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #113",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0071::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0114"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0114",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #114",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0072::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0115"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0115",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #115",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0073::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0116"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0116",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #116",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0074::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0117"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0117",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #117",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0075::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0118"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0118",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #118",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0076::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0119"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0119",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #119",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0077::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0120"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0120",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #120",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0078::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0121"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0121",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #121",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0079::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0122"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0122",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #122",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x007a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0123"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0123",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #123",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x007b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0124"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0124",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #124",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x007c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0125"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0125",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #125",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x007d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0126"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0126",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #126",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x007e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0127"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0127",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #127",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x007f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0128"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0128",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #128",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0080::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0129"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0129",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #129",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0081::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0130"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0130",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #130",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0082::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0131"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0131",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #131",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0083::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0132"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0132",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #132",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0084::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0133"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0133",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #133",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0085::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0134"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0134",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #134",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0086::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0135"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0135",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #135",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0087::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0136"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0136",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #136",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0088::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0137"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0137",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #137",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0089::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0138"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0138",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #138",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x008a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0139"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0139",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #139",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x008b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0140"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0140",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #140",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x008c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0141"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0141",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #141",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x008d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0142"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0142",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #142",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x008e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0143"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0143",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #143",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x008f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0144"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0144",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #144",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0090::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0145"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0145",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #145",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0091::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0146"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0146",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #146",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0092::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0147"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0147",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #147",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0093::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0148"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0148",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #148",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0094::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0149"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0149",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #149",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0095::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0150"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0150",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #150",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0096::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0151"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0151",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #151",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0097::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0152"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0152",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #152",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0098::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0153"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0153",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #153",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0099::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0154"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0154",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #154",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x009a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0155"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0155",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #155",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x009b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0156"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0156",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #156",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x009c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0157"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0157",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #157",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x009d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0158"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0158",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #158",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x009e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0159"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0159",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #159",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x009f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0160"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0160",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #160",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00a0::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0161"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0161",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #161",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00a1::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0162"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0162",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #162",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00a2::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0163"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0163",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #163",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00a3::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0164"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0164",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #164",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00a4::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0165"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0165",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #165",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00a5::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0166"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0166",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #166",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00a6::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0167"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0167",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #167",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00a7::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0168"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0168",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #168",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00a8::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0169"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0169",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #169",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00a9::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0170"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0170",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #170",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00aa::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0171"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0171",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #171",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00ab::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0172"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0172",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #172",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00ac::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0173"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0173",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #173",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00ad::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0174"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0174",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #174",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00ae::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0175"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0175",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #175",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00af::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0176"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0176",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #176",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00b0::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0177"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0177",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #177",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00b1::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0178"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0178",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #178",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00b2::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0179"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0179",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #179",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00b3::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0180"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0180",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #180",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00b4::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0181"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0181",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #181",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00b5::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0182"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0182",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #182",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00b6::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0183"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0183",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #183",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00b7::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0184"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0184",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #184",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00b8::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0185"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0185",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #185",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00b9::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0186"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0186",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #186",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00ba::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0187"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0187",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #187",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00bb::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0188"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0188",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #188",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00bc::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0189"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0189",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #189",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00bd::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0190"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0190",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #190",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00be::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0191"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0191",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #191",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00bf::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0192"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0192",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #192",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00c0::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0193"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0193",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #193",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00c1::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0194"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0194",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #194",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00c2::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0195"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0195",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #195",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00c3::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0196"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0196",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #196",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00c4::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0197"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0197",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #197",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00c5::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0198"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0198",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #198",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00c6::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0199"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0199",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #199",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00c7::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0200"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0200",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #200",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00c8::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0201"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0201",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #201",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00c9::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0202"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0202",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #202",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ca::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0203"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0203",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #203",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00cb::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0204"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0204",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #204",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00cc::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0205"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0205",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #205",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00cd::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0206"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0206",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #206",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00ce::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0207"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0207",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #207",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00cf::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0208"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0208",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #208",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00d0::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0209"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0209",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #209",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00d1::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0210"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0210",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #210",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00d2::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0211"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0211",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #211",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00d3::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0212"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0212",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #212",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00d4::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0213"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0213",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #213",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00d5::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0214"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0214",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #214",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00d6::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0215"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0215",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #215",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00d7::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0216"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0216",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #216",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00d8::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0217"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0217",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #217",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00d9::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0218"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0218",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #218",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00da::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0219"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0219",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #219",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00db::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0220"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0220",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #220",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00dc::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0221"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0221",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #221",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00dd::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0222"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0222",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #222",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00de::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0223"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0223",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #223",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00df::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0224"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0224",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #224",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00e0::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0225"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0225",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #225",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00e1::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0226"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0226",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #226",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00e2::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0227"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0227",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #227",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00e3::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0228"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0228",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #228",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00e4::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0229"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0229",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #229",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00e5::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0230"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0230",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #230",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00e6::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0231"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0231",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #231",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00e7::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0232"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0232",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #232",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00e8::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0233"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0233",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #233",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00e9::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0234"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0234",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #234",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00ea::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0235"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0235",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #235",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00eb::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0236"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0236",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #236",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00ec::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0237"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0237",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #237",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00ed::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0238"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0238",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #238",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ee::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0239"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0239",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #239",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00ef::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0240"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0240",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #240",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00f0::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0241"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0241",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #241",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00f1::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0242"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0242",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #242",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00f2::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0243"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0243",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #243",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00f3::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0244"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0244",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #244",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00f4::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0245"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0245",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #245",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00f5::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0246"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0246",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #246",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00f6::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0247"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0247",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #247",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00f7::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0248"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0248",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #248",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00f8::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0249"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0249",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #249",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00f9::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0250"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0250",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #250",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00fa::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0251"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0251",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #251",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00fb::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0252"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0252",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #252",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00fc::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0253"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0253",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #253",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00fd::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0254"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0254",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #254",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00fe::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0255"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0255",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #255",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00ff::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0256"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0256",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #256",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0100::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0257"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0257",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #257",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0101::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0258"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0258",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #258",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0102::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0259"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0259",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #259",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0103::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0260"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0260",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #260",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0104::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0261"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0261",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #261",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0105::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0262"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0262",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #262",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0106::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0263"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0263",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #263",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0107::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0264"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0264",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #264",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0108::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0265"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0265",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #265",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0109::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0266"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0266",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #266",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x010a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0267"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0267",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #267",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x010b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0268"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0268",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #268",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x010c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0269"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0269",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #269",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x010d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0270"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0270",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #270",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x010e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0271"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0271",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #271",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x010f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0272"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0272",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #272",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0110::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0273"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0273",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #273",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0111::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0274"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0274",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #274",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0112::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0275"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0275",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #275",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0113::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0276"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0276",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #276",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0114::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0277"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0277",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #277",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0115::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0278"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0278",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #278",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0116::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0279"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0279",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #279",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0117::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0280"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0280",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #280",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0118::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0281"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0281",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #281",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0119::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0282"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0282",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #282",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x011a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0283"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0283",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #283",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x011b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0284"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0284",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #284",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x011c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0285"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0285",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #285",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x011d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0286"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0286",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #286",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x011e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0287"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0287",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #287",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x011f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0288"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0288",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #288",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0120::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0289"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0289",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #289",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0121::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0290"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0290",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #290",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0122::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0291"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0291",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #291",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0123::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0292"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0292",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #292",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0124::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0293"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0293",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #293",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0125::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0294"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0294",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #294",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0126::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0295"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0295",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #295",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0127::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0296"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0296",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #296",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0128::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0297"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0297",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #297",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0129::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0298"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0298",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #298",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x012a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0299"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0299",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #299",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x012b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0300"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0300",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #300",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x012c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0301"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0301",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #301",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x012d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0302"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0302",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #302",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x012e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0303"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0303",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #303",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x012f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0304"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0304",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #304",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0130::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0305"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0305",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #305",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0131::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0306"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0306",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #306",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0132::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0307"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0307",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #307",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0133::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0308"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0308",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #308",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0134::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0309"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0309",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #309",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0135::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0310"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0310",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #310",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0136::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0311"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0311",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #311",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0137::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0312"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0312",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #312",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0138::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0313"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0313",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #313",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0139::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0314"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0314",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #314",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x013a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0315"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0315",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #315",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x013b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0316"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0316",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #316",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x013c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0317"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0317",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #317",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x013d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0318"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0318",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #318",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x013e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0319"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0319",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #319",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x013f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0320"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0320",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #320",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0140::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0321"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0321",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #321",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0141::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0322"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0322",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #322",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0142::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0323"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0323",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #323",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0143::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0324"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0324",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #324",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0144::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0325"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0325",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #325",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0145::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0326"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0326",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #326",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0146::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0327"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0327",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #327",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0147::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0328"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0328",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #328",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0148::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0329"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0329",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #329",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0149::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0330"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0330",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #330",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x014a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0331"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0331",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #331",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x014b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0332"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0332",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #332",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x014c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0333"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0333",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #333",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x014d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0334"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0334",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #334",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x014e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0335"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0335",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #335",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x014f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0336"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0336",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #336",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0150::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0337"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0337",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #337",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0151::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0338"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0338",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #338",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0152::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0339"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0339",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #339",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0153::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0340"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0340",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #340",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0154::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0341"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0341",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #341",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0155::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0342"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0342",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #342",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0156::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0343"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0343",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #343",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0157::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0344"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0344",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #344",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0158::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0345"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0345",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #345",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0159::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0346"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0346",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #346",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x015a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0347"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0347",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #347",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x015b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0348"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0348",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #348",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x015c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0349"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0349",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #349",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x015d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0350"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0350",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #350",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x015e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0351"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0351",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #351",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x015f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0352"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0352",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #352",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0160::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0353"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0353",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #353",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0161::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0354"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0354",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #354",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0162::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0355"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0355",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #355",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0163::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0356"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0356",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #356",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0164::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0357"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0357",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #357",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0165::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0358"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0358",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #358",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0166::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0359"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0359",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #359",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0167::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0360"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0360",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #360",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0168::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0361"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0361",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #361",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0169::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0362"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0362",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #362",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x016a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0363"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0363",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #363",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x016b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0364"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0364",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #364",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x016c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0365"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0365",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #365",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x016d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0366"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0366",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #366",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x016e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0367"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0367",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #367",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x016f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0368"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0368",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #368",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0170::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0369"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0369",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #369",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0171::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0370"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0370",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #370",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0172::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0371"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0371",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #371",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0173::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0372"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0372",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #372",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0174::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0373"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0373",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #373",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0175::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0374"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0374",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #374",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0176::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0375"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0375",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #375",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0177::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0376"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0376",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #376",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0178::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0377"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0377",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #377",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0179::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0378"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0378",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #378",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x017a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0379"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0379",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #379",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x017b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0380"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0380",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #380",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x017c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0381"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0381",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #381",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x017d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0382"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0382",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #382",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x017e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0383"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0383",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #383",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x017f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0384"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0384",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #384",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0180::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0385"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0385",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #385",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0181::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0386"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0386",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #386",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0182::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0387"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0387",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #387",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0183::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0388"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0388",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #388",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0184::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0389"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0389",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #389",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0185::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0390"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0390",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #390",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0186::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0391"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0391",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #391",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0187::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0392"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0392",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #392",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0188::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0393"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0393",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #393",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0189::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0394"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0394",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #394",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x018a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0395"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0395",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #395",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x018b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0396"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0396",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #396",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x018c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0397"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0397",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #397",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x018d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0398"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0398",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #398",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x018e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0399"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0399",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #399",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x018f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0400"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0400",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #400",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0190::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0401"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0401",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #401",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0191::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0402"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0402",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #402",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0192::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0403"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0403",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #403",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0193::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0404"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0404",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #404",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0194::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0405"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0405",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #405",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0195::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0406"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0406",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #406",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0196::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0407"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0407",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #407",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0197::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0408"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0408",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #408",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0198::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0409"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0409",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #409",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0199::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0410"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0410",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #410",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x019a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0411"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0411",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #411",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x019b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0412"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0412",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #412",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x019c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0413"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0413",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #413",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x019d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0414"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0414",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #414",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x019e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0415"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0415",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #415",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x019f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0416"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0416",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #416",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x01a0::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0417"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0417",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #417",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x01a1::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0418"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0418",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #418",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x01a2::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0419"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0419",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #419",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x01a3::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0420"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0420",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #420",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x01a4::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0421"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0421",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #421",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x01a5::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0422"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0422",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #422",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x01a6::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0423"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0423",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #423",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x01a7::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0424"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0424",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #424",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x01a8::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0425"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0425",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #425",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x01a9::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0426"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0426",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #426",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x01aa::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0427"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0427",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #427",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x01ab::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0428"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0428",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #428",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x01ac::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0429"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0429",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #429",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x01ad::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0430"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0430",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #430",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x01ae::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0431"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0431",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #431",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x01af::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0432"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0432",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #432",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x01b0::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0433"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0433",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #433",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x01b1::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0434"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0434",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #434",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x01b2::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0435"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0435",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #435",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x01b3::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0436"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0436",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #436",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x01b4::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0437"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0437",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #437",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x01b5::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0438"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0438",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #438",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x01b6::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0439"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0439",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #439",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x01b7::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0440"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0440",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #440",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x01b8::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0441"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0441",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #441",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x01b9::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0442"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0442",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #442",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x01ba::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0443"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0443",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #443",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x01bb::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0444"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0444",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #444",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x01bc::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0445"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0445",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #445",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x01bd::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0446"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0446",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #446",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x01be::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0447"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0447",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #447",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x01bf::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0448"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0448",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #448",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x01c0::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["SMBPIPEGUARD-R-0449"] = SmbPipeGuardRule(
            rule_id="SMBPIPEGUARD-R-0449",
            name="SMBv3 Named Pipe IPC & Remote Procedure Inspector Detection Signature #449",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x01c1::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )

    def evaluate_traffic_stream(self, header: SmbPipeGuardHeader) -> Dict[str, Any]:
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

smb_named_pipe_guard_instance = SmbPipeGuardEngine()

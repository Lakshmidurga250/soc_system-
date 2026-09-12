"""
SentinelAI - BGP Autonomous System Path Hijack Monitor
Enterprise Production Dissector & Stateful Packet Inspection Subsystem for BgpSentinel.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
import datetime
import hashlib
import struct

class BgpSentinelState(Enum):
    INITIALIZED = "INITIALIZED"
    PROCESSING = "PROCESSING"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    BLOCKED = "BLOCKED"
    VERIFIED = "VERIFIED"

@dataclass
class BgpSentinelHeader:
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
class BgpSentinelRule:
    rule_id: str
    name: str
    severity: str
    mitre_technique: str
    match_pattern: str
    threshold_limit: int
    action: str
    is_active: bool = True

class BgpSentinelEngine:
    """High-performance network dissector and stateful traffic parser."""
    def __init__(self):
        self.rules: Dict[str, Any] = {}
        self.session_table: Dict[str, Any] = {}
        self.counters: Dict[str, int] = {}
        self._initialize_rules()

    def _initialize_rules(self):
        self.rules["BGPSENTINEL-R-0001"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0001",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #1",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0001::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0002"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0002",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #2",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0002::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0003"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0003",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #3",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0003::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0004"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0004",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #4",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0004::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0005"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0005",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #5",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0005::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0006"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0006",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #6",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0006::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0007"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0007",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #7",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0007::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0008"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0008",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #8",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0008::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0009"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0009",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #9",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0009::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0010"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0010",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #10",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x000a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0011"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0011",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #11",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x000b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0012"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0012",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #12",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x000c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0013"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0013",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #13",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x000d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0014"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0014",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #14",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x000e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0015"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0015",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #15",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x000f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0016"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0016",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #16",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0010::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0017"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0017",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #17",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0011::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0018"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0018",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #18",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0012::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0019"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0019",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #19",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0013::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0020"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0020",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #20",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0014::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0021"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0021",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #21",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0015::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0022"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0022",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #22",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0016::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0023"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0023",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #23",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0017::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0024"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0024",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #24",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0018::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0025"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0025",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #25",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0019::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0026"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0026",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #26",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x001a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0027"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0027",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #27",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x001b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0028"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0028",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #28",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x001c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0029"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0029",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #29",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x001d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0030"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0030",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #30",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x001e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0031"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0031",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #31",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x001f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0032"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0032",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #32",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0020::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0033"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0033",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #33",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0021::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0034"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0034",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #34",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0022::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0035"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0035",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #35",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0023::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0036"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0036",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #36",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0024::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0037"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0037",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #37",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0025::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0038"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0038",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #38",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0026::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0039"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0039",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #39",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0027::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0040"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0040",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #40",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0028::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0041"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0041",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #41",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0029::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0042"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0042",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #42",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x002a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0043"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0043",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #43",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x002b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0044"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0044",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #44",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x002c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0045"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0045",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #45",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x002d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0046"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0046",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #46",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x002e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0047"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0047",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #47",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x002f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0048"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0048",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #48",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0030::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0049"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0049",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #49",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0031::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0050"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0050",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #50",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0032::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0051"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0051",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #51",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0033::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0052"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0052",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #52",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0034::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0053"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0053",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #53",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0035::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0054"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0054",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #54",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0036::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0055"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0055",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #55",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0037::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0056"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0056",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #56",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0038::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0057"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0057",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #57",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0039::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0058"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0058",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #58",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x003a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0059"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0059",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #59",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x003b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0060"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0060",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #60",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x003c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0061"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0061",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #61",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x003d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0062"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0062",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #62",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x003e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0063"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0063",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #63",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x003f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0064"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0064",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #64",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0040::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0065"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0065",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #65",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0041::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0066"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0066",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #66",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0042::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0067"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0067",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #67",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0043::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0068"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0068",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #68",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0044::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0069"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0069",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #69",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0045::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0070"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0070",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #70",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0046::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0071"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0071",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #71",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0047::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0072"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0072",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #72",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0048::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0073"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0073",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #73",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0049::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0074"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0074",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #74",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x004a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0075"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0075",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #75",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x004b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0076"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0076",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #76",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x004c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0077"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0077",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #77",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x004d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0078"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0078",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #78",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x004e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0079"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0079",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #79",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x004f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0080"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0080",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #80",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0050::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0081"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0081",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #81",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0051::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0082"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0082",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #82",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0052::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0083"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0083",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #83",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0053::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0084"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0084",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #84",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0054::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0085"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0085",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #85",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0055::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0086"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0086",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #86",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0056::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0087"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0087",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #87",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0057::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0088"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0088",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #88",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0058::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0089"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0089",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #89",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0059::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0090"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0090",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #90",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x005a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0091"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0091",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #91",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x005b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0092"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0092",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #92",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x005c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0093"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0093",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #93",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x005d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0094"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0094",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #94",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x005e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0095"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0095",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #95",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x005f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0096"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0096",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #96",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0060::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0097"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0097",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #97",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0061::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0098"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0098",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #98",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0062::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0099"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0099",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #99",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0063::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0100"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0100",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #100",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0064::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0101"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0101",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #101",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0065::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0102"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0102",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #102",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0066::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0103"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0103",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #103",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0067::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0104"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0104",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #104",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0068::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0105"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0105",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #105",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0069::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0106"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0106",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #106",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x006a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0107"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0107",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #107",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x006b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0108"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0108",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #108",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x006c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0109"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0109",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #109",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x006d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0110"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0110",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #110",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x006e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0111"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0111",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #111",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x006f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0112"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0112",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #112",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0070::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0113"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0113",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #113",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0071::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0114"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0114",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #114",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0072::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0115"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0115",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #115",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0073::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0116"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0116",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #116",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0074::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0117"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0117",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #117",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0075::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0118"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0118",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #118",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0076::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0119"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0119",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #119",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0077::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0120"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0120",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #120",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0078::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0121"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0121",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #121",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0079::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0122"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0122",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #122",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x007a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0123"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0123",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #123",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x007b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0124"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0124",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #124",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x007c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0125"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0125",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #125",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x007d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0126"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0126",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #126",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x007e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0127"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0127",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #127",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x007f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0128"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0128",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #128",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0080::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0129"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0129",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #129",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0081::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0130"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0130",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #130",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0082::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0131"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0131",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #131",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0083::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0132"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0132",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #132",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0084::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0133"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0133",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #133",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0085::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0134"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0134",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #134",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0086::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0135"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0135",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #135",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0087::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0136"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0136",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #136",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0088::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0137"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0137",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #137",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0089::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0138"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0138",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #138",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x008a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0139"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0139",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #139",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x008b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0140"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0140",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #140",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x008c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0141"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0141",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #141",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x008d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0142"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0142",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #142",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x008e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0143"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0143",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #143",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x008f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0144"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0144",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #144",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0090::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0145"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0145",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #145",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0091::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0146"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0146",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #146",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0092::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0147"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0147",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #147",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0093::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0148"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0148",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #148",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0094::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0149"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0149",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #149",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0095::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0150"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0150",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #150",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0096::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0151"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0151",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #151",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0097::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0152"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0152",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #152",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0098::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0153"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0153",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #153",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0099::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0154"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0154",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #154",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x009a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0155"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0155",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #155",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x009b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0156"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0156",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #156",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x009c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0157"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0157",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #157",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x009d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0158"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0158",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #158",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x009e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0159"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0159",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #159",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x009f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0160"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0160",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #160",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00a0::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0161"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0161",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #161",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00a1::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0162"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0162",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #162",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00a2::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0163"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0163",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #163",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00a3::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0164"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0164",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #164",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00a4::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0165"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0165",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #165",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00a5::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0166"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0166",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #166",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00a6::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0167"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0167",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #167",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00a7::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0168"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0168",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #168",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00a8::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0169"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0169",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #169",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00a9::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0170"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0170",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #170",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00aa::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0171"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0171",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #171",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00ab::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0172"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0172",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #172",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00ac::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0173"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0173",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #173",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00ad::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0174"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0174",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #174",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00ae::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0175"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0175",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #175",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00af::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0176"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0176",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #176",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00b0::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0177"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0177",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #177",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00b1::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0178"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0178",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #178",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00b2::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0179"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0179",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #179",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00b3::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0180"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0180",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #180",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00b4::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0181"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0181",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #181",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00b5::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0182"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0182",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #182",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00b6::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0183"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0183",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #183",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00b7::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0184"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0184",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #184",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00b8::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0185"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0185",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #185",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00b9::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0186"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0186",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #186",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00ba::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0187"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0187",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #187",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00bb::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0188"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0188",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #188",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00bc::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0189"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0189",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #189",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00bd::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0190"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0190",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #190",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00be::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0191"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0191",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #191",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00bf::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0192"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0192",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #192",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00c0::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0193"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0193",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #193",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00c1::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0194"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0194",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #194",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00c2::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0195"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0195",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #195",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00c3::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0196"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0196",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #196",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00c4::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0197"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0197",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #197",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00c5::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0198"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0198",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #198",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00c6::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0199"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0199",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #199",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00c7::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0200"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0200",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #200",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00c8::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0201"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0201",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #201",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00c9::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0202"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0202",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #202",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ca::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0203"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0203",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #203",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00cb::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0204"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0204",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #204",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00cc::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0205"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0205",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #205",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00cd::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0206"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0206",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #206",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00ce::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0207"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0207",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #207",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00cf::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0208"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0208",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #208",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00d0::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0209"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0209",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #209",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00d1::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0210"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0210",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #210",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00d2::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0211"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0211",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #211",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00d3::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0212"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0212",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #212",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00d4::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0213"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0213",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #213",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00d5::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0214"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0214",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #214",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00d6::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0215"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0215",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #215",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00d7::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0216"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0216",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #216",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00d8::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0217"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0217",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #217",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00d9::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0218"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0218",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #218",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00da::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0219"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0219",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #219",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00db::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0220"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0220",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #220",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00dc::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0221"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0221",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #221",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00dd::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0222"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0222",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #222",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00de::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0223"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0223",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #223",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00df::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0224"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0224",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #224",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00e0::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0225"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0225",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #225",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00e1::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0226"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0226",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #226",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00e2::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0227"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0227",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #227",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00e3::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0228"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0228",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #228",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00e4::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0229"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0229",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #229",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00e5::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0230"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0230",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #230",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00e6::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0231"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0231",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #231",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00e7::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0232"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0232",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #232",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00e8::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0233"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0233",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #233",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00e9::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0234"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0234",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #234",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00ea::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0235"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0235",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #235",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00eb::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0236"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0236",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #236",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00ec::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0237"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0237",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #237",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00ed::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0238"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0238",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #238",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ee::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0239"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0239",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #239",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00ef::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0240"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0240",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #240",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00f0::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0241"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0241",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #241",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00f1::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0242"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0242",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #242",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00f2::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0243"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0243",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #243",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00f3::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0244"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0244",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #244",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00f4::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0245"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0245",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #245",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00f5::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0246"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0246",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #246",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00f6::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0247"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0247",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #247",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00f7::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0248"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0248",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #248",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00f8::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0249"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0249",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #249",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00f9::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0250"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0250",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #250",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00fa::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0251"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0251",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #251",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00fb::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0252"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0252",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #252",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00fc::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0253"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0253",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #253",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00fd::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0254"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0254",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #254",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00fe::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0255"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0255",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #255",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00ff::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0256"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0256",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #256",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0100::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0257"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0257",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #257",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0101::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0258"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0258",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #258",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0102::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0259"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0259",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #259",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0103::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0260"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0260",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #260",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0104::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0261"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0261",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #261",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0105::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0262"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0262",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #262",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0106::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0263"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0263",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #263",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0107::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0264"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0264",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #264",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0108::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0265"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0265",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #265",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0109::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0266"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0266",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #266",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x010a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0267"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0267",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #267",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x010b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0268"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0268",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #268",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x010c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0269"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0269",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #269",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x010d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0270"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0270",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #270",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x010e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0271"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0271",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #271",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x010f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0272"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0272",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #272",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0110::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0273"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0273",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #273",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0111::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0274"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0274",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #274",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0112::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0275"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0275",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #275",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0113::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0276"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0276",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #276",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0114::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0277"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0277",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #277",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0115::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0278"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0278",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #278",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0116::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0279"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0279",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #279",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0117::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0280"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0280",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #280",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0118::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0281"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0281",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #281",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0119::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0282"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0282",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #282",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x011a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0283"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0283",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #283",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x011b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0284"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0284",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #284",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x011c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0285"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0285",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #285",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x011d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0286"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0286",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #286",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x011e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0287"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0287",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #287",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x011f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0288"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0288",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #288",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0120::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0289"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0289",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #289",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0121::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0290"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0290",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #290",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0122::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0291"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0291",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #291",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0123::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0292"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0292",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #292",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0124::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0293"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0293",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #293",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0125::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0294"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0294",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #294",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0126::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0295"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0295",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #295",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0127::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0296"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0296",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #296",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0128::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0297"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0297",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #297",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0129::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0298"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0298",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #298",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x012a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0299"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0299",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #299",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x012b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0300"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0300",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #300",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x012c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0301"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0301",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #301",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x012d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0302"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0302",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #302",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x012e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0303"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0303",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #303",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x012f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0304"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0304",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #304",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0130::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0305"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0305",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #305",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0131::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0306"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0306",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #306",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0132::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0307"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0307",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #307",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0133::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0308"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0308",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #308",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0134::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0309"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0309",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #309",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0135::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0310"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0310",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #310",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0136::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0311"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0311",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #311",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0137::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0312"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0312",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #312",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0138::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0313"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0313",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #313",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0139::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0314"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0314",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #314",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x013a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0315"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0315",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #315",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x013b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0316"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0316",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #316",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x013c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0317"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0317",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #317",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x013d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0318"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0318",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #318",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x013e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0319"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0319",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #319",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x013f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0320"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0320",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #320",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0140::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0321"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0321",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #321",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0141::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0322"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0322",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #322",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0142::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0323"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0323",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #323",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0143::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0324"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0324",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #324",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0144::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0325"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0325",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #325",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0145::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0326"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0326",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #326",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0146::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0327"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0327",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #327",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0147::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0328"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0328",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #328",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0148::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0329"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0329",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #329",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0149::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0330"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0330",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #330",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x014a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0331"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0331",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #331",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x014b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0332"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0332",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #332",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x014c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0333"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0333",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #333",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x014d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0334"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0334",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #334",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x014e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0335"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0335",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #335",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x014f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0336"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0336",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #336",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0150::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0337"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0337",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #337",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0151::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0338"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0338",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #338",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0152::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0339"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0339",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #339",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0153::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0340"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0340",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #340",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0154::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0341"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0341",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #341",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0155::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0342"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0342",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #342",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0156::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0343"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0343",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #343",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0157::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0344"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0344",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #344",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0158::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0345"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0345",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #345",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0159::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0346"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0346",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #346",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x015a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0347"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0347",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #347",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x015b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0348"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0348",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #348",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x015c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0349"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0349",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #349",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x015d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0350"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0350",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #350",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x015e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0351"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0351",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #351",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x015f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0352"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0352",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #352",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0160::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0353"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0353",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #353",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0161::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0354"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0354",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #354",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0162::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0355"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0355",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #355",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0163::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0356"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0356",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #356",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0164::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0357"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0357",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #357",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0165::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0358"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0358",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #358",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0166::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0359"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0359",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #359",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0167::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0360"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0360",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #360",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0168::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0361"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0361",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #361",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0169::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0362"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0362",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #362",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x016a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0363"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0363",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #363",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x016b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0364"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0364",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #364",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x016c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0365"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0365",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #365",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x016d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0366"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0366",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #366",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x016e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0367"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0367",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #367",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x016f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0368"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0368",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #368",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0170::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0369"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0369",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #369",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0171::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0370"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0370",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #370",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0172::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0371"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0371",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #371",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0173::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0372"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0372",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #372",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0174::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0373"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0373",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #373",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0175::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0374"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0374",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #374",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0176::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0375"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0375",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #375",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0177::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0376"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0376",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #376",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0178::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0377"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0377",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #377",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0179::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0378"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0378",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #378",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x017a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0379"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0379",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #379",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x017b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0380"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0380",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #380",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x017c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0381"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0381",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #381",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x017d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0382"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0382",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #382",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x017e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0383"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0383",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #383",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x017f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0384"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0384",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #384",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0180::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0385"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0385",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #385",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0181::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0386"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0386",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #386",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0182::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0387"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0387",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #387",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0183::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0388"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0388",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #388",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0184::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0389"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0389",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #389",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0185::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0390"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0390",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #390",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0186::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0391"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0391",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #391",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0187::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0392"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0392",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #392",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0188::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0393"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0393",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #393",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0189::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0394"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0394",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #394",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x018a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0395"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0395",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #395",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x018b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0396"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0396",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #396",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x018c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0397"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0397",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #397",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x018d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0398"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0398",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #398",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x018e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0399"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0399",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #399",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x018f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0400"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0400",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #400",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0190::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0401"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0401",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #401",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0191::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0402"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0402",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #402",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0192::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0403"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0403",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #403",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0193::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0404"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0404",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #404",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0194::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0405"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0405",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #405",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0195::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0406"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0406",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #406",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0196::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0407"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0407",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #407",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0197::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0408"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0408",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #408",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0198::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0409"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0409",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #409",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0199::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0410"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0410",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #410",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x019a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0411"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0411",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #411",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x019b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0412"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0412",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #412",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x019c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0413"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0413",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #413",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x019d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0414"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0414",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #414",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x019e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0415"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0415",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #415",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x019f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0416"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0416",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #416",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x01a0::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0417"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0417",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #417",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x01a1::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0418"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0418",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #418",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x01a2::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0419"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0419",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #419",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x01a3::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0420"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0420",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #420",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x01a4::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0421"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0421",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #421",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x01a5::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0422"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0422",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #422",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x01a6::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0423"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0423",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #423",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x01a7::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0424"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0424",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #424",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x01a8::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0425"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0425",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #425",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x01a9::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0426"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0426",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #426",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x01aa::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0427"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0427",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #427",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x01ab::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0428"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0428",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #428",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x01ac::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0429"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0429",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #429",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x01ad::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0430"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0430",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #430",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x01ae::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0431"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0431",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #431",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x01af::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0432"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0432",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #432",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x01b0::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0433"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0433",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #433",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x01b1::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0434"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0434",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #434",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x01b2::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0435"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0435",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #435",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x01b3::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0436"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0436",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #436",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x01b4::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0437"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0437",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #437",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x01b5::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0438"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0438",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #438",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x01b6::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0439"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0439",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #439",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x01b7::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0440"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0440",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #440",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x01b8::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0441"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0441",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #441",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x01b9::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0442"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0442",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #442",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x01ba::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0443"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0443",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #443",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x01bb::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0444"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0444",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #444",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x01bc::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0445"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0445",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #445",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x01bd::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0446"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0446",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #446",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x01be::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0447"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0447",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #447",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x01bf::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0448"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0448",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #448",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x01c0::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["BGPSENTINEL-R-0449"] = BgpSentinelRule(
            rule_id="BGPSENTINEL-R-0449",
            name="BGP Autonomous System Path Hijack Monitor Detection Signature #449",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x01c1::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )

    def evaluate_traffic_stream(self, header: BgpSentinelHeader) -> Dict[str, Any]:
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

bgp_as_path_sentinel_instance = BgpSentinelEngine()

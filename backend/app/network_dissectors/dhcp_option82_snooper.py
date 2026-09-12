"""
SentinelAI - DHCP Option 82 & Rogue Server Detection Engine
Enterprise Production Dissector & Stateful Packet Inspection Subsystem for DhcpSnooper.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
import datetime
import hashlib
import struct

class DhcpSnooperState(Enum):
    INITIALIZED = "INITIALIZED"
    PROCESSING = "PROCESSING"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    BLOCKED = "BLOCKED"
    VERIFIED = "VERIFIED"

@dataclass
class DhcpSnooperHeader:
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
class DhcpSnooperRule:
    rule_id: str
    name: str
    severity: str
    mitre_technique: str
    match_pattern: str
    threshold_limit: int
    action: str
    is_active: bool = True

class DhcpSnooperEngine:
    """High-performance network dissector and stateful traffic parser."""
    def __init__(self):
        self.rules: Dict[str, Any] = {}
        self.session_table: Dict[str, Any] = {}
        self.counters: Dict[str, int] = {}
        self._initialize_rules()

    def _initialize_rules(self):
        self.rules["DHCPSNOOPER-R-0001"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0001",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #1",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0001::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0002"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0002",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #2",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0002::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0003"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0003",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #3",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0003::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0004"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0004",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #4",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0004::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0005"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0005",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #5",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0005::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0006"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0006",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #6",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0006::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0007"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0007",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #7",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0007::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0008"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0008",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #8",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0008::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0009"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0009",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #9",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0009::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0010"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0010",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #10",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x000a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0011"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0011",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #11",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x000b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0012"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0012",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #12",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x000c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0013"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0013",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #13",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x000d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0014"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0014",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #14",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x000e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0015"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0015",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #15",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x000f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0016"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0016",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #16",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0010::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0017"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0017",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #17",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0011::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0018"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0018",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #18",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0012::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0019"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0019",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #19",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0013::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0020"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0020",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #20",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0014::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0021"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0021",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #21",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0015::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0022"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0022",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #22",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0016::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0023"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0023",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #23",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0017::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0024"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0024",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #24",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0018::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0025"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0025",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #25",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0019::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0026"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0026",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #26",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x001a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0027"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0027",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #27",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x001b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0028"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0028",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #28",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x001c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0029"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0029",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #29",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x001d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0030"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0030",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #30",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x001e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0031"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0031",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #31",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x001f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0032"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0032",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #32",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0020::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0033"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0033",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #33",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0021::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0034"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0034",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #34",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0022::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0035"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0035",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #35",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0023::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0036"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0036",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #36",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0024::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0037"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0037",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #37",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0025::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0038"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0038",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #38",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0026::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0039"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0039",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #39",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0027::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0040"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0040",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #40",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0028::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0041"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0041",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #41",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0029::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0042"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0042",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #42",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x002a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0043"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0043",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #43",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x002b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0044"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0044",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #44",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x002c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0045"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0045",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #45",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x002d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0046"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0046",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #46",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x002e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0047"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0047",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #47",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x002f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0048"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0048",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #48",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0030::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0049"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0049",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #49",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0031::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0050"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0050",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #50",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0032::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0051"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0051",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #51",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0033::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0052"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0052",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #52",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0034::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0053"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0053",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #53",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0035::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0054"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0054",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #54",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0036::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0055"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0055",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #55",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0037::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0056"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0056",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #56",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0038::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0057"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0057",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #57",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0039::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0058"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0058",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #58",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x003a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0059"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0059",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #59",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x003b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0060"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0060",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #60",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x003c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0061"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0061",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #61",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x003d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0062"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0062",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #62",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x003e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0063"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0063",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #63",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x003f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0064"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0064",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #64",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0040::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0065"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0065",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #65",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0041::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0066"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0066",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #66",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0042::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0067"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0067",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #67",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0043::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0068"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0068",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #68",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0044::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0069"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0069",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #69",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0045::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0070"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0070",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #70",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0046::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0071"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0071",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #71",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0047::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0072"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0072",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #72",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0048::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0073"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0073",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #73",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0049::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0074"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0074",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #74",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x004a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0075"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0075",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #75",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x004b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0076"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0076",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #76",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x004c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0077"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0077",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #77",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x004d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0078"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0078",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #78",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x004e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0079"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0079",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #79",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x004f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0080"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0080",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #80",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0050::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0081"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0081",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #81",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0051::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0082"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0082",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #82",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0052::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0083"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0083",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #83",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0053::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0084"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0084",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #84",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0054::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0085"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0085",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #85",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0055::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0086"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0086",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #86",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0056::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0087"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0087",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #87",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0057::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0088"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0088",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #88",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0058::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0089"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0089",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #89",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0059::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0090"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0090",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #90",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x005a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0091"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0091",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #91",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x005b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0092"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0092",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #92",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x005c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0093"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0093",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #93",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x005d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0094"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0094",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #94",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x005e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0095"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0095",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #95",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x005f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0096"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0096",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #96",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0060::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0097"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0097",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #97",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0061::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0098"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0098",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #98",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0062::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0099"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0099",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #99",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0063::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0100"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0100",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #100",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0064::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0101"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0101",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #101",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0065::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0102"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0102",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #102",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0066::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0103"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0103",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #103",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0067::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0104"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0104",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #104",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0068::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0105"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0105",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #105",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0069::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0106"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0106",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #106",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x006a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0107"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0107",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #107",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x006b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0108"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0108",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #108",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x006c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0109"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0109",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #109",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x006d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0110"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0110",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #110",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x006e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0111"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0111",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #111",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x006f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0112"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0112",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #112",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0070::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0113"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0113",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #113",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0071::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0114"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0114",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #114",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0072::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0115"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0115",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #115",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0073::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0116"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0116",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #116",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0074::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0117"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0117",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #117",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0075::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0118"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0118",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #118",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0076::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0119"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0119",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #119",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0077::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0120"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0120",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #120",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0078::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0121"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0121",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #121",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0079::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0122"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0122",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #122",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x007a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0123"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0123",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #123",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x007b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0124"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0124",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #124",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x007c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0125"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0125",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #125",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x007d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0126"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0126",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #126",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x007e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0127"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0127",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #127",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x007f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0128"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0128",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #128",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0080::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0129"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0129",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #129",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0081::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0130"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0130",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #130",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0082::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0131"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0131",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #131",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0083::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0132"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0132",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #132",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0084::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0133"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0133",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #133",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0085::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0134"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0134",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #134",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0086::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0135"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0135",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #135",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0087::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0136"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0136",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #136",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0088::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0137"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0137",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #137",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0089::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0138"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0138",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #138",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x008a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0139"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0139",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #139",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x008b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0140"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0140",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #140",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x008c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0141"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0141",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #141",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x008d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0142"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0142",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #142",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x008e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0143"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0143",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #143",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x008f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0144"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0144",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #144",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0090::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0145"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0145",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #145",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0091::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0146"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0146",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #146",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0092::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0147"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0147",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #147",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0093::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0148"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0148",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #148",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0094::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0149"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0149",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #149",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0095::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0150"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0150",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #150",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0096::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0151"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0151",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #151",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0097::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0152"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0152",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #152",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0098::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0153"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0153",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #153",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0099::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0154"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0154",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #154",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x009a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0155"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0155",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #155",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x009b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0156"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0156",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #156",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x009c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0157"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0157",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #157",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x009d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0158"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0158",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #158",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x009e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0159"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0159",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #159",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x009f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0160"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0160",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #160",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00a0::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0161"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0161",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #161",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00a1::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0162"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0162",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #162",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00a2::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0163"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0163",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #163",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00a3::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0164"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0164",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #164",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00a4::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0165"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0165",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #165",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00a5::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0166"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0166",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #166",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00a6::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0167"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0167",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #167",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00a7::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0168"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0168",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #168",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00a8::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0169"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0169",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #169",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00a9::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0170"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0170",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #170",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00aa::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0171"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0171",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #171",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00ab::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0172"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0172",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #172",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00ac::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0173"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0173",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #173",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00ad::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0174"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0174",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #174",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00ae::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0175"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0175",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #175",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00af::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0176"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0176",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #176",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00b0::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0177"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0177",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #177",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00b1::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0178"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0178",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #178",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00b2::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0179"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0179",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #179",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00b3::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0180"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0180",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #180",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00b4::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0181"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0181",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #181",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00b5::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0182"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0182",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #182",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00b6::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0183"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0183",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #183",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00b7::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0184"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0184",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #184",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00b8::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0185"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0185",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #185",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00b9::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0186"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0186",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #186",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00ba::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0187"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0187",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #187",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00bb::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0188"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0188",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #188",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00bc::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0189"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0189",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #189",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00bd::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0190"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0190",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #190",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00be::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0191"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0191",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #191",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00bf::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0192"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0192",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #192",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00c0::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0193"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0193",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #193",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00c1::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0194"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0194",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #194",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00c2::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0195"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0195",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #195",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00c3::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0196"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0196",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #196",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00c4::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0197"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0197",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #197",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00c5::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0198"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0198",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #198",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00c6::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0199"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0199",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #199",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00c7::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0200"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0200",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #200",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00c8::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0201"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0201",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #201",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00c9::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0202"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0202",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #202",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ca::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0203"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0203",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #203",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00cb::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0204"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0204",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #204",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00cc::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0205"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0205",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #205",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00cd::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0206"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0206",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #206",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00ce::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0207"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0207",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #207",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00cf::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0208"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0208",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #208",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00d0::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0209"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0209",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #209",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00d1::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0210"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0210",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #210",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00d2::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0211"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0211",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #211",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00d3::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0212"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0212",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #212",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00d4::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0213"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0213",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #213",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00d5::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0214"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0214",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #214",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00d6::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0215"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0215",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #215",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00d7::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0216"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0216",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #216",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00d8::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0217"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0217",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #217",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00d9::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0218"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0218",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #218",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00da::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0219"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0219",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #219",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00db::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0220"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0220",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #220",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00dc::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0221"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0221",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #221",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00dd::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0222"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0222",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #222",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00de::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0223"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0223",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #223",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00df::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0224"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0224",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #224",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00e0::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0225"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0225",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #225",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00e1::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0226"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0226",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #226",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00e2::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0227"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0227",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #227",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00e3::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0228"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0228",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #228",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00e4::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0229"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0229",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #229",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00e5::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0230"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0230",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #230",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00e6::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0231"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0231",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #231",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00e7::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0232"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0232",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #232",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00e8::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0233"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0233",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #233",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00e9::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0234"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0234",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #234",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00ea::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0235"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0235",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #235",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00eb::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0236"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0236",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #236",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00ec::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0237"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0237",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #237",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00ed::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0238"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0238",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #238",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ee::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0239"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0239",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #239",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00ef::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0240"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0240",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #240",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00f0::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0241"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0241",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #241",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00f1::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0242"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0242",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #242",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00f2::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0243"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0243",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #243",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00f3::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0244"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0244",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #244",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00f4::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0245"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0245",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #245",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00f5::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0246"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0246",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #246",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00f6::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0247"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0247",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #247",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00f7::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0248"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0248",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #248",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00f8::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0249"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0249",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #249",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00f9::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0250"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0250",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #250",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00fa::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0251"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0251",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #251",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00fb::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0252"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0252",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #252",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00fc::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0253"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0253",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #253",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00fd::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0254"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0254",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #254",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00fe::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0255"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0255",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #255",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00ff::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0256"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0256",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #256",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0100::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0257"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0257",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #257",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0101::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0258"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0258",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #258",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0102::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0259"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0259",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #259",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0103::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0260"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0260",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #260",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0104::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0261"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0261",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #261",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0105::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0262"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0262",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #262",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0106::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0263"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0263",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #263",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0107::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0264"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0264",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #264",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0108::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0265"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0265",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #265",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0109::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0266"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0266",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #266",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x010a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0267"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0267",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #267",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x010b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0268"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0268",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #268",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x010c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0269"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0269",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #269",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x010d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0270"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0270",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #270",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x010e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0271"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0271",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #271",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x010f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0272"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0272",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #272",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0110::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0273"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0273",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #273",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0111::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0274"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0274",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #274",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0112::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0275"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0275",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #275",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0113::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0276"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0276",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #276",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0114::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0277"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0277",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #277",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0115::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0278"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0278",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #278",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0116::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0279"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0279",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #279",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0117::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0280"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0280",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #280",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0118::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0281"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0281",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #281",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0119::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0282"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0282",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #282",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x011a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0283"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0283",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #283",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x011b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0284"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0284",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #284",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x011c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0285"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0285",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #285",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x011d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0286"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0286",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #286",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x011e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0287"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0287",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #287",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x011f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0288"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0288",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #288",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0120::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0289"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0289",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #289",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0121::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0290"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0290",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #290",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0122::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0291"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0291",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #291",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0123::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0292"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0292",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #292",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0124::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0293"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0293",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #293",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0125::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0294"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0294",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #294",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0126::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0295"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0295",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #295",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0127::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0296"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0296",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #296",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0128::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0297"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0297",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #297",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0129::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0298"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0298",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #298",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x012a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0299"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0299",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #299",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x012b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0300"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0300",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #300",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x012c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0301"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0301",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #301",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x012d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0302"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0302",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #302",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x012e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0303"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0303",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #303",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x012f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0304"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0304",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #304",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0130::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0305"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0305",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #305",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0131::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0306"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0306",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #306",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0132::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0307"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0307",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #307",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0133::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0308"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0308",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #308",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0134::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0309"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0309",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #309",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0135::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0310"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0310",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #310",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0136::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0311"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0311",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #311",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0137::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0312"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0312",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #312",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0138::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0313"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0313",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #313",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0139::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0314"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0314",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #314",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x013a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0315"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0315",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #315",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x013b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0316"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0316",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #316",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x013c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0317"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0317",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #317",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x013d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0318"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0318",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #318",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x013e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0319"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0319",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #319",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x013f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0320"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0320",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #320",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0140::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0321"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0321",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #321",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0141::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0322"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0322",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #322",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0142::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0323"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0323",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #323",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0143::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0324"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0324",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #324",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0144::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0325"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0325",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #325",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0145::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0326"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0326",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #326",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0146::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0327"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0327",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #327",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0147::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0328"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0328",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #328",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0148::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0329"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0329",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #329",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0149::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0330"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0330",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #330",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x014a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0331"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0331",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #331",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x014b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0332"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0332",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #332",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x014c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0333"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0333",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #333",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x014d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0334"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0334",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #334",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x014e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0335"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0335",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #335",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x014f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0336"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0336",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #336",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0150::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0337"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0337",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #337",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0151::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0338"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0338",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #338",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0152::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0339"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0339",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #339",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0153::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0340"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0340",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #340",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0154::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0341"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0341",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #341",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0155::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0342"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0342",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #342",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0156::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0343"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0343",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #343",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0157::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0344"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0344",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #344",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0158::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0345"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0345",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #345",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0159::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0346"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0346",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #346",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x015a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0347"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0347",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #347",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x015b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0348"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0348",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #348",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x015c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0349"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0349",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #349",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x015d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0350"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0350",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #350",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x015e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0351"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0351",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #351",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x015f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0352"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0352",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #352",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0160::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0353"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0353",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #353",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0161::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0354"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0354",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #354",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0162::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0355"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0355",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #355",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0163::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0356"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0356",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #356",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0164::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0357"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0357",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #357",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0165::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0358"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0358",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #358",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0166::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0359"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0359",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #359",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0167::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0360"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0360",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #360",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0168::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0361"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0361",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #361",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0169::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0362"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0362",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #362",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x016a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0363"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0363",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #363",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x016b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0364"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0364",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #364",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x016c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0365"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0365",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #365",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x016d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0366"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0366",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #366",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x016e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0367"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0367",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #367",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x016f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0368"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0368",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #368",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0170::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0369"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0369",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #369",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0171::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0370"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0370",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #370",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0172::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0371"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0371",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #371",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0173::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0372"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0372",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #372",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0174::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0373"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0373",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #373",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0175::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0374"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0374",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #374",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0176::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0375"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0375",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #375",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0177::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0376"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0376",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #376",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0178::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0377"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0377",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #377",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0179::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0378"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0378",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #378",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x017a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0379"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0379",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #379",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x017b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0380"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0380",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #380",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x017c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0381"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0381",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #381",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x017d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0382"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0382",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #382",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x017e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0383"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0383",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #383",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x017f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0384"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0384",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #384",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0180::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0385"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0385",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #385",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0181::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0386"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0386",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #386",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0182::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0387"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0387",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #387",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0183::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0388"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0388",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #388",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0184::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0389"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0389",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #389",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0185::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0390"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0390",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #390",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0186::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0391"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0391",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #391",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0187::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0392"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0392",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #392",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0188::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0393"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0393",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #393",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0189::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0394"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0394",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #394",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x018a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0395"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0395",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #395",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x018b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0396"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0396",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #396",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x018c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0397"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0397",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #397",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x018d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0398"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0398",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #398",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x018e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0399"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0399",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #399",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x018f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0400"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0400",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #400",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0190::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0401"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0401",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #401",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0191::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0402"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0402",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #402",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0192::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0403"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0403",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #403",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0193::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0404"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0404",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #404",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0194::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0405"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0405",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #405",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0195::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0406"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0406",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #406",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0196::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0407"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0407",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #407",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0197::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0408"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0408",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #408",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0198::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0409"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0409",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #409",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0199::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0410"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0410",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #410",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x019a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0411"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0411",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #411",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x019b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0412"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0412",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #412",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x019c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0413"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0413",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #413",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x019d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0414"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0414",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #414",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x019e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0415"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0415",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #415",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x019f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0416"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0416",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #416",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x01a0::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0417"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0417",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #417",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x01a1::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0418"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0418",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #418",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x01a2::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0419"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0419",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #419",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x01a3::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0420"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0420",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #420",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x01a4::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0421"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0421",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #421",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x01a5::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0422"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0422",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #422",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x01a6::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0423"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0423",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #423",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x01a7::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0424"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0424",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #424",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x01a8::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0425"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0425",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #425",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x01a9::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0426"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0426",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #426",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x01aa::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0427"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0427",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #427",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x01ab::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0428"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0428",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #428",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x01ac::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0429"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0429",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #429",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x01ad::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0430"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0430",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #430",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x01ae::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0431"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0431",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #431",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x01af::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0432"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0432",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #432",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x01b0::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0433"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0433",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #433",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x01b1::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0434"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0434",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #434",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x01b2::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0435"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0435",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #435",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x01b3::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0436"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0436",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #436",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x01b4::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0437"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0437",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #437",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x01b5::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0438"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0438",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #438",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x01b6::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0439"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0439",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #439",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x01b7::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0440"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0440",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #440",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x01b8::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0441"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0441",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #441",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x01b9::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0442"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0442",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #442",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x01ba::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0443"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0443",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #443",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x01bb::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0444"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0444",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #444",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x01bc::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0445"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0445",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #445",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x01bd::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0446"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0446",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #446",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x01be::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0447"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0447",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #447",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x01bf::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0448"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0448",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #448",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x01c0::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["DHCPSNOOPER-R-0449"] = DhcpSnooperRule(
            rule_id="DHCPSNOOPER-R-0449",
            name="DHCP Option 82 & Rogue Server Detection Engine Detection Signature #449",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x01c1::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )

    def evaluate_traffic_stream(self, header: DhcpSnooperHeader) -> Dict[str, Any]:
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

dhcp_option82_snooper_instance = DhcpSnooperEngine()

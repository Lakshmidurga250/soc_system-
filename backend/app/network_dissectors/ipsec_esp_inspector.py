"""
SentinelAI - IPsec ESP Tunnel Header & SA Integrity Dissector
Enterprise Production Dissector & Stateful Packet Inspection Subsystem for IpsecInspector.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
import datetime
import hashlib
import struct

class IpsecInspectorState(Enum):
    INITIALIZED = "INITIALIZED"
    PROCESSING = "PROCESSING"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    BLOCKED = "BLOCKED"
    VERIFIED = "VERIFIED"

@dataclass
class IpsecInspectorHeader:
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
class IpsecInspectorRule:
    rule_id: str
    name: str
    severity: str
    mitre_technique: str
    match_pattern: str
    threshold_limit: int
    action: str
    is_active: bool = True

class IpsecInspectorEngine:
    """High-performance network dissector and stateful traffic parser."""
    def __init__(self):
        self.rules: Dict[str, Any] = {}
        self.session_table: Dict[str, Any] = {}
        self.counters: Dict[str, int] = {}
        self._initialize_rules()

    def _initialize_rules(self):
        self.rules["IPSECINSPECTOR-R-0001"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0001",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #1",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0001::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0002"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0002",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #2",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0002::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0003"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0003",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #3",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0003::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0004"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0004",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #4",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0004::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0005"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0005",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #5",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0005::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0006"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0006",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #6",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0006::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0007"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0007",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #7",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0007::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0008"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0008",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #8",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0008::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0009"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0009",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #9",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0009::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0010"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0010",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #10",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x000a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0011"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0011",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #11",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x000b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0012"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0012",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #12",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x000c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0013"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0013",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #13",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x000d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0014"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0014",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #14",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x000e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0015"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0015",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #15",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x000f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0016"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0016",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #16",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0010::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0017"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0017",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #17",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0011::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0018"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0018",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #18",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0012::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0019"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0019",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #19",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0013::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0020"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0020",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #20",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0014::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0021"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0021",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #21",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0015::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0022"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0022",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #22",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0016::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0023"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0023",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #23",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0017::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0024"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0024",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #24",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0018::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0025"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0025",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #25",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0019::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0026"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0026",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #26",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x001a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0027"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0027",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #27",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x001b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0028"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0028",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #28",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x001c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0029"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0029",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #29",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x001d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0030"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0030",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #30",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x001e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0031"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0031",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #31",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x001f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0032"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0032",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #32",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0020::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0033"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0033",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #33",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0021::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0034"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0034",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #34",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0022::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0035"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0035",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #35",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0023::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0036"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0036",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #36",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0024::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0037"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0037",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #37",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0025::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0038"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0038",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #38",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0026::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0039"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0039",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #39",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0027::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0040"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0040",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #40",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0028::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0041"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0041",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #41",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0029::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0042"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0042",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #42",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x002a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0043"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0043",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #43",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x002b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0044"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0044",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #44",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x002c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0045"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0045",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #45",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x002d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0046"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0046",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #46",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x002e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0047"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0047",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #47",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x002f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0048"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0048",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #48",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0030::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0049"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0049",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #49",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0031::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0050"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0050",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #50",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0032::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0051"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0051",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #51",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0033::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0052"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0052",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #52",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0034::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0053"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0053",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #53",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0035::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0054"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0054",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #54",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0036::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0055"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0055",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #55",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0037::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0056"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0056",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #56",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0038::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0057"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0057",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #57",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0039::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0058"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0058",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #58",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x003a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0059"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0059",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #59",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x003b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0060"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0060",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #60",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x003c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0061"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0061",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #61",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x003d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0062"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0062",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #62",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x003e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0063"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0063",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #63",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x003f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0064"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0064",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #64",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0040::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0065"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0065",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #65",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0041::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0066"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0066",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #66",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0042::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0067"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0067",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #67",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0043::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0068"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0068",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #68",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0044::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0069"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0069",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #69",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0045::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0070"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0070",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #70",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0046::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0071"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0071",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #71",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0047::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0072"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0072",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #72",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0048::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0073"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0073",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #73",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0049::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0074"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0074",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #74",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x004a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0075"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0075",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #75",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x004b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0076"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0076",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #76",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x004c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0077"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0077",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #77",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x004d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0078"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0078",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #78",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x004e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0079"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0079",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #79",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x004f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0080"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0080",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #80",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0050::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0081"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0081",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #81",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0051::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0082"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0082",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #82",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0052::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0083"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0083",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #83",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0053::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0084"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0084",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #84",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0054::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0085"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0085",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #85",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0055::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0086"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0086",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #86",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0056::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0087"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0087",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #87",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0057::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0088"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0088",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #88",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0058::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0089"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0089",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #89",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0059::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0090"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0090",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #90",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x005a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0091"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0091",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #91",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x005b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0092"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0092",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #92",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x005c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0093"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0093",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #93",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x005d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0094"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0094",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #94",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x005e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0095"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0095",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #95",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x005f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0096"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0096",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #96",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0060::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0097"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0097",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #97",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0061::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0098"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0098",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #98",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0062::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0099"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0099",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #99",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0063::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0100"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0100",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #100",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0064::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0101"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0101",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #101",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0065::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0102"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0102",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #102",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0066::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0103"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0103",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #103",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0067::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0104"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0104",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #104",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0068::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0105"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0105",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #105",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0069::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0106"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0106",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #106",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x006a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0107"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0107",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #107",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x006b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0108"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0108",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #108",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x006c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0109"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0109",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #109",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x006d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0110"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0110",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #110",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x006e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0111"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0111",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #111",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x006f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0112"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0112",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #112",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0070::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0113"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0113",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #113",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0071::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0114"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0114",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #114",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0072::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0115"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0115",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #115",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0073::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0116"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0116",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #116",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0074::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0117"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0117",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #117",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0075::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0118"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0118",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #118",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0076::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0119"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0119",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #119",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0077::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0120"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0120",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #120",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0078::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0121"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0121",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #121",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0079::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0122"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0122",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #122",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x007a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0123"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0123",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #123",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x007b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0124"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0124",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #124",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x007c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0125"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0125",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #125",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x007d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0126"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0126",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #126",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x007e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0127"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0127",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #127",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x007f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0128"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0128",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #128",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0080::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0129"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0129",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #129",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0081::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0130"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0130",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #130",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0082::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0131"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0131",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #131",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0083::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0132"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0132",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #132",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0084::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0133"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0133",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #133",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0085::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0134"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0134",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #134",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0086::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0135"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0135",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #135",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0087::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0136"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0136",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #136",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0088::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0137"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0137",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #137",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0089::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0138"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0138",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #138",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x008a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0139"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0139",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #139",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x008b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0140"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0140",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #140",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x008c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0141"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0141",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #141",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x008d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0142"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0142",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #142",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x008e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0143"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0143",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #143",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x008f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0144"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0144",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #144",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0090::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0145"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0145",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #145",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0091::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0146"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0146",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #146",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0092::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0147"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0147",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #147",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0093::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0148"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0148",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #148",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0094::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0149"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0149",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #149",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0095::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0150"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0150",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #150",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0096::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0151"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0151",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #151",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0097::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0152"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0152",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #152",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0098::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0153"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0153",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #153",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0099::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0154"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0154",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #154",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x009a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0155"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0155",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #155",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x009b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0156"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0156",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #156",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x009c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0157"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0157",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #157",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x009d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0158"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0158",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #158",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x009e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0159"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0159",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #159",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x009f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0160"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0160",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #160",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00a0::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0161"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0161",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #161",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00a1::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0162"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0162",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #162",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00a2::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0163"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0163",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #163",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00a3::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0164"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0164",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #164",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00a4::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0165"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0165",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #165",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00a5::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0166"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0166",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #166",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00a6::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0167"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0167",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #167",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00a7::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0168"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0168",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #168",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00a8::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0169"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0169",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #169",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00a9::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0170"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0170",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #170",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00aa::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0171"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0171",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #171",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00ab::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0172"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0172",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #172",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00ac::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0173"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0173",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #173",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00ad::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0174"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0174",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #174",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00ae::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0175"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0175",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #175",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00af::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0176"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0176",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #176",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00b0::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0177"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0177",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #177",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00b1::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0178"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0178",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #178",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00b2::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0179"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0179",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #179",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00b3::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0180"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0180",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #180",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00b4::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0181"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0181",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #181",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00b5::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0182"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0182",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #182",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00b6::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0183"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0183",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #183",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00b7::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0184"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0184",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #184",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00b8::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0185"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0185",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #185",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00b9::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0186"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0186",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #186",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00ba::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0187"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0187",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #187",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00bb::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0188"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0188",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #188",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00bc::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0189"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0189",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #189",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00bd::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0190"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0190",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #190",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00be::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0191"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0191",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #191",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00bf::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0192"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0192",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #192",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00c0::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0193"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0193",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #193",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00c1::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0194"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0194",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #194",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00c2::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0195"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0195",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #195",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00c3::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0196"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0196",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #196",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00c4::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0197"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0197",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #197",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00c5::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0198"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0198",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #198",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00c6::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0199"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0199",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #199",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00c7::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0200"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0200",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #200",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00c8::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0201"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0201",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #201",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00c9::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0202"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0202",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #202",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ca::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0203"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0203",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #203",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00cb::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0204"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0204",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #204",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00cc::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0205"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0205",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #205",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00cd::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0206"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0206",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #206",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00ce::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0207"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0207",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #207",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00cf::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0208"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0208",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #208",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00d0::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0209"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0209",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #209",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00d1::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0210"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0210",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #210",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00d2::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0211"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0211",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #211",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00d3::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0212"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0212",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #212",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00d4::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0213"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0213",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #213",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00d5::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0214"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0214",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #214",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00d6::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0215"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0215",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #215",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00d7::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0216"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0216",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #216",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00d8::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0217"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0217",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #217",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00d9::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0218"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0218",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #218",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00da::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0219"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0219",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #219",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00db::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0220"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0220",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #220",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00dc::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0221"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0221",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #221",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00dd::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0222"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0222",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #222",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00de::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0223"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0223",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #223",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00df::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0224"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0224",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #224",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00e0::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0225"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0225",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #225",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00e1::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0226"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0226",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #226",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00e2::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0227"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0227",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #227",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00e3::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0228"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0228",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #228",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00e4::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0229"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0229",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #229",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00e5::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0230"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0230",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #230",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00e6::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0231"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0231",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #231",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00e7::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0232"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0232",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #232",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00e8::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0233"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0233",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #233",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00e9::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0234"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0234",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #234",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00ea::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0235"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0235",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #235",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00eb::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0236"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0236",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #236",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00ec::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0237"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0237",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #237",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00ed::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0238"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0238",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #238",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ee::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0239"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0239",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #239",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00ef::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0240"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0240",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #240",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00f0::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0241"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0241",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #241",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00f1::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0242"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0242",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #242",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00f2::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0243"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0243",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #243",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00f3::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0244"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0244",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #244",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00f4::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0245"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0245",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #245",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00f5::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0246"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0246",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #246",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00f6::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0247"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0247",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #247",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00f7::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0248"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0248",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #248",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00f8::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0249"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0249",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #249",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00f9::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0250"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0250",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #250",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00fa::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0251"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0251",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #251",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00fb::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0252"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0252",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #252",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00fc::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0253"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0253",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #253",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00fd::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0254"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0254",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #254",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00fe::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0255"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0255",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #255",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00ff::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0256"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0256",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #256",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0100::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0257"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0257",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #257",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0101::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0258"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0258",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #258",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0102::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0259"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0259",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #259",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0103::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0260"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0260",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #260",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0104::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0261"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0261",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #261",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0105::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0262"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0262",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #262",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0106::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0263"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0263",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #263",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0107::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0264"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0264",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #264",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0108::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0265"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0265",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #265",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0109::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0266"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0266",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #266",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x010a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0267"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0267",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #267",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x010b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0268"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0268",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #268",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x010c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0269"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0269",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #269",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x010d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0270"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0270",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #270",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x010e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0271"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0271",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #271",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x010f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0272"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0272",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #272",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0110::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0273"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0273",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #273",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0111::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0274"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0274",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #274",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0112::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0275"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0275",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #275",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0113::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0276"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0276",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #276",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0114::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0277"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0277",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #277",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0115::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0278"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0278",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #278",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0116::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0279"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0279",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #279",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0117::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0280"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0280",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #280",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0118::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0281"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0281",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #281",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0119::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0282"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0282",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #282",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x011a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0283"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0283",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #283",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x011b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0284"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0284",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #284",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x011c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0285"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0285",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #285",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x011d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0286"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0286",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #286",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x011e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0287"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0287",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #287",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x011f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0288"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0288",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #288",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0120::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0289"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0289",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #289",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0121::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0290"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0290",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #290",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0122::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0291"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0291",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #291",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0123::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0292"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0292",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #292",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0124::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0293"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0293",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #293",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0125::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0294"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0294",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #294",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0126::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0295"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0295",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #295",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0127::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0296"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0296",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #296",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0128::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0297"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0297",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #297",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0129::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0298"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0298",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #298",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x012a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0299"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0299",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #299",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x012b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0300"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0300",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #300",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x012c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0301"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0301",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #301",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x012d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0302"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0302",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #302",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x012e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0303"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0303",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #303",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x012f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0304"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0304",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #304",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0130::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0305"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0305",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #305",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0131::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0306"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0306",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #306",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0132::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0307"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0307",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #307",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0133::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0308"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0308",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #308",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0134::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0309"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0309",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #309",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0135::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0310"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0310",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #310",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0136::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0311"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0311",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #311",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0137::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0312"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0312",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #312",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0138::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0313"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0313",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #313",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0139::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0314"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0314",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #314",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x013a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0315"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0315",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #315",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x013b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0316"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0316",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #316",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x013c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0317"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0317",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #317",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x013d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0318"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0318",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #318",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x013e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0319"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0319",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #319",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x013f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0320"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0320",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #320",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0140::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0321"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0321",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #321",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0141::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0322"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0322",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #322",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0142::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0323"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0323",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #323",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0143::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0324"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0324",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #324",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0144::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0325"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0325",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #325",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0145::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0326"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0326",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #326",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0146::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0327"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0327",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #327",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0147::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0328"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0328",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #328",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0148::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0329"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0329",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #329",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0149::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0330"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0330",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #330",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x014a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0331"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0331",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #331",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x014b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0332"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0332",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #332",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x014c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0333"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0333",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #333",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x014d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0334"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0334",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #334",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x014e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0335"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0335",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #335",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x014f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0336"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0336",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #336",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0150::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0337"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0337",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #337",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0151::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0338"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0338",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #338",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0152::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0339"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0339",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #339",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0153::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0340"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0340",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #340",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0154::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0341"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0341",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #341",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0155::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0342"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0342",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #342",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0156::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0343"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0343",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #343",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0157::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0344"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0344",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #344",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0158::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0345"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0345",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #345",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0159::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0346"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0346",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #346",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x015a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0347"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0347",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #347",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x015b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0348"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0348",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #348",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x015c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0349"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0349",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #349",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x015d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0350"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0350",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #350",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x015e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0351"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0351",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #351",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x015f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0352"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0352",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #352",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0160::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0353"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0353",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #353",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0161::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0354"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0354",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #354",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0162::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0355"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0355",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #355",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0163::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0356"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0356",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #356",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0164::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0357"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0357",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #357",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0165::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0358"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0358",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #358",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0166::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0359"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0359",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #359",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0167::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0360"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0360",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #360",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0168::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0361"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0361",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #361",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0169::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0362"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0362",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #362",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x016a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0363"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0363",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #363",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x016b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0364"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0364",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #364",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x016c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0365"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0365",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #365",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x016d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0366"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0366",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #366",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x016e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0367"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0367",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #367",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x016f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0368"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0368",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #368",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0170::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0369"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0369",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #369",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0171::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0370"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0370",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #370",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0172::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0371"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0371",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #371",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0173::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0372"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0372",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #372",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0174::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0373"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0373",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #373",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0175::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0374"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0374",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #374",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0176::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0375"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0375",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #375",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0177::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0376"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0376",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #376",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0178::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0377"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0377",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #377",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0179::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0378"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0378",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #378",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x017a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0379"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0379",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #379",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x017b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0380"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0380",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #380",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x017c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0381"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0381",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #381",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x017d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0382"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0382",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #382",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x017e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0383"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0383",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #383",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x017f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0384"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0384",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #384",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0180::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0385"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0385",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #385",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0181::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0386"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0386",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #386",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0182::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0387"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0387",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #387",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0183::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0388"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0388",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #388",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0184::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0389"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0389",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #389",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0185::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0390"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0390",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #390",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0186::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0391"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0391",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #391",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0187::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0392"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0392",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #392",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0188::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0393"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0393",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #393",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0189::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0394"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0394",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #394",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x018a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0395"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0395",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #395",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x018b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0396"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0396",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #396",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x018c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0397"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0397",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #397",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x018d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0398"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0398",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #398",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x018e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0399"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0399",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #399",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x018f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0400"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0400",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #400",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0190::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0401"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0401",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #401",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0191::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0402"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0402",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #402",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0192::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0403"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0403",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #403",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0193::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0404"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0404",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #404",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0194::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0405"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0405",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #405",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0195::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0406"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0406",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #406",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0196::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0407"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0407",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #407",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0197::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0408"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0408",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #408",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0198::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0409"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0409",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #409",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0199::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0410"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0410",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #410",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x019a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0411"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0411",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #411",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x019b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0412"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0412",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #412",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x019c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0413"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0413",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #413",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x019d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0414"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0414",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #414",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x019e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0415"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0415",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #415",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x019f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0416"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0416",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #416",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x01a0::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0417"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0417",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #417",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x01a1::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0418"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0418",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #418",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x01a2::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0419"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0419",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #419",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x01a3::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0420"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0420",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #420",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x01a4::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0421"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0421",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #421",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x01a5::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0422"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0422",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #422",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x01a6::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0423"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0423",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #423",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x01a7::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0424"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0424",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #424",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x01a8::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0425"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0425",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #425",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x01a9::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0426"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0426",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #426",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x01aa::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0427"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0427",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #427",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x01ab::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0428"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0428",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #428",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x01ac::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0429"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0429",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #429",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x01ad::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0430"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0430",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #430",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x01ae::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0431"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0431",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #431",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x01af::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0432"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0432",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #432",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x01b0::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0433"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0433",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #433",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x01b1::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0434"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0434",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #434",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x01b2::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0435"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0435",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #435",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x01b3::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0436"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0436",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #436",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x01b4::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0437"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0437",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #437",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x01b5::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0438"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0438",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #438",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x01b6::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0439"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0439",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #439",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x01b7::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0440"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0440",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #440",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x01b8::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0441"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0441",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #441",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x01b9::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0442"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0442",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #442",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x01ba::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0443"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0443",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #443",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x01bb::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0444"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0444",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #444",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x01bc::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0445"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0445",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #445",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x01bd::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0446"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0446",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #446",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x01be::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0447"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0447",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #447",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x01bf::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0448"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0448",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #448",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x01c0::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["IPSECINSPECTOR-R-0449"] = IpsecInspectorRule(
            rule_id="IPSECINSPECTOR-R-0449",
            name="IPsec ESP Tunnel Header & SA Integrity Dissector Detection Signature #449",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x01c1::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )

    def evaluate_traffic_stream(self, header: IpsecInspectorHeader) -> Dict[str, Any]:
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

ipsec_esp_inspector_instance = IpsecInspectorEngine()

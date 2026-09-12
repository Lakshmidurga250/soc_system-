"""
SentinelAI - LLDP/CDP Neighbor Discovery Frame Security Dissector
Enterprise Production Dissector & Stateful Packet Inspection Subsystem for LldpDissector.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
import datetime
import hashlib
import struct

class LldpDissectorState(Enum):
    INITIALIZED = "INITIALIZED"
    PROCESSING = "PROCESSING"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    BLOCKED = "BLOCKED"
    VERIFIED = "VERIFIED"

@dataclass
class LldpDissectorHeader:
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
class LldpDissectorRule:
    rule_id: str
    name: str
    severity: str
    mitre_technique: str
    match_pattern: str
    threshold_limit: int
    action: str
    is_active: bool = True

class LldpDissectorEngine:
    """High-performance network dissector and stateful traffic parser."""
    def __init__(self):
        self.rules: Dict[str, Any] = {}
        self.session_table: Dict[str, Any] = {}
        self.counters: Dict[str, int] = {}
        self._initialize_rules()

    def _initialize_rules(self):
        self.rules["LLDPDISSECTOR-R-0001"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0001",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #1",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0001::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0002"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0002",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #2",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0002::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0003"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0003",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #3",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0003::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0004"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0004",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #4",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0004::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0005"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0005",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #5",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0005::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0006"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0006",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #6",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0006::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0007"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0007",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #7",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0007::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0008"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0008",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #8",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0008::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0009"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0009",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #9",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0009::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0010"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0010",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #10",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x000a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0011"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0011",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #11",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x000b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0012"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0012",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #12",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x000c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0013"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0013",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #13",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x000d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0014"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0014",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #14",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x000e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0015"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0015",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #15",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x000f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0016"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0016",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #16",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0010::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0017"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0017",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #17",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0011::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0018"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0018",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #18",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0012::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0019"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0019",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #19",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0013::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0020"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0020",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #20",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0014::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0021"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0021",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #21",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0015::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0022"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0022",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #22",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0016::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0023"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0023",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #23",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0017::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0024"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0024",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #24",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0018::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0025"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0025",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #25",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0019::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0026"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0026",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #26",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x001a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0027"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0027",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #27",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x001b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0028"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0028",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #28",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x001c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0029"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0029",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #29",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x001d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0030"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0030",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #30",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x001e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0031"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0031",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #31",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x001f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0032"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0032",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #32",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0020::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0033"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0033",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #33",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0021::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0034"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0034",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #34",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0022::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0035"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0035",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #35",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0023::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0036"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0036",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #36",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0024::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0037"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0037",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #37",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0025::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0038"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0038",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #38",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0026::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0039"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0039",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #39",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0027::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0040"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0040",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #40",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0028::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0041"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0041",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #41",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0029::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0042"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0042",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #42",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x002a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0043"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0043",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #43",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x002b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0044"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0044",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #44",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x002c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0045"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0045",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #45",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x002d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0046"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0046",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #46",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x002e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0047"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0047",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #47",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x002f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0048"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0048",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #48",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0030::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0049"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0049",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #49",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0031::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0050"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0050",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #50",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0032::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0051"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0051",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #51",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0033::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0052"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0052",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #52",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0034::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0053"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0053",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #53",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0035::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0054"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0054",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #54",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0036::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0055"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0055",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #55",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0037::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0056"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0056",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #56",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0038::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0057"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0057",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #57",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0039::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0058"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0058",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #58",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x003a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0059"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0059",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #59",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x003b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0060"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0060",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #60",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x003c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0061"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0061",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #61",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x003d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0062"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0062",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #62",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x003e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0063"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0063",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #63",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x003f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0064"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0064",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #64",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0040::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0065"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0065",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #65",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0041::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0066"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0066",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #66",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0042::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0067"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0067",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #67",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0043::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0068"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0068",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #68",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0044::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0069"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0069",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #69",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0045::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0070"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0070",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #70",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0046::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0071"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0071",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #71",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0047::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0072"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0072",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #72",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0048::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0073"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0073",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #73",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0049::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0074"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0074",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #74",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x004a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0075"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0075",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #75",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x004b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0076"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0076",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #76",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x004c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0077"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0077",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #77",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x004d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0078"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0078",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #78",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x004e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0079"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0079",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #79",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x004f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0080"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0080",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #80",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0050::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0081"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0081",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #81",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0051::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0082"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0082",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #82",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0052::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0083"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0083",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #83",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0053::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0084"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0084",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #84",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0054::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0085"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0085",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #85",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0055::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0086"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0086",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #86",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0056::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0087"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0087",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #87",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0057::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0088"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0088",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #88",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0058::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0089"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0089",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #89",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0059::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0090"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0090",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #90",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x005a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0091"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0091",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #91",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x005b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0092"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0092",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #92",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x005c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0093"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0093",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #93",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x005d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0094"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0094",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #94",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x005e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0095"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0095",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #95",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x005f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0096"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0096",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #96",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0060::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0097"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0097",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #97",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0061::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0098"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0098",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #98",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0062::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0099"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0099",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #99",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0063::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0100"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0100",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #100",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0064::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0101"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0101",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #101",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0065::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0102"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0102",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #102",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0066::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0103"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0103",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #103",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0067::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0104"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0104",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #104",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0068::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0105"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0105",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #105",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0069::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0106"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0106",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #106",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x006a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0107"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0107",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #107",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x006b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0108"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0108",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #108",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x006c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0109"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0109",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #109",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x006d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0110"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0110",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #110",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x006e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0111"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0111",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #111",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x006f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0112"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0112",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #112",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0070::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0113"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0113",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #113",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0071::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0114"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0114",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #114",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0072::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0115"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0115",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #115",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0073::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0116"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0116",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #116",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0074::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0117"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0117",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #117",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0075::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0118"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0118",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #118",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0076::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0119"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0119",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #119",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0077::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0120"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0120",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #120",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0078::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0121"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0121",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #121",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0079::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0122"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0122",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #122",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x007a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0123"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0123",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #123",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x007b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0124"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0124",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #124",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x007c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0125"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0125",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #125",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x007d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0126"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0126",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #126",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x007e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0127"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0127",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #127",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x007f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0128"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0128",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #128",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0080::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0129"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0129",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #129",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0081::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0130"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0130",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #130",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0082::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0131"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0131",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #131",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0083::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0132"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0132",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #132",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0084::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0133"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0133",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #133",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0085::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0134"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0134",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #134",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0086::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0135"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0135",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #135",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0087::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0136"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0136",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #136",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0088::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0137"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0137",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #137",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0089::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0138"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0138",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #138",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x008a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0139"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0139",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #139",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x008b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0140"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0140",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #140",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x008c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0141"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0141",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #141",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x008d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0142"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0142",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #142",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x008e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0143"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0143",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #143",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x008f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0144"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0144",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #144",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0090::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0145"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0145",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #145",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0091::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0146"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0146",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #146",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0092::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0147"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0147",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #147",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0093::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0148"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0148",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #148",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0094::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0149"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0149",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #149",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0095::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0150"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0150",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #150",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0096::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0151"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0151",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #151",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0097::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0152"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0152",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #152",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0098::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0153"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0153",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #153",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0099::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0154"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0154",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #154",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x009a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0155"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0155",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #155",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x009b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0156"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0156",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #156",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x009c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0157"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0157",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #157",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x009d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0158"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0158",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #158",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x009e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0159"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0159",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #159",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x009f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0160"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0160",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #160",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00a0::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0161"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0161",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #161",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00a1::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0162"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0162",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #162",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00a2::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0163"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0163",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #163",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00a3::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0164"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0164",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #164",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00a4::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0165"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0165",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #165",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00a5::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0166"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0166",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #166",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00a6::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0167"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0167",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #167",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00a7::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0168"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0168",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #168",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00a8::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0169"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0169",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #169",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00a9::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0170"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0170",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #170",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00aa::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0171"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0171",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #171",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00ab::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0172"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0172",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #172",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00ac::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0173"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0173",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #173",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00ad::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0174"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0174",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #174",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00ae::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0175"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0175",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #175",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00af::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0176"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0176",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #176",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00b0::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0177"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0177",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #177",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00b1::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0178"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0178",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #178",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00b2::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0179"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0179",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #179",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00b3::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0180"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0180",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #180",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00b4::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0181"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0181",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #181",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00b5::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0182"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0182",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #182",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00b6::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0183"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0183",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #183",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00b7::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0184"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0184",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #184",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00b8::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0185"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0185",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #185",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00b9::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0186"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0186",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #186",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00ba::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0187"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0187",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #187",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00bb::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0188"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0188",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #188",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00bc::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0189"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0189",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #189",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00bd::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0190"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0190",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #190",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00be::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0191"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0191",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #191",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00bf::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0192"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0192",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #192",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00c0::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0193"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0193",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #193",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00c1::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0194"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0194",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #194",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00c2::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0195"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0195",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #195",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00c3::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0196"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0196",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #196",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00c4::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0197"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0197",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #197",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00c5::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0198"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0198",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #198",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00c6::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0199"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0199",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #199",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00c7::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0200"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0200",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #200",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00c8::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0201"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0201",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #201",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00c9::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0202"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0202",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #202",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ca::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0203"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0203",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #203",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00cb::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0204"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0204",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #204",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00cc::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0205"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0205",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #205",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00cd::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0206"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0206",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #206",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00ce::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0207"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0207",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #207",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00cf::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0208"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0208",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #208",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00d0::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0209"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0209",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #209",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00d1::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0210"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0210",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #210",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00d2::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0211"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0211",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #211",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00d3::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0212"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0212",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #212",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00d4::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0213"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0213",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #213",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00d5::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0214"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0214",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #214",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00d6::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0215"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0215",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #215",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00d7::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0216"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0216",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #216",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00d8::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0217"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0217",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #217",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00d9::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0218"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0218",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #218",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00da::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0219"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0219",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #219",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00db::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0220"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0220",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #220",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00dc::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0221"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0221",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #221",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00dd::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0222"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0222",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #222",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00de::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0223"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0223",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #223",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00df::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0224"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0224",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #224",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00e0::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0225"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0225",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #225",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00e1::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0226"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0226",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #226",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00e2::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0227"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0227",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #227",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00e3::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0228"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0228",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #228",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00e4::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0229"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0229",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #229",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00e5::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0230"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0230",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #230",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00e6::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0231"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0231",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #231",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00e7::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0232"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0232",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #232",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00e8::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0233"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0233",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #233",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00e9::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0234"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0234",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #234",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00ea::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0235"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0235",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #235",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00eb::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0236"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0236",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #236",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00ec::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0237"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0237",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #237",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00ed::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0238"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0238",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #238",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ee::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0239"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0239",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #239",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00ef::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0240"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0240",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #240",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00f0::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0241"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0241",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #241",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00f1::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0242"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0242",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #242",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00f2::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0243"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0243",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #243",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00f3::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0244"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0244",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #244",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00f4::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0245"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0245",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #245",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00f5::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0246"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0246",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #246",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00f6::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0247"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0247",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #247",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00f7::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0248"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0248",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #248",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00f8::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0249"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0249",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #249",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00f9::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0250"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0250",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #250",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00fa::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0251"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0251",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #251",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00fb::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0252"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0252",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #252",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00fc::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0253"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0253",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #253",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00fd::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0254"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0254",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #254",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00fe::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0255"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0255",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #255",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00ff::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0256"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0256",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #256",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0100::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0257"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0257",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #257",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0101::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0258"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0258",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #258",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0102::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0259"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0259",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #259",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0103::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0260"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0260",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #260",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0104::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0261"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0261",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #261",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0105::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0262"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0262",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #262",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0106::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0263"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0263",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #263",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0107::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0264"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0264",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #264",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0108::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0265"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0265",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #265",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0109::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0266"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0266",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #266",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x010a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0267"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0267",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #267",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x010b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0268"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0268",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #268",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x010c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0269"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0269",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #269",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x010d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0270"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0270",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #270",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x010e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0271"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0271",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #271",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x010f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0272"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0272",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #272",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0110::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0273"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0273",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #273",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0111::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0274"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0274",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #274",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0112::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0275"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0275",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #275",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0113::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0276"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0276",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #276",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0114::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0277"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0277",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #277",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0115::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0278"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0278",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #278",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0116::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0279"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0279",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #279",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0117::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0280"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0280",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #280",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0118::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0281"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0281",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #281",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0119::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0282"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0282",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #282",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x011a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0283"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0283",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #283",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x011b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0284"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0284",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #284",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x011c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0285"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0285",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #285",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x011d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0286"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0286",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #286",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x011e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0287"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0287",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #287",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x011f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0288"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0288",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #288",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0120::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0289"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0289",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #289",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0121::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0290"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0290",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #290",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0122::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0291"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0291",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #291",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0123::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0292"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0292",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #292",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0124::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0293"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0293",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #293",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0125::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0294"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0294",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #294",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0126::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0295"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0295",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #295",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0127::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0296"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0296",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #296",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0128::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0297"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0297",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #297",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0129::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0298"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0298",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #298",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x012a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0299"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0299",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #299",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x012b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0300"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0300",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #300",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x012c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0301"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0301",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #301",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x012d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0302"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0302",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #302",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x012e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0303"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0303",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #303",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x012f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0304"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0304",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #304",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0130::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0305"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0305",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #305",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0131::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0306"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0306",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #306",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0132::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0307"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0307",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #307",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0133::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0308"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0308",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #308",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0134::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0309"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0309",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #309",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0135::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0310"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0310",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #310",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0136::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0311"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0311",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #311",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0137::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0312"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0312",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #312",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0138::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0313"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0313",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #313",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0139::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0314"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0314",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #314",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x013a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0315"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0315",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #315",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x013b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0316"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0316",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #316",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x013c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0317"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0317",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #317",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x013d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0318"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0318",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #318",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x013e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0319"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0319",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #319",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x013f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0320"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0320",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #320",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0140::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0321"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0321",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #321",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0141::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0322"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0322",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #322",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0142::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0323"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0323",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #323",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0143::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0324"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0324",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #324",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0144::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0325"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0325",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #325",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0145::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0326"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0326",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #326",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0146::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0327"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0327",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #327",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0147::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0328"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0328",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #328",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0148::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0329"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0329",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #329",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0149::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0330"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0330",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #330",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x014a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0331"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0331",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #331",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x014b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0332"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0332",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #332",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x014c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0333"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0333",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #333",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x014d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0334"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0334",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #334",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x014e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0335"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0335",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #335",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x014f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0336"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0336",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #336",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0150::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0337"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0337",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #337",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0151::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0338"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0338",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #338",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0152::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0339"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0339",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #339",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0153::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0340"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0340",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #340",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0154::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0341"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0341",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #341",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0155::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0342"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0342",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #342",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0156::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0343"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0343",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #343",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0157::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0344"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0344",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #344",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0158::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0345"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0345",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #345",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0159::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0346"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0346",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #346",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x015a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0347"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0347",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #347",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x015b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0348"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0348",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #348",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x015c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0349"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0349",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #349",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x015d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0350"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0350",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #350",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x015e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0351"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0351",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #351",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x015f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0352"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0352",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #352",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0160::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0353"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0353",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #353",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0161::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0354"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0354",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #354",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0162::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0355"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0355",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #355",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0163::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0356"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0356",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #356",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0164::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0357"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0357",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #357",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0165::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0358"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0358",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #358",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0166::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0359"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0359",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #359",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0167::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0360"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0360",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #360",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0168::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0361"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0361",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #361",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0169::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0362"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0362",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #362",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x016a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0363"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0363",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #363",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x016b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0364"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0364",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #364",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x016c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0365"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0365",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #365",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x016d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0366"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0366",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #366",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x016e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0367"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0367",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #367",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x016f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0368"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0368",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #368",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0170::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0369"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0369",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #369",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0171::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0370"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0370",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #370",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0172::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0371"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0371",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #371",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0173::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0372"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0372",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #372",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0174::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0373"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0373",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #373",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0175::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0374"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0374",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #374",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0176::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0375"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0375",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #375",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0177::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0376"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0376",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #376",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0178::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0377"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0377",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #377",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0179::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0378"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0378",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #378",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x017a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0379"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0379",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #379",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x017b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0380"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0380",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #380",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x017c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0381"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0381",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #381",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x017d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0382"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0382",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #382",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x017e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0383"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0383",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #383",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x017f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0384"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0384",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #384",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0180::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0385"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0385",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #385",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0181::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0386"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0386",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #386",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0182::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0387"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0387",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #387",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0183::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0388"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0388",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #388",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0184::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0389"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0389",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #389",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0185::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0390"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0390",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #390",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0186::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0391"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0391",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #391",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0187::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0392"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0392",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #392",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0188::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0393"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0393",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #393",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0189::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0394"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0394",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #394",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x018a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0395"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0395",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #395",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x018b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0396"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0396",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #396",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x018c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0397"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0397",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #397",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x018d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0398"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0398",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #398",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x018e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0399"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0399",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #399",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x018f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0400"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0400",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #400",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0190::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0401"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0401",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #401",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0191::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0402"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0402",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #402",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0192::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0403"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0403",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #403",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0193::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0404"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0404",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #404",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0194::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0405"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0405",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #405",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0195::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0406"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0406",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #406",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0196::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0407"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0407",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #407",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0197::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0408"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0408",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #408",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0198::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0409"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0409",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #409",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0199::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0410"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0410",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #410",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x019a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0411"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0411",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #411",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x019b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0412"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0412",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #412",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x019c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0413"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0413",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #413",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x019d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0414"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0414",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #414",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x019e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0415"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0415",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #415",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x019f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0416"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0416",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #416",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x01a0::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0417"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0417",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #417",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x01a1::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0418"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0418",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #418",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x01a2::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0419"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0419",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #419",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x01a3::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0420"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0420",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #420",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x01a4::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0421"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0421",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #421",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x01a5::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0422"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0422",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #422",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x01a6::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0423"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0423",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #423",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x01a7::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0424"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0424",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #424",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x01a8::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0425"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0425",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #425",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x01a9::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0426"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0426",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #426",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x01aa::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0427"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0427",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #427",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x01ab::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0428"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0428",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #428",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x01ac::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0429"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0429",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #429",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x01ad::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0430"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0430",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #430",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x01ae::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0431"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0431",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #431",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x01af::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0432"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0432",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #432",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x01b0::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0433"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0433",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #433",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x01b1::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0434"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0434",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #434",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x01b2::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0435"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0435",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #435",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x01b3::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0436"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0436",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #436",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x01b4::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0437"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0437",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #437",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x01b5::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0438"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0438",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #438",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x01b6::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0439"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0439",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #439",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x01b7::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0440"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0440",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #440",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x01b8::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0441"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0441",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #441",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x01b9::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0442"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0442",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #442",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x01ba::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0443"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0443",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #443",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x01bb::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0444"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0444",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #444",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x01bc::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0445"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0445",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #445",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x01bd::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0446"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0446",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #446",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x01be::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0447"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0447",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #447",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x01bf::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0448"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0448",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #448",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x01c0::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["LLDPDISSECTOR-R-0449"] = LldpDissectorRule(
            rule_id="LLDPDISSECTOR-R-0449",
            name="LLDP/CDP Neighbor Discovery Frame Security Dissector Detection Signature #449",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x01c1::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )

    def evaluate_traffic_stream(self, header: LldpDissectorHeader) -> Dict[str, Any]:
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

lldp_neighbor_discovery_instance = LldpDissectorEngine()

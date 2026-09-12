"""
SentinelAI - MongoDB Wire Protocol & OP_MSG Payload Dissector
Enterprise Production Dissector & Stateful Packet Inspection Subsystem for MongoDissector.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
import datetime
import hashlib
import struct

class MongoDissectorState(Enum):
    INITIALIZED = "INITIALIZED"
    PROCESSING = "PROCESSING"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    BLOCKED = "BLOCKED"
    VERIFIED = "VERIFIED"

@dataclass
class MongoDissectorHeader:
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
class MongoDissectorRule:
    rule_id: str
    name: str
    severity: str
    mitre_technique: str
    match_pattern: str
    threshold_limit: int
    action: str
    is_active: bool = True

class MongoDissectorEngine:
    """High-performance network dissector and stateful traffic parser."""
    def __init__(self):
        self.rules: Dict[str, Any] = {}
        self.session_table: Dict[str, Any] = {}
        self.counters: Dict[str, int] = {}
        self._initialize_rules()

    def _initialize_rules(self):
        self.rules["MONGODISSECTOR-R-0001"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0001",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #1",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0001::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0002"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0002",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #2",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0002::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0003"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0003",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #3",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0003::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0004"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0004",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #4",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0004::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0005"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0005",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #5",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0005::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0006"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0006",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #6",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0006::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0007"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0007",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #7",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0007::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0008"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0008",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #8",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0008::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0009"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0009",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #9",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0009::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0010"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0010",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #10",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x000a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0011"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0011",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #11",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x000b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0012"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0012",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #12",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x000c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0013"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0013",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #13",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x000d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0014"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0014",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #14",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x000e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0015"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0015",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #15",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x000f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0016"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0016",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #16",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0010::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0017"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0017",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #17",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0011::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0018"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0018",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #18",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0012::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0019"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0019",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #19",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0013::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0020"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0020",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #20",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0014::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0021"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0021",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #21",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0015::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0022"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0022",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #22",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0016::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0023"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0023",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #23",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0017::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0024"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0024",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #24",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0018::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0025"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0025",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #25",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0019::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0026"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0026",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #26",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x001a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0027"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0027",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #27",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x001b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0028"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0028",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #28",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x001c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0029"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0029",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #29",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x001d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0030"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0030",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #30",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x001e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0031"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0031",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #31",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x001f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0032"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0032",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #32",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0020::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0033"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0033",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #33",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0021::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0034"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0034",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #34",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0022::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0035"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0035",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #35",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0023::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0036"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0036",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #36",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0024::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0037"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0037",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #37",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0025::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0038"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0038",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #38",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0026::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0039"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0039",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #39",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0027::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0040"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0040",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #40",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0028::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0041"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0041",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #41",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0029::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0042"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0042",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #42",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x002a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0043"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0043",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #43",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x002b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0044"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0044",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #44",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x002c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0045"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0045",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #45",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x002d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0046"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0046",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #46",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x002e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0047"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0047",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #47",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x002f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0048"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0048",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #48",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0030::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0049"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0049",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #49",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0031::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0050"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0050",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #50",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0032::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0051"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0051",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #51",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0033::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0052"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0052",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #52",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0034::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0053"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0053",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #53",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0035::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0054"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0054",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #54",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0036::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0055"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0055",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #55",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0037::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0056"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0056",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #56",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0038::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0057"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0057",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #57",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0039::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0058"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0058",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #58",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x003a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0059"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0059",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #59",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x003b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0060"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0060",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #60",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x003c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0061"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0061",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #61",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x003d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0062"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0062",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #62",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x003e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0063"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0063",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #63",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x003f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0064"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0064",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #64",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0040::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0065"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0065",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #65",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0041::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0066"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0066",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #66",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0042::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0067"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0067",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #67",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0043::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0068"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0068",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #68",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0044::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0069"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0069",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #69",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0045::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0070"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0070",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #70",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0046::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0071"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0071",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #71",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0047::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0072"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0072",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #72",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0048::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0073"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0073",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #73",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0049::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0074"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0074",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #74",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x004a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0075"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0075",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #75",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x004b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0076"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0076",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #76",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x004c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0077"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0077",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #77",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x004d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0078"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0078",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #78",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x004e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0079"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0079",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #79",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x004f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0080"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0080",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #80",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0050::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0081"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0081",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #81",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0051::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0082"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0082",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #82",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0052::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0083"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0083",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #83",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0053::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0084"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0084",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #84",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0054::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0085"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0085",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #85",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0055::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0086"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0086",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #86",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0056::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0087"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0087",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #87",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0057::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0088"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0088",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #88",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0058::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0089"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0089",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #89",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0059::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0090"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0090",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #90",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x005a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0091"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0091",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #91",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x005b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0092"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0092",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #92",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x005c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0093"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0093",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #93",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x005d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0094"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0094",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #94",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x005e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0095"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0095",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #95",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x005f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0096"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0096",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #96",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0060::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0097"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0097",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #97",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0061::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0098"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0098",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #98",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0062::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0099"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0099",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #99",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0063::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0100"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0100",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #100",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0064::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0101"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0101",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #101",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0065::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0102"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0102",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #102",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0066::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0103"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0103",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #103",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0067::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0104"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0104",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #104",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0068::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0105"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0105",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #105",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0069::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0106"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0106",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #106",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x006a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0107"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0107",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #107",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x006b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0108"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0108",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #108",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x006c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0109"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0109",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #109",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x006d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0110"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0110",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #110",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x006e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0111"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0111",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #111",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x006f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0112"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0112",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #112",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0070::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0113"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0113",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #113",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0071::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0114"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0114",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #114",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0072::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0115"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0115",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #115",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0073::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0116"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0116",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #116",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0074::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0117"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0117",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #117",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0075::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0118"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0118",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #118",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0076::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0119"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0119",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #119",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0077::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0120"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0120",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #120",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0078::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0121"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0121",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #121",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0079::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0122"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0122",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #122",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x007a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0123"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0123",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #123",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x007b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0124"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0124",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #124",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x007c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0125"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0125",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #125",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x007d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0126"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0126",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #126",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x007e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0127"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0127",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #127",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x007f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0128"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0128",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #128",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0080::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0129"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0129",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #129",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0081::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0130"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0130",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #130",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0082::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0131"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0131",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #131",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0083::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0132"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0132",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #132",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0084::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0133"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0133",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #133",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0085::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0134"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0134",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #134",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0086::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0135"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0135",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #135",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0087::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0136"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0136",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #136",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0088::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0137"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0137",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #137",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0089::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0138"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0138",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #138",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x008a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0139"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0139",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #139",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x008b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0140"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0140",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #140",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x008c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0141"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0141",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #141",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x008d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0142"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0142",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #142",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x008e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0143"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0143",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #143",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x008f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0144"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0144",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #144",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0090::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0145"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0145",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #145",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0091::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0146"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0146",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #146",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0092::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0147"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0147",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #147",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0093::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0148"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0148",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #148",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0094::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0149"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0149",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #149",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0095::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0150"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0150",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #150",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0096::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0151"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0151",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #151",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0097::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0152"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0152",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #152",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0098::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0153"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0153",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #153",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0099::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0154"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0154",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #154",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x009a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0155"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0155",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #155",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x009b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0156"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0156",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #156",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x009c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0157"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0157",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #157",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x009d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0158"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0158",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #158",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x009e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0159"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0159",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #159",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x009f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0160"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0160",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #160",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00a0::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0161"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0161",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #161",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00a1::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0162"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0162",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #162",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00a2::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0163"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0163",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #163",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00a3::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0164"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0164",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #164",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00a4::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0165"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0165",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #165",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00a5::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0166"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0166",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #166",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00a6::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0167"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0167",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #167",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00a7::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0168"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0168",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #168",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00a8::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0169"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0169",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #169",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00a9::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0170"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0170",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #170",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00aa::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0171"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0171",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #171",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00ab::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0172"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0172",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #172",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00ac::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0173"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0173",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #173",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00ad::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0174"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0174",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #174",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00ae::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0175"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0175",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #175",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00af::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0176"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0176",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #176",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00b0::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0177"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0177",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #177",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00b1::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0178"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0178",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #178",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00b2::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0179"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0179",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #179",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00b3::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0180"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0180",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #180",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00b4::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0181"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0181",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #181",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00b5::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0182"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0182",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #182",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00b6::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0183"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0183",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #183",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00b7::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0184"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0184",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #184",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00b8::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0185"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0185",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #185",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00b9::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0186"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0186",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #186",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00ba::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0187"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0187",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #187",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00bb::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0188"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0188",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #188",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00bc::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0189"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0189",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #189",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00bd::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0190"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0190",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #190",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00be::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0191"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0191",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #191",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00bf::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0192"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0192",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #192",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00c0::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0193"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0193",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #193",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00c1::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0194"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0194",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #194",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00c2::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0195"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0195",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #195",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00c3::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0196"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0196",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #196",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00c4::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0197"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0197",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #197",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00c5::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0198"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0198",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #198",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00c6::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0199"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0199",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #199",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00c7::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0200"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0200",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #200",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00c8::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0201"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0201",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #201",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00c9::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0202"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0202",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #202",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ca::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0203"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0203",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #203",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00cb::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0204"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0204",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #204",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00cc::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0205"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0205",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #205",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00cd::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0206"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0206",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #206",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00ce::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0207"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0207",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #207",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00cf::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0208"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0208",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #208",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00d0::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0209"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0209",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #209",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00d1::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0210"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0210",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #210",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00d2::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0211"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0211",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #211",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00d3::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0212"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0212",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #212",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00d4::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0213"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0213",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #213",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00d5::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0214"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0214",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #214",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00d6::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0215"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0215",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #215",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00d7::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0216"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0216",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #216",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00d8::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0217"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0217",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #217",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00d9::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0218"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0218",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #218",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00da::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0219"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0219",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #219",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00db::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0220"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0220",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #220",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00dc::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0221"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0221",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #221",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00dd::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0222"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0222",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #222",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00de::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0223"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0223",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #223",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00df::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0224"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0224",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #224",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00e0::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0225"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0225",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #225",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00e1::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0226"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0226",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #226",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00e2::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0227"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0227",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #227",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00e3::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0228"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0228",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #228",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00e4::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0229"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0229",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #229",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00e5::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0230"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0230",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #230",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00e6::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0231"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0231",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #231",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00e7::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0232"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0232",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #232",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00e8::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0233"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0233",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #233",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00e9::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0234"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0234",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #234",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00ea::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0235"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0235",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #235",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00eb::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0236"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0236",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #236",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00ec::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0237"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0237",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #237",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00ed::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0238"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0238",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #238",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ee::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0239"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0239",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #239",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00ef::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0240"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0240",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #240",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00f0::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0241"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0241",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #241",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00f1::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0242"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0242",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #242",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00f2::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0243"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0243",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #243",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00f3::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0244"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0244",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #244",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00f4::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0245"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0245",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #245",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00f5::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0246"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0246",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #246",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00f6::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0247"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0247",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #247",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00f7::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0248"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0248",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #248",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00f8::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0249"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0249",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #249",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00f9::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0250"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0250",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #250",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00fa::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0251"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0251",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #251",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00fb::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0252"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0252",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #252",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00fc::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0253"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0253",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #253",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00fd::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0254"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0254",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #254",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00fe::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0255"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0255",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #255",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00ff::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0256"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0256",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #256",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0100::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0257"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0257",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #257",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0101::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0258"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0258",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #258",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0102::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0259"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0259",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #259",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0103::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0260"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0260",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #260",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0104::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0261"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0261",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #261",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0105::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0262"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0262",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #262",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0106::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0263"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0263",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #263",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0107::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0264"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0264",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #264",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0108::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0265"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0265",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #265",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0109::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0266"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0266",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #266",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x010a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0267"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0267",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #267",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x010b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0268"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0268",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #268",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x010c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0269"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0269",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #269",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x010d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0270"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0270",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #270",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x010e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0271"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0271",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #271",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x010f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0272"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0272",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #272",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0110::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0273"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0273",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #273",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0111::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0274"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0274",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #274",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0112::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0275"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0275",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #275",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0113::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0276"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0276",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #276",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0114::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0277"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0277",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #277",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0115::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0278"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0278",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #278",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0116::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0279"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0279",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #279",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0117::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0280"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0280",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #280",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0118::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0281"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0281",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #281",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0119::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0282"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0282",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #282",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x011a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0283"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0283",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #283",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x011b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0284"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0284",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #284",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x011c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0285"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0285",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #285",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x011d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0286"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0286",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #286",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x011e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0287"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0287",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #287",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x011f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0288"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0288",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #288",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0120::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0289"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0289",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #289",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0121::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0290"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0290",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #290",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0122::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0291"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0291",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #291",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0123::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0292"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0292",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #292",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0124::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0293"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0293",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #293",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0125::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0294"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0294",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #294",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0126::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0295"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0295",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #295",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0127::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0296"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0296",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #296",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0128::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0297"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0297",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #297",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0129::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0298"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0298",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #298",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x012a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0299"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0299",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #299",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x012b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0300"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0300",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #300",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x012c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0301"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0301",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #301",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x012d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0302"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0302",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #302",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x012e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0303"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0303",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #303",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x012f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0304"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0304",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #304",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0130::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0305"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0305",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #305",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0131::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0306"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0306",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #306",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0132::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0307"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0307",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #307",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0133::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0308"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0308",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #308",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0134::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0309"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0309",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #309",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0135::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0310"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0310",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #310",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0136::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0311"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0311",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #311",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0137::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0312"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0312",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #312",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0138::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0313"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0313",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #313",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0139::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0314"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0314",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #314",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x013a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0315"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0315",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #315",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x013b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0316"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0316",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #316",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x013c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0317"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0317",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #317",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x013d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0318"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0318",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #318",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x013e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0319"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0319",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #319",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x013f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0320"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0320",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #320",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0140::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0321"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0321",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #321",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0141::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0322"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0322",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #322",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0142::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0323"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0323",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #323",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0143::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0324"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0324",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #324",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0144::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0325"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0325",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #325",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0145::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0326"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0326",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #326",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0146::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0327"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0327",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #327",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0147::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0328"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0328",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #328",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0148::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0329"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0329",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #329",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0149::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0330"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0330",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #330",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x014a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0331"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0331",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #331",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x014b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0332"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0332",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #332",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x014c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0333"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0333",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #333",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x014d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0334"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0334",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #334",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x014e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0335"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0335",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #335",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x014f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0336"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0336",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #336",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0150::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0337"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0337",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #337",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0151::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0338"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0338",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #338",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0152::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0339"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0339",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #339",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0153::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0340"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0340",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #340",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0154::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0341"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0341",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #341",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0155::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0342"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0342",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #342",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0156::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0343"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0343",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #343",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0157::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0344"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0344",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #344",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0158::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0345"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0345",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #345",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0159::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0346"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0346",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #346",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x015a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0347"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0347",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #347",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x015b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0348"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0348",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #348",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x015c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0349"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0349",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #349",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x015d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0350"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0350",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #350",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x015e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0351"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0351",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #351",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x015f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0352"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0352",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #352",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0160::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0353"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0353",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #353",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0161::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0354"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0354",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #354",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0162::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0355"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0355",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #355",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0163::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0356"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0356",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #356",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0164::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0357"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0357",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #357",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0165::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0358"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0358",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #358",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0166::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0359"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0359",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #359",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0167::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0360"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0360",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #360",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0168::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0361"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0361",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #361",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0169::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0362"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0362",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #362",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x016a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0363"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0363",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #363",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x016b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0364"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0364",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #364",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x016c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0365"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0365",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #365",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x016d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0366"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0366",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #366",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x016e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0367"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0367",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #367",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x016f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0368"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0368",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #368",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0170::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0369"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0369",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #369",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0171::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0370"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0370",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #370",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0172::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0371"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0371",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #371",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0173::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0372"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0372",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #372",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0174::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0373"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0373",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #373",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0175::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0374"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0374",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #374",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0176::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0375"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0375",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #375",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0177::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0376"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0376",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #376",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0178::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0377"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0377",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #377",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0179::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0378"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0378",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #378",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x017a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0379"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0379",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #379",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x017b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0380"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0380",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #380",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x017c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0381"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0381",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #381",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x017d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0382"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0382",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #382",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x017e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0383"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0383",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #383",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x017f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0384"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0384",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #384",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0180::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0385"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0385",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #385",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0181::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0386"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0386",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #386",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0182::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0387"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0387",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #387",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0183::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0388"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0388",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #388",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0184::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0389"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0389",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #389",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0185::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0390"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0390",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #390",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0186::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0391"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0391",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #391",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0187::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0392"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0392",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #392",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0188::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0393"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0393",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #393",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0189::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0394"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0394",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #394",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x018a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0395"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0395",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #395",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x018b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0396"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0396",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #396",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x018c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0397"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0397",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #397",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x018d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0398"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0398",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #398",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x018e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0399"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0399",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #399",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x018f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0400"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0400",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #400",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0190::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0401"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0401",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #401",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0191::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0402"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0402",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #402",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0192::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0403"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0403",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #403",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0193::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0404"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0404",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #404",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0194::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0405"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0405",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #405",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0195::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0406"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0406",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #406",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0196::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0407"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0407",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #407",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0197::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0408"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0408",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #408",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0198::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0409"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0409",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #409",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0199::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0410"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0410",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #410",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x019a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0411"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0411",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #411",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x019b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0412"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0412",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #412",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x019c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0413"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0413",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #413",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x019d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0414"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0414",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #414",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x019e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0415"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0415",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #415",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x019f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0416"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0416",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #416",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x01a0::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0417"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0417",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #417",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x01a1::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0418"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0418",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #418",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x01a2::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0419"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0419",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #419",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x01a3::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0420"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0420",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #420",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x01a4::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0421"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0421",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #421",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x01a5::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0422"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0422",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #422",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x01a6::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0423"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0423",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #423",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x01a7::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0424"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0424",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #424",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x01a8::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0425"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0425",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #425",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x01a9::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0426"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0426",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #426",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x01aa::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0427"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0427",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #427",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x01ab::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0428"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0428",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #428",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x01ac::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0429"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0429",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #429",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x01ad::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0430"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0430",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #430",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x01ae::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0431"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0431",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #431",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x01af::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0432"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0432",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #432",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x01b0::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0433"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0433",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #433",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x01b1::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0434"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0434",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #434",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x01b2::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0435"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0435",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #435",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x01b3::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0436"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0436",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #436",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x01b4::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0437"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0437",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #437",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x01b5::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0438"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0438",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #438",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x01b6::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0439"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0439",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #439",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x01b7::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0440"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0440",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #440",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x01b8::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0441"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0441",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #441",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x01b9::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0442"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0442",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #442",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x01ba::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0443"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0443",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #443",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x01bb::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0444"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0444",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #444",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x01bc::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0445"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0445",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #445",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x01bd::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0446"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0446",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #446",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x01be::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0447"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0447",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #447",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x01bf::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0448"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0448",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #448",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x01c0::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["MONGODISSECTOR-R-0449"] = MongoDissectorRule(
            rule_id="MONGODISSECTOR-R-0449",
            name="MongoDB Wire Protocol & OP_MSG Payload Dissector Detection Signature #449",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x01c1::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )

    def evaluate_traffic_stream(self, header: MongoDissectorHeader) -> Dict[str, Any]:
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

mongodb_op_query_dissector_instance = MongoDissectorEngine()

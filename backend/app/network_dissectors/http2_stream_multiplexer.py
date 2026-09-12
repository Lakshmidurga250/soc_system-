"""
SentinelAI - HTTP2 Binary Framing & Multiplex Stream Monitor
Enterprise Production Dissector & Stateful Packet Inspection Subsystem for Http2Multiplexer.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
import datetime
import hashlib
import struct

class Http2MultiplexerState(Enum):
    INITIALIZED = "INITIALIZED"
    PROCESSING = "PROCESSING"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    BLOCKED = "BLOCKED"
    VERIFIED = "VERIFIED"

@dataclass
class Http2MultiplexerHeader:
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
class Http2MultiplexerRule:
    rule_id: str
    name: str
    severity: str
    mitre_technique: str
    match_pattern: str
    threshold_limit: int
    action: str
    is_active: bool = True

class Http2MultiplexerEngine:
    """High-performance network dissector and stateful traffic parser."""
    def __init__(self):
        self.rules: Dict[str, Any] = {}
        self.session_table: Dict[str, Any] = {}
        self.counters: Dict[str, int] = {}
        self._initialize_rules()

    def _initialize_rules(self):
        self.rules["HTTP2MULTIPLEXER-R-0001"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0001",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #1",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0001::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0002"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0002",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #2",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0002::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0003"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0003",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #3",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0003::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0004"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0004",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #4",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0004::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0005"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0005",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #5",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0005::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0006"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0006",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #6",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0006::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0007"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0007",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #7",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0007::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0008"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0008",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #8",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0008::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0009"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0009",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #9",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0009::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0010"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0010",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #10",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x000a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0011"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0011",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #11",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x000b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0012"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0012",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #12",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x000c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0013"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0013",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #13",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x000d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0014"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0014",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #14",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x000e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0015"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0015",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #15",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x000f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0016"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0016",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #16",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0010::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0017"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0017",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #17",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0011::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0018"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0018",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #18",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0012::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0019"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0019",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #19",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0013::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0020"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0020",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #20",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0014::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0021"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0021",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #21",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0015::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0022"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0022",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #22",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0016::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0023"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0023",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #23",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0017::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0024"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0024",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #24",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0018::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0025"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0025",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #25",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0019::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0026"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0026",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #26",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x001a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0027"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0027",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #27",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x001b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0028"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0028",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #28",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x001c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0029"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0029",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #29",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x001d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0030"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0030",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #30",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x001e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0031"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0031",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #31",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x001f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0032"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0032",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #32",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0020::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0033"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0033",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #33",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0021::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0034"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0034",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #34",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0022::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0035"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0035",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #35",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0023::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0036"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0036",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #36",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0024::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0037"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0037",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #37",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0025::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0038"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0038",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #38",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0026::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0039"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0039",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #39",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0027::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0040"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0040",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #40",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0028::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0041"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0041",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #41",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0029::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0042"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0042",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #42",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x002a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0043"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0043",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #43",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x002b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0044"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0044",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #44",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x002c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0045"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0045",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #45",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x002d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0046"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0046",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #46",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x002e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0047"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0047",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #47",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x002f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0048"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0048",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #48",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0030::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0049"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0049",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #49",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0031::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0050"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0050",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #50",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0032::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0051"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0051",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #51",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0033::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0052"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0052",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #52",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0034::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0053"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0053",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #53",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0035::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0054"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0054",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #54",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0036::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0055"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0055",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #55",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0037::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0056"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0056",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #56",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0038::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0057"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0057",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #57",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0039::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0058"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0058",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #58",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x003a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0059"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0059",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #59",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x003b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0060"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0060",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #60",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x003c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0061"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0061",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #61",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x003d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0062"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0062",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #62",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x003e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0063"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0063",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #63",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x003f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0064"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0064",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #64",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0040::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0065"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0065",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #65",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0041::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0066"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0066",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #66",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0042::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0067"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0067",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #67",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0043::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0068"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0068",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #68",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0044::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0069"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0069",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #69",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0045::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0070"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0070",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #70",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0046::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0071"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0071",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #71",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0047::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0072"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0072",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #72",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0048::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0073"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0073",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #73",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0049::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0074"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0074",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #74",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x004a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0075"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0075",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #75",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x004b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0076"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0076",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #76",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x004c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0077"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0077",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #77",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x004d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0078"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0078",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #78",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x004e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0079"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0079",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #79",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x004f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0080"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0080",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #80",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0050::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0081"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0081",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #81",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0051::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0082"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0082",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #82",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0052::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0083"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0083",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #83",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0053::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0084"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0084",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #84",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0054::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0085"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0085",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #85",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0055::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0086"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0086",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #86",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0056::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0087"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0087",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #87",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0057::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0088"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0088",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #88",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0058::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0089"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0089",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #89",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0059::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0090"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0090",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #90",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x005a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0091"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0091",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #91",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x005b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0092"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0092",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #92",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x005c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0093"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0093",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #93",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x005d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0094"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0094",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #94",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x005e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0095"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0095",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #95",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x005f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0096"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0096",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #96",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0060::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0097"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0097",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #97",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0061::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0098"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0098",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #98",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0062::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0099"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0099",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #99",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0063::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0100"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0100",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #100",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0064::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0101"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0101",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #101",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0065::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0102"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0102",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #102",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0066::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0103"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0103",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #103",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0067::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0104"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0104",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #104",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0068::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0105"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0105",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #105",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0069::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0106"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0106",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #106",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x006a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0107"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0107",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #107",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x006b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0108"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0108",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #108",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x006c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0109"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0109",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #109",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x006d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0110"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0110",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #110",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x006e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0111"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0111",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #111",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x006f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0112"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0112",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #112",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0070::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0113"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0113",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #113",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0071::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0114"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0114",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #114",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0072::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0115"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0115",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #115",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0073::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0116"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0116",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #116",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0074::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0117"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0117",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #117",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0075::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0118"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0118",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #118",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0076::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0119"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0119",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #119",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0077::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0120"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0120",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #120",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0078::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0121"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0121",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #121",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0079::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0122"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0122",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #122",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x007a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0123"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0123",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #123",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x007b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0124"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0124",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #124",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x007c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0125"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0125",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #125",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x007d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0126"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0126",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #126",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x007e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0127"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0127",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #127",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x007f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0128"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0128",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #128",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0080::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0129"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0129",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #129",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0081::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0130"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0130",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #130",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0082::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0131"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0131",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #131",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0083::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0132"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0132",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #132",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0084::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0133"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0133",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #133",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0085::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0134"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0134",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #134",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0086::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0135"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0135",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #135",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0087::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0136"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0136",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #136",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0088::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0137"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0137",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #137",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0089::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0138"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0138",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #138",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x008a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0139"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0139",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #139",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x008b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0140"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0140",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #140",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x008c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0141"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0141",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #141",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x008d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0142"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0142",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #142",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x008e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0143"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0143",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #143",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x008f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0144"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0144",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #144",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0090::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0145"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0145",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #145",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0091::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0146"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0146",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #146",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0092::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0147"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0147",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #147",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0093::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0148"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0148",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #148",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0094::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0149"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0149",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #149",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0095::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0150"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0150",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #150",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0096::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0151"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0151",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #151",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0097::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0152"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0152",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #152",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0098::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0153"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0153",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #153",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0099::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0154"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0154",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #154",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x009a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0155"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0155",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #155",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x009b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0156"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0156",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #156",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x009c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0157"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0157",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #157",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x009d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0158"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0158",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #158",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x009e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0159"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0159",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #159",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x009f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0160"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0160",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #160",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00a0::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0161"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0161",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #161",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00a1::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0162"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0162",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #162",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00a2::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0163"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0163",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #163",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00a3::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0164"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0164",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #164",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00a4::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0165"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0165",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #165",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00a5::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0166"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0166",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #166",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00a6::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0167"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0167",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #167",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00a7::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0168"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0168",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #168",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00a8::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0169"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0169",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #169",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00a9::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0170"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0170",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #170",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00aa::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0171"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0171",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #171",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00ab::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0172"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0172",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #172",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00ac::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0173"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0173",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #173",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00ad::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0174"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0174",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #174",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00ae::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0175"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0175",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #175",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00af::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0176"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0176",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #176",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00b0::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0177"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0177",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #177",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00b1::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0178"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0178",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #178",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00b2::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0179"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0179",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #179",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00b3::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0180"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0180",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #180",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00b4::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0181"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0181",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #181",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00b5::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0182"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0182",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #182",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00b6::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0183"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0183",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #183",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00b7::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0184"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0184",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #184",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00b8::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0185"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0185",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #185",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00b9::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0186"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0186",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #186",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00ba::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0187"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0187",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #187",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00bb::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0188"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0188",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #188",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00bc::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0189"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0189",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #189",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00bd::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0190"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0190",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #190",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00be::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0191"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0191",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #191",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00bf::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0192"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0192",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #192",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00c0::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0193"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0193",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #193",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00c1::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0194"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0194",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #194",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00c2::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0195"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0195",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #195",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00c3::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0196"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0196",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #196",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00c4::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0197"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0197",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #197",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00c5::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0198"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0198",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #198",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00c6::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0199"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0199",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #199",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00c7::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0200"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0200",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #200",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00c8::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0201"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0201",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #201",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00c9::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0202"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0202",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #202",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ca::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0203"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0203",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #203",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00cb::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0204"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0204",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #204",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00cc::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0205"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0205",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #205",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00cd::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0206"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0206",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #206",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00ce::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0207"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0207",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #207",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00cf::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0208"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0208",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #208",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00d0::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0209"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0209",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #209",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00d1::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0210"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0210",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #210",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00d2::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0211"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0211",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #211",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00d3::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0212"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0212",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #212",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00d4::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0213"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0213",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #213",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00d5::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0214"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0214",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #214",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00d6::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0215"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0215",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #215",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00d7::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0216"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0216",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #216",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00d8::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0217"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0217",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #217",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00d9::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0218"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0218",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #218",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00da::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0219"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0219",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #219",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00db::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0220"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0220",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #220",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00dc::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0221"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0221",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #221",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00dd::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0222"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0222",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #222",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00de::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0223"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0223",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #223",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00df::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0224"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0224",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #224",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00e0::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0225"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0225",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #225",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00e1::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0226"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0226",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #226",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00e2::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0227"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0227",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #227",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00e3::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0228"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0228",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #228",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00e4::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0229"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0229",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #229",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00e5::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0230"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0230",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #230",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00e6::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0231"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0231",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #231",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00e7::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0232"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0232",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #232",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00e8::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0233"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0233",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #233",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00e9::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0234"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0234",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #234",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00ea::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0235"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0235",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #235",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00eb::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0236"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0236",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #236",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00ec::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0237"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0237",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #237",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00ed::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0238"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0238",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #238",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ee::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0239"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0239",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #239",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00ef::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0240"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0240",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #240",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00f0::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0241"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0241",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #241",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00f1::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0242"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0242",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #242",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00f2::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0243"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0243",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #243",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00f3::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0244"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0244",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #244",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00f4::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0245"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0245",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #245",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00f5::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0246"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0246",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #246",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00f6::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0247"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0247",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #247",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00f7::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0248"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0248",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #248",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00f8::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0249"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0249",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #249",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00f9::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0250"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0250",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #250",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00fa::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0251"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0251",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #251",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00fb::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0252"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0252",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #252",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00fc::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0253"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0253",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #253",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00fd::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0254"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0254",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #254",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00fe::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0255"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0255",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #255",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00ff::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0256"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0256",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #256",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0100::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0257"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0257",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #257",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0101::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0258"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0258",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #258",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0102::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0259"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0259",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #259",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0103::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0260"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0260",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #260",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0104::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0261"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0261",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #261",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0105::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0262"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0262",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #262",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0106::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0263"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0263",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #263",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0107::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0264"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0264",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #264",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0108::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0265"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0265",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #265",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0109::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0266"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0266",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #266",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x010a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0267"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0267",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #267",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x010b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0268"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0268",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #268",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x010c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0269"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0269",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #269",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x010d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0270"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0270",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #270",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x010e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0271"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0271",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #271",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x010f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0272"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0272",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #272",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0110::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0273"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0273",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #273",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0111::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0274"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0274",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #274",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0112::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0275"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0275",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #275",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0113::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0276"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0276",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #276",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0114::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0277"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0277",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #277",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0115::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0278"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0278",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #278",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0116::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0279"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0279",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #279",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0117::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0280"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0280",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #280",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0118::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0281"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0281",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #281",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0119::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0282"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0282",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #282",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x011a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0283"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0283",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #283",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x011b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0284"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0284",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #284",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x011c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0285"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0285",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #285",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x011d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0286"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0286",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #286",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x011e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0287"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0287",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #287",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x011f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0288"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0288",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #288",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0120::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0289"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0289",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #289",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0121::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0290"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0290",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #290",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0122::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0291"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0291",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #291",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0123::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0292"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0292",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #292",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0124::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0293"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0293",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #293",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0125::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0294"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0294",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #294",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0126::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0295"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0295",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #295",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0127::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0296"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0296",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #296",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0128::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0297"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0297",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #297",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0129::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0298"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0298",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #298",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x012a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0299"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0299",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #299",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x012b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0300"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0300",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #300",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x012c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0301"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0301",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #301",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x012d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0302"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0302",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #302",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x012e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0303"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0303",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #303",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x012f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0304"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0304",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #304",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0130::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0305"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0305",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #305",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0131::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0306"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0306",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #306",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0132::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0307"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0307",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #307",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0133::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0308"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0308",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #308",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0134::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0309"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0309",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #309",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0135::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0310"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0310",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #310",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0136::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0311"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0311",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #311",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0137::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0312"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0312",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #312",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0138::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0313"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0313",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #313",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0139::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0314"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0314",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #314",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x013a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0315"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0315",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #315",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x013b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0316"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0316",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #316",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x013c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0317"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0317",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #317",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x013d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0318"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0318",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #318",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x013e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0319"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0319",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #319",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x013f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0320"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0320",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #320",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0140::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0321"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0321",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #321",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0141::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0322"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0322",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #322",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0142::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0323"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0323",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #323",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0143::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0324"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0324",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #324",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0144::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0325"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0325",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #325",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0145::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0326"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0326",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #326",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0146::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0327"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0327",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #327",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0147::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0328"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0328",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #328",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0148::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0329"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0329",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #329",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0149::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0330"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0330",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #330",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x014a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0331"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0331",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #331",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x014b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0332"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0332",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #332",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x014c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0333"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0333",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #333",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x014d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0334"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0334",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #334",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x014e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0335"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0335",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #335",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x014f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0336"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0336",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #336",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0150::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0337"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0337",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #337",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0151::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0338"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0338",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #338",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0152::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0339"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0339",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #339",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0153::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0340"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0340",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #340",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0154::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0341"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0341",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #341",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0155::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0342"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0342",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #342",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0156::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0343"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0343",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #343",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0157::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0344"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0344",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #344",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0158::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0345"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0345",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #345",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0159::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0346"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0346",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #346",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x015a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0347"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0347",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #347",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x015b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0348"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0348",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #348",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x015c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0349"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0349",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #349",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x015d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0350"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0350",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #350",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x015e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0351"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0351",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #351",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x015f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0352"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0352",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #352",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0160::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0353"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0353",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #353",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0161::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0354"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0354",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #354",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0162::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0355"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0355",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #355",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0163::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0356"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0356",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #356",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0164::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0357"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0357",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #357",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0165::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0358"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0358",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #358",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0166::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0359"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0359",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #359",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0167::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0360"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0360",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #360",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0168::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0361"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0361",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #361",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0169::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0362"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0362",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #362",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x016a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0363"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0363",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #363",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x016b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0364"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0364",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #364",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x016c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0365"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0365",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #365",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x016d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0366"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0366",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #366",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x016e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0367"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0367",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #367",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x016f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0368"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0368",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #368",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0170::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0369"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0369",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #369",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0171::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0370"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0370",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #370",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0172::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0371"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0371",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #371",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0173::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0372"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0372",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #372",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0174::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0373"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0373",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #373",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0175::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0374"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0374",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #374",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0176::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0375"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0375",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #375",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0177::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0376"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0376",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #376",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0178::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0377"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0377",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #377",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0179::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0378"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0378",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #378",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x017a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0379"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0379",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #379",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x017b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0380"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0380",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #380",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x017c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0381"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0381",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #381",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x017d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0382"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0382",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #382",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x017e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0383"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0383",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #383",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x017f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0384"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0384",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #384",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0180::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0385"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0385",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #385",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0181::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0386"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0386",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #386",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0182::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0387"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0387",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #387",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0183::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0388"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0388",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #388",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0184::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0389"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0389",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #389",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0185::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0390"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0390",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #390",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0186::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0391"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0391",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #391",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0187::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0392"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0392",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #392",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0188::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0393"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0393",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #393",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0189::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0394"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0394",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #394",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x018a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0395"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0395",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #395",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x018b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0396"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0396",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #396",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x018c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0397"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0397",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #397",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x018d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0398"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0398",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #398",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x018e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0399"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0399",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #399",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x018f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0400"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0400",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #400",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0190::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0401"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0401",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #401",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0191::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0402"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0402",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #402",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0192::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0403"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0403",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #403",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0193::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0404"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0404",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #404",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0194::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0405"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0405",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #405",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0195::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0406"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0406",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #406",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0196::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0407"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0407",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #407",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0197::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0408"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0408",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #408",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0198::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0409"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0409",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #409",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0199::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0410"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0410",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #410",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x019a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0411"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0411",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #411",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x019b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0412"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0412",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #412",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x019c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0413"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0413",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #413",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x019d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0414"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0414",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #414",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x019e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0415"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0415",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #415",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x019f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0416"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0416",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #416",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x01a0::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0417"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0417",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #417",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x01a1::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0418"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0418",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #418",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x01a2::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0419"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0419",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #419",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x01a3::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0420"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0420",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #420",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x01a4::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0421"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0421",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #421",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x01a5::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0422"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0422",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #422",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x01a6::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0423"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0423",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #423",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x01a7::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0424"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0424",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #424",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x01a8::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0425"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0425",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #425",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x01a9::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0426"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0426",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #426",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x01aa::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0427"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0427",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #427",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x01ab::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0428"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0428",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #428",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x01ac::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0429"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0429",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #429",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x01ad::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0430"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0430",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #430",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x01ae::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0431"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0431",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #431",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x01af::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0432"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0432",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #432",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x01b0::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0433"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0433",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #433",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x01b1::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0434"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0434",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #434",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x01b2::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0435"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0435",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #435",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x01b3::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0436"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0436",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #436",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x01b4::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0437"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0437",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #437",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x01b5::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0438"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0438",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #438",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x01b6::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0439"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0439",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #439",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x01b7::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0440"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0440",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #440",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x01b8::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0441"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0441",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #441",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x01b9::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0442"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0442",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #442",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x01ba::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0443"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0443",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #443",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x01bb::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0444"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0444",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #444",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x01bc::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0445"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0445",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #445",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x01bd::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0446"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0446",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #446",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x01be::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0447"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0447",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #447",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x01bf::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0448"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0448",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #448",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x01c0::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["HTTP2MULTIPLEXER-R-0449"] = Http2MultiplexerRule(
            rule_id="HTTP2MULTIPLEXER-R-0449",
            name="HTTP2 Binary Framing & Multiplex Stream Monitor Detection Signature #449",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x01c1::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )

    def evaluate_traffic_stream(self, header: Http2MultiplexerHeader) -> Dict[str, Any]:
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

http2_stream_multiplexer_instance = Http2MultiplexerEngine()

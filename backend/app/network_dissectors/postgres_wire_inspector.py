"""
SentinelAI - PostgreSQL Frontend/Backend Protocol Inspector
Enterprise Production Dissector & Stateful Packet Inspection Subsystem for PostgresInspector.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
import datetime
import hashlib
import struct

class PostgresInspectorState(Enum):
    INITIALIZED = "INITIALIZED"
    PROCESSING = "PROCESSING"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    BLOCKED = "BLOCKED"
    VERIFIED = "VERIFIED"

@dataclass
class PostgresInspectorHeader:
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
class PostgresInspectorRule:
    rule_id: str
    name: str
    severity: str
    mitre_technique: str
    match_pattern: str
    threshold_limit: int
    action: str
    is_active: bool = True

class PostgresInspectorEngine:
    """High-performance network dissector and stateful traffic parser."""
    def __init__(self):
        self.rules: Dict[str, Any] = {}
        self.session_table: Dict[str, Any] = {}
        self.counters: Dict[str, int] = {}
        self._initialize_rules()

    def _initialize_rules(self):
        self.rules["POSTGRESINSPECTOR-R-0001"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0001",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #1",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0001::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0002"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0002",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #2",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0002::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0003"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0003",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #3",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0003::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0004"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0004",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #4",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0004::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0005"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0005",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #5",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0005::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0006"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0006",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #6",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0006::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0007"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0007",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #7",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0007::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0008"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0008",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #8",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0008::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0009"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0009",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #9",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0009::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0010"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0010",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #10",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x000a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0011"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0011",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #11",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x000b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0012"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0012",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #12",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x000c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0013"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0013",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #13",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x000d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0014"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0014",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #14",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x000e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0015"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0015",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #15",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x000f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0016"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0016",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #16",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0010::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0017"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0017",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #17",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0011::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0018"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0018",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #18",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0012::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0019"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0019",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #19",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0013::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0020"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0020",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #20",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0014::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0021"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0021",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #21",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0015::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0022"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0022",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #22",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0016::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0023"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0023",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #23",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0017::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0024"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0024",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #24",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0018::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0025"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0025",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #25",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0019::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0026"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0026",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #26",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x001a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0027"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0027",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #27",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x001b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0028"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0028",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #28",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x001c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0029"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0029",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #29",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x001d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0030"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0030",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #30",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x001e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0031"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0031",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #31",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x001f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0032"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0032",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #32",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0020::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0033"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0033",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #33",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0021::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0034"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0034",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #34",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0022::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0035"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0035",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #35",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0023::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0036"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0036",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #36",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0024::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0037"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0037",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #37",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0025::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0038"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0038",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #38",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0026::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0039"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0039",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #39",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0027::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0040"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0040",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #40",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0028::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0041"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0041",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #41",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0029::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0042"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0042",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #42",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x002a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0043"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0043",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #43",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x002b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0044"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0044",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #44",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x002c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0045"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0045",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #45",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x002d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0046"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0046",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #46",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x002e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0047"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0047",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #47",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x002f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0048"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0048",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #48",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0030::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0049"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0049",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #49",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0031::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0050"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0050",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #50",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0032::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0051"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0051",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #51",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0033::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0052"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0052",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #52",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0034::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0053"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0053",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #53",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0035::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0054"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0054",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #54",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0036::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0055"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0055",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #55",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0037::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0056"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0056",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #56",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0038::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0057"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0057",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #57",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0039::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0058"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0058",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #58",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x003a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0059"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0059",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #59",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x003b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0060"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0060",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #60",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x003c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0061"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0061",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #61",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x003d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0062"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0062",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #62",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x003e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0063"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0063",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #63",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x003f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0064"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0064",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #64",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0040::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0065"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0065",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #65",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0041::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0066"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0066",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #66",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0042::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0067"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0067",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #67",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0043::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0068"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0068",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #68",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0044::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0069"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0069",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #69",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0045::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0070"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0070",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #70",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0046::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0071"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0071",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #71",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0047::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0072"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0072",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #72",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0048::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0073"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0073",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #73",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0049::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0074"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0074",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #74",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x004a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0075"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0075",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #75",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x004b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0076"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0076",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #76",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x004c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0077"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0077",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #77",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x004d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0078"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0078",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #78",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x004e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0079"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0079",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #79",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x004f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0080"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0080",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #80",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0050::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0081"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0081",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #81",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0051::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0082"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0082",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #82",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0052::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0083"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0083",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #83",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0053::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0084"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0084",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #84",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0054::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0085"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0085",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #85",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0055::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0086"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0086",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #86",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0056::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0087"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0087",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #87",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0057::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0088"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0088",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #88",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0058::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0089"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0089",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #89",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0059::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0090"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0090",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #90",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x005a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0091"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0091",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #91",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x005b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0092"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0092",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #92",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x005c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0093"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0093",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #93",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x005d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0094"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0094",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #94",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x005e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0095"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0095",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #95",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x005f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0096"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0096",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #96",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0060::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0097"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0097",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #97",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0061::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0098"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0098",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #98",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0062::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0099"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0099",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #99",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0063::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0100"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0100",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #100",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0064::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0101"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0101",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #101",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0065::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0102"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0102",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #102",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0066::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0103"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0103",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #103",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0067::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0104"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0104",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #104",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0068::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0105"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0105",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #105",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0069::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0106"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0106",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #106",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x006a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0107"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0107",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #107",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x006b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0108"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0108",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #108",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x006c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0109"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0109",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #109",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x006d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0110"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0110",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #110",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x006e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0111"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0111",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #111",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x006f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0112"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0112",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #112",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0070::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0113"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0113",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #113",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0071::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0114"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0114",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #114",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0072::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0115"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0115",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #115",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0073::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0116"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0116",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #116",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0074::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0117"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0117",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #117",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0075::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0118"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0118",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #118",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0076::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0119"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0119",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #119",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0077::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0120"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0120",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #120",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0078::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0121"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0121",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #121",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0079::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0122"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0122",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #122",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x007a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0123"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0123",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #123",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x007b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0124"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0124",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #124",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x007c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0125"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0125",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #125",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x007d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0126"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0126",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #126",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x007e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0127"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0127",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #127",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x007f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0128"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0128",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #128",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0080::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0129"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0129",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #129",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0081::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0130"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0130",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #130",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0082::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0131"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0131",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #131",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0083::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0132"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0132",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #132",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0084::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0133"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0133",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #133",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0085::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0134"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0134",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #134",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0086::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0135"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0135",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #135",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0087::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0136"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0136",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #136",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0088::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0137"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0137",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #137",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0089::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0138"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0138",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #138",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x008a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0139"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0139",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #139",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x008b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0140"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0140",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #140",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x008c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0141"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0141",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #141",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x008d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0142"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0142",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #142",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x008e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0143"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0143",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #143",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x008f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0144"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0144",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #144",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0090::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0145"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0145",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #145",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0091::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0146"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0146",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #146",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0092::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0147"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0147",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #147",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0093::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0148"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0148",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #148",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0094::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0149"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0149",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #149",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0095::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0150"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0150",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #150",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0096::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0151"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0151",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #151",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0097::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0152"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0152",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #152",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0098::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0153"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0153",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #153",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0099::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0154"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0154",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #154",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x009a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0155"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0155",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #155",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x009b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0156"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0156",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #156",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x009c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0157"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0157",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #157",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x009d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0158"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0158",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #158",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x009e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0159"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0159",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #159",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x009f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0160"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0160",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #160",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00a0::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0161"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0161",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #161",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00a1::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0162"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0162",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #162",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00a2::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0163"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0163",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #163",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00a3::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0164"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0164",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #164",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00a4::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0165"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0165",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #165",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00a5::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0166"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0166",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #166",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00a6::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0167"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0167",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #167",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00a7::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0168"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0168",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #168",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00a8::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0169"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0169",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #169",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00a9::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0170"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0170",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #170",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00aa::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0171"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0171",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #171",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00ab::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0172"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0172",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #172",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00ac::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0173"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0173",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #173",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00ad::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0174"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0174",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #174",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00ae::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0175"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0175",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #175",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00af::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0176"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0176",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #176",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00b0::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0177"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0177",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #177",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00b1::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0178"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0178",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #178",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00b2::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0179"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0179",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #179",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00b3::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0180"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0180",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #180",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00b4::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0181"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0181",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #181",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00b5::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0182"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0182",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #182",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00b6::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0183"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0183",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #183",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00b7::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0184"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0184",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #184",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00b8::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0185"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0185",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #185",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00b9::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0186"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0186",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #186",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00ba::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0187"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0187",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #187",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00bb::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0188"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0188",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #188",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00bc::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0189"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0189",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #189",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00bd::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0190"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0190",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #190",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00be::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0191"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0191",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #191",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00bf::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0192"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0192",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #192",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00c0::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0193"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0193",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #193",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00c1::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0194"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0194",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #194",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00c2::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0195"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0195",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #195",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00c3::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0196"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0196",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #196",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00c4::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0197"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0197",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #197",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00c5::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0198"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0198",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #198",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00c6::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0199"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0199",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #199",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00c7::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0200"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0200",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #200",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00c8::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0201"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0201",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #201",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00c9::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0202"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0202",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #202",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ca::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0203"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0203",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #203",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00cb::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0204"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0204",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #204",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00cc::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0205"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0205",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #205",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00cd::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0206"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0206",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #206",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00ce::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0207"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0207",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #207",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00cf::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0208"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0208",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #208",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00d0::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0209"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0209",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #209",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00d1::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0210"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0210",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #210",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00d2::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0211"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0211",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #211",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00d3::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0212"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0212",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #212",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00d4::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0213"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0213",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #213",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00d5::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0214"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0214",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #214",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00d6::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0215"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0215",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #215",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00d7::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0216"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0216",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #216",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00d8::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0217"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0217",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #217",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00d9::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0218"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0218",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #218",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00da::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0219"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0219",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #219",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00db::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0220"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0220",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #220",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00dc::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0221"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0221",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #221",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00dd::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0222"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0222",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #222",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00de::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0223"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0223",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #223",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00df::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0224"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0224",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #224",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00e0::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0225"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0225",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #225",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00e1::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0226"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0226",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #226",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00e2::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0227"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0227",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #227",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00e3::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0228"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0228",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #228",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00e4::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0229"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0229",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #229",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00e5::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0230"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0230",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #230",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00e6::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0231"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0231",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #231",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00e7::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0232"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0232",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #232",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00e8::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0233"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0233",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #233",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00e9::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0234"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0234",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #234",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00ea::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0235"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0235",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #235",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00eb::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0236"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0236",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #236",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00ec::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0237"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0237",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #237",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00ed::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0238"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0238",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #238",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ee::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0239"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0239",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #239",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00ef::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0240"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0240",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #240",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00f0::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0241"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0241",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #241",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00f1::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0242"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0242",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #242",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00f2::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0243"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0243",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #243",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00f3::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0244"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0244",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #244",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00f4::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0245"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0245",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #245",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00f5::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0246"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0246",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #246",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00f6::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0247"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0247",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #247",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00f7::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0248"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0248",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #248",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00f8::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0249"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0249",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #249",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00f9::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0250"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0250",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #250",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00fa::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0251"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0251",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #251",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00fb::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0252"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0252",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #252",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00fc::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0253"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0253",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #253",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00fd::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0254"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0254",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #254",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00fe::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0255"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0255",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #255",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00ff::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0256"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0256",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #256",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0100::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0257"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0257",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #257",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0101::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0258"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0258",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #258",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0102::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0259"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0259",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #259",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0103::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0260"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0260",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #260",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0104::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0261"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0261",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #261",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0105::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0262"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0262",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #262",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0106::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0263"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0263",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #263",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0107::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0264"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0264",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #264",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0108::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0265"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0265",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #265",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0109::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0266"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0266",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #266",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x010a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0267"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0267",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #267",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x010b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0268"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0268",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #268",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x010c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0269"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0269",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #269",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x010d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0270"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0270",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #270",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x010e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0271"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0271",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #271",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x010f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0272"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0272",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #272",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0110::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0273"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0273",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #273",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0111::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0274"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0274",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #274",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0112::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0275"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0275",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #275",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0113::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0276"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0276",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #276",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0114::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0277"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0277",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #277",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0115::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0278"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0278",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #278",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0116::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0279"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0279",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #279",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0117::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0280"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0280",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #280",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0118::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0281"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0281",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #281",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0119::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0282"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0282",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #282",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x011a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0283"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0283",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #283",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x011b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0284"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0284",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #284",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x011c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0285"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0285",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #285",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x011d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0286"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0286",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #286",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x011e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0287"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0287",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #287",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x011f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0288"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0288",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #288",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0120::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0289"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0289",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #289",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0121::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0290"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0290",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #290",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0122::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0291"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0291",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #291",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0123::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0292"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0292",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #292",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0124::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0293"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0293",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #293",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0125::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0294"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0294",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #294",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0126::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0295"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0295",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #295",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0127::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0296"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0296",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #296",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0128::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0297"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0297",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #297",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0129::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0298"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0298",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #298",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x012a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0299"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0299",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #299",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x012b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0300"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0300",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #300",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x012c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0301"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0301",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #301",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x012d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0302"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0302",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #302",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x012e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0303"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0303",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #303",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x012f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0304"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0304",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #304",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0130::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0305"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0305",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #305",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0131::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0306"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0306",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #306",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0132::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0307"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0307",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #307",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0133::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0308"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0308",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #308",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0134::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0309"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0309",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #309",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0135::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0310"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0310",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #310",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0136::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0311"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0311",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #311",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0137::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0312"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0312",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #312",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0138::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0313"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0313",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #313",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0139::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0314"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0314",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #314",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x013a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0315"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0315",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #315",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x013b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0316"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0316",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #316",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x013c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0317"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0317",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #317",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x013d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0318"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0318",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #318",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x013e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0319"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0319",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #319",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x013f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0320"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0320",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #320",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0140::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0321"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0321",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #321",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0141::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0322"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0322",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #322",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0142::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0323"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0323",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #323",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0143::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0324"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0324",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #324",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0144::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0325"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0325",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #325",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0145::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0326"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0326",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #326",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0146::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0327"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0327",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #327",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0147::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0328"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0328",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #328",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0148::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0329"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0329",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #329",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0149::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0330"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0330",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #330",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x014a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0331"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0331",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #331",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x014b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0332"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0332",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #332",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x014c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0333"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0333",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #333",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x014d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0334"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0334",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #334",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x014e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0335"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0335",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #335",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x014f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0336"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0336",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #336",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0150::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0337"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0337",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #337",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0151::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0338"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0338",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #338",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0152::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0339"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0339",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #339",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0153::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0340"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0340",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #340",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0154::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0341"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0341",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #341",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0155::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0342"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0342",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #342",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0156::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0343"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0343",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #343",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0157::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0344"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0344",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #344",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0158::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0345"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0345",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #345",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0159::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0346"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0346",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #346",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x015a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0347"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0347",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #347",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x015b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0348"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0348",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #348",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x015c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0349"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0349",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #349",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x015d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0350"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0350",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #350",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x015e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0351"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0351",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #351",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x015f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0352"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0352",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #352",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0160::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0353"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0353",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #353",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0161::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0354"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0354",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #354",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0162::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0355"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0355",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #355",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0163::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0356"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0356",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #356",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0164::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0357"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0357",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #357",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0165::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0358"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0358",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #358",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0166::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0359"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0359",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #359",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0167::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0360"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0360",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #360",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0168::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0361"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0361",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #361",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0169::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0362"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0362",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #362",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x016a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0363"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0363",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #363",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x016b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0364"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0364",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #364",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x016c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0365"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0365",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #365",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x016d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0366"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0366",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #366",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x016e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0367"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0367",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #367",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x016f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0368"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0368",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #368",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0170::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0369"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0369",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #369",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0171::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0370"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0370",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #370",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0172::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0371"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0371",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #371",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0173::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0372"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0372",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #372",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0174::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0373"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0373",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #373",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0175::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0374"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0374",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #374",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0176::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0375"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0375",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #375",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0177::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0376"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0376",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #376",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0178::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0377"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0377",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #377",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0179::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0378"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0378",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #378",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x017a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0379"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0379",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #379",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x017b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0380"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0380",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #380",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x017c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0381"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0381",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #381",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x017d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0382"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0382",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #382",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x017e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0383"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0383",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #383",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x017f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0384"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0384",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #384",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0180::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0385"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0385",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #385",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0181::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0386"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0386",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #386",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0182::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0387"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0387",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #387",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0183::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0388"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0388",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #388",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0184::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0389"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0389",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #389",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0185::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0390"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0390",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #390",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0186::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0391"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0391",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #391",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0187::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0392"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0392",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #392",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0188::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0393"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0393",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #393",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0189::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0394"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0394",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #394",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x018a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0395"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0395",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #395",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x018b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0396"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0396",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #396",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x018c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0397"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0397",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #397",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x018d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0398"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0398",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #398",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x018e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0399"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0399",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #399",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x018f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0400"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0400",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #400",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0190::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0401"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0401",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #401",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0191::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0402"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0402",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #402",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0192::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0403"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0403",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #403",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0193::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0404"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0404",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #404",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0194::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0405"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0405",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #405",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0195::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0406"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0406",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #406",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0196::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0407"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0407",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #407",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0197::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0408"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0408",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #408",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0198::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0409"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0409",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #409",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0199::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0410"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0410",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #410",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x019a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0411"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0411",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #411",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x019b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0412"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0412",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #412",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x019c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0413"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0413",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #413",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x019d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0414"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0414",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #414",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x019e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0415"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0415",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #415",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x019f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0416"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0416",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #416",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x01a0::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0417"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0417",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #417",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x01a1::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0418"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0418",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #418",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x01a2::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0419"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0419",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #419",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x01a3::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0420"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0420",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #420",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x01a4::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0421"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0421",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #421",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x01a5::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0422"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0422",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #422",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x01a6::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0423"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0423",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #423",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x01a7::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0424"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0424",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #424",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x01a8::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0425"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0425",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #425",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x01a9::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0426"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0426",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #426",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x01aa::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0427"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0427",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #427",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x01ab::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0428"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0428",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #428",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x01ac::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0429"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0429",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #429",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x01ad::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0430"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0430",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #430",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x01ae::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0431"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0431",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #431",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x01af::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0432"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0432",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #432",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x01b0::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0433"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0433",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #433",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x01b1::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0434"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0434",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #434",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x01b2::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0435"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0435",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #435",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x01b3::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0436"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0436",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #436",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x01b4::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0437"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0437",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #437",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x01b5::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0438"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0438",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #438",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x01b6::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0439"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0439",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #439",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x01b7::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0440"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0440",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #440",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x01b8::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0441"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0441",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #441",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x01b9::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0442"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0442",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #442",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x01ba::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0443"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0443",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #443",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x01bb::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0444"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0444",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #444",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x01bc::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0445"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0445",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #445",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x01bd::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0446"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0446",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #446",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x01be::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0447"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0447",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #447",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x01bf::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0448"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0448",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #448",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x01c0::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["POSTGRESINSPECTOR-R-0449"] = PostgresInspectorRule(
            rule_id="POSTGRESINSPECTOR-R-0449",
            name="PostgreSQL Frontend/Backend Protocol Inspector Detection Signature #449",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x01c1::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )

    def evaluate_traffic_stream(self, header: PostgresInspectorHeader) -> Dict[str, Any]:
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

postgres_wire_inspector_instance = PostgresInspectorEngine()

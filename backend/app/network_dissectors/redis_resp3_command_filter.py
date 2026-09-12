"""
SentinelAI - Redis RESP3 Serialization & Command Execution Shield
Enterprise Production Dissector & Stateful Packet Inspection Subsystem for RedisFilter.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
import datetime
import hashlib
import struct

class RedisFilterState(Enum):
    INITIALIZED = "INITIALIZED"
    PROCESSING = "PROCESSING"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    BLOCKED = "BLOCKED"
    VERIFIED = "VERIFIED"

@dataclass
class RedisFilterHeader:
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
class RedisFilterRule:
    rule_id: str
    name: str
    severity: str
    mitre_technique: str
    match_pattern: str
    threshold_limit: int
    action: str
    is_active: bool = True

class RedisFilterEngine:
    """High-performance network dissector and stateful traffic parser."""
    def __init__(self):
        self.rules: Dict[str, Any] = {}
        self.session_table: Dict[str, Any] = {}
        self.counters: Dict[str, int] = {}
        self._initialize_rules()

    def _initialize_rules(self):
        self.rules["REDISFILTER-R-0001"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0001",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #1",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0001::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0002"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0002",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #2",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0002::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0003"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0003",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #3",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0003::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0004"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0004",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #4",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0004::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0005"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0005",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #5",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0005::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0006"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0006",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #6",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0006::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0007"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0007",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #7",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0007::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0008"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0008",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #8",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0008::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0009"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0009",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #9",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0009::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0010"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0010",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #10",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x000a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0011"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0011",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #11",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x000b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0012"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0012",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #12",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x000c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0013"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0013",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #13",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x000d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0014"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0014",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #14",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x000e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0015"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0015",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #15",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x000f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0016"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0016",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #16",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0010::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0017"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0017",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #17",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0011::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0018"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0018",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #18",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0012::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0019"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0019",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #19",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0013::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0020"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0020",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #20",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0014::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0021"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0021",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #21",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0015::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0022"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0022",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #22",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0016::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0023"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0023",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #23",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0017::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0024"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0024",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #24",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0018::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0025"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0025",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #25",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0019::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0026"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0026",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #26",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x001a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0027"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0027",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #27",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x001b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0028"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0028",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #28",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x001c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0029"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0029",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #29",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x001d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0030"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0030",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #30",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x001e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0031"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0031",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #31",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x001f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0032"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0032",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #32",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0020::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0033"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0033",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #33",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0021::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0034"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0034",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #34",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0022::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0035"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0035",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #35",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0023::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0036"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0036",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #36",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0024::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0037"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0037",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #37",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0025::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0038"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0038",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #38",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0026::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0039"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0039",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #39",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0027::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0040"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0040",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #40",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0028::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0041"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0041",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #41",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0029::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0042"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0042",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #42",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x002a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0043"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0043",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #43",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x002b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0044"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0044",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #44",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x002c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0045"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0045",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #45",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x002d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0046"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0046",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #46",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x002e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0047"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0047",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #47",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x002f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0048"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0048",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #48",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0030::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0049"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0049",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #49",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0031::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0050"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0050",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #50",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0032::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0051"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0051",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #51",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0033::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0052"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0052",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #52",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0034::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0053"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0053",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #53",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0035::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0054"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0054",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #54",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0036::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0055"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0055",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #55",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0037::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0056"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0056",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #56",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0038::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0057"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0057",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #57",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0039::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0058"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0058",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #58",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x003a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0059"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0059",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #59",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x003b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0060"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0060",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #60",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x003c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0061"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0061",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #61",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x003d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0062"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0062",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #62",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x003e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0063"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0063",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #63",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x003f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0064"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0064",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #64",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0040::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0065"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0065",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #65",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0041::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0066"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0066",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #66",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0042::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0067"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0067",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #67",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0043::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0068"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0068",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #68",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0044::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0069"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0069",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #69",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0045::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0070"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0070",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #70",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0046::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0071"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0071",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #71",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0047::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0072"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0072",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #72",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0048::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0073"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0073",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #73",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0049::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0074"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0074",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #74",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x004a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0075"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0075",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #75",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x004b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0076"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0076",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #76",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x004c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0077"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0077",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #77",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x004d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0078"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0078",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #78",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x004e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0079"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0079",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #79",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x004f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0080"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0080",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #80",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0050::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0081"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0081",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #81",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0051::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0082"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0082",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #82",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0052::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0083"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0083",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #83",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0053::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0084"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0084",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #84",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0054::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0085"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0085",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #85",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0055::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0086"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0086",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #86",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0056::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0087"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0087",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #87",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0057::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0088"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0088",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #88",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0058::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0089"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0089",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #89",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0059::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0090"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0090",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #90",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x005a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0091"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0091",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #91",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x005b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0092"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0092",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #92",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x005c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0093"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0093",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #93",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x005d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0094"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0094",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #94",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x005e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0095"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0095",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #95",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x005f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0096"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0096",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #96",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0060::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0097"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0097",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #97",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0061::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0098"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0098",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #98",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0062::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0099"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0099",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #99",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0063::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0100"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0100",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #100",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0064::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0101"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0101",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #101",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0065::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0102"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0102",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #102",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0066::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0103"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0103",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #103",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0067::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0104"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0104",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #104",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0068::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0105"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0105",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #105",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0069::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0106"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0106",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #106",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x006a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0107"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0107",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #107",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x006b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0108"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0108",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #108",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x006c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0109"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0109",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #109",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x006d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0110"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0110",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #110",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x006e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0111"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0111",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #111",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x006f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0112"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0112",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #112",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0070::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0113"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0113",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #113",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0071::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0114"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0114",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #114",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0072::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0115"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0115",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #115",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0073::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0116"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0116",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #116",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0074::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0117"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0117",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #117",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0075::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0118"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0118",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #118",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0076::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0119"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0119",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #119",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0077::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0120"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0120",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #120",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0078::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0121"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0121",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #121",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0079::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0122"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0122",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #122",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x007a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0123"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0123",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #123",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x007b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0124"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0124",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #124",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x007c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0125"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0125",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #125",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x007d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0126"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0126",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #126",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x007e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0127"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0127",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #127",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x007f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0128"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0128",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #128",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0080::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0129"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0129",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #129",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0081::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0130"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0130",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #130",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0082::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0131"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0131",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #131",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0083::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0132"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0132",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #132",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0084::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0133"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0133",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #133",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0085::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0134"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0134",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #134",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0086::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0135"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0135",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #135",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0087::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0136"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0136",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #136",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0088::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0137"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0137",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #137",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0089::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0138"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0138",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #138",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x008a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0139"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0139",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #139",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x008b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0140"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0140",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #140",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x008c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0141"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0141",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #141",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x008d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0142"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0142",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #142",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x008e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0143"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0143",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #143",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x008f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0144"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0144",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #144",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0090::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0145"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0145",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #145",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0091::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0146"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0146",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #146",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0092::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0147"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0147",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #147",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0093::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0148"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0148",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #148",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0094::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0149"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0149",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #149",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0095::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0150"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0150",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #150",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0096::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0151"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0151",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #151",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0097::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0152"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0152",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #152",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0098::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0153"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0153",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #153",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0099::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0154"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0154",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #154",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x009a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0155"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0155",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #155",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x009b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0156"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0156",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #156",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x009c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0157"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0157",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #157",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x009d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0158"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0158",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #158",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x009e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0159"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0159",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #159",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x009f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0160"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0160",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #160",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00a0::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0161"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0161",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #161",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00a1::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0162"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0162",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #162",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00a2::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0163"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0163",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #163",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00a3::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0164"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0164",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #164",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00a4::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0165"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0165",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #165",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00a5::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0166"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0166",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #166",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00a6::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0167"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0167",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #167",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00a7::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0168"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0168",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #168",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00a8::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0169"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0169",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #169",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00a9::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0170"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0170",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #170",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00aa::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0171"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0171",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #171",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00ab::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0172"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0172",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #172",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00ac::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0173"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0173",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #173",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00ad::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0174"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0174",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #174",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00ae::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0175"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0175",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #175",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00af::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0176"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0176",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #176",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00b0::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0177"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0177",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #177",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00b1::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0178"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0178",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #178",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00b2::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0179"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0179",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #179",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00b3::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0180"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0180",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #180",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00b4::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0181"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0181",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #181",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00b5::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0182"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0182",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #182",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00b6::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0183"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0183",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #183",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00b7::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0184"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0184",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #184",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00b8::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0185"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0185",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #185",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00b9::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0186"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0186",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #186",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00ba::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0187"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0187",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #187",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00bb::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0188"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0188",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #188",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00bc::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0189"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0189",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #189",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00bd::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0190"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0190",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #190",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00be::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0191"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0191",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #191",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00bf::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0192"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0192",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #192",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00c0::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0193"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0193",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #193",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00c1::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0194"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0194",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #194",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00c2::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0195"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0195",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #195",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00c3::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0196"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0196",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #196",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00c4::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0197"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0197",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #197",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00c5::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0198"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0198",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #198",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00c6::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0199"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0199",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #199",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00c7::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0200"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0200",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #200",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00c8::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0201"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0201",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #201",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00c9::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0202"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0202",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #202",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ca::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0203"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0203",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #203",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00cb::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0204"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0204",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #204",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00cc::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0205"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0205",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #205",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00cd::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0206"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0206",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #206",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00ce::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0207"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0207",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #207",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00cf::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0208"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0208",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #208",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00d0::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0209"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0209",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #209",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00d1::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0210"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0210",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #210",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00d2::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0211"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0211",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #211",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00d3::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0212"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0212",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #212",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00d4::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0213"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0213",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #213",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00d5::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0214"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0214",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #214",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00d6::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0215"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0215",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #215",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00d7::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0216"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0216",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #216",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00d8::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0217"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0217",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #217",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00d9::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0218"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0218",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #218",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00da::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0219"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0219",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #219",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00db::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0220"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0220",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #220",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00dc::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0221"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0221",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #221",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00dd::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0222"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0222",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #222",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00de::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0223"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0223",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #223",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00df::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0224"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0224",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #224",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00e0::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0225"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0225",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #225",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00e1::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0226"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0226",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #226",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00e2::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0227"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0227",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #227",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00e3::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0228"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0228",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #228",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00e4::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0229"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0229",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #229",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00e5::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0230"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0230",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #230",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00e6::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0231"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0231",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #231",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00e7::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0232"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0232",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #232",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00e8::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0233"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0233",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #233",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00e9::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0234"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0234",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #234",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00ea::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0235"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0235",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #235",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00eb::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0236"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0236",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #236",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00ec::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0237"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0237",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #237",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00ed::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0238"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0238",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #238",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ee::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0239"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0239",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #239",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00ef::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0240"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0240",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #240",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00f0::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0241"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0241",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #241",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00f1::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0242"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0242",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #242",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00f2::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0243"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0243",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #243",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00f3::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0244"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0244",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #244",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00f4::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0245"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0245",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #245",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00f5::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0246"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0246",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #246",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00f6::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0247"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0247",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #247",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00f7::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0248"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0248",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #248",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00f8::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0249"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0249",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #249",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00f9::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0250"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0250",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #250",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00fa::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0251"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0251",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #251",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00fb::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0252"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0252",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #252",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00fc::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0253"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0253",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #253",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00fd::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0254"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0254",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #254",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00fe::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0255"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0255",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #255",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00ff::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0256"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0256",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #256",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0100::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0257"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0257",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #257",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0101::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0258"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0258",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #258",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0102::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0259"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0259",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #259",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0103::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0260"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0260",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #260",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0104::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0261"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0261",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #261",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0105::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0262"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0262",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #262",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0106::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0263"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0263",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #263",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0107::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0264"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0264",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #264",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0108::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0265"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0265",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #265",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0109::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0266"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0266",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #266",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x010a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0267"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0267",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #267",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x010b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0268"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0268",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #268",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x010c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0269"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0269",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #269",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x010d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0270"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0270",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #270",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x010e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0271"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0271",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #271",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x010f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0272"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0272",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #272",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0110::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0273"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0273",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #273",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0111::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0274"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0274",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #274",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0112::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0275"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0275",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #275",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0113::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0276"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0276",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #276",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0114::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0277"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0277",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #277",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0115::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0278"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0278",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #278",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0116::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0279"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0279",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #279",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0117::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0280"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0280",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #280",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0118::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0281"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0281",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #281",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0119::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0282"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0282",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #282",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x011a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0283"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0283",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #283",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x011b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0284"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0284",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #284",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x011c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0285"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0285",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #285",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x011d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0286"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0286",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #286",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x011e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0287"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0287",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #287",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x011f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0288"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0288",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #288",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0120::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0289"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0289",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #289",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0121::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0290"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0290",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #290",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0122::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0291"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0291",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #291",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0123::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0292"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0292",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #292",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0124::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0293"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0293",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #293",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0125::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0294"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0294",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #294",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0126::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0295"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0295",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #295",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0127::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0296"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0296",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #296",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0128::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0297"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0297",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #297",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0129::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0298"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0298",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #298",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x012a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0299"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0299",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #299",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x012b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0300"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0300",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #300",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x012c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0301"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0301",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #301",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x012d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0302"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0302",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #302",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x012e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0303"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0303",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #303",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x012f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0304"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0304",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #304",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0130::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0305"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0305",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #305",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0131::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0306"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0306",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #306",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0132::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0307"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0307",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #307",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0133::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0308"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0308",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #308",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0134::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0309"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0309",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #309",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0135::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0310"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0310",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #310",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0136::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0311"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0311",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #311",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0137::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0312"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0312",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #312",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0138::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0313"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0313",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #313",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0139::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0314"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0314",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #314",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x013a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0315"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0315",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #315",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x013b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0316"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0316",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #316",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x013c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0317"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0317",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #317",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x013d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0318"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0318",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #318",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x013e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0319"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0319",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #319",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x013f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0320"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0320",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #320",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0140::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0321"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0321",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #321",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0141::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0322"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0322",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #322",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0142::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0323"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0323",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #323",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0143::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0324"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0324",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #324",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0144::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0325"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0325",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #325",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0145::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0326"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0326",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #326",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0146::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0327"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0327",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #327",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0147::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0328"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0328",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #328",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0148::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0329"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0329",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #329",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0149::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0330"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0330",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #330",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x014a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0331"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0331",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #331",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x014b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0332"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0332",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #332",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x014c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0333"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0333",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #333",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x014d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0334"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0334",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #334",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x014e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0335"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0335",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #335",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x014f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0336"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0336",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #336",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0150::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0337"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0337",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #337",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0151::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0338"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0338",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #338",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0152::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0339"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0339",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #339",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0153::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0340"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0340",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #340",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0154::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0341"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0341",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #341",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0155::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0342"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0342",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #342",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0156::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0343"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0343",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #343",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0157::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0344"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0344",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #344",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0158::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0345"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0345",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #345",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0159::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0346"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0346",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #346",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x015a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0347"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0347",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #347",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x015b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0348"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0348",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #348",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x015c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0349"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0349",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #349",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x015d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0350"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0350",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #350",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x015e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0351"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0351",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #351",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x015f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0352"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0352",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #352",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0160::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0353"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0353",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #353",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0161::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0354"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0354",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #354",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0162::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0355"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0355",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #355",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0163::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0356"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0356",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #356",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0164::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0357"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0357",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #357",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0165::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0358"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0358",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #358",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0166::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0359"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0359",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #359",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0167::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0360"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0360",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #360",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0168::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0361"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0361",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #361",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0169::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0362"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0362",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #362",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x016a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0363"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0363",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #363",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x016b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0364"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0364",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #364",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x016c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0365"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0365",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #365",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x016d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0366"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0366",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #366",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x016e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0367"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0367",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #367",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x016f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0368"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0368",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #368",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0170::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0369"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0369",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #369",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0171::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0370"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0370",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #370",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0172::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0371"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0371",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #371",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0173::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0372"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0372",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #372",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0174::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0373"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0373",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #373",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0175::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0374"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0374",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #374",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0176::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0375"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0375",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #375",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0177::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0376"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0376",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #376",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0178::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0377"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0377",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #377",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0179::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0378"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0378",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #378",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x017a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0379"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0379",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #379",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x017b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0380"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0380",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #380",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x017c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0381"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0381",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #381",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x017d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0382"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0382",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #382",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x017e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0383"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0383",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #383",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x017f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0384"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0384",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #384",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0180::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0385"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0385",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #385",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0181::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0386"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0386",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #386",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0182::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0387"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0387",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #387",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0183::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0388"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0388",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #388",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0184::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0389"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0389",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #389",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0185::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0390"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0390",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #390",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0186::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0391"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0391",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #391",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0187::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0392"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0392",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #392",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0188::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0393"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0393",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #393",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0189::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0394"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0394",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #394",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x018a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0395"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0395",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #395",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x018b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0396"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0396",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #396",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x018c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0397"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0397",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #397",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x018d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0398"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0398",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #398",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x018e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0399"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0399",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #399",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x018f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0400"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0400",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #400",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0190::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0401"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0401",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #401",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0191::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0402"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0402",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #402",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0192::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0403"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0403",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #403",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0193::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0404"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0404",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #404",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0194::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0405"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0405",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #405",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0195::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0406"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0406",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #406",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0196::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0407"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0407",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #407",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0197::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0408"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0408",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #408",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0198::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0409"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0409",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #409",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0199::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0410"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0410",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #410",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x019a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0411"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0411",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #411",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x019b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0412"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0412",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #412",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x019c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0413"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0413",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #413",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x019d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0414"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0414",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #414",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x019e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0415"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0415",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #415",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x019f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0416"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0416",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #416",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x01a0::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0417"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0417",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #417",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x01a1::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0418"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0418",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #418",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x01a2::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0419"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0419",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #419",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x01a3::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0420"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0420",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #420",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x01a4::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0421"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0421",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #421",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x01a5::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0422"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0422",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #422",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x01a6::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0423"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0423",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #423",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x01a7::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0424"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0424",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #424",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x01a8::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0425"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0425",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #425",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x01a9::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0426"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0426",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #426",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x01aa::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0427"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0427",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #427",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x01ab::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0428"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0428",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #428",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x01ac::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0429"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0429",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #429",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x01ad::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0430"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0430",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #430",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x01ae::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0431"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0431",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #431",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x01af::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0432"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0432",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #432",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x01b0::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0433"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0433",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #433",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x01b1::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0434"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0434",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #434",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x01b2::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0435"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0435",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #435",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x01b3::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0436"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0436",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #436",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x01b4::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0437"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0437",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #437",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x01b5::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0438"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0438",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #438",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x01b6::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0439"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0439",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #439",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x01b7::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0440"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0440",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #440",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x01b8::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0441"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0441",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #441",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x01b9::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0442"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0442",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #442",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x01ba::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0443"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0443",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #443",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x01bb::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0444"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0444",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #444",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x01bc::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0445"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0445",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #445",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x01bd::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["REDISFILTER-R-0446"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0446",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #446",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x01be::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["REDISFILTER-R-0447"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0447",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #447",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x01bf::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["REDISFILTER-R-0448"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0448",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #448",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x01c0::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["REDISFILTER-R-0449"] = RedisFilterRule(
            rule_id="REDISFILTER-R-0449",
            name="Redis RESP3 Serialization & Command Execution Shield Detection Signature #449",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x01c1::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )

    def evaluate_traffic_stream(self, header: RedisFilterHeader) -> Dict[str, Any]:
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

redis_resp3_command_filter_instance = RedisFilterEngine()

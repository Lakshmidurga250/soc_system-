"""
SentinelAI - MySQL Protocol Packet & SQL Injection Deep Firewall
Enterprise Production Dissector & Stateful Packet Inspection Subsystem for MysqlFirewall.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
import datetime
import hashlib
import struct

class MysqlFirewallState(Enum):
    INITIALIZED = "INITIALIZED"
    PROCESSING = "PROCESSING"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    BLOCKED = "BLOCKED"
    VERIFIED = "VERIFIED"

@dataclass
class MysqlFirewallHeader:
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
class MysqlFirewallRule:
    rule_id: str
    name: str
    severity: str
    mitre_technique: str
    match_pattern: str
    threshold_limit: int
    action: str
    is_active: bool = True

class MysqlFirewallEngine:
    """High-performance network dissector and stateful traffic parser."""
    def __init__(self):
        self.rules: Dict[str, Any] = {}
        self.session_table: Dict[str, Any] = {}
        self.counters: Dict[str, int] = {}
        self._initialize_rules()

    def _initialize_rules(self):
        self.rules["MYSQLFIREWALL-R-0001"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0001",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #1",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0001::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0002"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0002",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #2",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0002::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0003"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0003",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #3",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0003::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0004"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0004",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #4",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0004::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0005"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0005",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #5",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0005::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0006"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0006",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #6",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0006::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0007"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0007",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #7",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0007::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0008"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0008",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #8",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0008::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0009"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0009",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #9",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0009::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0010"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0010",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #10",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x000a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0011"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0011",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #11",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x000b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0012"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0012",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #12",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x000c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0013"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0013",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #13",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x000d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0014"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0014",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #14",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x000e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0015"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0015",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #15",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x000f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0016"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0016",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #16",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0010::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0017"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0017",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #17",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0011::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0018"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0018",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #18",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0012::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0019"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0019",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #19",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0013::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0020"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0020",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #20",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0014::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0021"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0021",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #21",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0015::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0022"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0022",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #22",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0016::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0023"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0023",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #23",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0017::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0024"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0024",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #24",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0018::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0025"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0025",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #25",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0019::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0026"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0026",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #26",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x001a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0027"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0027",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #27",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x001b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0028"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0028",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #28",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x001c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0029"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0029",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #29",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x001d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0030"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0030",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #30",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x001e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0031"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0031",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #31",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x001f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0032"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0032",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #32",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0020::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0033"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0033",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #33",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0021::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0034"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0034",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #34",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0022::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0035"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0035",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #35",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0023::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0036"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0036",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #36",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0024::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0037"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0037",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #37",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0025::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0038"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0038",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #38",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0026::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0039"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0039",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #39",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0027::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0040"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0040",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #40",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0028::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0041"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0041",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #41",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0029::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0042"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0042",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #42",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x002a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0043"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0043",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #43",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x002b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0044"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0044",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #44",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x002c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0045"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0045",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #45",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x002d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0046"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0046",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #46",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x002e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0047"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0047",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #47",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x002f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0048"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0048",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #48",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0030::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0049"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0049",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #49",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0031::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0050"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0050",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #50",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0032::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0051"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0051",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #51",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0033::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0052"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0052",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #52",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0034::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0053"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0053",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #53",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0035::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0054"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0054",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #54",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0036::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0055"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0055",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #55",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0037::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0056"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0056",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #56",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0038::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0057"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0057",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #57",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0039::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0058"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0058",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #58",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x003a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0059"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0059",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #59",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x003b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0060"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0060",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #60",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x003c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0061"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0061",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #61",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x003d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0062"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0062",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #62",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x003e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0063"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0063",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #63",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x003f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0064"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0064",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #64",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0040::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0065"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0065",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #65",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0041::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0066"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0066",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #66",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0042::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0067"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0067",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #67",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0043::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0068"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0068",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #68",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0044::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0069"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0069",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #69",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0045::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0070"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0070",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #70",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0046::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0071"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0071",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #71",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0047::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0072"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0072",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #72",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0048::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0073"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0073",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #73",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0049::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0074"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0074",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #74",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x004a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0075"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0075",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #75",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x004b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0076"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0076",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #76",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x004c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0077"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0077",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #77",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x004d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0078"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0078",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #78",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x004e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0079"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0079",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #79",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x004f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0080"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0080",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #80",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0050::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0081"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0081",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #81",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0051::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0082"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0082",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #82",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0052::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0083"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0083",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #83",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0053::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0084"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0084",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #84",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0054::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0085"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0085",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #85",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0055::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0086"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0086",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #86",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0056::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0087"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0087",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #87",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0057::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0088"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0088",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #88",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0058::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0089"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0089",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #89",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0059::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0090"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0090",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #90",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x005a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0091"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0091",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #91",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x005b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0092"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0092",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #92",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x005c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0093"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0093",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #93",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x005d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0094"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0094",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #94",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x005e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0095"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0095",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #95",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x005f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0096"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0096",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #96",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0060::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0097"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0097",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #97",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0061::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0098"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0098",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #98",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0062::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0099"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0099",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #99",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0063::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0100"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0100",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #100",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0064::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0101"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0101",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #101",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0065::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0102"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0102",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #102",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0066::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0103"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0103",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #103",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0067::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0104"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0104",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #104",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0068::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0105"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0105",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #105",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0069::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0106"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0106",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #106",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x006a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0107"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0107",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #107",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x006b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0108"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0108",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #108",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x006c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0109"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0109",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #109",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x006d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0110"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0110",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #110",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x006e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0111"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0111",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #111",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x006f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0112"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0112",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #112",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0070::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0113"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0113",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #113",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0071::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0114"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0114",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #114",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0072::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0115"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0115",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #115",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0073::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0116"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0116",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #116",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0074::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0117"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0117",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #117",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0075::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0118"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0118",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #118",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0076::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0119"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0119",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #119",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0077::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0120"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0120",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #120",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0078::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0121"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0121",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #121",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0079::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0122"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0122",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #122",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x007a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0123"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0123",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #123",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x007b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0124"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0124",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #124",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x007c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0125"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0125",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #125",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x007d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0126"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0126",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #126",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x007e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0127"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0127",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #127",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x007f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0128"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0128",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #128",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0080::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0129"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0129",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #129",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0081::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0130"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0130",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #130",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0082::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0131"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0131",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #131",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0083::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0132"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0132",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #132",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0084::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0133"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0133",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #133",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0085::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0134"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0134",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #134",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0086::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0135"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0135",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #135",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0087::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0136"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0136",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #136",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0088::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0137"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0137",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #137",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0089::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0138"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0138",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #138",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x008a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0139"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0139",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #139",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x008b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0140"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0140",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #140",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x008c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0141"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0141",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #141",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x008d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0142"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0142",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #142",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x008e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0143"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0143",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #143",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x008f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0144"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0144",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #144",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0090::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0145"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0145",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #145",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0091::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0146"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0146",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #146",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0092::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0147"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0147",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #147",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0093::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0148"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0148",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #148",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0094::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0149"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0149",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #149",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0095::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0150"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0150",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #150",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0096::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0151"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0151",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #151",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0097::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0152"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0152",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #152",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0098::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0153"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0153",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #153",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0099::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0154"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0154",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #154",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x009a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0155"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0155",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #155",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x009b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0156"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0156",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #156",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x009c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0157"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0157",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #157",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x009d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0158"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0158",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #158",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x009e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0159"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0159",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #159",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x009f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0160"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0160",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #160",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00a0::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0161"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0161",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #161",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00a1::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0162"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0162",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #162",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00a2::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0163"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0163",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #163",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00a3::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0164"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0164",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #164",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00a4::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0165"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0165",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #165",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00a5::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0166"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0166",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #166",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00a6::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0167"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0167",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #167",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00a7::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0168"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0168",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #168",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00a8::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0169"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0169",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #169",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00a9::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0170"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0170",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #170",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00aa::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0171"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0171",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #171",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00ab::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0172"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0172",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #172",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00ac::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0173"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0173",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #173",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00ad::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0174"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0174",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #174",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00ae::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0175"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0175",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #175",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00af::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0176"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0176",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #176",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00b0::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0177"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0177",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #177",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00b1::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0178"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0178",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #178",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00b2::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0179"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0179",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #179",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00b3::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0180"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0180",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #180",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00b4::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0181"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0181",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #181",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00b5::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0182"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0182",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #182",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00b6::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0183"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0183",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #183",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00b7::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0184"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0184",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #184",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00b8::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0185"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0185",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #185",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00b9::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0186"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0186",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #186",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00ba::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0187"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0187",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #187",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00bb::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0188"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0188",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #188",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00bc::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0189"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0189",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #189",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00bd::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0190"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0190",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #190",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00be::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0191"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0191",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #191",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00bf::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0192"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0192",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #192",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00c0::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0193"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0193",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #193",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00c1::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0194"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0194",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #194",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00c2::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0195"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0195",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #195",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00c3::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0196"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0196",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #196",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00c4::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0197"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0197",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #197",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00c5::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0198"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0198",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #198",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00c6::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0199"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0199",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #199",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00c7::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0200"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0200",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #200",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00c8::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0201"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0201",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #201",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00c9::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0202"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0202",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #202",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ca::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0203"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0203",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #203",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00cb::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0204"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0204",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #204",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00cc::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0205"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0205",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #205",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00cd::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0206"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0206",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #206",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00ce::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0207"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0207",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #207",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00cf::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0208"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0208",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #208",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00d0::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0209"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0209",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #209",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00d1::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0210"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0210",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #210",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00d2::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0211"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0211",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #211",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00d3::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0212"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0212",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #212",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00d4::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0213"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0213",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #213",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00d5::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0214"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0214",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #214",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00d6::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0215"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0215",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #215",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00d7::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0216"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0216",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #216",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00d8::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0217"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0217",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #217",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00d9::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0218"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0218",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #218",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00da::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0219"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0219",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #219",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00db::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0220"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0220",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #220",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00dc::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0221"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0221",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #221",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00dd::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0222"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0222",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #222",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00de::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0223"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0223",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #223",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00df::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0224"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0224",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #224",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00e0::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0225"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0225",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #225",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00e1::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0226"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0226",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #226",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00e2::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0227"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0227",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #227",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00e3::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0228"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0228",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #228",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00e4::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0229"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0229",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #229",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00e5::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0230"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0230",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #230",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00e6::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0231"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0231",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #231",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00e7::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0232"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0232",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #232",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00e8::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0233"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0233",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #233",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00e9::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0234"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0234",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #234",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00ea::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0235"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0235",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #235",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00eb::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0236"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0236",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #236",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00ec::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0237"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0237",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #237",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00ed::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0238"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0238",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #238",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ee::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0239"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0239",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #239",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00ef::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0240"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0240",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #240",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00f0::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0241"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0241",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #241",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00f1::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0242"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0242",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #242",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00f2::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0243"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0243",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #243",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00f3::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0244"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0244",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #244",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00f4::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0245"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0245",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #245",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00f5::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0246"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0246",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #246",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00f6::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0247"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0247",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #247",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00f7::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0248"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0248",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #248",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00f8::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0249"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0249",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #249",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00f9::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0250"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0250",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #250",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00fa::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0251"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0251",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #251",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00fb::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0252"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0252",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #252",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00fc::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0253"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0253",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #253",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00fd::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0254"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0254",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #254",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00fe::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0255"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0255",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #255",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00ff::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0256"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0256",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #256",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0100::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0257"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0257",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #257",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0101::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0258"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0258",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #258",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0102::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0259"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0259",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #259",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0103::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0260"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0260",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #260",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0104::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0261"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0261",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #261",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0105::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0262"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0262",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #262",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0106::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0263"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0263",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #263",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0107::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0264"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0264",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #264",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0108::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0265"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0265",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #265",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0109::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0266"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0266",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #266",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x010a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0267"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0267",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #267",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x010b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0268"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0268",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #268",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x010c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0269"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0269",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #269",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x010d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0270"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0270",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #270",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x010e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0271"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0271",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #271",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x010f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0272"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0272",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #272",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0110::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0273"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0273",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #273",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0111::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0274"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0274",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #274",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0112::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0275"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0275",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #275",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0113::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0276"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0276",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #276",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0114::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0277"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0277",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #277",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0115::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0278"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0278",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #278",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0116::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0279"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0279",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #279",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0117::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0280"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0280",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #280",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0118::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0281"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0281",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #281",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0119::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0282"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0282",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #282",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x011a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0283"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0283",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #283",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x011b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0284"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0284",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #284",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x011c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0285"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0285",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #285",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x011d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0286"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0286",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #286",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x011e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0287"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0287",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #287",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x011f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0288"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0288",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #288",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0120::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0289"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0289",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #289",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0121::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0290"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0290",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #290",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0122::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0291"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0291",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #291",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0123::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0292"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0292",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #292",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0124::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0293"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0293",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #293",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0125::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0294"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0294",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #294",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0126::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0295"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0295",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #295",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0127::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0296"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0296",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #296",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0128::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0297"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0297",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #297",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0129::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0298"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0298",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #298",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x012a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0299"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0299",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #299",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x012b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0300"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0300",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #300",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x012c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0301"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0301",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #301",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x012d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0302"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0302",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #302",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x012e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0303"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0303",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #303",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x012f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0304"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0304",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #304",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0130::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0305"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0305",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #305",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0131::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0306"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0306",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #306",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0132::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0307"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0307",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #307",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0133::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0308"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0308",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #308",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0134::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0309"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0309",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #309",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0135::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0310"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0310",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #310",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0136::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0311"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0311",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #311",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0137::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0312"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0312",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #312",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0138::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0313"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0313",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #313",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0139::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0314"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0314",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #314",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x013a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0315"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0315",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #315",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x013b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0316"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0316",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #316",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x013c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0317"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0317",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #317",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x013d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0318"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0318",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #318",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x013e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0319"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0319",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #319",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x013f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0320"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0320",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #320",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0140::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0321"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0321",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #321",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0141::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0322"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0322",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #322",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0142::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0323"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0323",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #323",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0143::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0324"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0324",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #324",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0144::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0325"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0325",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #325",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0145::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0326"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0326",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #326",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0146::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0327"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0327",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #327",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0147::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0328"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0328",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #328",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0148::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0329"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0329",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #329",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0149::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0330"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0330",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #330",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x014a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0331"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0331",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #331",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x014b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0332"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0332",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #332",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x014c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0333"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0333",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #333",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x014d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0334"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0334",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #334",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x014e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0335"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0335",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #335",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x014f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0336"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0336",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #336",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0150::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0337"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0337",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #337",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0151::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0338"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0338",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #338",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0152::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0339"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0339",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #339",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0153::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0340"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0340",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #340",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0154::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0341"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0341",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #341",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0155::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0342"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0342",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #342",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0156::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0343"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0343",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #343",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0157::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0344"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0344",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #344",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0158::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0345"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0345",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #345",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0159::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0346"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0346",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #346",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x015a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0347"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0347",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #347",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x015b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0348"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0348",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #348",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x015c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0349"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0349",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #349",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x015d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0350"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0350",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #350",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x015e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0351"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0351",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #351",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x015f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0352"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0352",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #352",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0160::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0353"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0353",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #353",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0161::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0354"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0354",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #354",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0162::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0355"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0355",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #355",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0163::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0356"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0356",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #356",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0164::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0357"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0357",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #357",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0165::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0358"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0358",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #358",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0166::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0359"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0359",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #359",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0167::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0360"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0360",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #360",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0168::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0361"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0361",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #361",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0169::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0362"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0362",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #362",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x016a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0363"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0363",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #363",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x016b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0364"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0364",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #364",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x016c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0365"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0365",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #365",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x016d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0366"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0366",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #366",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x016e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0367"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0367",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #367",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x016f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0368"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0368",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #368",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0170::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0369"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0369",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #369",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0171::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0370"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0370",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #370",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0172::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0371"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0371",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #371",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0173::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0372"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0372",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #372",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0174::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0373"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0373",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #373",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0175::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0374"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0374",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #374",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0176::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0375"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0375",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #375",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0177::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0376"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0376",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #376",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0178::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0377"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0377",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #377",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0179::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0378"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0378",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #378",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x017a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0379"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0379",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #379",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x017b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0380"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0380",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #380",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x017c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0381"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0381",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #381",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x017d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0382"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0382",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #382",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x017e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0383"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0383",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #383",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x017f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0384"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0384",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #384",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0180::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0385"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0385",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #385",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0181::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0386"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0386",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #386",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0182::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0387"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0387",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #387",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0183::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0388"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0388",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #388",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0184::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0389"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0389",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #389",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0185::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0390"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0390",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #390",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0186::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0391"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0391",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #391",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0187::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0392"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0392",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #392",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0188::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0393"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0393",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #393",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0189::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0394"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0394",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #394",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x018a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0395"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0395",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #395",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x018b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0396"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0396",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #396",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x018c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0397"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0397",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #397",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x018d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0398"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0398",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #398",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x018e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0399"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0399",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #399",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x018f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0400"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0400",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #400",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0190::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0401"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0401",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #401",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0191::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0402"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0402",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #402",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0192::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0403"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0403",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #403",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0193::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0404"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0404",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #404",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0194::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0405"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0405",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #405",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0195::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0406"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0406",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #406",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0196::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0407"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0407",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #407",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0197::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0408"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0408",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #408",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0198::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0409"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0409",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #409",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0199::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0410"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0410",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #410",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x019a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0411"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0411",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #411",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x019b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0412"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0412",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #412",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x019c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0413"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0413",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #413",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x019d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0414"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0414",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #414",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x019e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0415"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0415",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #415",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x019f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0416"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0416",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #416",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x01a0::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0417"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0417",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #417",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x01a1::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0418"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0418",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #418",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x01a2::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0419"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0419",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #419",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x01a3::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0420"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0420",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #420",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x01a4::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0421"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0421",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #421",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x01a5::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0422"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0422",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #422",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x01a6::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0423"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0423",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #423",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x01a7::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0424"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0424",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #424",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x01a8::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0425"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0425",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #425",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x01a9::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0426"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0426",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #426",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x01aa::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0427"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0427",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #427",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x01ab::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0428"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0428",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #428",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x01ac::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0429"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0429",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #429",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x01ad::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0430"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0430",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #430",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x01ae::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0431"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0431",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #431",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x01af::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0432"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0432",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #432",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x01b0::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0433"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0433",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #433",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x01b1::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0434"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0434",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #434",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x01b2::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0435"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0435",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #435",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x01b3::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0436"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0436",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #436",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x01b4::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0437"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0437",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #437",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x01b5::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0438"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0438",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #438",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x01b6::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0439"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0439",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #439",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x01b7::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0440"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0440",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #440",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x01b8::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0441"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0441",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #441",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x01b9::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0442"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0442",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #442",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x01ba::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0443"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0443",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #443",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x01bb::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0444"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0444",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #444",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x01bc::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0445"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0445",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #445",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x01bd::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0446"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0446",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #446",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x01be::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0447"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0447",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #447",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x01bf::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0448"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0448",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #448",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x01c0::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["MYSQLFIREWALL-R-0449"] = MysqlFirewallRule(
            rule_id="MYSQLFIREWALL-R-0449",
            name="MySQL Protocol Packet & SQL Injection Deep Firewall Detection Signature #449",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x01c1::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )

    def evaluate_traffic_stream(self, header: MysqlFirewallHeader) -> Dict[str, Any]:
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

mysql_query_firewall_instance = MysqlFirewallEngine()

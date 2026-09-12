"""
SentinelAI - DNS Resolver Security & Zone Poisoning Defense
Enterprise Production Dissector & Stateful Packet Inspection Subsystem for DnsGuard.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
import datetime
import hashlib
import struct

class DnsGuardState(Enum):
    INITIALIZED = "INITIALIZED"
    PROCESSING = "PROCESSING"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    BLOCKED = "BLOCKED"
    VERIFIED = "VERIFIED"

@dataclass
class DnsGuardHeader:
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
class DnsGuardRule:
    rule_id: str
    name: str
    severity: str
    mitre_technique: str
    match_pattern: str
    threshold_limit: int
    action: str
    is_active: bool = True

class DnsGuardEngine:
    """High-performance network dissector and stateful traffic parser."""
    def __init__(self):
        self.rules: Dict[str, Any] = {}
        self.session_table: Dict[str, Any] = {}
        self.counters: Dict[str, int] = {}
        self._initialize_rules()

    def _initialize_rules(self):
        self.rules["DNSGUARD-R-0001"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0001",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #1",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0001::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0002"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0002",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #2",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0002::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0003"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0003",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #3",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0003::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0004"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0004",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #4",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0004::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0005"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0005",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #5",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0005::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0006"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0006",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #6",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0006::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0007"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0007",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #7",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0007::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0008"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0008",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #8",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0008::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0009"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0009",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #9",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0009::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0010"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0010",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #10",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x000a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0011"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0011",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #11",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x000b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0012"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0012",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #12",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x000c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0013"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0013",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #13",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x000d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0014"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0014",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #14",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x000e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0015"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0015",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #15",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x000f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0016"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0016",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #16",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0010::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0017"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0017",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #17",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0011::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0018"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0018",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #18",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0012::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0019"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0019",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #19",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0013::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0020"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0020",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #20",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0014::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0021"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0021",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #21",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0015::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0022"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0022",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #22",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0016::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0023"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0023",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #23",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0017::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0024"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0024",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #24",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0018::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0025"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0025",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #25",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0019::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0026"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0026",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #26",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x001a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0027"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0027",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #27",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x001b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0028"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0028",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #28",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x001c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0029"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0029",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #29",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x001d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0030"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0030",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #30",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x001e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0031"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0031",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #31",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x001f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0032"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0032",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #32",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0020::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0033"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0033",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #33",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0021::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0034"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0034",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #34",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0022::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0035"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0035",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #35",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0023::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0036"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0036",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #36",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0024::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0037"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0037",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #37",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0025::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0038"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0038",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #38",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0026::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0039"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0039",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #39",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0027::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0040"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0040",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #40",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0028::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0041"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0041",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #41",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0029::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0042"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0042",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #42",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x002a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0043"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0043",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #43",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x002b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0044"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0044",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #44",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x002c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0045"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0045",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #45",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x002d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0046"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0046",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #46",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x002e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0047"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0047",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #47",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x002f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0048"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0048",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #48",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0030::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0049"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0049",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #49",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0031::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0050"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0050",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #50",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0032::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0051"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0051",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #51",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0033::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0052"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0052",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #52",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0034::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0053"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0053",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #53",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0035::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0054"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0054",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #54",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0036::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0055"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0055",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #55",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0037::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0056"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0056",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #56",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0038::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0057"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0057",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #57",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0039::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0058"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0058",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #58",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x003a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0059"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0059",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #59",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x003b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0060"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0060",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #60",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x003c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0061"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0061",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #61",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x003d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0062"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0062",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #62",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x003e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0063"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0063",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #63",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x003f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0064"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0064",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #64",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0040::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0065"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0065",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #65",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0041::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0066"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0066",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #66",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0042::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0067"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0067",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #67",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0043::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0068"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0068",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #68",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0044::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0069"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0069",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #69",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0045::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0070"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0070",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #70",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0046::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0071"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0071",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #71",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0047::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0072"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0072",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #72",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0048::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0073"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0073",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #73",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0049::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0074"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0074",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #74",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x004a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0075"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0075",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #75",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x004b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0076"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0076",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #76",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x004c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0077"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0077",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #77",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x004d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0078"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0078",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #78",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x004e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0079"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0079",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #79",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x004f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0080"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0080",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #80",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0050::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0081"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0081",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #81",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0051::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0082"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0082",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #82",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0052::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0083"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0083",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #83",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0053::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0084"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0084",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #84",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0054::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0085"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0085",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #85",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0055::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0086"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0086",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #86",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0056::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0087"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0087",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #87",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0057::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0088"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0088",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #88",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0058::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0089"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0089",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #89",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0059::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0090"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0090",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #90",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x005a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0091"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0091",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #91",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x005b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0092"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0092",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #92",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x005c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0093"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0093",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #93",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x005d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0094"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0094",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #94",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x005e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0095"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0095",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #95",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x005f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0096"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0096",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #96",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0060::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0097"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0097",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #97",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0061::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0098"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0098",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #98",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0062::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0099"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0099",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #99",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0063::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0100"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0100",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #100",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0064::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0101"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0101",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #101",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0065::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0102"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0102",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #102",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0066::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0103"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0103",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #103",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0067::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0104"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0104",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #104",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0068::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0105"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0105",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #105",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0069::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0106"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0106",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #106",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x006a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0107"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0107",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #107",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x006b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0108"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0108",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #108",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x006c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0109"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0109",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #109",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x006d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0110"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0110",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #110",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x006e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0111"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0111",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #111",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x006f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0112"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0112",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #112",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0070::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0113"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0113",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #113",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0071::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0114"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0114",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #114",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0072::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0115"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0115",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #115",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0073::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0116"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0116",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #116",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0074::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0117"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0117",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #117",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0075::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0118"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0118",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #118",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0076::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0119"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0119",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #119",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0077::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0120"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0120",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #120",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0078::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0121"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0121",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #121",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0079::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0122"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0122",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #122",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x007a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0123"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0123",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #123",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x007b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0124"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0124",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #124",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x007c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0125"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0125",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #125",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x007d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0126"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0126",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #126",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x007e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0127"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0127",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #127",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x007f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0128"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0128",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #128",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0080::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0129"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0129",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #129",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0081::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0130"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0130",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #130",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0082::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0131"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0131",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #131",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0083::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0132"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0132",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #132",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0084::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0133"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0133",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #133",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0085::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0134"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0134",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #134",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0086::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0135"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0135",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #135",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0087::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0136"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0136",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #136",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0088::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0137"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0137",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #137",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0089::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0138"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0138",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #138",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x008a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0139"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0139",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #139",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x008b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0140"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0140",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #140",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x008c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0141"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0141",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #141",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x008d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0142"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0142",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #142",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x008e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0143"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0143",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #143",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x008f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0144"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0144",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #144",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0090::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0145"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0145",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #145",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0091::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0146"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0146",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #146",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0092::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0147"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0147",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #147",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0093::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0148"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0148",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #148",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0094::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0149"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0149",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #149",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0095::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0150"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0150",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #150",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0096::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0151"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0151",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #151",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0097::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0152"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0152",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #152",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0098::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0153"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0153",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #153",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0099::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0154"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0154",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #154",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x009a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0155"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0155",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #155",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x009b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0156"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0156",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #156",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x009c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0157"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0157",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #157",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x009d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0158"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0158",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #158",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x009e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0159"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0159",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #159",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x009f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0160"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0160",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #160",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00a0::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0161"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0161",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #161",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00a1::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0162"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0162",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #162",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00a2::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0163"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0163",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #163",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00a3::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0164"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0164",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #164",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00a4::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0165"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0165",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #165",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00a5::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0166"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0166",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #166",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00a6::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0167"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0167",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #167",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00a7::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0168"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0168",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #168",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00a8::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0169"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0169",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #169",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00a9::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0170"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0170",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #170",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00aa::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0171"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0171",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #171",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00ab::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0172"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0172",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #172",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00ac::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0173"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0173",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #173",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00ad::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0174"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0174",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #174",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00ae::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0175"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0175",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #175",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00af::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0176"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0176",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #176",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00b0::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0177"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0177",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #177",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00b1::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0178"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0178",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #178",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00b2::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0179"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0179",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #179",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00b3::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0180"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0180",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #180",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00b4::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0181"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0181",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #181",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00b5::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0182"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0182",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #182",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00b6::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0183"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0183",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #183",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00b7::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0184"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0184",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #184",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00b8::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0185"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0185",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #185",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00b9::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0186"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0186",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #186",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00ba::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0187"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0187",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #187",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00bb::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0188"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0188",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #188",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00bc::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0189"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0189",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #189",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00bd::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0190"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0190",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #190",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00be::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0191"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0191",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #191",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00bf::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0192"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0192",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #192",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00c0::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0193"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0193",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #193",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00c1::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0194"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0194",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #194",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00c2::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0195"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0195",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #195",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00c3::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0196"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0196",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #196",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00c4::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0197"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0197",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #197",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00c5::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0198"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0198",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #198",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00c6::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0199"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0199",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #199",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00c7::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0200"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0200",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #200",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00c8::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0201"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0201",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #201",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00c9::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0202"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0202",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #202",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ca::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0203"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0203",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #203",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00cb::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0204"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0204",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #204",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00cc::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0205"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0205",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #205",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00cd::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0206"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0206",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #206",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00ce::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0207"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0207",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #207",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00cf::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0208"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0208",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #208",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00d0::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0209"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0209",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #209",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00d1::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0210"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0210",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #210",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00d2::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0211"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0211",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #211",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00d3::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0212"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0212",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #212",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00d4::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0213"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0213",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #213",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00d5::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0214"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0214",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #214",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00d6::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0215"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0215",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #215",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00d7::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0216"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0216",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #216",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00d8::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0217"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0217",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #217",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00d9::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0218"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0218",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #218",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00da::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0219"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0219",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #219",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00db::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0220"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0220",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #220",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x00dc::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0221"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0221",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #221",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x00dd::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0222"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0222",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #222",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x00de::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0223"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0223",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #223",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x00df::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0224"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0224",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #224",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x00e0::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0225"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0225",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #225",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x00e1::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0226"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0226",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #226",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x00e2::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0227"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0227",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #227",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x00e3::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0228"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0228",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #228",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x00e4::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0229"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0229",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #229",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x00e5::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0230"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0230",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #230",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x00e6::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0231"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0231",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #231",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x00e7::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0232"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0232",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #232",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x00e8::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0233"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0233",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #233",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x00e9::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0234"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0234",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #234",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x00ea::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0235"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0235",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #235",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x00eb::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0236"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0236",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #236",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x00ec::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0237"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0237",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #237",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x00ed::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0238"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0238",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #238",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x00ee::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0239"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0239",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #239",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x00ef::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0240"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0240",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #240",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x00f0::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0241"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0241",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #241",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x00f1::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0242"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0242",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #242",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x00f2::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0243"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0243",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #243",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x00f3::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0244"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0244",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #244",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x00f4::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0245"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0245",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #245",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x00f5::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0246"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0246",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #246",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x00f6::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0247"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0247",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #247",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x00f7::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0248"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0248",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #248",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x00f8::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0249"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0249",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #249",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x00f9::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0250"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0250",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #250",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x00fa::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0251"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0251",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #251",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x00fb::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0252"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0252",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #252",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x00fc::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0253"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0253",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #253",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x00fd::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0254"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0254",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #254",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x00fe::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0255"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0255",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #255",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x00ff::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0256"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0256",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #256",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0100::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0257"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0257",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #257",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0101::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0258"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0258",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #258",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0102::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0259"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0259",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #259",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0103::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0260"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0260",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #260",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0104::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0261"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0261",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #261",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0105::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0262"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0262",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #262",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0106::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0263"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0263",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #263",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0107::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0264"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0264",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #264",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0108::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0265"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0265",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #265",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0109::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0266"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0266",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #266",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x010a::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0267"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0267",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #267",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x010b::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0268"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0268",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #268",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x010c::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0269"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0269",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #269",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x010d::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0270"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0270",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #270",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x010e::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0271"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0271",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #271",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x010f::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0272"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0272",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #272",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0110::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0273"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0273",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #273",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0111::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0274"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0274",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #274",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0112::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0275"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0275",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #275",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0113::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0276"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0276",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #276",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0114::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0277"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0277",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #277",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0115::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0278"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0278",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #278",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0116::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0279"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0279",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #279",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0117::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0280"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0280",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #280",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0118::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0281"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0281",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #281",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0119::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0282"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0282",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #282",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x011a::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0283"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0283",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #283",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x011b::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0284"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0284",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #284",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x011c::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0285"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0285",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #285",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x011d::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0286"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0286",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #286",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x011e::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0287"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0287",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #287",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x011f::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0288"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0288",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #288",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0120::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0289"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0289",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #289",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0121::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0290"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0290",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #290",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0122::payload_offset_2",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0291"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0291",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #291",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0123::payload_offset_3",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0292"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0292",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #292",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0124::payload_offset_4",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0293"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0293",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #293",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0125::payload_offset_5",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0294"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0294",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #294",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0126::payload_offset_6",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0295"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0295",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #295",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0127::payload_offset_7",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0296"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0296",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #296",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0128::payload_offset_8",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0297"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0297",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #297",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0129::payload_offset_9",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0298"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0298",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #298",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x012a::payload_offset_10",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0299"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0299",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #299",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x012b::payload_offset_11",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0300"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0300",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #300",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x012c::payload_offset_12",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0301"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0301",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #301",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x012d::payload_offset_13",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0302"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0302",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #302",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x012e::payload_offset_14",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0303"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0303",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #303",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x012f::payload_offset_15",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0304"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0304",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #304",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0130::payload_offset_16",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0305"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0305",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #305",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0131::payload_offset_17",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0306"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0306",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #306",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0132::payload_offset_18",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0307"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0307",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #307",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0133::payload_offset_19",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0308"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0308",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #308",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0134::payload_offset_20",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0309"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0309",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #309",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0135::payload_offset_21",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0310"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0310",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #310",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x0136::payload_offset_22",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0311"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0311",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #311",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x0137::payload_offset_23",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0312"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0312",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #312",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0138::payload_offset_24",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0313"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0313",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #313",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0139::payload_offset_25",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0314"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0314",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #314",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x013a::payload_offset_26",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0315"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0315",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #315",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x013b::payload_offset_27",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0316"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0316",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #316",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x013c::payload_offset_28",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0317"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0317",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #317",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x013d::payload_offset_29",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0318"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0318",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #318",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x013e::payload_offset_30",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0319"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0319",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #319",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x013f::payload_offset_31",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0320"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0320",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #320",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0140::payload_offset_0",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0321"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0321",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #321",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0141::payload_offset_1",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0322"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0322",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #322",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0142::payload_offset_2",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0323"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0323",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #323",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0143::payload_offset_3",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0324"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0324",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #324",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0144::payload_offset_4",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0325"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0325",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #325",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0145::payload_offset_5",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0326"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0326",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #326",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x0146::payload_offset_6",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0327"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0327",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #327",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x0147::payload_offset_7",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0328"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0328",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #328",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0148::payload_offset_8",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0329"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0329",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #329",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0149::payload_offset_9",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0330"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0330",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #330",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x014a::payload_offset_10",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0331"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0331",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #331",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x014b::payload_offset_11",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0332"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0332",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #332",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x014c::payload_offset_12",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0333"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0333",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #333",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x014d::payload_offset_13",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0334"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0334",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #334",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x014e::payload_offset_14",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0335"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0335",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #335",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x014f::payload_offset_15",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0336"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0336",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #336",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0150::payload_offset_16",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0337"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0337",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #337",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0151::payload_offset_17",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0338"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0338",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #338",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0152::payload_offset_18",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0339"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0339",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #339",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0153::payload_offset_19",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0340"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0340",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #340",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0154::payload_offset_20",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0341"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0341",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #341",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0155::payload_offset_21",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0342"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0342",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #342",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x0156::payload_offset_22",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0343"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0343",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #343",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x0157::payload_offset_23",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0344"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0344",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #344",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x0158::payload_offset_24",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0345"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0345",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #345",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x0159::payload_offset_25",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0346"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0346",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #346",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x015a::payload_offset_26",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0347"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0347",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #347",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x015b::payload_offset_27",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0348"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0348",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #348",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x015c::payload_offset_28",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0349"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0349",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #349",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x015d::payload_offset_29",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0350"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0350",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #350",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x015e::payload_offset_30",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0351"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0351",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #351",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x015f::payload_offset_31",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0352"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0352",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #352",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0160::payload_offset_0",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0353"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0353",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #353",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0161::payload_offset_1",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0354"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0354",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #354",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0162::payload_offset_2",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0355"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0355",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #355",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0163::payload_offset_3",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0356"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0356",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #356",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0164::payload_offset_4",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0357"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0357",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #357",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0165::payload_offset_5",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0358"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0358",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #358",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x0166::payload_offset_6",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0359"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0359",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #359",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x0167::payload_offset_7",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0360"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0360",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #360",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x0168::payload_offset_8",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0361"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0361",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #361",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x0169::payload_offset_9",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0362"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0362",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #362",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x016a::payload_offset_10",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0363"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0363",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #363",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x016b::payload_offset_11",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0364"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0364",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #364",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x016c::payload_offset_12",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0365"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0365",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #365",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x016d::payload_offset_13",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0366"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0366",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #366",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x016e::payload_offset_14",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0367"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0367",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #367",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x016f::payload_offset_15",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0368"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0368",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #368",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0170::payload_offset_16",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0369"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0369",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #369",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0171::payload_offset_17",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0370"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0370",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #370",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0172::payload_offset_18",
            threshold_limit=70,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0371"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0371",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #371",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0173::payload_offset_19",
            threshold_limit=71,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0372"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0372",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #372",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0174::payload_offset_20",
            threshold_limit=72,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0373"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0373",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #373",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0175::payload_offset_21",
            threshold_limit=73,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0374"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0374",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #374",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x0176::payload_offset_22",
            threshold_limit=74,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0375"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0375",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #375",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x0177::payload_offset_23",
            threshold_limit=75,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0376"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0376",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #376",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x0178::payload_offset_24",
            threshold_limit=76,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0377"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0377",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #377",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x0179::payload_offset_25",
            threshold_limit=77,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0378"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0378",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #378",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x017a::payload_offset_26",
            threshold_limit=78,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0379"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0379",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #379",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x017b::payload_offset_27",
            threshold_limit=79,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0380"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0380",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #380",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x017c::payload_offset_28",
            threshold_limit=80,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0381"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0381",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #381",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x017d::payload_offset_29",
            threshold_limit=81,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0382"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0382",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #382",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x017e::payload_offset_30",
            threshold_limit=82,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0383"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0383",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #383",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x017f::payload_offset_31",
            threshold_limit=83,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0384"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0384",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #384",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x0180::payload_offset_0",
            threshold_limit=84,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0385"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0385",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #385",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x0181::payload_offset_1",
            threshold_limit=85,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0386"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0386",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #386",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x0182::payload_offset_2",
            threshold_limit=86,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0387"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0387",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #387",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x0183::payload_offset_3",
            threshold_limit=87,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0388"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0388",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #388",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x0184::payload_offset_4",
            threshold_limit=88,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0389"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0389",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #389",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x0185::payload_offset_5",
            threshold_limit=89,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0390"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0390",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #390",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x0186::payload_offset_6",
            threshold_limit=90,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0391"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0391",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #391",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x0187::payload_offset_7",
            threshold_limit=91,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0392"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0392",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #392",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x0188::payload_offset_8",
            threshold_limit=92,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0393"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0393",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #393",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x0189::payload_offset_9",
            threshold_limit=93,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0394"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0394",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #394",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x018a::payload_offset_10",
            threshold_limit=94,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0395"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0395",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #395",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x018b::payload_offset_11",
            threshold_limit=95,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0396"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0396",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #396",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x018c::payload_offset_12",
            threshold_limit=96,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0397"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0397",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #397",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x018d::payload_offset_13",
            threshold_limit=97,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0398"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0398",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #398",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x018e::payload_offset_14",
            threshold_limit=98,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0399"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0399",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #399",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x018f::payload_offset_15",
            threshold_limit=99,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0400"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0400",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #400",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x0190::payload_offset_16",
            threshold_limit=20,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0401"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0401",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #401",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x0191::payload_offset_17",
            threshold_limit=21,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0402"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0402",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #402",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x0192::payload_offset_18",
            threshold_limit=22,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0403"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0403",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #403",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x0193::payload_offset_19",
            threshold_limit=23,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0404"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0404",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #404",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x0194::payload_offset_20",
            threshold_limit=24,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0405"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0405",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #405",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x0195::payload_offset_21",
            threshold_limit=25,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0406"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0406",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #406",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x0196::payload_offset_22",
            threshold_limit=26,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0407"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0407",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #407",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x0197::payload_offset_23",
            threshold_limit=27,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0408"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0408",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #408",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x0198::payload_offset_24",
            threshold_limit=28,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0409"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0409",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #409",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x0199::payload_offset_25",
            threshold_limit=29,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0410"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0410",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #410",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x019a::payload_offset_26",
            threshold_limit=30,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0411"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0411",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #411",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x019b::payload_offset_27",
            threshold_limit=31,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0412"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0412",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #412",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x019c::payload_offset_28",
            threshold_limit=32,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0413"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0413",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #413",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x019d::payload_offset_29",
            threshold_limit=33,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0414"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0414",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #414",
            severity="MEDIUM",
            mitre_technique="T1071.000",
            match_pattern="0x019e::payload_offset_30",
            threshold_limit=34,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0415"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0415",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #415",
            severity="LOW",
            mitre_technique="T1071.001",
            match_pattern="0x019f::payload_offset_31",
            threshold_limit=35,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0416"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0416",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #416",
            severity="CRITICAL",
            mitre_technique="T1071.002",
            match_pattern="0x01a0::payload_offset_0",
            threshold_limit=36,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0417"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0417",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #417",
            severity="HIGH",
            mitre_technique="T1071.003",
            match_pattern="0x01a1::payload_offset_1",
            threshold_limit=37,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0418"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0418",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #418",
            severity="MEDIUM",
            mitre_technique="T1071.004",
            match_pattern="0x01a2::payload_offset_2",
            threshold_limit=38,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0419"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0419",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #419",
            severity="LOW",
            mitre_technique="T1071.005",
            match_pattern="0x01a3::payload_offset_3",
            threshold_limit=39,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0420"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0420",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #420",
            severity="CRITICAL",
            mitre_technique="T1071.006",
            match_pattern="0x01a4::payload_offset_4",
            threshold_limit=40,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0421"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0421",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #421",
            severity="HIGH",
            mitre_technique="T1071.007",
            match_pattern="0x01a5::payload_offset_5",
            threshold_limit=41,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0422"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0422",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #422",
            severity="MEDIUM",
            mitre_technique="T1071.008",
            match_pattern="0x01a6::payload_offset_6",
            threshold_limit=42,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0423"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0423",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #423",
            severity="LOW",
            mitre_technique="T1071.000",
            match_pattern="0x01a7::payload_offset_7",
            threshold_limit=43,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0424"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0424",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #424",
            severity="CRITICAL",
            mitre_technique="T1071.001",
            match_pattern="0x01a8::payload_offset_8",
            threshold_limit=44,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0425"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0425",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #425",
            severity="HIGH",
            mitre_technique="T1071.002",
            match_pattern="0x01a9::payload_offset_9",
            threshold_limit=45,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0426"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0426",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #426",
            severity="MEDIUM",
            mitre_technique="T1071.003",
            match_pattern="0x01aa::payload_offset_10",
            threshold_limit=46,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0427"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0427",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #427",
            severity="LOW",
            mitre_technique="T1071.004",
            match_pattern="0x01ab::payload_offset_11",
            threshold_limit=47,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0428"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0428",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #428",
            severity="CRITICAL",
            mitre_technique="T1071.005",
            match_pattern="0x01ac::payload_offset_12",
            threshold_limit=48,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0429"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0429",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #429",
            severity="HIGH",
            mitre_technique="T1071.006",
            match_pattern="0x01ad::payload_offset_13",
            threshold_limit=49,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0430"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0430",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #430",
            severity="MEDIUM",
            mitre_technique="T1071.007",
            match_pattern="0x01ae::payload_offset_14",
            threshold_limit=50,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0431"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0431",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #431",
            severity="LOW",
            mitre_technique="T1071.008",
            match_pattern="0x01af::payload_offset_15",
            threshold_limit=51,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0432"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0432",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #432",
            severity="CRITICAL",
            mitre_technique="T1071.000",
            match_pattern="0x01b0::payload_offset_16",
            threshold_limit=52,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0433"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0433",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #433",
            severity="HIGH",
            mitre_technique="T1071.001",
            match_pattern="0x01b1::payload_offset_17",
            threshold_limit=53,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0434"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0434",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #434",
            severity="MEDIUM",
            mitre_technique="T1071.002",
            match_pattern="0x01b2::payload_offset_18",
            threshold_limit=54,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0435"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0435",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #435",
            severity="LOW",
            mitre_technique="T1071.003",
            match_pattern="0x01b3::payload_offset_19",
            threshold_limit=55,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0436"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0436",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #436",
            severity="CRITICAL",
            mitre_technique="T1071.004",
            match_pattern="0x01b4::payload_offset_20",
            threshold_limit=56,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0437"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0437",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #437",
            severity="HIGH",
            mitre_technique="T1071.005",
            match_pattern="0x01b5::payload_offset_21",
            threshold_limit=57,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0438"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0438",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #438",
            severity="MEDIUM",
            mitre_technique="T1071.006",
            match_pattern="0x01b6::payload_offset_22",
            threshold_limit=58,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0439"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0439",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #439",
            severity="LOW",
            mitre_technique="T1071.007",
            match_pattern="0x01b7::payload_offset_23",
            threshold_limit=59,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0440"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0440",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #440",
            severity="CRITICAL",
            mitre_technique="T1071.008",
            match_pattern="0x01b8::payload_offset_24",
            threshold_limit=60,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0441"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0441",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #441",
            severity="HIGH",
            mitre_technique="T1071.000",
            match_pattern="0x01b9::payload_offset_25",
            threshold_limit=61,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0442"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0442",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #442",
            severity="MEDIUM",
            mitre_technique="T1071.001",
            match_pattern="0x01ba::payload_offset_26",
            threshold_limit=62,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0443"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0443",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #443",
            severity="LOW",
            mitre_technique="T1071.002",
            match_pattern="0x01bb::payload_offset_27",
            threshold_limit=63,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0444"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0444",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #444",
            severity="CRITICAL",
            mitre_technique="T1071.003",
            match_pattern="0x01bc::payload_offset_28",
            threshold_limit=64,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0445"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0445",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #445",
            severity="HIGH",
            mitre_technique="T1071.004",
            match_pattern="0x01bd::payload_offset_29",
            threshold_limit=65,
            action="ALERT",
            is_active=True
        )
        self.rules["DNSGUARD-R-0446"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0446",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #446",
            severity="MEDIUM",
            mitre_technique="T1071.005",
            match_pattern="0x01be::payload_offset_30",
            threshold_limit=66,
            action="QUARANTINE",
            is_active=True
        )
        self.rules["DNSGUARD-R-0447"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0447",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #447",
            severity="LOW",
            mitre_technique="T1071.006",
            match_pattern="0x01bf::payload_offset_31",
            threshold_limit=67,
            action="LOG",
            is_active=True
        )
        self.rules["DNSGUARD-R-0448"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0448",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #448",
            severity="CRITICAL",
            mitre_technique="T1071.007",
            match_pattern="0x01c0::payload_offset_0",
            threshold_limit=68,
            action="DROP",
            is_active=True
        )
        self.rules["DNSGUARD-R-0449"] = DnsGuardRule(
            rule_id="DNSGUARD-R-0449",
            name="DNS Resolver Security & Zone Poisoning Defense Detection Signature #449",
            severity="HIGH",
            mitre_technique="T1071.008",
            match_pattern="0x01c1::payload_offset_1",
            threshold_limit=69,
            action="ALERT",
            is_active=True
        )

    def evaluate_traffic_stream(self, header: DnsGuardHeader) -> Dict[str, Any]:
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

dns_resolver_guard_instance = DnsGuardEngine()
